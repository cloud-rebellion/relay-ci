"""One hard-bounded Linux filesystem and a separate owned Docker daemon.

No fallback to the runner's default Docker socket, shared image cache or remote
daemon. Refuse unsupported hosts before downloading any image or layer. This
backend is for a fresh public GitHub-hosted VM, never a developer/OVH host.
"""
from contextlib import AbstractContextManager
import json
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import subprocess
import time
import uuid
from types import SimpleNamespace

from registry import require, Refusal

GIB = 1 << 30


def public_runner(environ):
    require(environ.get("GITHUB_ACTIONS") == "true" and environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and environ.get("RUNNER_OS") == "Linux" and environ.get("RUNNER_ARCH") == "X64",
            "fresh-public-linux-runner-required")
    require(environ.get("GITHUB_REPOSITORY") == "cloud-rebellion/relay-ci" and
            environ.get("GITHUB_REPOSITORY_ID") == "1457664829" and
            environ.get("GITHUB_EVENT_NAME") == "push" and
            environ.get("GITHUB_REF") == "refs/heads/scanner/assessment-20261114",
            "scanner-assessment-event-required")
    require(not environ.get("RELAY_SOURCE_READ_KEY") and not environ.get("RELAY_PRIVATE_SOURCE_ROOT"),
            "public-scanner-private-source-forbidden")


def owned_loop(rows, expected_device, expected_file):
    require(isinstance(rows, list) and len(rows) == 1, "loop-ownership-count")
    row = rows[0]
    require(row.get("name") == expected_device and row.get("back-file") == str(expected_file),
            "loop-ownership-mismatch")


class BoundedDaemon(AbstractContextManager):
    """8 GiB *allocated* ext4 image contains all OCI, DB and daemon storage.

    The filesystem is the hard capacity boundary. All commands and stderr are
    retained privately by the caller; polling is readiness, never quota.
    """
    def __init__(self, results, *, run=subprocess.run):
        public_runner(os.environ)
        self.run = run
        self.results = Path(results).resolve()
        self.owner = uuid.uuid4().hex
        self.unit = "relay-scanner-" + self.owner
        temporary = Path(os.environ["RUNNER_TEMP"])
        require(temporary.is_absolute() and temporary.resolve() == temporary and not temporary.is_symlink(),
                "runner-temporary-root")
        self.root = temporary / self.unit
        self.mount = self.root / "bounded"
        self.backing = self.root / "storage.ext4"
        self.device = None
        self.loop_attempted = False
        self.mount_attempted = False
        self.mounted = False
        self.unit_started = False
        self.daemon_id = None
        self.commands = 0

    def command(self, args, *, allow_failure=False, timeout=60, docker=False, allocation=False):
        self.commands += 1
        name = "storage-command-" + str(self.commands)
        env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
               "HOME": str(self.root), "LANG": "C.UTF-8"}
        if docker:
            env["DOCKER_HOST"] = "unix://" + str(self.root / "docker.sock")
            env["DOCKER_CONFIG"] = str(self.root / "docker-client")
        stdout = self.results / (name + ".stdout")
        stderr = self.results / (name + ".stderr")
        def file_bound():
            maximum = 8 * GIB if allocation else 64 << 20
            resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
        try:
            with stdout.open("xb") as out, stderr.open("xb") as err:
                child = self.run(args, env=env, cwd=self.root, stdout=out, stderr=err,
                                 timeout=timeout, preexec_fn=file_bound)
        except (OSError, subprocess.TimeoutExpired):
            raise Refusal("bounded-command-transport") from None
        require(sum(x.stat().st_size for x in self.results.iterdir() if x.is_file()) <= 256 << 20,
                "bounded-diagnostic-total")
        result = SimpleNamespace(returncode=child.returncode, stdout=stdout.read_bytes(), stderr=stderr.read_bytes())
        require(allow_failure or result.returncode == 0, "bounded-command-failed-" + str(self.commands))
        return result

    def docker(self, args, **kwargs):
        require(self.daemon_id is not None, "owned-daemon-not-ready")
        return self.command(["docker", *args], docker=True, **kwargs)

    def verify_loop(self):
        require(self.device is not None and re.fullmatch(r"/dev/loop[0-9]+", self.device),
                "loop-device-shape")
        result = self.command(["sudo", "-n", "losetup", "--json", "--output", "NAME,BACK-FILE", self.device])
        owned_loop(json.loads(result.stdout)["loopdevices"], self.device, self.backing)
        info = self.backing.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                and info.st_size == 8 * GIB and stat.S_IMODE(info.st_mode) == 0o600,
                "bounded-backing-file-identity")

    def verify_mount(self):
        self.verify_loop()
        result = self.command(["findmnt", "--json", "--mountpoint", str(self.mount), "--output", "SOURCE,TARGET,FSTYPE"])
        rows = json.loads(result.stdout)["filesystems"]
        require(len(rows) == 1 and rows[0]["source"] == self.device and
                rows[0]["target"] == str(self.mount) and rows[0]["fstype"] == "ext4", "bounded-mount-identity")
        fs = os.statvfs(self.mount)
        require(0 < fs.f_blocks * fs.f_frsize <= 8 * GIB, "bounded-filesystem-capacity")

    def resolve_loop(self):
        # Resolve even a lost losetup response. No successful inventory means no
        # detach/unlink. A loop attached to an unknown backing file is not ours.
        result = self.command(["sudo", "-n", "losetup", "--json", "--output", "NAME,BACK-FILE",
                               "--associated", str(self.backing)])
        rows = json.loads(result.stdout).get("loopdevices")
        require(isinstance(rows, list) and len(rows) <= 1, "loop-inventory-ambiguous")
        if not rows:
            self.device = None
            return
        device = rows[0].get("name", "")
        require(re.fullmatch(r"/dev/loop[0-9]+", device) and
                (self.device is None or self.device == device), "loop-inventory-identity")
        owned_loop(rows, device, self.backing)
        self.device = device

    def resolve_mount(self):
        # A filtered findmnt exit1 conflates no match and read failure. Instead
        # require one successful complete inventory, then select our exact target
        # in memory. Failure/invalid JSON/wrong source preserves the resources.
        result = self.command(["findmnt", "--json", "--list", "--output", "SOURCE,TARGET,FSTYPE"])
        rows = json.loads(result.stdout).get("filesystems")
        require(isinstance(rows, list) and rows and all(isinstance(x, dict) for x in rows),
                "mount-inventory-unavailable")
        matching = [x for x in rows if x.get("target") == str(self.mount)]
        require(len(matching) <= 1, "mount-inventory-ambiguous")
        if not matching:
            self.mounted = False
            return
        require(self.device is not None and matching[0].get("source") == self.device
                and matching[0].get("fstype") == "ext4", "bounded-mount-identity")
        self.mounted = True

    def verify_unit(self):
        result = self.command(["sudo", "-n", "systemctl", "show", self.unit, "--property=MainPID,ActiveState,ExecStart,ControlGroup"])
        fields = dict(x.split("=", 1) for x in result.stdout.decode().splitlines() if "=" in x)
        require(fields.get("ActiveState") == "active" and fields.get("MainPID", "0").isdecimal()
                and int(fields["MainPID"]) > 1 and
                str(self.root / "docker.sock") in fields.get("ExecStart", "") and
                str(self.mount / "docker") in fields.get("ExecStart", "") and
                fields.get("ControlGroup", "").endswith("/" + self.unit + ".service"), "owned-daemon-unit-identity")
        return int(fields["MainPID"])

    def __enter__(self):
        require(shutil.disk_usage(self.root.parent).free >= 11 * GIB, "bounded-storage-free-space")
        self.root.mkdir(mode=0o700)
        self.mount.mkdir(mode=0o700)
        (self.root / "docker-client").mkdir(mode=0o700)
        try:
            # No truncate/sparse fallback: an inability to allocate is a refusal.
            descriptor = os.open(self.backing, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            self.command(["fallocate", "--length", str(8 * GIB), str(self.backing)], allocation=True)
            info = self.backing.stat()
            require(info.st_size == 8 * GIB and info.st_blocks * 512 >= 8 * GIB, "bounded-file-not-allocated")
            self.loop_attempted = True
            result = self.command(["sudo", "-n", "losetup", "--find", "--show", str(self.backing)])
            self.device = result.stdout.decode().strip()
            self.verify_loop()
            self.command(["sudo", "-n", "mkfs.ext4", "-F", "-q", "-m", "0", self.device])
            self.mount_attempted = True
            self.command(["sudo", "-n", "mount", "-o", "nodev,nosuid,noatime", self.device, str(self.mount)])
            self.mounted = True
            self.verify_mount()
            self.command(["sudo", "-n", "chown", str(os.getuid()) + ":" + str(os.getgid()), str(self.mount)])
            self.command(["sudo", "-n", "chmod", "0700", str(self.mount)])
            (self.root / "daemon.json").write_text("{}\n")
            self.unit_started = True
            self.command(["sudo", "-n", "systemd-run", "--unit=" + self.unit, "--collect",
                "--property=MemoryMax=1G", "--property=CPUQuota=200%", "--property=TasksMax=512",
                "--property=RuntimeMaxSec=7200", "--property=KillMode=control-group", "--property=TimeoutStopSec=20",
                "--property=StandardOutput=append:" + str(self.mount / "dockerd.log"),
                "--property=StandardError=append:" + str(self.mount / "dockerd.log"),
                "dockerd", "--host=unix://" + str(self.root / "docker.sock"),
                "--data-root=" + str(self.mount / "docker"), "--exec-root=" + str(self.root / "exec"),
                "--pidfile=" + str(self.root / "dockerd.pid"), "--storage-driver=vfs",
                "--config-file=" + str(self.root / "daemon.json"), "--bridge=none", "--iptables=false", "--ip-forward=false",
                "--ip-masq=false", "--userland-proxy=false", "--containerd-namespace=" + self.unit,
                "--containerd-plugins-namespace=" + self.unit + "-plugins"])
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                socket = self.root / "docker.sock"
                if socket.exists():
                    require(stat.S_ISSOCK(socket.lstat().st_mode), "owned-daemon-socket-type")
                    self.command(["sudo", "-n", "chown", str(os.getuid()) + ":" + str(os.getgid()), str(socket)])
                    self.command(["sudo", "-n", "chmod", "0600", str(socket)])
                    result = self.command(["docker", "info", "--format", "{{json .}}"], docker=True, allow_failure=True)
                    if result.returncode == 0:
                        value = json.loads(result.stdout)
                        require(value["DockerRootDir"] == str(self.mount / "docker") and value["Driver"] == "vfs"
                                and value.get("OSType") == "linux" and value.get("ID"), "owned-daemon-storage-identity")
                        self.daemon_id = value["ID"]
                        self.verify_unit()
                        return self
                time.sleep(1)
            raise Refusal("owned-daemon-readiness-timeout")
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        # Leave ambiguous resources intact and fail. Never detach an unverified
        # loop, unmount somebody else's mount or stop a default/shared daemon.
        if self.loop_attempted:
            self.resolve_loop()
        if self.mount_attempted:
            self.resolve_mount()
        if self.unit_started:
            self.verify_unit()
            self.command(["sudo", "-n", "systemctl", "stop", self.unit], timeout=60)
            self.unit_started = False
            self.daemon_id = None
            self.command(["sudo", "-n", "tail", "--bytes", str(4 << 20), str(self.mount / "dockerd.log")])
        if self.mounted:
            self.verify_mount()
            self.command(["sudo", "-n", "umount", str(self.mount)])
            self.resolve_mount()
            require(not self.mounted, "owned-mount-not-settled")
        if self.device:
            self.verify_loop()
            self.command(["sudo", "-n", "losetup", "--detach", self.device])
            self.resolve_loop()
            require(self.device is None, "owned-loop-not-settled")
        if self.backing.exists():
            require(not self.backing.is_symlink() and self.backing.stat().st_uid == os.getuid(),
                    "bounded-file-cleanup-identity")
            self.backing.unlink()
        return False
