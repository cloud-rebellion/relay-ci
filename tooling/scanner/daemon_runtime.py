"""Phase1-only owned bridge/tracer/container. Qualified storage.py is unchanged."""
from contextlib import AbstractContextManager
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import time

from daemon_policy import CONFIG, CONFIG_PATH, DB_PATH, MEMORY, REFERENCE, SETTINGS, SUBNET
from registry import require, Refusal


def rule_identity(tokens):
    require(len(tokens) >= 4 and tokens[0] == "-A", "private-rule-inventory-shape")
    values, modules = {}, []
    for offset in range(2, len(tokens), 2):
        require(offset + 1 < len(tokens), "private-rule-inventory-shape")
        key, value = tokens[offset:offset + 2]
        require(key in {"-i", "-o", "-s", "-d", "-p", "--dports", "--ctstate", "--comment", "-j", "-m"},
                "private-rule-inventory-unknown-option")
        if key == "-m":
            modules.append(value)
        else:
            require(key not in values, "private-rule-inventory-duplicate-option")
            values[key] = ",".join(sorted(value.split(","))) if key in {"--dports", "--ctstate"} else value
    # iptables-save may print an implicit protocol module; no extra predicates
    # are admitted, and every other module/option remains part of identity.
    modules = [x for x in modules if x != values.get("-p")]
    return json.dumps([tokens[1], values, sorted(modules)], sort_keys=True)


class PrivateEgress(AbstractContextManager):
    """Only an owned bridge on a fresh public VM; never default-Docker settings.

    The existing dockerd keeps iptables=false/ip-forward=false. Require existing
    host forwarding, do not change a sysctl, and add/delete only these exact
    owner-commented rules. No published/listening host port is introduced.
    """
    def __init__(self, daemon):
        self.d = daemon
        self.name = "relay-phase1-" + daemon.owner
        self.bridge = "rsc" + daemon.owner[:12]
        self.rules = []
        self.network_attempted = False

    def rule(self, table, chain, arguments):
        full = ["-t", table, chain, *arguments, "-m", "comment", "--comment", self.name]
        self.rules.append(full)  # intent precedes an operation with unknown response
        self.d.command(["sudo", "-n", "iptables", "-w", "10", *full[:2], "-I", full[2], "1", *full[3:]])

    def verify(self):
        rows = json.loads(self.d.docker(["network", "inspect", self.name]).stdout)
        require(len(rows) == 1, "private-network-count")
        value = rows[0]
        require(value.get("Name") == self.name and value.get("Driver") == "bridge"
                and value.get("Labels") == {"relay.ci.owner": self.d.owner}
                and value.get("Options", {}).get("com.docker.network.bridge.name") == self.bridge
                and value.get("IPAM", {}).get("Config") == [{"Subnet": SUBNET, "Gateway": "172.30.247.1"}],
                "private-network-identity")
        return value

    def inventory(self, table):
        result = self.d.command(["sudo", "-n", "iptables-save", "-t", table])
        require(result.returncode == 0, "private-rule-inventory-unknown")
        selected = []
        for line in result.stdout.decode().splitlines():
            if not line.startswith("-A "):
                continue
            tokens = shlex.split(line)
            if "--comment" in tokens and tokens[tokens.index("--comment") + 1] == self.name:
                selected.append(rule_identity(tokens))
        require(len(selected) == len(set(selected)), "private-rule-inventory-duplicate")
        expected = {rule_identity(["-A", full[2], *full[3:]]) for full in self.rules if full[1] == table}
        require(set(selected) <= expected, "private-rule-inventory-foreign-owned-comment")
        return set(selected)

    def __enter__(self):
        require(Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1",
                "existing-ipv4-forwarding-required-no-sysctl-change")
        routes = json.loads(self.d.command(["ip", "-j", "-4", "route", "show", "table", "all"]).stdout)
        selected = ipaddress.ip_network(SUBNET)
        require(all(not selected.overlaps(ipaddress.ip_network(x["dst"], strict=False))
                    for x in routes if x.get("dst") not in {None, "default", "0.0.0.0/0"}),
                "private-subnet-overlaps-existing-route")
        route = json.loads(self.d.command(["ip", "-j", "-4", "route", "get", "1.1.1.1"]).stdout)
        require(len(route) == 1 and re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", route[0].get("dev", "")),
                "private-egress-interface")
        self.outbound = route[0]["dev"]
        try:
            self.network_attempted = True
            self.d.docker(["network", "create", "--driver", "bridge", "--subnet", SUBNET,
                "--gateway", "172.30.247.1", "--label", "relay.ci.owner=" + self.d.owner,
                "--opt", "com.docker.network.bridge.name=" + self.bridge,
                "--opt", "com.docker.network.bridge.enable_ip_masquerade=false", self.name])
            require(not self.verify().get("Containers"), "private-network-not-empty")
            # Insert drop first; later insertions place finite web/DNS and reply
            # accepts above it. Never flush, change policy, or touch Docker chains.
            self.rule("filter", "FORWARD", ["-i", self.bridge, "-j", "DROP"])
            self.rule("filter", "INPUT", ["-i", self.bridge, "-j", "DROP"])
            self.rule("filter", "INPUT", ["-i", self.bridge, "-m", "conntrack",
                "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
            self.rule("filter", "FORWARD", ["-i", self.outbound, "-o", self.bridge, "-d", SUBNET,
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
            for protocol, ports in (("tcp", "80,443,53"), ("udp", "53")):
                self.rule("filter", "FORWARD", ["-i", self.bridge, "-o", self.outbound, "-s", SUBNET,
                    "-p", protocol, "-m", "multiport", "--dports", ports,
                    "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED", "-j", "ACCEPT"])
            self.rule("nat", "POSTROUTING", ["-s", SUBNET, "-o", self.outbound, "-j", "MASQUERADE"])
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        # Container cleanup is a precondition: don't remove a populated bridge.
        if self.network_attempted:
            require(not self.verify().get("Containers"), "private-network-still-populated")
        for full in reversed(self.rules):
            prefix, chain, args = full[:2], full[2], full[3:]
            identity = rule_identity(["-A", chain, *args])
            if identity in self.inventory(full[1]):
                self.d.command(["sudo", "-n", "iptables", "-w", "10", *prefix, "-C", chain, *args])
                self.d.command(["sudo", "-n", "iptables", "-w", "10", *prefix, "-D", chain, *args])
                require(identity not in self.inventory(full[1]), "private-rule-not-settled")
        if self.network_attempted:
            self.verify()
            self.d.docker(["network", "rm", self.name])
            rows = self.d.docker(["network", "ls", "--filter", "name=^" + self.name + "$", "--format", "{{.ID}}"])
            require(not rows.stdout.strip(), "private-network-not-settled")
        return False


class OwnedTrace(AbstractContextManager):
    """Trace only the owned service tree before container creation, capped8MiB."""
    def __init__(self, daemon):
        self.d = daemon
        self.unit = daemon.unit + "-trace"
        self.path = daemon.mount / "clamd-config.trace"
        self.attempted = False

    def state(self):
        result = self.d.command(["sudo", "-n", "systemctl", "show", self.unit,
            "--property=ActiveState,MainPID,ExecStart,ControlGroup"])
        value = dict(x.split("=", 1) for x in result.stdout.decode().splitlines() if "=" in x)
        require(str(self.path) in value.get("ExecStart", "") and "strace" in value["ExecStart"]
                and value.get("ControlGroup", "").endswith("/" + self.unit + ".service"),
                "owned-trace-unit-identity")
        return value

    def __enter__(self):
        main = self.d.verify_unit()
        # The unit owns dockerd and its private containerd. Existing children
        # must be attached too; future clamd children are followed by strace-f.
        result = self.d.command(["sudo", "-n", "cat", "/sys/fs/cgroup/system.slice/" + self.d.unit + ".service/cgroup.procs"])
        pids = [int(x) for x in result.stdout.split() if x.isdigit()]
        require(main in pids and 1 <= len(pids) <= 32 and all(x > 1 for x in pids), "owned-trace-service-pids")
        self.d.command(["strace", "--version"])
        self.attempted = True
        self.d.command(["sudo", "-n", "systemd-run", "--unit=" + self.unit,
            "--property=MemoryMax=256M", "--property=CPUQuota=100%", "--property=TasksMax=128",
            "--property=RuntimeMaxSec=6600", "--property=LimitFSIZE=8388608",
            "--property=KillMode=control-group", "--property=TimeoutStopSec=10",
            "strace", "-f", "-s", "4096", "-e", "trace=openat,openat2,execve", "-o", str(self.path),
            *[part for pid in pids for part in ("-p", str(pid))]])
        # systemd-active alone is insufficient: prove every current thread in
        # the captured owned service processes is already traced before create.
        probe = ("import json,pathlib,sys; rows=[]; "
                 "pids=[int(x) for x in sys.argv[1:]]; "
                 "tasks=[p for n in pids for p in pathlib.Path('/proc/'+str(n)+'/task').glob('*/status')]; "
                 "assert 0<len(tasks)<=512; "
                 "rows=[int(next(x.split(':',1)[1] for x in p.read_text().splitlines() if x.startswith('TracerPid:'))) for p in tasks]; "
                 "print(json.dumps(rows))")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            state = self.state()
            require(state.get("ActiveState") == "active" and state.get("MainPID", "0").isdecimal(), "owned-trace-not-active")
            values = json.loads(self.d.command(["sudo", "-n", "python3", "-c", probe, *map(str, pids)]).stdout)
            if values and all(type(x) is int and x == int(state["MainPID"]) > 1 for x in values):
                return self
            time.sleep(0.2)
        raise Refusal("owned-trace-attachment-not-proven")

    def snapshot(self):
        require(self.state().get("ActiveState") == "active", "owned-trace-stopped-before-witness")
        value = self.d.command(["sudo", "-n", "cat", str(self.path)]).stdout
        require(0 < len(value) < 8 << 20, "owned-trace-exhausted-or-empty")
        return value

    def __exit__(self, *_):
        if self.attempted:
            self.state()
            self.d.command(["sudo", "-n", "systemctl", "stop", self.unit])
            require(self.state().get("ActiveState") != "active", "owned-trace-not-settled")
        return False


class Candidate(AbstractContextManager):
    def __init__(self, daemon, network, exact_config):
        self.d, self.network, self.exact_config = daemon, network, exact_config
        self.name = "relay-daemon-" + daemon.owner
        self.volume = self.name + "-signatures"
        self.cid = None
        self.create_attempted = False
        self.volume_attempted = False

    def inspect(self):
        rows = json.loads(self.d.docker(["inspect", self.name]).stdout)
        require(len(rows) == 1, "candidate-inspect-count")
        value = rows[0]
        require(value.get("Name") == "/" + self.name and re.fullmatch(r"[a-f0-9]{64}", value.get("Id", ""))
                and (self.cid is None or value["Id"] == self.cid)
                and value.get("Image") == CONFIG
                and value.get("Config", {}).get("Labels", {}).get("relay.ci.owner") == self.d.owner,
                "candidate-exact-identity")
        host = value.get("HostConfig", {})
        require(host.get("Memory") == MEMORY and host.get("MemorySwap") == MEMORY
                and host.get("NanoCpus") == 2000000000 and host.get("PidsLimit") == 256
                and not host.get("Privileged") and not host.get("PortBindings")
                and host.get("SecurityOpt") == ["no-new-privileges:true"], "candidate-runtime-bounds")
        config = value["Config"]
        original = self.exact_config["config"]
        require(config.get("Entrypoint") == original.get("Entrypoint") == ["/init"]
                and config.get("Cmd") == original.get("Cmd")
                and config.get("User", "") == original.get("User", ""), "candidate-inherited-startup-changed")
        expected = dict(x.split("=", 1) for x in original["Env"])
        expected.update({"CLAMD_CONF_" + k: v for k, v in SETTINGS.items()})
        expected["FRESHCLAM_CHECKS"] = "4"
        require(len(config["Env"]) == len(expected) and
                dict(x.split("=", 1) for x in config["Env"]) == expected, "candidate-environment-changed")
        networks = value.get("NetworkSettings", {}).get("Networks", {})
        require(set(networks) == {self.network.name} and not value.get("NetworkSettings", {}).get("Ports", {}).get("3310/tcp"),
                "candidate-network-or-published-port")
        members = self.network.verify().get("Containers", {})
        require(set(members) == {value["Id"]}, "candidate-private-network-membership")
        mounts = value.get("Mounts", [])
        require(len(mounts) == 1 and mounts[0].get("Type") == "volume" and mounts[0].get("Name") == self.volume
                and mounts[0].get("Destination") == DB_PATH and mounts[0].get("RW") is True,
                "candidate-signature-volume")
        return value

    def __enter__(self):
        self.d.docker(["pull", "--platform", "linux/amd64", REFERENCE], timeout=900)
        image = json.loads(self.d.docker(["image", "inspect", REFERENCE]).stdout)
        require(len(image) == 1 and image[0]["Id"] == CONFIG and
                image[0]["RootFS"]["Layers"] == self.exact_config["rootfs"]["diff_ids"], "candidate-pulled-image-closure")
        require(not self.d.docker(["volume", "ls", "--filter", "name=^" + self.volume + "$", "--format", "{{.Name}}"])
                .stdout.strip(), "candidate-volume-already-exists")
        self.volume_attempted = True
        self.d.docker(["volume", "create", "--label", "relay.ci.owner=" + self.d.owner, self.volume])
        self.verify_volume()
        self.create()
        return self

    def verify_volume(self):
        rows = json.loads(self.d.docker(["volume", "inspect", self.volume]).stdout)
        require(len(rows) == 1 and rows[0].get("Name") == self.volume and
                rows[0].get("Labels") == {"relay.ci.owner": self.d.owner} and rows[0].get("Driver") == "local"
                and not rows[0].get("Options") and rows[0].get("Mountpoint") ==
                str(self.d.mount / "docker/volumes" / self.volume / "_data"), "candidate-volume-identity")

    def create(self):
        self.create_attempted = True
        result = self.d.docker(["create", "--name", self.name, "--label", "relay.ci.owner=" + self.d.owner,
            "--network", self.network.name, "--memory=4g", "--memory-swap=4g", "--cpus=2", "--pids-limit=256",
            "--security-opt=no-new-privileges:true", "--health-start-period=35m",
            "--mount", "type=volume,src=" + self.volume + ",dst=" + DB_PATH,
            *[part for k, v in SETTINGS.items() for part in ("--env", "CLAMD_CONF_" + k + "=" + v)],
            "--env", "FRESHCLAM_CHECKS=4", REFERENCE])
        cid = result.stdout.decode().strip()
        require(re.fullmatch(r"[0-9a-f]{64}", cid) is not None, "candidate-create-response")
        self.cid = cid

    def start(self):
        self.d.docker(["start", self.name])
        self.inspect()

    def address(self):
        info = self.inspect()
        address = info["NetworkSettings"]["Networks"][self.network.name].get("IPAddress", "")
        require(ipaddress.ip_address(address) in ipaddress.ip_network(SUBNET), "candidate-private-address")
        return address

    def exchange(self, blocks, timeout=40):
        with socket.create_connection((self.address(), 3310), timeout=min(timeout, 10)) as connection:
            connection.settimeout(timeout)
            try:
                for block in blocks:
                    connection.sendall(block)
            except BrokenPipeError:
                pass  # Still require an explicit bounded nonclean response.
            output = bytearray()
            while len(output) <= 4096:
                block = connection.recv(4097 - len(output))
                if not block:
                    break
                output.extend(block)
                if b"\x00" in block:
                    break
            require(len(output) <= 4096, "candidate-response-too-large")
            return bytes(output)

    def ready(self, seconds=2100):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            info = self.inspect()
            require(info["State"]["Running"] and not info["State"].get("OOMKilled"), "candidate-exited-during-readiness")
            try:
                if self.exchange([b"zPING\x00"], 5).rstrip(b"\x00\n") == b"PONG":
                    return
            except (OSError, Refusal):
                pass
            time.sleep(5)
        raise Refusal("candidate-initial-database-or-readiness-timeout")

    def execute(self, args, timeout=60):
        self.inspect()
        return self.d.docker(["exec", self.cid, *args], timeout=timeout).stdout

    def resources(self):
        info = self.inspect()
        pid = info["State"]["Pid"]
        require(type(pid) is int and pid > 1 and not info["State"].get("OOMKilled"), "candidate-process-or-oom")
        raw = self.d.command(["sudo", "-n", "cat", "/proc/" + str(pid) + "/cgroup"]).stdout.decode()
        rows = [x[3:] for x in raw.splitlines() if x.startswith("0::")]
        require(len(rows) == 1 and rows[0].startswith("/") and ".." not in rows[0].split("/")
                and self.cid in rows[0], "candidate-cgroup-v2-identity")
        base = Path("/sys/fs/cgroup") / rows[0].lstrip("/")
        names = ("memory.max", "memory.swap.max", "memory.peak", "memory.events", "cpu.max", "cpu.stat", "pids.max", "pids.current")
        return {name: self.d.command(["sudo", "-n", "cat", str(base / name)]).stdout.decode().strip() for name in names}

    def remove(self):
        if self.create_attempted:
            info = self.inspect()
            if info["State"]["Running"]:
                self.d.docker(["stop", "--time", "30", self.cid], timeout=60)
            self.d.docker(["rm", self.cid])  # no force; never remove a running/foreign CID
            rows = self.d.docker(["ps", "-a", "--filter", "name=^/" + self.name + "$", "--format", "{{.ID}}"])
            require(not rows.stdout.strip(), "candidate-container-not-settled")
            self.cid, self.create_attempted = None, False

    def __exit__(self, *_):
        self.remove()
        if self.volume_attempted:
            self.verify_volume()
            self.d.docker(["volume", "rm", self.volume])
            rows = self.d.docker(["volume", "ls", "--filter", "name=^" + self.volume + "$", "--format", "{{.Name}}"])
            require(not rows.stdout.strip(), "candidate-volume-not-settled")
        return False
