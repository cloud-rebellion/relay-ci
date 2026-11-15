"""Phase1-only owned bridge/tracer/container. Qualified storage.py is unchanged."""
from contextlib import AbstractContextManager
import hashlib
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
from storage import UNIT_PROPERTIES, unit_state


PROCESS_PROBE = r'''
import json, os, pathlib, stat, sys

def bounded(path, maximum=16384):
    with open(path, 'rb') as handle:
        body = handle.read(maximum + 1)
    assert len(body) <= maximum
    return body

def identity(pid, full=False, required=None, candidate=False):
    path = pathlib.Path('/proc') / str(pid)
    raw = bounded(path / 'stat').decode()
    assert raw.split('(', 1)[0].strip() == str(pid)
    fields = raw.rsplit(')', 1)[1].split()
    start = fields[19]
    assert start.isdecimal() and int(start) > 0
    result = {'status': 'present', 'pid': pid, 'start_ticks': start, 'state': fields[0], 'ppid': int(fields[1])}
    if required is not None:
        rows = bounded(path / 'cgroup').decode().splitlines()
        groups = [row[3:] for row in rows if row.startswith('0::')]
        assert len(groups) == 1
        group = groups[0]
        assert (required in group if candidate else group == required or group.startswith(required + '/'))
        result['cgroup'] = group
    if full:
        status = dict(line.split(':', 1) for line in bounded(path / 'status').decode().splitlines() if ':' in line)
        result.update(cmdline=bounded(path / 'cmdline', 8192).decode('utf-8', 'replace').split('\0')[:-1],
                      exe=os.readlink(path / 'exe'), nspid=[int(x) for x in status['NSpid'].split()],
                      tracer_pid=int(status['TracerPid']))
        assert len(result['exe'].encode()) <= 8192 and result['nspid']
        details = os.stat(path / 'exe')
        result['exe_metadata'] = {'dev': details.st_dev, 'ino': details.st_ino, 'uid': details.st_uid,
                                  'gid': details.st_gid, 'mode': stat.S_IMODE(details.st_mode), 'bytes': details.st_size}
    assert bounded(path / 'stat').decode().rsplit(')', 1)[1].split()[19] == start
    return result

mode = sys.argv[1]
if mode == 'settled':
    pid = int(sys.argv[2]); assert pid > 1
    try:
        result = identity(pid)
    except FileNotFoundError:
        result = {'status': 'absent', 'pid': pid}
elif mode in ('identity', 'candidate'):
    pid = int(sys.argv[2]); required = sys.argv[3]; assert pid > 1
    if mode == 'candidate':
        assert len(required) == 64 and all(c in '0123456789abcdef' for c in required)
    else:
        assert required.startswith('/system.slice/relay-scanner-') and required.endswith('-trace.service')
    result = identity(pid, full=True, required=required, candidate=mode == 'candidate')
elif mode == 'tree':
    group = sys.argv[2]
    assert group.startswith('/system.slice/relay-scanner-') and group.endswith('.service')
    assert '..' not in group.split('/')
    root = pathlib.Path('/sys/fs/cgroup') / group.lstrip('/')
    assert root.resolve() == root and root.is_dir()
    directories, pids, pending = [], set(), [root]
    while pending:
        directory = pending.pop()
        assert directory.resolve() == directory and not directory.is_symlink()
        assert len(directory.relative_to(root).parts) <= 8
        directories.append('/' + directory.relative_to(pathlib.Path('/sys/fs/cgroup')).as_posix())
        assert len(directories) <= 64
        values = bounded(directory / 'cgroup.procs').split()
        assert all(value.isdigit() and int(value) > 1 for value in values)
        pids.update(int(value) for value in values); assert len(pids) <= 32
        for child in directory.iterdir():
            assert not child.is_symlink()
            if child.is_dir():
                pending.append(child)
    rows, total = [], 0
    for pid in sorted(pids):
        row = identity(pid, required=group)
        tasks = sorted((pathlib.Path('/proc') / str(pid) / 'task').iterdir())
        total += len(tasks); assert 0 < len(tasks) and total <= 512
        threads = []
        for task in tasks:
            status = dict(line.split(':', 1) for line in bounded(task / 'status').decode().splitlines() if ':' in line)
            threads.append({'tid': int(task.name), 'tracer_pid': int(status['TracerPid'])})
        row['threads'] = threads; rows.append(row)
    result = {'cgroup': group, 'directories': sorted(directories), 'processes': rows}
else:
    raise AssertionError('unsupported finite probe')
print(json.dumps(result, sort_keys=True))
'''


def owned_inventory(value, group, main):
    require(isinstance(value, dict) and value.get("cgroup") == group, "owned-trace-inventory-root")
    directories, rows = value.get("directories"), value.get("processes")
    require(isinstance(directories, list) and 0 < len(directories) <= 64 and len(set(directories)) == len(directories)
            and group in directories and all(isinstance(path, str) and ".." not in path.split("/") and
                (path == group or path.startswith(group + "/")) for path in directories), "owned-trace-inventory-escape")
    require(isinstance(rows, list) and 0 < len(rows) <= 32, "owned-trace-service-pids")
    pids, threads = set(), []
    for row in rows:
        pid = row.get("pid")
        require(type(pid) is int and pid > 1 and pid not in pids and row.get("status") == "present"
                and isinstance(row.get("start_ticks"), str) and row["start_ticks"].isdecimal()
                and row.get("cgroup") in directories, "owned-trace-process-ownership")
        pids.add(pid)
        values = row.get("threads")
        require(isinstance(values, list) and values and all(type(item.get("tid")) is int and item["tid"] > 1
                and type(item.get("tracer_pid")) is int and item["tracer_pid"] >= 0 for item in values),
                "owned-trace-thread-inventory")
        threads.extend(values)
    require(main in pids and 0 < len(threads) <= 512 and len({x["tid"] for x in threads}) == len(threads),
            "owned-trace-thread-bound")
    return sorted(pids), threads


def prior_process_settled(value, pid, start):
    require(isinstance(value, dict) and value.get("pid") == pid, "owned-trace-process-readback")
    if value.get("status") == "absent":
        return "absent"
    require(value.get("status") == "present" and isinstance(value.get("start_ticks"), str)
            and value["start_ticks"].isdecimal(), "owned-trace-process-unknown")
    require(value["start_ticks"] != start, "owned-trace-prior-process-still-present")
    return "pid-reused-prior-process-absent"


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


def error_code(error):
    value = str(error) if isinstance(error, Refusal) else type(error).__name__
    return value if re.fullmatch(r"[A-Za-z0-9-]{1,120}", value) else "details-withheld"


class OwnedTrace(AbstractContextManager):
    """Finite owned service subtree only; active identity and retired proof differ."""
    def __init__(self, daemon):
        self.d = daemon
        self.unit = daemon.unit + "-trace"
        self.path = daemon.mount / "clamd-config.trace"
        self.attempted = False
        self.stop_attempted = False
        self.prior = None
        self.cleanup_error = None
        self.cleanup_phase = "not-started"
        self.last_state = None
        self.state_reads = 0

    def _record(self, value):
        raw = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
        require(len(raw) <= 64 << 10, "owned-trace-cleanup-receipt-bound")
        (self.d.results / "owned-trace-cleanup.json").write_bytes(raw)

    def probe(self, mode, *arguments):
        result = self.d.command(["sudo", "-n", "python3", "-c", PROCESS_PROBE, mode, *map(str, arguments)])
        require(result.returncode == 0 and 0 < len(result.stdout) <= 2 << 20, "owned-process-probe-bound")
        return json.loads(result.stdout)

    def _raw_state(self, *, allow_unloaded=False):
        result = self.d.command(["sudo", "-n", "systemctl", "show", "--all", self.unit,
                                 "--property=" + UNIT_PROPERTIES])
        require(result.returncode == 0 and len(result.stdout) <= 64 << 10, "owned-trace-state-unknown")
        self.state_reads += 1
        pairs = [line.split("=",1) for line in result.stdout.decode().splitlines() if "=" in line]
        keys = [row[0] for row in pairs]; expected = set(UNIT_PROPERTIES.split(","))
        # Retain the exact failed predicate without exporting arbitrary values.
        shape = {"allow_unloaded":allow_unloaded,"cleanup_phase":self.cleanup_phase,"pair_count":len(keys),
                 "missing":sorted(expected-set(keys)),"duplicate_expected":[key for key in sorted(expected) if keys.count(key)>1],
                 "unexpected_count":sum(key not in expected for key in keys)}
        (self.d.results / ("owned-trace-state-shape-"+str(self.state_reads)+".json")).write_text(json.dumps(shape,sort_keys=True)+"\n")
        value = unit_state(result.stdout, allow_unloaded=allow_unloaded)
        self.last_state = value
        return value

    def _active(self, value):
        require(value.get("LoadState") == "loaded" and value.get("ActiveState") == "active"
                and value.get("ControlPID") == "0" and value.get("MainPID", "").isdecimal()
                and int(value["MainPID"]) > 1 and str(self.path) in value.get("ExecStart", "")
                and "strace" in value["ExecStart"]
                and value.get("ControlGroup") == "/system.slice/" + self.unit + ".service"
                and re.fullmatch(r"[0-9a-f]{32}", value.get("InvocationID", "")), "owned-trace-unit-identity")
        if self.prior is not None:
            require(all(value[key] == self.prior[key] for key in ("MainPID", "ExecStart", "ControlGroup", "InvocationID")),
                    "owned-trace-active-generation-changed")
        process = self.probe("identity", value["MainPID"], value["ControlGroup"])
        require(process.get("pid") == int(value["MainPID"]) and process.get("status") == "present"
                and isinstance(process.get("start_ticks"), str) and process["start_ticks"].isdecimal()
                and process.get("exe", "").endswith("/strace")
                and str(self.path) in process.get("cmdline", []), "owned-trace-process-identity")
        identity = {key: value[key] for key in ("MainPID", "ExecStart", "ControlGroup", "InvocationID")}
        identity["start_ticks"] = process["start_ticks"]
        if self.prior is None:
            self.prior = identity
        require(identity == self.prior, "owned-trace-active-generation-changed")
        return value

    def state(self):
        return self._active(self._raw_state())

    def inventory(self, main):
        roots = [(self.d.unit, main)]
        if getattr(self.d, "private_containerd", False):
            roots.append((self.d.runtime_unit, self.d.verify_runtime_unit()))
        services, pids, threads = [], [], []
        for unit, pid in roots:
            group = "/system.slice/" + unit + ".service"
            value = self.probe("tree", group)
            selected, current = owned_inventory(value, group, pid)
            require(not set(selected) & set(pids), "owned-trace-service-overlap")
            services.append(value); pids.extend(selected); threads.extend(current)
        require(0 < len(pids) <= 32 and 0 < len(threads) <= 512
                and len({item["tid"] for item in threads}) == len(threads), "owned-trace-combined-bound")
        return {"services":services}, sorted(pids), threads

    def __enter__(self):
        main = self.d.verify_unit()
        initial, pids, _ = self.inventory(main)
        (self.d.results / "owned-trace-initial-inventory.json").write_text(json.dumps(initial, sort_keys=True) + "\n")
        self.d.command(["strace", "--version"])
        self.attempted = True
        try:
            self.d.command(["sudo", "-n", "systemd-run", "--unit=" + self.unit,
                "--property=MemoryMax=256M", "--property=CPUQuota=100%", "--property=TasksMax=128",
                "--property=RuntimeMaxSec=6600", "--property=LimitFSIZE=8388608",
                "--property=KillMode=control-group", "--property=TimeoutStopSec=10",
                "strace", "-f", "-s", "4096", "-e",
                "trace=open,openat,openat2,execve,execveat,clone,clone3,fork,vfork", "-o", str(self.path),
                *[part for pid in pids for part in ("-p", str(pid))]])
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                state = self.state()
                current, _, threads = self.inventory(self.d.verify_unit())
                if all(item["tracer_pid"] == int(state["MainPID"]) for item in threads):
                    (self.d.results / "owned-trace-attached-inventory.json").write_text(json.dumps(current, sort_keys=True) + "\n")
                    return self
                time.sleep(0.2)
            raise Refusal("owned-trace-attachment-not-proven")
        except BaseException as primary:
            self.__exit__(type(primary), primary, primary.__traceback__)
            raise

    def snapshot(self):
        self.state()
        value = self.d.command(["sudo", "-n", "cat", str(self.path)]).stdout
        require(0 < len(value) < 8 << 20, "owned-trace-exhausted-or-empty")
        return value

    def _settle(self):
        require(self.prior is not None, "owned-trace-no-verified-prior-identity")
        self.cleanup_phase = "read-before-stop"
        value = self._raw_state(allow_unloaded=True)
        stop_error = None
        if value.get("ActiveState") == "active":
            self._active(value)  # Never stop a replacement or foreign active unit.
            require(not self.stop_attempted, "owned-trace-stop-already-attempted-no-repeat")
            self.stop_attempted = True
            self.cleanup_phase = "stop-attempted"
            try:
                self.d.command(["sudo", "-n", "systemctl", "stop", self.unit])
            except BaseException as error:
                stop_error = error_code(error)
            self.cleanup_phase = "read-after-stop"
            value = self._raw_state(allow_unloaded=True)
        absent = value.get("LoadState") == "not-found"
        require(value.get("ActiveState") == "inactive" and (absent or (value.get("LoadState") == "loaded"
                and value.get("MainPID") == "0" and value.get("ControlPID") == "0")), "owned-trace-not-settled")
        if not absent:
            for key in ("ExecStart", "ControlGroup", "InvocationID"):
                require(value.get(key) in {"", self.prior[key]}, "owned-trace-retired-identity-changed")
        self.cleanup_phase = "verify-prior-process"
        process = self.probe("settled", self.prior["MainPID"])
        absence = prior_process_settled(process, int(self.prior["MainPID"]), self.prior["start_ticks"])
        # Retain final flushed trace for diagnostics only. It never revises a failed witness verdict.
        self.cleanup_phase = "capture-final-trace"
        final = self.d.command(["sudo", "-n", "cat", str(self.path)]).stdout
        require(0 < len(final) < 8 << 20, "owned-trace-final-exhausted-or-empty")
        (self.d.results / "actual-clamd-config-trace-poststop.stdout").write_bytes(final)
        self.cleanup_phase = "settled"
        return {"settled": True, "state": value, "prior_identity": self.prior,
                "unloaded_service_pid_fields_inapplicable":absent,
                "prior_process": absence, "stop_attempted": self.stop_attempted,
                "stop_response_error": stop_error, "final_trace_sha256": hashlib.sha256(final).hexdigest(),
                "final_trace_bytes": len(final), "final_trace_changes_witness_verdict": False}

    def __exit__(self, exc_type, primary, traceback):
        if not self.attempted:
            return False
        value = {"schema": 1, "settled": False, "primary_error": error_code(primary) if primary else None}
        try:
            value.update(self._settle())
        except BaseException as error:
            self.cleanup_error = error
            value["cleanup_error"] = error_code(error)
        value.update(prior_identity=self.prior,stop_attempted=self.stop_attempted,
                     cleanup_phase=self.cleanup_phase,last_successful_state=self.last_state)
        try:
            self._record(value)
        except BaseException as error:
            self.cleanup_error = self.cleanup_error or error
        if self.cleanup_error is not None and primary is None:
            raise self.cleanup_error
        return False  # An existing primary error always propagates without cleanup masking it.


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

    def process_metadata(self, pid):
        self.inspect()
        require(type(pid) is int and pid > 1, "candidate-diagnostic-pid")
        result = self.d.command(["sudo", "-n", "python3", "-c", PROCESS_PROBE, "candidate", str(pid), self.cid])
        require(result.returncode == 0 and 0 < len(result.stdout) <= 64 << 10, "candidate-process-metadata-bound")
        value = json.loads(result.stdout)
        require(value.get("pid") == pid and value.get("status") == "present"
                and self.cid in value.get("cgroup", ""), "candidate-process-metadata-identity")
        return value

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
