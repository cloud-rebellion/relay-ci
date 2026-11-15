"""Finite, daemon-only direct-official candidate. No production acceptance."""
import datetime as dt
import hashlib
import re
import struct

from registry import require

REFERENCE = "docker.io/clamav/clamav@sha256:b2c2f5c9a557dc1c1249e09448a84c59c3e414bb3bbbac0a9d065236c779842c"
CONFIG = "sha256:f8ffef1c9fad7bf457d91ea84eee10883b86f810e8768bc5adc863ed4d188f6d"
SETTINGS = {
    "ScanArchive": "yes", "ScanOLE2": "yes", "ScanPDF": "yes", "ScanXMLDOCS": "yes",
    "ScanHTML": "yes", "ScanPE": "yes", "HeuristicAlerts": "yes",
    "AlertEncryptedArchive": "yes", "AlertEncryptedDoc": "yes", "AlertExceedsMax": "yes",
    "StreamMaxLength": "25M", "MaxFileSize": "25M", "MaxScanSize": "100M",
    "MaxRecursion": "16", "MaxFiles": "10000", "MaxScanTime": "10000", "MaxThreads": "2",
    "MaxQueue": "8", "MaxConnectionQueueLength": "8", "ReadTimeout": "30",
    "CommandReadTimeout": "5", "SendBufTimeout": "500",
}
CONFIG_PATH = "/etc/clamav/clamd.conf"
DB_PATH = "/var/lib/clamav"
MEMORY = 4 << 30
SUBNET = "172.30.247.0/28"
MARKER = b"Relay-ClamAV-Only-Controlled-Signature-20261115-Not-EICAR"
SECOND = b"Relay-ClamAV-Only-Second-Engine-Control-20261115-Not-EICAR"


def normalized(name, value):
    value = value.strip().strip('"')
    if SETTINGS.get(name) == "yes":
        require(value.lower() in {"yes", "true", "1"}, "required-boolean-not-enabled")
        return True
    require(re.fullmatch(r"[0-9]+[KMG]?", value) is not None, "required-numeric-value")
    multiplier = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}.get(value[-1], 1)
    return int(value[:-1] if multiplier != 1 else value) * multiplier


def config_witness(raw, parsed):
    """Conflicts/includes/exclusions refuse. Identical duplicates need live parser proof."""
    require(0 < len(raw) <= 256 << 10 and 0 < len(parsed) <= 1 << 20, "config-witness-bound")
    occurrences = {key: [] for key in SETTINGS}
    for line in raw.decode("utf-8", "strict").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        require(len(parts) == 2, "config-directive-shape")
        name, value = parts
        require(not name.lower().startswith(("include", "exclude")), "config-include-or-exclusion")
        if name in SETTINGS:
            require(normalized(name, value) == normalized(name, SETTINGS[name]), "config-conflicting-policy")
            occurrences[name].append(value)
    require(all(occurrences.values()), "config-required-setting-missing")
    # clamconf is explicitly pointed at the same directory. A section from
    # another file, an omitted default, or ambiguous output cannot clear a gate.
    text = parsed.decode("utf-8", "strict")
    sections = re.split(r"(?m)^Config file:\s*", text)
    clamd = [x for x in sections[1:] if x.splitlines()[0].strip() == "clamd.conf"]
    require(len(clamd) == 1, "clamconf-exact-config-section")
    loaded = {}
    for line in clamd[0].splitlines()[1:]:
        match = re.fullmatch(r"\s*([A-Za-z0-9]+)\s*=\s*(.*?)\s*", line)
        if match and match[1] in SETTINGS:
            require(match[1] not in loaded, "clamconf-duplicate-value")
            loaded[match[1]] = normalized(match[1], match[2])
    require(loaded == {k: normalized(k, v) for k, v in SETTINGS.items()}, "clamconf-loaded-policy-mismatch")
    return {"config_sha256": hashlib.sha256(raw).hexdigest(), "loaded_settings": loaded,
            "active_occurrences": {k: len(v) for k, v in occurrences.items()},
            "identical_duplicates": any(len(v) > 1 for v in occurrences.values())}


def trace_witness(raw, pid):
    require(type(pid) is int and pid > 1 and 0 < len(raw) <= 8 << 20, "trace-witness-bound")
    lines = raw.decode("utf-8", "strict").splitlines()
    selected = [x for x in lines if re.match(r"^" + str(pid) + r"\s", x)]
    require(any(re.search(r'execve\("[^"\n]*/clamd",.*\)\s*=\s*0$', x) for x in selected),
            "actual-clamd-exec-not-witnessed")
    # musl may use the legacy open syscall for fopen. Admit only these three
    # kernel forms with the exact pathname argument; PID/read-only/FD checks stay.
    path = re.escape(CONFIG_PATH)
    opens = [x for x in selected if re.search(
        r'(?:^|\s)(?:open\("' + path + r'"|openat2?\([^,\n]+,\s*"' + path + r'")\s*,', x)]
    require(opens and any(re.search(r"O_RDONLY[^\n]*\)\s*=\s*[0-9]+(?:<[^>]+>)?$", x) for x in opens),
            "actual-clamd-config-open-not-witnessed")
    require(not any(re.search(r"O_WRONLY|O_RDWR|O_TRUNC", x) for x in opens), "daemon-config-open-for-write")
    return {"actual_clamd_host_pid": pid, "actual_opened_config": CONFIG_PATH,
            "successful_read_open": True, "trace_sha256": hashlib.sha256(raw).hexdigest()}


def fresh_version(raw, now):
    text = raw.rstrip(b"\x00\n").decode("ascii", "strict")
    match = re.fullmatch(r"ClamAV 1\.5\.4/([0-9]+)/(.+)", text)
    require(match is not None, "clamd-version-or-loaded-signatures")
    # Image TZ is checked against exact immutable OCI config; no local TZ guess.
    date = dt.datetime.strptime(match[2], "%a %b %d %H:%M:%S %Y").replace(tzinfo=dt.timezone.utc)
    age = (now - date).total_seconds()
    require(0 <= age <= 86400, "loaded-clamav-signatures-stale-or-future")
    return {"engine_version": "1.5.4", "daily_version": int(match[1]),
            "loaded_signature_date_utc": date.isoformat(), "age_seconds": age}


def verdict(raw, expected):
    require(0 < len(raw) <= 4096, "clamd-response-bound")
    value = raw.rstrip(b"\x00\n")
    require(b"\n" not in value and b"\x00" not in value, "clamd-response-framing")
    if expected == "clean":
        require(value == b"stream: OK", "daemon-clean-control-refused")
    elif expected == "controlled":
        require(re.fullmatch(rb"stream: Relay\.CI\.(Controlled|Second)(?:\.UNOFFICIAL)? FOUND", value) is not None,
                "daemon-controlled-signature-not-detected")
    else:
        require(b"ERROR" in value or value.endswith(b" FOUND"), "daemon-refusal-returned-clean")
    return {"expected": expected, "response": value.decode("ascii", "strict")}


def stream_chunks(data):
    yield b"zINSTREAM\x00"
    for offset in range(0, len(data), 65536):
        block = data[offset:offset + 65536]
        yield struct.pack("!I", len(block)) + block
    yield b"\x00\x00\x00\x00"


def resource_witness(value):
    require(value.get("memory.max") == str(MEMORY) and value.get("memory.swap.max") == "0",
            "candidate-hard-memory-or-swap-bound")
    peak = int(value["memory.peak"])
    events = dict(x.split() for x in value["memory.events"].splitlines())
    require(0 < peak <= MEMORY and int(events.get("oom", "-1")) == 0
            and int(events.get("oom_kill", "-1")) == 0, "candidate-memory-or-oom")
    require(value.get("pids.max") == "256" and value.get("cpu.max") == "200000 100000",
            "candidate-cpu-or-pid-bound")
    return {"hard_memory_bytes": MEMORY, "memory_peak_bytes": peak, "memory_events": events,
            "cpu_stat": value["cpu.stat"], "pids_current": int(value["pids.current"]),
            "cpu_max": value["cpu.max"], "pids_max": 256}
