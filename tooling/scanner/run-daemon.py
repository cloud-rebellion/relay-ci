#!/usr/bin/env python3
"""Public daemon subset assessment. Inert without --execute; no app/source key."""
import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import signal
import struct
import sys
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from binding import HARNESS, verify_public, git
from registry import Registry, document, materialize, Refusal, require
from artifact import Trivy, validate_tool_manifest
from profile import load
from storage import BoundedDaemon, public_runner
from daemon_policy import (CONFIG, CONFIG_PATH, DB_PATH, MARKER, SECOND, MEMORY, REFERENCE, SETTINGS,
                           config_witness, trace_witness, fresh_version, verdict, stream_chunks, resource_witness)
from daemon_runtime import PrivateEgress, OwnedTrace, Candidate, error_code
from freshclam_check import check_inherited
from direct_fixtures import (CONTROL_COUNT as FIXTURE_CONTROL_COUNT, FixtureDaemon, prepare_host_tools, build_corpus, scan_corpus)

KIND = "relay-public-scanner-daemon-subset-v1"
CONTROL_COUNT = 41


def record(root, name, value):
    require(re.fullmatch(r"[a-z0-9-]{1,80}", name) is not None, "phase1-report-leaf")
    raw = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
    require(len(raw) <= 4 << 20, "phase1-report-bound")
    (root / (name + ".json")).write_bytes(raw)


def owned_results():
    runner = Path(os.environ["RUNNER_TEMP"]).resolve()
    root = Path(os.environ["RELAY_SCANNER_PHASE1_RESULTS_DIR"])
    require(root == runner / ("relay-scanner-phase1-" + os.environ["GITHUB_RUN_ID"] + "-" +
            os.environ["GITHUB_RUN_ATTEMPT"]) and root.resolve() == root and not root.is_symlink()
            and root.is_dir() and root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o777 == 0o700,
            "phase1-owned-private-results")
    require({x.name for x in root.iterdir()} == {"daemon-controls.stdout", "daemon-controls.stderr",
            "daemon-controls-summary.json", "scanner-controls.stdout", "scanner-controls.stderr",
            "scanner-controls-summary.json", "direct-fixtures-controls.stdout", "direct-fixtures-controls.stderr",
            "direct-fixtures-controls-summary.json"}, "phase1-fresh-results-files")
    for name, count in (("daemon", CONTROL_COUNT), ("scanner", 42), ("direct-fixtures", FIXTURE_CONTROL_COUNT)):
        require(document((root / (name + "-controls-summary.json")).read_bytes()) ==
                {"schema": 1, "tests": count, "failures": 0, "errors": 0, "skips": 0, "status": "passed"},
                "phase1-closed-controls-not-passed")
    return root


def wait_control(candidate, marker, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            return verdict(candidate.exchange(stream_chunks(marker)), "controlled")
        except (OSError, Refusal):
            time.sleep(2)
    raise Refusal("controlled-signature-engine-reload-not-proven")


def write_signature(candidate, second=False):
    # Fixed harmless test-only signature. This exec neither replaces startup nor
    # adds a production signature, image layer or host bind.
    rows = ["Relay.CI.Controlled:0:*:" + MARKER.hex()]
    if second:
        rows.append("Relay.CI.Second:0:*:" + SECOND.hex())
    script = "umask 022; printf '%s\\n' " + " ".join("'" + x + "'" for x in rows) + \
             " > /var/lib/clamav/relay-ci-control.ndb"
    candidate.execute(["sh", "-c", script])
    require(candidate.exchange([b"zRELOAD\x00"]).rstrip(b"\x00\n") == b"RELOADING", "daemon-reload-refused")
    wait_control(candidate, SECOND if second else MARKER)


def witness(candidate, trace, results, phase):
    # Diagnostic bytes are captured before strict parsing. Presence alone never qualifies a loaded config.
    diagnostics = {"status": "captured-not-qualified", "container_id": candidate.cid, "phase": phase}
    try:
        info = candidate.inspect()
        diagnostics["container"] = {"id": info["Id"], "image": info["Image"], "state": info["State"]}
        top = candidate.d.docker(["top", candidate.cid, "-eo", "pid,comm"]).stdout
        require(0 < len(top) <= 64 << 10, "actual-clamd-top-bound")
        (results / (phase + "-docker-top.stdout")).write_bytes(top)
        rows = [x.split() for x in top.decode().splitlines()[1:]]
        pids = [int(x[0]) for x in rows if len(x) == 2 and x[0].isdecimal() and x[1] == "clamd"]
        require(len(pids) == 1, "actual-clamd-process-not-unique")
        diagnostics["actual_clamd_process"] = candidate.process_metadata(pids[0])
        captures = {}
        for name, command, limit in (
            ("init", ["cat", "/init"], 256 << 10),
            ("clamd-config", ["cat", CONFIG_PATH], 256 << 10),
            ("clamd-config-stat", ["stat", "-c", "%d:%i:%u:%g:%a:%s:%Y:%Z", CONFIG_PATH], 4096),
            ("clamconf", ["clamconf", "--config-dir=/etc/clamav"], 1 << 20)):
            candidate.inspect()
            output = candidate.d.docker(["exec", candidate.cid, *command], allow_failure=True)
            require(len(output.stdout) + len(output.stderr) <= limit, "actual-diagnostic-capture-bound")
            for suffix in ("stdout", "stderr"):
                (results / (phase + "-" + name + "." + suffix)).write_bytes(getattr(output, suffix))
            captures[name] = output
            diagnostics[name] = {"exit_code": output.returncode, "stdout_bytes": len(output.stdout),
                                 "stdout_sha256": hashlib.sha256(output.stdout).hexdigest()}
        record(results, phase + "-diagnostic-capture", diagnostics)
        require(all(value.returncode == 0 for value in captures.values()), "actual-diagnostic-command-failed")
        entrypoint, before, parsed = (captures[name].stdout for name in ("init", "clamd-config", "clamconf"))
        require(entrypoint and before and parsed, "actual-diagnostic-capture-empty")
        # Existing acceptance is deliberately unchanged: exact clamd PID exec AND successful read-open.
        traced = trace_witness(trace.snapshot(), pids[0])
        require(candidate.execute(["cat", CONFIG_PATH]) == before, "config-changed-during-parser-witness")
        settings = config_witness(before, parsed)
        version = fresh_version(candidate.exchange([b"zVERSION\x00"]), dt.datetime.now(dt.timezone.utc))
        resources = resource_witness(candidate.resources())
        record(results, phase + "-witness", {"image_config": CONFIG, "container_id": candidate.cid,
            "inherited_startup_verified": True, "entrypoint_sha256": hashlib.sha256(entrypoint).hexdigest(),
            "trace": traced, "configuration": settings, "loaded_signatures": version, "resources": resources,
            "container_oom_killed": info["State"].get("OOMKilled", False)})
        return {"phase": phase, "loaded_settings": len(settings["loaded_settings"]), "freshness": version,
                "resources": resources, "identical_duplicates": settings["identical_duplicates"]}
    except BaseException as error:
        diagnostics.update(status="failed-not-qualified", primary_error=error_code(error))
        record(results, phase + "-diagnostic-capture", diagnostics)
        raise


def cases(candidate):
    controls = []
    for name, data in (("clean-text", b"Relay clean text\n"), ("clean-csv", b"name,email\nExample,synthetic@example.invalid\n")):
        controls.append({"case": name, **verdict(candidate.exchange(stream_chunks(data)), "clean")})
    controls.append({"case": "controlled-raw-not-eicar", **verdict(candidate.exchange(stream_chunks(MARKER)), "controlled")})
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr("controlled.txt", MARKER)
    require(MARKER not in archive.getvalue(), "compressed-signature-fixture-not-compressed")
    controls.append({"case": "controlled-deflated-zip", **verdict(candidate.exchange(stream_chunks(archive.getvalue())), "controlled")})
    controls.append({"case": "stream-above-25m", **verdict(candidate.exchange(stream_chunks(b"x" * ((25 << 20) + 1))), "refuse")})
    # A declared-but-truncated chunk must not return clean. Half-close makes EOF
    # deliberate rather than waiting for an unrelated socket deadline.
    with __import__("socket").create_connection((candidate.address(), 3310), timeout=10) as connection:
        connection.settimeout(40)
        connection.sendall(b"zINSTREAM\x00" + struct.pack("!I", 100) + b"partial")
        connection.shutdown(__import__("socket").SHUT_WR)
        response = connection.recv(4096)
    require(response.rstrip(b"\x00\n") != b"stream: OK", "truncated-stream-returned-clean")
    controls.append({"case": "truncated-stream", "refused_or_closed_without_clean": True})
    return controls


def assess(root, profile):
    with FixtureDaemon(root, private_containerd=True) as daemon:
        work = daemon.mount / "assessment"
        work.mkdir(mode=0o700)
        (work / "cache/tmp").mkdir(parents=True, mode=0o700)
        (work / "cache").chmod(0o700)
        (work / "empty.yaml").write_text("{}\n")
        (work / "empty.ignore").write_text("")
        registry = Registry("clamav/clamav")
        try:
            registry.authorize()
            custody = materialize(registry, profile, work / "oci")
        finally:
            registry.close()
            record(root, "phase1-registry-requests", registry.receipts)
            record(root, "phase1-registry-refusals", registry.refused_routes)
        config = document((work / "oci/blobs/sha256" / CONFIG[7:]).read_bytes())
        require(profile["image"]["config_digest"] == CONFIG and config["config"].get("Entrypoint") == ["/init"]
                and config["config"].get("Env") == ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TZ=Etc/UTC"],
                "phase1-exact-vendor-config")
        tools = Registry("aquasec/trivy", max_bytes=4 << 20)
        try:
            tools.authorize()
            tool = validate_tool_manifest(tools, profile["tool"]["reference"])
        finally:
            tools.close()
            record(root, "phase1-tool-registry-refusals", tools.refused_routes)
        security = Trivy(daemon, tool, work, root).assess({**profile, "observed_diff_ids": config["rootfs"]["diff_ids"]})
        record(root, "phase1-artifact-security", security)
        require(security.get("verdict") == "passed" and security.get("high") == 0 and security.get("critical") == 0
                and security.get("sbom_generated") is True, "phase1-image-security-not-clear")
        record(root, "phase1-oci-custody", custody)
        fixture_tools = prepare_host_tools(daemon, root)
        fixture_corpus = build_corpus(daemon, fixture_tools)
        phases, observations = [], []
        with PrivateEgress(daemon) as network, OwnedTrace(daemon) as trace, Candidate(daemon, network, config) as candidate:
            candidate.start()
            candidate.ready()
            phases.append(witness(candidate, trace, root, "initial-load"))
            write_signature(candidate)
            observations.append({"phase": "first-test-signature-reload", "cases": cases(candidate),
                "direct_fixtures": scan_corpus(candidate, fixture_corpus, root, "first-reload")})
            phases.append(witness(candidate, trace, root, "first-reload"))
            # Freshclam's real check may report up-to-date. Record that honestly;
            # a synthetic vendor version increment is never fabricated.
            update = check_inherited(candidate,root)
            record(root,"real-freshclam-check",update)
            write_signature(candidate, second=True)
            phases.append(witness(candidate, trace, root, "second-reload-after-freshclam-check"))
            observations.append({"phase": "second-reload", "second_signature": wait_control(candidate, SECOND)})
            address = candidate.address()
            daemon.docker(["stop", "--time", "30", candidate.cid], timeout=60)
            try:
                with __import__("socket").create_connection((address, 3310), timeout=5):
                    raise Refusal("stopped-daemon-still-accepts-connections")
            except OSError:
                observations.append({"phase": "outage", "connection_refused_or_unavailable": True})
            candidate.start()
            candidate.ready(300)
            phases.append(witness(candidate, trace, root, "ordinary-restart"))
            observations.append({"phase": "recovered", "cases": cases(candidate),
                "direct_fixtures": scan_corpus(candidate, fixture_corpus, root, "recovered")})
            candidate.remove()
            candidate.create()
            candidate.start()
            candidate.ready(300)
            phases.append(witness(candidate, trace, root, "retained-volume-recreation"))
            observations.append({"phase": "retained-recreation", "cases": cases(candidate),
                "direct_fixtures": scan_corpus(candidate, fixture_corpus, root, "retained-recreation"),
                "second_signature": wait_control(candidate, SECOND)})
            # Keep actual syscall witness private and bounded. It is not source ancestry.
            (root / "actual-clamd-config-trace.stdout").write_bytes(trace.snapshot())
        # Context cleanup must succeed before a passed subset receipt exists.
        require(not daemon.docker(["ps", "-a", "--format", "{{.ID}}"]).stdout.strip(), "phase1-containers-not-settled")
        daemon.verify_mount()
    return {"artifact_security": security, "phases": phases, "observations": observations,
            "owned_resources_settled": True, "hard_filesystem_bytes": 8 << 30,
            "candidate_memory_limit_bytes": MEMORY, "freshclam_check_performed": True,
            "vendor_signature_version_advance_required_or_claimed": False,
            "direct_document_limit_subset": {"case_count_per_phase": 11,
                "phases": ["first-reload", "recovered", "retained-recreation"],
                "time_queue_stall_or_app_acceptance_claimed": False}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({"status": "authored-unpublished-not-executed", "kind": KIND,
            "image": REFERENCE, "config": CONFIG, "settings": SETTINGS,
            "full_scanner_qualified": False, "deployment_authorized": False}, sort_keys=True))
        return 0
    os.umask(0o077)
    public_runner(os.environ)
    root = owned_results()
    profile, profile_hash = load(HARNESS / "profiles/scanner-artifact.json")
    g = verify_public(HARNESS)
    report = {"schema": 1, "kind": KIND, "status": "failed", "workflow_commit": g,
        "workflow_tree": git(HARNESS, "rev-parse", g + "^{tree}").decode().strip(),
        "profile_sha256": profile_hash, "image": profile["image"], "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "delivery_trust": "official-docker-hub-tls-and-immutable-content-digests",
        "publisher_signature_verified": False, "source_ancestry_verified": False,
        "full_scanner_qualified": False, "private_app_source_used": False, "application_acceptance": False,
        "ovh_capacity_acceptance": False, "deployment_authorized": False,
        "pending_categories": ["encrypted-PDF-archive", "office-PDF-utility", "all-parser-limits",
            "queue-and-app-latency", "real-app-ingress-no-persistence", "target-capacity-maintenance"]}
    handlers = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        handlers[signum] = signal.signal(signum, lambda sig, _: (_ for _ in ()).throw(SystemExit(128 + sig)))
    try:
        report.update(assess(root, profile))
        require(verify_public(HARNESS) == g, "phase1-public-source-changed")
        report["status"] = "passed-daemon-subset-only"
    except BaseException as error:
        report["error"] = str(error) if isinstance(error, Refusal) else type(error).__name__
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
        report["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        record(root, "scanner-daemon-subset", report)
    print("Relay scanner daemon subset: " + report["status"] + "; full scanner/application/OVH acceptance remains pending.")
    return 0 if report["status"] == "passed-daemon-subset-only" else 1


if __name__ == "__main__":
    raise SystemExit(main())
