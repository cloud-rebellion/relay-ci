#!/usr/bin/env python3
"""One artifact-only assessment, without private source or a ClamAV process."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from binding import HARNESS, verify_public, git
from registry import Registry, document, materialize, Refusal, require
from artifact import Trivy, custody_tar, validate_tool_manifest
from profile import load
from storage import BoundedDaemon, public_runner


def results_directory():
    path = Path(os.environ["RELAY_SCANNER_RESULTS_DIR"])
    runner = Path(os.environ["RUNNER_TEMP"]).resolve()
    require(path.is_absolute() and path.resolve() == path and not path.is_symlink()
            and path.parent == runner and path.name == "relay-scanner-results-" + os.environ["GITHUB_RUN_ID"] + "-" +
            os.environ["GITHUB_RUN_ATTEMPT"], "scanner-results-owned-path")
    required = {"scanner-controls.stdout", "scanner-controls.stderr", "scanner-controls-summary.json"}
    require(path.is_dir() and {x.name for x in path.iterdir()} == required and
            all(x.is_file() and not x.is_symlink() and x.stat().st_nlink == 1 for x in path.iterdir()) and
            path.stat().st_uid == os.getuid()
            and path.stat().st_mode & 0o777 == 0o700, "scanner-results-directory-not-fresh-private")
    controls = document((path / "scanner-controls-summary.json").read_bytes())
    require(controls == {"schema": 1, "tests": 40, "failures": 0, "errors": 0, "skips": 0,
                         "status": "passed"}, "scanner-closed-controls-not-passed")
    return path


def assess(results, profile):
    with BoundedDaemon(results) as daemon:
        work = daemon.mount / "assessment"
        work.mkdir(mode=0o700)
        (work / "cache").mkdir(mode=0o700)
        (work / "cache/tmp").mkdir(mode=0o700)
        (work / "empty.yaml").write_text("{}\n")
        (work / "empty.ignore").write_text("")
        registry = Registry("clamav/clamav")
        try:
            registry.authorize()
            custody = materialize(registry, profile, work / "oci")
        finally:
            registry.close()
            (results / "registry-custody-requests.json").write_text(json.dumps(registry.receipts, indent=2) + "\n")
            (results / "registry-refused-routes.json").write_text(json.dumps(registry.refused_routes, indent=2) + "\n")
        (results / "oci-custody.json").write_text(json.dumps(custody, indent=2) + "\n")
        config = document((work / "oci/blobs/sha256" / profile["image"]["config_digest"][7:]).read_bytes())
        # Derived only from the verified immutable config, never profile-supplied.
        scan_profile = {**profile, "observed_diff_ids": config["rootfs"]["diff_ids"]}
        tool_registry = Registry("aquasec/trivy", max_bytes=4 << 20)
        try:
            tool_registry.authorize()
            tool = validate_tool_manifest(tool_registry, profile["tool"]["reference"])
        finally:
            tool_registry.close()
            (results / "trivy-registry-refused-routes.json").write_text(json.dumps(tool_registry.refused_routes, indent=2) + "\n")
        (results / "trivy-tool-identity.json").write_text(json.dumps(tool, indent=2) + "\n")
        result = Trivy(daemon, tool, work, results).assess(scan_profile)
        # Attestation and OCI custody survive daemon cleanup. Fixed public image
        # bytes are separate from the bounded 256 MiB raw diagnostic allowance.
        archive = results / "official-scanner-oci.tar"
        archive_receipt = custody_tar(work / "oci", archive)
        (results / "oci-archive-receipt.json").write_text(json.dumps(archive_receipt, indent=2) + "\n")
        attestations = work / "attestations"
        (results / "attestation-statements.json").write_text(json.dumps({
            path.name: document(path.read_bytes()) for path in sorted(attestations.glob("*.json"))}, sort_keys=True) + "\n")
        actual = daemon.docker(["ps", "-a", "--format", "{{.ID}}"])
        require(not actual.stdout.strip(), "scanner-owned-containers-not-settled")
        daemon.verify_mount()
        return {"artifact_security": result, "custody": custody, "tool": tool,
                "archive_sha256": archive_receipt["archive_sha256"],
                "hard_filesystem_bytes": 8 << 30, "candidate_image_executed": False}


def main():
    os.umask(0o077)
    public_runner(os.environ)
    results = results_directory()
    profile, profile_hash = load(HARNESS / "profiles/scanner-artifact.json")
    g = verify_public(HARNESS)
    report = {"schema": 1, "kind": "relay-public-scanner-artifact-assessment-v1", "status": "failed",
              "workflow_commit": g, "workflow_tree": git(HARNESS, "rev-parse", g + "^{tree}").decode().strip(),
              "profile_sha256": profile_hash, "image": profile["image"], "app_six_job_qualification": False,
              "full_scanner_qualified": False, "daemon_qualification_started": False,
              "private_app_source_used": False, "deployment_authorized": False,
              "started_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    old_handlers = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        old_handlers[signum] = signal.signal(signum, lambda sig, _: (_ for _ in ()).throw(SystemExit(128 + sig)))
    try:
        report.update(assess(results, profile))
        require(verify_public(HARNESS) == g, "scanner-public-source-changed")
        if report["artifact_security"]["verdict"] == "passed":
            report["status"] = "passed-artifact-security-only"
        else:
            report["error"] = "scanner-high-critical-findings"
    except BaseException as error:
        report["error"] = str(error) if isinstance(error, Refusal) else type(error).__name__
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        report["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        (results / "scanner-artifact-assessment.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("Relay scanner artifact assessment: " + report["status"] + "; daemon/app/production acceptance remains pending.")
    return 0 if report["status"] == "passed-artifact-security-only" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("Scanner assessment refused before an artifact verdict; inspect encrypted diagnostics.", file=sys.stderr)
        raise SystemExit(1)
