#!/usr/bin/env python3
"""Bounded phase1 ciphertext plus an allowlisted daemon-subset summary."""
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from binding import HARNESS, verify_public, git
from registry import document, require
from profile import load
from storage import public_runner
from daemon_policy import CONFIG, MEMORY

KIND = "relay-public-scanner-daemon-subset-v1"
FLAGS = ("full_scanner_qualified", "private_app_source_used", "application_acceptance",
         "ovh_capacity_acceptance", "deployment_authorized", "publisher_signature_verified", "source_ancestry_verified")


def summary(raw, profile, profile_hash, g):
    require(raw.get("schema") == 1 and raw.get("kind") == KIND and raw.get("workflow_commit") == g
            and raw.get("profile_sha256") == profile_hash and raw.get("image") == profile["image"],
            "phase1-summary-identity")
    require(all(raw.get(key) is False for key in FLAGS), "daemon-subset-cannot-claim-full-acceptance")
    passed = raw.get("status") == "passed-daemon-subset-only"
    if passed:
        phases = raw.get("phases", [])
        security = raw.get("artifact_security", {})
        require([x.get("phase") for x in phases] == ["initial-load", "first-reload",
                "second-reload-after-freshclam-check", "ordinary-restart", "retained-volume-recreation"]
                and all(x.get("loaded_settings") == 22 and
                        x.get("resources", {}).get("hard_memory_bytes") == MEMORY and
                        0 <= x.get("freshness", {}).get("age_seconds", -1) <= 86400 for x in phases),
                "phase1-summary-required-witnesses")
        require(security.get("verdict") == "passed" and security.get("high") == 0 and security.get("critical") == 0
                and security.get("sbom_generated") is True and raw.get("owned_resources_settled") is True
                and raw.get("hard_filesystem_bytes") == 8 << 30 and raw.get("freshclam_check_performed") is True,
                "phase1-summary-security-or-cleanup")
    return {"schema": 1, "kind": KIND, "status": "passed-daemon-subset-only" if passed else "failed",
        "workflow_commit": g, "profile_sha256": profile_hash,
        "subject_manifest_digest": profile["image"]["manifest_digest"], "subject_config_digest": CONFIG,
        "delivery_trust": "official-docker-hub-tls-and-immutable-content-digests",
        "counts": {"loaded_policy_settings": 22 if passed else 0, "lifecycle_witnesses": 5 if passed else 0,
                   "high": raw.get("artifact_security", {}).get("high", 0),
                   "critical": raw.get("artifact_security", {}).get("critical", 0)},
        **{key: False for key in FLAGS},
        "pending_categories": ["encrypted-PDF-archive", "office-PDF-utility", "all-parser-limits",
            "queue-and-app-latency", "real-app-ingress-no-persistence", "target-capacity-maintenance"]}


def main():
    os.umask(0o077)
    public_runner(os.environ)
    g = verify_public(HARNESS)
    profile, profile_hash = load(HARNESS / "profiles/scanner-artifact.json")
    runner = Path(os.environ["RUNNER_TEMP"]).resolve()
    root = Path(os.environ["RELAY_SCANNER_PHASE1_RESULTS_DIR"])
    expected = runner / ("relay-scanner-phase1-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"])
    require(root == expected and root.resolve() == root and not root.is_symlink() and root.is_dir()
            and root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o777 == 0o700, "phase1-seal-owned-path")
    path = root / "scanner-daemon-subset.json"
    raw = document(path.read_bytes()) if path.is_file() else {"schema": 1, "kind": KIND, "status": "failed",
        "workflow_commit": g, "profile_sha256": profile_hash, "image": profile["image"], **{key: False for key in FLAGS}}
    safe = summary(raw, profile, profile_hash, g)
    safe.update(workflow_tree=git(HARNESS, "rev-parse", g + "^{tree}").decode().strip(),
                run_id=int(os.environ["GITHUB_RUN_ID"]), run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]))
    require(all(type(x) is int and 0 <= x <= 10000000 for x in safe["counts"].values()), "phase1-public-counts")
    spec = spec_from_file_location("relay_existing_sealer", HARNESS / "tooling/seal-reports.py")
    sealer = module_from_spec(spec); spec.loader.exec_module(sealer)
    paths, total = sealer.report_paths(root)
    require(re.fullmatch(r"age1[0-9a-z]{58}", profile["age"]["recipient"]) is not None, "phase1-age-recipient")
    destination = runner / "relay-sealed-scanner-daemon"
    destination.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="relay-daemon-seal-", dir=runner) as temporary:
        temporary = Path(temporary)
        age, age_hash = sealer.age_binary(profile, temporary)
        archive = temporary / "diagnostics.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            for path in paths:
                bundle.add(path, arcname=path.name, recursive=False)
        ciphertext = destination / "diagnostics.tar.gz.age"
        process = subprocess.run([str(age), "-r", profile["age"]["recipient"], "-o", str(ciphertext), str(archive)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        require(process.returncode == 0 and ciphertext.is_file() and ciphertext.stat().st_size > 0,
                "phase1-diagnostics-encryption-failed")
        require(verify_public(HARNESS) == g, "phase1-sealer-public-source-changed")
        safe.update(diagnostics_sealed=True, diagnostic_file_count=len(paths), diagnostic_bytes=total,
            ciphertext_sha256=hashlib.sha256(ciphertext.read_bytes()).hexdigest(), encryption_binary_sha256=age_hash)
        (destination / "public-summary.json").write_text(json.dumps(safe, sort_keys=True, indent=2) + "\n")
    print("Relay daemon subset: bounded ciphertext and allowlisted summary prepared.")


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        print("Daemon subset sealing refused; plaintext upload is forbidden.", file=sys.stderr)
        sys.exit(1)
