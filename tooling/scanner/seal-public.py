#!/usr/bin/env python3
"""Separate scanner summary schema; never an application or Stage receipt."""
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


def fingerprint(path):
    checksum = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1 << 20):
            checksum.update(block)
    return checksum.hexdigest()


def summary(profile, profile_hash, raw, g):
    require(raw.get("kind") == "relay-public-scanner-artifact-assessment-v1" and raw.get("schema") == 1,
            "scanner-summary-kind")
    require(raw.get("workflow_commit") == g and raw.get("profile_sha256") == profile_hash
            and raw.get("image") == profile["image"], "scanner-summary-identity")
    require(all(raw.get(key) is False for key in ("full_scanner_qualified", "daemon_qualification_started",
            "private_app_source_used", "app_six_job_qualification", "deployment_authorized")),
            "artifact-assessment-cannot-claim-full-acceptance")
    verdict = raw.get("artifact_security", {})
    passed = raw.get("status") == "passed-artifact-security-only"
    require(not passed or verdict.get("verdict") == "passed" and
            verdict.get("high") == 0 and verdict.get("critical") == 0 and
            type(verdict.get("packages")) is int and verdict["packages"] > 0 and
            verdict.get("sbom_generated") is True and raw.get("candidate_image_executed") is False,
            "scanner-summary-incomplete-clear-verdict")
    counts = {key: verdict.get(key, 0) for key in ("high", "critical", "packages")}
    require(all(type(x) is int and 0 <= x <= 10000000 for x in counts.values()), "scanner-summary-counts")
    return {"schema": 1, "kind": "relay-public-scanner-artifact-assessment-v1",
        "status": "passed-artifact-security-only" if passed else "failed",
        "workflow_commit": g, "profile_sha256": profile_hash,
        "subject_manifest_digest": profile["image"]["manifest_digest"],
        "subject_config_digest": profile["image"]["config_digest"],
        "counts": counts, "full_scanner_qualified": False, "daemon_qualification_started": False,
        "app_six_job_qualification": False, "private_app_source_used": False, "deployment_authorized": False,
        "publisher_signature_trust": "unverified-blocks-full-acceptance"}


def main():
    os.umask(0o077)
    public_runner(os.environ)
    profile, profile_hash = load(HARNESS / "profiles/scanner-artifact.json")
    g = verify_public(HARNESS)
    runner = Path(os.environ["RUNNER_TEMP"]).resolve()
    directory = Path(os.environ["RELAY_SCANNER_RESULTS_DIR"])
    expected = runner / ("relay-scanner-results-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"])
    require(directory == expected and directory.resolve() == expected and not directory.is_symlink(), "scanner-seal-owned-path")
    path = directory / "scanner-artifact-assessment.json"
    if path.is_file():
        raw = document(path.read_bytes())
    else:
        raw = {"schema": 1, "kind": "relay-public-scanner-artifact-assessment-v1", "status": "failed",
               "workflow_commit": g, "profile_sha256": profile_hash, "image": profile["image"],
               **{key: False for key in ("full_scanner_qualified", "daemon_qualification_started", "private_app_source_used",
                                        "app_six_job_qualification", "deployment_authorized")}}
    safe = summary(profile, profile_hash, raw, g)
    safe.update(workflow_tree=git(HARNESS, "rev-parse", g + "^{tree}").decode().strip(),
                run_id=int(os.environ["GITHUB_RUN_ID"]), run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]))
    # Reuse only the established bounded encryption and diagnostic selection.
    # Do not call that module's private-app summary or load its private profile.
    spec = spec_from_file_location("relay_existing_report_sealer", HARNESS / "tooling/seal-reports.py")
    sealer = module_from_spec(spec); spec.loader.exec_module(sealer)
    paths, total = sealer.report_paths(directory)
    require(re.fullmatch(r"age1[0-9a-z]{58}", profile["age"]["recipient"]) is not None, "scanner-seal-recipient")
    destination = runner / "relay-sealed-scanner-artifact"
    destination.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="relay-scanner-seal-", dir=runner) as temporary:
        temporary = Path(temporary)
        age, age_sha = sealer.age_binary(profile, temporary)
        archive = temporary / "diagnostics.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            for path in paths:
                bundle.add(path, arcname=path.name, recursive=False)
        sources = [(archive, "diagnostics.tar.gz.age")]
        oci = directory / "official-scanner-oci.tar"
        if oci.exists():
            require(oci.is_file() and not oci.is_symlink() and oci.stat().st_nlink == 1 and
                    0 < oci.stat().st_size <= 1 << 30, "scanner-seal-oci-bound")
            receipt = document((directory / "oci-archive-receipt.json").read_bytes())
            require(receipt.get("archive_sha256") == fingerprint(oci) and
                    receipt.get("archive_bytes") == oci.stat().st_size, "scanner-seal-oci-custody")
            sources.append((oci, "official-scanner-oci.tar.age"))
        ciphertexts = {}
        for source, leaf in sources:
            target = destination / leaf
            process = subprocess.run([str(age), "-r", profile["age"]["recipient"], "-o", str(target), str(source)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            require(process.returncode == 0 and target.is_file() and target.stat().st_size > 0,
                    "scanner-diagnostics-encryption-failed")
            ciphertexts[leaf] = fingerprint(target)
        require(verify_public(HARNESS) == g, "scanner-seal-public-source-changed")
        safe.update(diagnostics_sealed=True, diagnostic_file_count=len(paths), diagnostic_bytes=total,
                    ciphertext_sha256=ciphertexts, encryption_binary_sha256=age_sha)
        (destination / "public-summary.json").write_text(json.dumps(safe, indent=2, sort_keys=True) + "\n")
    print("Relay scanner artifact assessment: encrypted diagnostics and separate bounded summary prepared.")


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        print("Scanner diagnostic encryption or summary validation refused; plaintext upload is forbidden.", file=sys.stderr)
        sys.exit(1)
