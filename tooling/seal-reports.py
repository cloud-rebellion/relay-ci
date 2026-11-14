#!/usr/bin/env python3
"""Publish an allowlisted summary and age ciphertext, never private diagnostics."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import urllib.request

from binding import HARNESS, SHA, DIGEST, load_profile, verify_public, verify, git, digest
from importlib.util import module_from_spec, spec_from_file_location

MAX_REPORT_BYTES = 256 * 1024 * 1024
MAX_SINGLE_REPORT = 64 * 1024 * 1024


def report_paths(directory):
    paths = set()
    for pattern in ("*.json", "*.stdout", "*.stderr", "browser-failures/**/error-context.md",
                    "frontend-tests/*.junit.xml", "frontend-tests/summary.json"):
        paths.update(directory.glob(pattern))
    total = 0
    result = []
    for path in sorted(paths):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()):
            raise RuntimeError("Linked or nonregular diagnostic refused")
        if info.st_size > MAX_SINGLE_REPORT:
            raise RuntimeError("Diagnostic exceeded its explicit bound")
        total += info.st_size
        if total > MAX_REPORT_BYTES:
            raise RuntimeError("Diagnostic archive exceeded its explicit bound")
        result.append(path)
    if not result:
        raise RuntimeError("No original diagnostics were retained")
    return result, total


def age_binary(profile, temporary):
    pin = profile["age"]
    if pin.get("version") != "1.3.2" or not DIGEST.fullmatch(pin.get("archive_sha256", "")):
        raise RuntimeError("Missing reviewed age archive pin")
    url = pin["linux_amd64_archive_url"]
    if url != "https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz":
        raise RuntimeError("Unexpected encryption download source")
    request = urllib.request.Request(url, headers={"User-Agent": "relay-ci/1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        archive = response.read(25 * 1024 * 1024 + 1)
    if len(archive) > 25 * 1024 * 1024 or hashlib.sha256(archive).hexdigest() != pin["archive_sha256"]:
        raise RuntimeError("Encryption archive identity mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        members = [m for m in bundle.getmembers() if m.name == "age/age"]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 32 * 1024 * 1024:
            raise RuntimeError("Unexpected encryption binary member")
        executable = temporary / "age"
        executable.write_bytes(bundle.extractfile(members[0]).read()); executable.chmod(0o700)
    result = subprocess.run([str(executable), "--version"], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=15)
    if result.returncode or result.stdout.strip() not in ("v1.3.2", "1.3.2"):
        raise RuntimeError("Encryption CLI version mismatch")
    actual = hashlib.sha256(executable.read_bytes()).hexdigest()
    if pin.get("binary_sha256") and actual != pin["binary_sha256"]:
        raise RuntimeError("Encryption binary identity mismatch")
    return executable, actual


def safe_summary(profile, gate, directory):
    path = directory / "gate-execution.json"
    raw = json.loads(path.read_text()) if path.is_file() else {}
    g = verify_public(HARNESS)
    if not SHA.fullmatch(g) or os.environ.get("GITHUB_SHA") != g:
        raise RuntimeError("Public source identity is unavailable")
    passed = raw.get("gate") == gate and raw.get("status") == "passed" and raw.get("binding_verified") is True
    if passed:
        verify(profile, harness=HARNESS, initial=False)
    for key, expected in (("workflow_commit", g), ("private_context_commit", profile["context_commit"]),
                          ("private_context_tree", profile["context_tree"]),
                          ("origin_stage_commit", profile["origin_stage_commit"]),
                          ("context_manifest_sha256", profile["context_manifest_sha256"])):
        if passed and raw.get(key) != expected:
            raise RuntimeError("Gate report identity mismatch")
    result = {"schema": 1, "gate": gate, "status": "passed" if passed else "failed",
              "binding_verified": raw.get("binding_verified") is True, "workflow_commit": g,
              "workflow_tree": git(HARNESS, "rev-parse", g + "^{tree}").decode().strip(),
              "workflow_inputs_sha256": digest(git(HARNESS, "ls-tree", "-r", "-z", "--full-tree", g)),
              "private_context_commit": profile["context_commit"], "origin_stage_commit": profile["origin_stage_commit"],
              "private_context_tree": profile["context_tree"],
              "context_manifest_sha256": profile["context_manifest_sha256"],
              "profile_sha256": hashlib.sha256((HARNESS / "profiles/relay.json").read_bytes()).hexdigest(),
              "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
              "counts": {}, "fingerprints": {}, "deployment_authorized": False}
    # Only explicit numeric counts and validated digests cross the public boundary.
    if passed:
        def read(name):
            item = json.loads((directory / name).read_text())
            if item.get("status") != "passed":
                raise RuntimeError("Required structured gate summary is absent")
            return item
        if gate == "core":
            front, back = read("frontend-summary.json"), read("backend-summary.json")
            governance = read("governance-summary.json")
            if governance.get("selected_guard_count") != 10:
                raise RuntimeError("Complete selected governance proof missing")
            if front.get("browser_passes") != 97 or back.get("invitation_proved") is not True:
                raise RuntimeError("Complete browser/invitation proof missing")
            result["counts"] = {"selected_governance_guards": 10, "browser_passes": 97, "go_packages": len(back["packages"]),
                                "go_test_outcomes": sum(x["test_outcomes"] for x in back["packages"])}
        elif gate == "voip":
            item = read("voip-summary.json")
            result["counts"] = {"go_packages": len(item["packages"]), "builds": 3}
        elif gate == "source-security":
            read("security-summary.json")
            for root in profile["execution_roots"]:
                item = read("source-scan-" + root + ".json")
                if item.get("blocking"):
                    raise RuntimeError("Source findings block success")
                result["counts"][root + "_blocking"] = 0
                result["counts"][root + "_advisory"] = len(item["advisory"])
        elif gate == "go-vulnerabilities":
            item = read("vulnerability-summary.json")
            result["counts"] = {"modules": len(item["modules"])}
            result["fingerprints"]["scanner_sha256"] = item["scanner_sha256"]
        elif gate == "final-image":
            item = read("image-summary.json")
            result["fingerprints"] = {key: item[key] for key in ("image_id", "archive_sha256", "scanner_image_id")}
        elif gate == "migrations":
            item = read("migration-summary.json")
            result["counts"] = {"migrations": len(item["migrations"]), "rollback_versions": len(item["rollback_versions"])}
            result["fingerprints"]["goose_sha256"] = item["goose_sha256"]
    if any(type(n) is not int or not 0 <= n <= 10000000 for n in result["counts"].values()):
        raise RuntimeError("Non-numeric public count refused")
    for value in result["fingerprints"].values():
        if not isinstance(value, str) or not DIGEST.fullmatch(value.removeprefix("sha256:")):
            raise RuntimeError("Non-fingerprint public value refused")
    return result


def main(gate):
    os.umask(0o077)
    profile = load_profile()
    if gate not in ("core", "voip", "source-security", "go-vulnerabilities", "final-image", "migrations"):
        raise RuntimeError("Unknown gate")
    recipient = profile["age"].get("recipient", "")
    if not re.fullmatch(r"age1[0-9a-z]{58}", recipient):
        raise RuntimeError("A pinned public age recipient is required")
    runner = Path(os.environ["RUNNER_TEMP"]).resolve()
    directory = Path(os.environ["RELAY_CI_RESULTS_DIR"]).resolve()
    if not directory.is_relative_to(runner):
        raise RuntimeError("Diagnostics must use an owned runner temporary path")
    import tempfile
    with tempfile.TemporaryDirectory(prefix="relay-seal-", dir=runner) as temporary:
        temporary = Path(temporary)
        executable, age_hash = age_binary(profile, temporary)
        paths, total = report_paths(directory)
        summary = safe_summary(profile, gate, directory)
        archive = temporary / "diagnostics.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            for path in paths:
                bundle.add(path, arcname=path.relative_to(directory).as_posix(), recursive=False)
        sealed = runner / ("relay-sealed-" + gate)
        if sealed.exists():
            raise RuntimeError("Encrypted output path is not fresh")
        sealed.mkdir(mode=0o700)
        target = sealed / (gate + "-diagnostics.tar.gz.age")
        process = subprocess.run([str(executable), "-r", recipient, "-o", str(target), str(archive)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if process.returncode or not target.is_file() or target.stat().st_size == 0:
            if target.is_file():
                target.unlink()
            raise RuntimeError("Private diagnostics were not encrypted")
        summary.update(diagnostics_sealed=True, diagnostic_file_count=len(paths), diagnostic_bytes=total,
                       encrypted_diagnostics_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                       encryption_binary_sha256=age_hash)
        (sealed / "public-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print("Relay " + gate + ": diagnostics encrypted; public summary contains only statuses, counts and fingerprints.")


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except BaseException:
        print("Private diagnostic encryption or summary validation failed; no plaintext upload is allowed.", file=sys.stderr)
        sys.exit(1)
