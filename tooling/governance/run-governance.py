#!/usr/bin/env python3
"""Run the ten Relay-owned repository assertions without exposing private output."""
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from binding import HARNESS, private_product, verify

REQUIRED_CONTROLS = {
    "TestCleanAndExplicitApplicability", "TestSelectedPolicyRefusals",
    "TestPublishContractAndFalseGreen", "TestRaceParityExactTokens",
    "TestCompilerRefusals", "TestProviderAndContextCredentialControls",
    "TestCredentialCandidateClassification", "TestOperationalExternalCredentialMarker",
    "TestRegistryCannotOmitDuplicateOrAddSelectedGuard",
    "TestProvenanceMissingTamperedAndUnboundedInput",
    "TestActiveCompilerFloor", "TestHistoricalCompilerProfile", "TestDeployedNativeCompilerProfile",
}


def validate_controls(path):
    started, passed = set(), set()
    outcomes = 0
    package_passed = False
    for line in path.read_text().splitlines():
        event = json.loads(line)
        action, test = event.get("Action"), event.get("Test")
        if action in ("fail", "skip"):
            raise RuntimeError("A governance control failed or skipped")
        if test and action == "run":
            if test in started:
                raise RuntimeError("Duplicate governance control execution")
            started.add(test)
        if test and action == "pass":
            if test not in started or test in passed:
                raise RuntimeError("Unmatched governance control result")
            passed.add(test)
            outcomes += 1
        if not test and action == "pass":
            package_passed = True
    if not package_passed or started != passed or not REQUIRED_CONTROLS.issubset(passed):
        raise RuntimeError("A required governance control was omitted")
    return {"top_level": len({name for name in passed if "/" not in name}),
            "outcomes": outcomes, "skipped": 0}


NATIVE_PROFILE = "deployed-native-relay-7-9-10-v1"


def validate_helper_report(report):
    results = report.get("assertions", [])
    if report.get("status") != "passed" or report.get("selected_guard_count") != 10 or len(results) != 10 or \
            len({entry.get("name") for entry in results}) != 10 or \
            any(entry.get("status") != "passed" for entry in results) or \
            report.get("native_controller_profile") != NATIVE_PROFILE or \
            report.get("native_go11_admitted") is not False or report.get("public_go11_required") is not True:
        raise RuntimeError("Required governance assertions or finite compiler provenance missing")


def output_directory(value, harness=HARNESS):
    directory = Path(value)
    if not directory.is_absolute():
        raise RuntimeError("Governance output requires an absolute owned directory")
    directory = directory.resolve()
    if directory.is_relative_to(harness.resolve()):
        raise RuntimeError("Governance output cannot modify trusted tooling or private source")
    return directory


def execute(command, cwd, directory, name, env):
    with (directory / (name + ".stdout")).open("w") as stdout, \
            (directory / (name + ".stderr")).open("w") as stderr:
        return subprocess.run(command, cwd=cwd, env=env, stdout=stdout,
                              stderr=stderr, timeout=600).returncode


def main():
    os.umask(0o077)
    directory = output_directory(os.environ["RELAY_CI_RESULTS_DIR"])
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    identity = verify(initial=True)
    product = private_product()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        scratch = os.environ.get("BUILD_SCRATCH_DIR")
        if not scratch or not HERE.is_relative_to(Path(scratch).resolve()):
            raise RuntimeError("Local governance qualification must use official scratch")
    env = {name: os.environ[name] for name in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL",
            "GOCACHE", "GOMODCACHE", "GOPATH", "GOROOT") if name in os.environ}
    env.update(GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")
    binary = directory / "relay-governance"
    report_path = directory / "governance-summary.json"
    helper_report_path = directory / "governance-helper.json"
    report_path.write_text(json.dumps({"schema": 1, "status": "failed", "assertions": [],
                                       "refusal": "qualification not complete"}) + "\n")
    if execute([sys.executable, "-B", "-m", "unittest", "discover", "-s", str(HERE),
                "-p", "governance_tests.py"], HERE, directory, "governance-driver-controls", env):
        raise RuntimeError("Governance driver refusal controls failed")
    if execute(["go", "test", "-json", "-race", "-count=1", "-timeout=240s", "./..."], HERE,
               directory, "governance-controls", env):
        raise RuntimeError("Governance positive/refusal controls failed")
    counts = validate_controls(directory / "governance-controls.stdout")
    if execute(["go", "build", "-trimpath", "-o", str(binary), "."], HERE,
               directory, "governance-build", env):
        raise RuntimeError("Governance helper build failed")
    status = execute([str(binary), "--root", str(product.parent), "--provenance",
                      str(HERE / "source-origin.json"), "--report", str(helper_report_path)],
                     HERE, directory, "governance-check", env)
    report = json.loads(helper_report_path.read_text())
    if status:
        raise RuntimeError("Required governance helper refused qualification")
    validate_helper_report(report)
    if verify(initial=False) != identity:
        raise RuntimeError("Source binding changed during governance validation")
    report.update(identity, controls={"status": "passed", **counts}, status="passed")
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print("Relay governance: passed; 10/10 assertions; private diagnostics withheld.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("Relay governance: failed; private diagnostics withheld.", file=sys.stderr)
        sys.exit(1)
