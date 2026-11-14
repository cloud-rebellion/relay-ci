#!/usr/bin/env python3
"""Run trusted drivers with all app output captured outside public Actions logs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback
import time

from binding import HARNESS, load_profile, verify, verify_public

GATES = {
    "core": (["governance/run-governance.py", "github/run-frontend.py", "github/run-backend.py"], 6600),
    "voip": (["github/run-voip.py"], 1800),
    "source-security": (["release/run-security.py"], 2400),
    "go-vulnerabilities": (["release/run-vulncheck.py"], 3300),
    "final-image": (["release/run-image-scan.py"], 4200),
    "migrations": (["release/run-migration.py"], 3300),
}


def run(gate):
    os.umask(0o077)
    if gate not in GATES:
        raise RuntimeError("Unknown gate")
    directory = Path(os.environ["RELAY_CI_RESULTS_DIR"]).resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    scripts, timeout = GATES[gate]
    outcome = {"gate": gate, "status": "failed", "binding_verified": False, "commands": []}
    with (directory / "gate-driver.stdout").open("w") as stdout, (directory / "gate-driver.stderr").open("w") as stderr:
        try:
            identity = verify(initial=True)
            outcome.update(identity, binding_verified=True)
            (directory / "source-identity.json").write_text(json.dumps(identity, indent=2) + "\n")
            env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "RUNNER_TEMP",
                   "GITHUB_ACTIONS", "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_REF",
                   "GITHUB_EVENT_NAME", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GOCACHE", "GOMODCACHE", "GOPATH", "GOROOT",
                   "BUILD_SCRATCH_DIR", "RELAY_PRIVATE_SOURCE_ROOT", "RELAY_CI_RESULTS_DIR") if k in os.environ}
            deadline = time.monotonic() + timeout
            source_check = subprocess.run([sys.executable, "-B", str(HARNESS / "tooling/github/verify-source.py")],
                                          cwd=HARNESS, env=env, stdout=stdout, stderr=stderr,
                                          timeout=max(1, deadline - time.monotonic()))
            if source_check.returncode:
                raise RuntimeError("The complete source/compiler verification failed")
            for subdirectory, pattern in (("tooling", "harness_tests.py"),
                                          ("tooling/github", "validators_test.py"),
                                          ("tooling/release", "release_tests.py")):
                verify_public()
                control = subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", subdirectory, "-p", pattern],
                                         cwd=HARNESS, env=env, stdout=stdout, stderr=stderr,
                                         timeout=max(1, deadline - time.monotonic()))
                if control.returncode:
                    raise RuntimeError("A trusted false-green control failed")
                verify_public()
            for script in scripts:
                verify(initial=False)
                process = subprocess.run([sys.executable, "-B", str(HARNESS / "tooling" / script)],
                                         cwd=HARNESS, env=env, stdout=stdout, stderr=stderr, timeout=max(1, deadline - time.monotonic()))
                outcome["commands"].append({"driver": script, "exit_code": process.returncode})
                if process.returncode:
                    raise RuntimeError("A required driver failed")
                verify(initial=False)
            if verify(initial=False) != identity:
                raise RuntimeError("Source identity changed during validation")
            outcome["status"] = "passed"
        except BaseException:
            traceback.print_exc(file=stderr)
        finally:
            (directory / "gate-execution.json").write_text(json.dumps(outcome, indent=2) + "\n")
    print("Relay " + gate + ": " + outcome["status"] + "; raw diagnostics withheld.")
    return 0 if outcome["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        sys.exit(run(sys.argv[1]))
    except Exception:
        print("Relay gate refused; raw diagnostics withheld.", file=sys.stderr)
        sys.exit(1)
