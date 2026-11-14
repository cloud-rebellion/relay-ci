#!/usr/bin/env python3
"""Run trusted drivers with all app output captured outside public Actions logs."""
import json
import os
from pathlib import Path
import subprocess
import stat
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


def physical_process(command, **kwargs):
    # Private capture files belong to this parent process. Build/test children
    # must retain ordinary explicit file modes for their container fixtures.
    return subprocess.run(command, umask=0o022, **kwargs)


def protect_reports(directory):
    directory.chmod(0o700)
    paths = set()
    for pattern in ("*.json", "*.stdout", "*.stderr", "browser-failures/**/error-context.md",
                    "frontend-tests/*.junit.xml", "frontend-tests/summary.json"):
        paths.update(directory.glob(pattern))
    for path in paths:
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode) or not path.resolve().is_relative_to(directory.resolve()):
            raise RuntimeError("Nonregular private diagnostic refused")
        parent = path.parent
        while parent != directory:
            if parent.is_symlink():
                raise RuntimeError("Linked private diagnostic parent refused")
            parent.chmod(0o700)
            parent = parent.parent
        path.chmod(0o600)


def run(gate):
    os.umask(0o077)
    if gate not in GATES:
        raise RuntimeError("Unknown gate")
    directory = Path(os.environ["RELAY_CI_RESULTS_DIR"]).resolve()
    temporary = os.environ.get("RUNNER_TEMP") or os.environ.get("BUILD_SCRATCH_DIR")
    if not temporary or not directory.is_relative_to(Path(temporary).resolve()) or directory.is_relative_to(HARNESS):
        raise RuntimeError("Private diagnostics require an owned temporary path outside source")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    protect_reports(directory)
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
            source_check = physical_process([sys.executable, "-B", str(HARNESS / "tooling/github/verify-source.py")],
                                          cwd=HARNESS, env=env, stdout=stdout, stderr=stderr,
                                          timeout=max(1, deadline - time.monotonic()))
            if source_check.returncode:
                raise RuntimeError("The complete source/compiler verification failed")
            protect_reports(directory)
            for subdirectory, pattern in (("tooling", "harness_tests.py"),
                                          ("tooling/github", "validators_test.py"),
                                          ("tooling/release", "release_tests.py")):
                verify_public()
                control = physical_process([sys.executable, "-B", "-m", "unittest", "discover", "-s", subdirectory, "-p", pattern],
                                         cwd=HARNESS, env=env, stdout=stdout, stderr=stderr,
                                         timeout=max(1, deadline - time.monotonic()))
                if control.returncode:
                    raise RuntimeError("A trusted false-green control failed")
                protect_reports(directory)
                verify_public()
            for script in scripts:
                verify(initial=False)
                process = physical_process([sys.executable, "-B", str(HARNESS / "tooling" / script)],
                                         cwd=HARNESS, env=env, stdout=stdout, stderr=stderr, timeout=max(1, deadline - time.monotonic()))
                outcome["commands"].append({"driver": script, "exit_code": process.returncode})
                protect_reports(directory)
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
            protect_reports(directory)
    print("Relay " + gate + ": " + outcome["status"] + "; raw diagnostics withheld.")
    return 0 if outcome["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        sys.exit(run(sys.argv[1]))
    except Exception:
        print("Relay gate refused; raw diagnostics withheld.", file=sys.stderr)
        sys.exit(1)
