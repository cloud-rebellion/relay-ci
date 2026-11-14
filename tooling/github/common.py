"""Small, credential-free helpers for Relay's repository-owned CI commands."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from binding import private_product, source_sha, origin_sha

PRODUCT = private_product()
REPOSITORY = PRODUCT.parent
PINS = json.loads((Path(__file__).parent / "pins.json").read_text())


def results_directory():
    value = os.environ.get("RELAY_CI_RESULTS_DIR")
    if not value:
        scratch = os.environ.get("BUILD_SCRATCH_DIR")
        if not scratch:
            raise RuntimeError("Set an owned absolute RELAY_CI_RESULTS_DIR or BUILD_SCRATCH_DIR")
        value = str(Path(scratch) / "relay-ci-results")
    path = Path(value)
    if not path.is_absolute():
        raise RuntimeError("CI results must use an absolute owned temporary path")
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_environment():
    # Do not pass GitHub tokens, provider/mail credentials or host app config
    # into test/build subprocesses. System/tool cache settings retain their
    # caller-selected values; this does not create another Go build cache.
    names = ["PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL",
             "GOCACHE", "GOMODCACHE", "GOPATH", "GOROOT", "CC", "CXX",
             "SSL_CERT_FILE", "SSL_CERT_DIR", "BUILD_SCRATCH_DIR"]
    env = {name: os.environ[name] for name in names if name in os.environ}
    env.update(CI="true", GOTOOLCHAIN="local", ENVIRONMENT="development")
    return env


def require_ephemeral_workspace():
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return
    scratch = os.environ.get("BUILD_SCRATCH_DIR")
    if not scratch or not PRODUCT.is_relative_to(Path(scratch).resolve()):
        raise RuntimeError("Export source into official build scratch before local build commands")


def capture(command, name, cwd=PRODUCT, env=None):
    directory = results_directory()
    with (directory / (name + ".stdout")).open("w") as stdout, \
            (directory / (name + ".stderr")).open("w") as stderr:
        result = subprocess.run(command, cwd=cwd, env=env or test_environment(),
                                stdout=stdout, stderr=stderr, timeout=2700)
    print(f"{name}: exit {result.returncode}", flush=True)
    return result.returncode


def require_success(command, name, cwd=PRODUCT, env=None):
    status = capture(command, name, cwd, env)
    if status:
        raise RuntimeError(f"{name} failed; inspect its retained report")
