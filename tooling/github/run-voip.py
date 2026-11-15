#!/usr/bin/env python3
"""Qualify the explicitly integrated VoIP module without starting its services."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

from common import PRODUCT, PINS, capture, require_ephemeral_workspace, require_success, results_directory, source_sha, test_environment
from binding import inspect_go_binary

require_ephemeral_workspace()
module = PRODUCT / "voip"
if not (module / "go.mod").is_file() or not (module / "SOURCE-ORIGIN.json").is_file():
    raise RuntimeError("The required integrated VoIP source module is missing")
env = test_environment()
version = subprocess.check_output(["go", "env", "GOVERSION"], env=env, text=True).strip()
if version != "go" + PINS["go"]:
    raise RuntimeError("VoIP CI must use the unified reviewed Go compiler")
directory = results_directory()
require_success(["go", "mod", "download"], "voip-mod-download", module, env)
env.update(GOPROXY="off", CGO_ENABLED="1")
require_success(["go", "vet", "./..."], "voip-vet", module, env)
packages = subprocess.check_output(["go", "list", "./..."], cwd=module, env=env, text=True).splitlines()
if not packages or len(packages) != len(set(packages)):
    raise RuntimeError("Missing or duplicate VoIP package inventory")
spec = importlib.util.spec_from_file_location("go_results", Path(__file__).with_name("validate-go-results.py"))
validator = importlib.util.module_from_spec(spec); spec.loader.exec_module(validator)
outcomes = []
for index, package in enumerate(packages):
    metadata = json.loads(subprocess.check_output(["go", "list", "-json", package], cwd=module, env=env, text=True))
    name = f"voip-package-{index:03d}"
    status = capture(["go", "test", "-json", "-race", "-count=1", "-p=1", "-parallel=1", "-timeout=5m", package], name, module, env)
    events = [json.loads(line) for line in (directory / (name + ".stdout")).read_text().splitlines() if line.strip()]
    count = validator.validate(events, status, allow_no_tests=not metadata.get("TestGoFiles") and not metadata.get("XTestGoFiles"))
    outcomes.append({"package": package, "status": "passed", "test_outcomes": count})
binaries = []
(directory / "bin").mkdir()
for process in ["api", "sip", "webrtc"]:
    output = directory / "bin" / ("relay-voip-" + process)
    require_success(["go", "build", "-o", str(output), "./cmd/" + process], "voip-build-" + process, module, env)
    binaries.append({"process": process, **inspect_go_binary(output, results_root=directory)})
(directory / "voip-summary.json").write_text(json.dumps({"source_sha": source_sha(), "go": version,
                                                        "source_origin_sha256": hashlib.sha256((module / "SOURCE-ORIGIN.json").read_bytes()).hexdigest(),
                                                        "packages": outcomes, "binaries": binaries, "status": "passed"}, indent=2) + "\n")
print(f"Relay VoIP: {len(outcomes)} full packages and all three process builds passed")
