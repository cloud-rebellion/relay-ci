#!/usr/bin/env python3
"""Exact frontend registry, production build and complete compiled UI suite."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

from common import PRODUCT, PINS, capture, require_ephemeral_workspace, require_success, results_directory, source_sha, origin_sha, test_environment

require_ephemeral_workspace()
directory = results_directory()
env = test_environment()
version = subprocess.check_output(["bun", "--version"], env=env, text=True).strip()
if version != PINS["bun"]:
    raise RuntimeError("Bun does not match the production frontend contract")
env.update(PUBLIC_FLARE_RELEASE=origin_sha(), PUBLIC_FLARE_DSN="",
           BRIGHTCRM_FRONTEND_TEST_REPORT_DIR=str(directory / "frontend-tests"))
frontend, tests = PRODUCT / "frontend", PRODUCT / "tests/e2e"
require_success(["bun", "--no-env-file", "install", "--frozen-lockfile"], "frontend-install", frontend, env)
require_success(["bun", "run", "--no-env-file", "--no-install", "check"], "frontend-check", frontend, env)
require_success(["bun", "run", "--no-env-file", "--no-install", "test"], "frontend-test", frontend, env)
require_success(["bun", "--no-env-file", "--no-install", "scripts/write-build-manifest.mjs", "--validate-config"], "frontend-manifest-config", frontend, env)
require_success(["bun", "run", "--no-env-file", "--no-install", "build", "--sourcemap", "hidden"], "frontend-build", frontend, env)
require_success(["bun", "--no-env-file", "--no-install", "scripts/stage-source-maps.mjs"], "frontend-private-maps", frontend, env)
require_success(["bun", "--no-env-file", "--no-install", "scripts/write-build-manifest.mjs"], "frontend-build-manifest", frontend, env)
embedded = PRODUCT / "cmd/server/frontend/build"
if embedded.exists():
    raise RuntimeError("Frontend embedding requires a fresh generated target")
shutil.copytree(frontend / "build", embedded)
require_success(["bun", "--no-env-file", "install", "--frozen-lockfile"], "e2e-install", tests, env)
require_success(["bun", "run", "--bun", "playwright", "install", "--with-deps", "chromium"], "browser-install", tests, env)
env["PLAYWRIGHT_JSON_OUTPUT_NAME"] = str(directory / "browser-results.json")
command = ["bun", "run", "--bun", "playwright", "test", "--config", "playwright.bootstrap.config.ts", "--forbid-only", "--reporter=list,json"]
status = capture(command, "browser-run", tests, env)
for context in (tests / "test-results").rglob("error-context.md"):
    target = directory / "browser-failures" / context.relative_to(tests / "test-results")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(context, target)
spec = importlib.util.spec_from_file_location("browser_results", Path(__file__).with_name("validate-browser-results.py"))
validator = importlib.util.module_from_spec(spec); spec.loader.exec_module(validator)
count = validator.validate(json.loads((directory / "browser-results.json").read_text()),
                           json.loads(Path(__file__).with_name("browser-cases.json").read_text()), status)
(directory / "frontend-summary.json").write_text(json.dumps({"source_sha": source_sha(), "bun": version, "browser_passes": count, "status": "passed"}, indent=2) + "\n")
print(f"Relay frontend and {count} browser cases passed; reports: {directory}")
