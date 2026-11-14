#!/usr/bin/env python3
"""Reject partial, retried, skipped or substituted compiled-browser outcomes."""
import json
from pathlib import Path
import sys


def all_specs(suites):
    return [spec for suite in suites for spec in suite.get("specs", [])] + [
        spec for suite in suites for spec in all_specs(suite.get("suites", []))]


def identities(report):
    specs = all_specs(report.get("suites", []))
    keys = [(spec["file"], spec["title"]) for spec in specs]
    if not keys or len(keys) != len(set(keys)):
        raise ValueError("Missing or duplicate browser cases")
    return specs, set(keys)


def validate(report, manifest, exit_code):
    if exit_code != 0 or report.get("errors"):
        raise ValueError("Browser process or global error failed")
    expected = {(row["file"], row["title"]) for row in manifest["cases"]}
    if len(expected) != manifest["expectedTests"] or not expected:
        raise ValueError("Invalid browser case manifest")
    specs, observed = identities(report)
    if observed != expected:
        raise ValueError("Browser case inventory does not match the exact manifest")
    projects = report["config"]["projects"]
    if len(projects) != 1 or projects[0]["timeout"] != 30000 or projects[0]["retries"] != 0:
        raise ValueError("Browser timeout/project/retry contract changed")
    for spec in specs:
        tests = spec.get("tests", [])
        if len(tests) != 1 or tests[0].get("expectedStatus") != "passed":
            raise ValueError("Missing project or expected-failure case")
        runs = tests[0].get("results", [])
        if len(runs) != 1 or runs[0].get("status") != "passed" or runs[0].get("retry") != 0 or runs[0].get("errors"):
            raise ValueError("Non-passing, skipped or retried browser case")
    stats = report["stats"]
    if stats["expected"] != len(expected) or any(stats[key] != 0 for key in ["skipped", "unexpected", "flaky"]):
        raise ValueError("Browser aggregate result is incomplete")
    return len(expected)


if __name__ == "__main__":
    report = json.loads(Path(sys.argv[1]).read_text())
    manifest = json.loads(Path(sys.argv[2]).read_text())
    print(f"Validated {validate(report, manifest, int(sys.argv[3]))} exact browser passes")
