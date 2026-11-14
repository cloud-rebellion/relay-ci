#!/usr/bin/env python3
"""Separate trusted scanner installation from read-only complete module scans."""
import hashlib

from common import (PRODUCT, POLICY, DockerSession, classify_vulncheck,
                    compiler_inputs, module_export, output_directory,
                    require_ephemeral, source_sha, write_report)


def main():
    require_ephemeral()
    inputs = compiler_inputs()
    sha = source_sha()
    directory = output_directory()
    if POLICY["accepted_go_advisories"]:
        raise RuntimeError("Relay has no reviewed Go vulnerability exemptions")
    tools = directory / "vulnerability-tools"
    tools.mkdir()
    version_check = "test \"$(go env GOVERSION)\" = go" + inputs["go"] + "; "
    outcomes = []
    with DockerSession() as docker:
        image = docker.pull(inputs["go_image"], "vulnerability-go")
        install = "set -e; export GOTOOLCHAIN=local; cd /tmp; " + version_check + \
                  "GOBIN=/tools go install " + POLICY["govulncheck_module"]
        status, _ = docker.run("vulnerability-install", image, ["sh", "-c", install],
                               mounts=[(tools, "/tools", False)])
        if status:
            raise RuntimeError("Source-free govulncheck installation failed")
        executable = tools / "govulncheck"
        tool_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
        for label, module in [("crm", PRODUCT), ("voip", PRODUCT / "voip")]:
            exported = module_export(module, directory / ("vulnerability-source-" + label))
            # A repo-influenced C compiler never has write access to the scanner
            # binary. CGO remains enabled, matching the actual Stage package graph.
            scan = "set -e; export GOTOOLCHAIN=local CGO_ENABLED=1; " + version_check + \
                   "apk add --no-cache gcc musl-dev >/dev/null; cd /src; /tools/govulncheck ./..."
            status, _ = docker.run("vulnerability-scan-" + label, image, ["sh", "-c", scan],
                                   mounts=[(tools, "/tools", True), (exported, "/src", True)])
            outcome = {"module": label, "exit_code": status, "scanner_sha256": tool_hash}
            outcomes.append(outcome)
            write_report("vulnerability-" + label, {"source_sha": sha, **outcome,
                         "status": "passed" if status == 0 else "findings" if status == 3 else "scanner-error"})
            classify_vulncheck(status)
            if hashlib.sha256(executable.read_bytes()).hexdigest() != tool_hash:
                raise RuntimeError("The trusted scanner binary changed")
    if compiler_inputs() != inputs:
        raise RuntimeError("Compiler inputs changed during vulnerability scanning")
    write_report("vulnerability-summary", {"source_sha": sha, "status": "passed", "toolchains": inputs,
                 "modules": outcomes, "accepted_advisories": [],
                 "scanner_reference": POLICY["govulncheck_module"], "scanner_sha256": tool_hash,
                 "scanner_install_source_mount": False, "scan_tool_mount_readonly": True})


if __name__ == "__main__":
    main()
