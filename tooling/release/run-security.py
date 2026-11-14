#!/usr/bin/env python3
"""Apply the existing Relay source, transport, vet and strict frontend policy."""
import hashlib
import shutil
import subprocess

from common import (PRODUCT, ROOT, DockerSession, clean_environment, compiler_inputs,
                    execute, module_export, output_directory, require_ephemeral,
                    require_zero, source_sha, write_report)


def main():
    require_ephemeral()
    inputs = compiler_inputs()
    sha = source_sha()
    directory = output_directory()
    env = clean_environment()
    if subprocess.check_output(["go", "env", "GOVERSION"], env=env, text=True).strip() != "go" + inputs["go"]:
        raise RuntimeError("The source scanner/vet must use the reviewed production compiler")
    scanner = ROOT / "source-scan"
    require_zero(["go", "test", "-count=1", "."], "source-scanner-positive-controls", cwd=scanner, env=env)
    for label, source in [("brightcrm", PRODUCT), ("ops", PRODUCT.parent / "ops")]:
        if not source.is_dir():
            raise RuntimeError("Required complete security execution root is absent")
        require_zero(["go", "run", ".", "-root", str(source),
                      "-report", str(directory / ("source-scan-" + label + ".json"))],
                     "source-scan-" + label, cwd=scanner, env=env)
    for label, module in [("crm", PRODUCT), ("voip", PRODUCT / "voip")]:
        exported = module_export(module, directory / ("vet-source-" + label))
        require_zero(["go", "mod", "download"], "vet-download-" + label, cwd=exported, env=env)
        vet_env = dict(env, GOPROXY="off", CGO_ENABLED="1")
        require_zero(["go", "vet", "./..."], "security-vet-" + label, cwd=exported, env=vet_env)
    frontend = directory / "frontend-check-source"
    shutil.copytree(PRODUCT / "frontend", frontend,
                    ignore=shutil.ignore_patterns("node_modules", ".svelte-kit", "build", "dist", ".env", ".env.*"))
    lock_before = hashlib.sha256((frontend / "bun.lock").read_bytes()).hexdigest()
    prelude = "set -e; test \"$(bun --version)\" = " + inputs["bun"] + "; cd /src; "
    with DockerSession() as docker:
        image = docker.pull(inputs["bun_image"], "security-bun")
        mounts = [(frontend, "/src", False)]
        status, _ = docker.run("frontend-frozen-install", image,
                               ["sh", "-c", prelude + "bun --no-env-file install --frozen-lockfile"], mounts=mounts)
        if status:
            raise RuntimeError("Frozen frontend installation failed")
        status, _ = docker.run("frontend-strict-check", image,
                               ["sh", "-c", prelude + "bun run --no-env-file --no-install check"],
                               mounts=mounts, network="none")
        if status:
            raise RuntimeError("Strict offline Svelte/TypeScript check failed")
    if hashlib.sha256((frontend / "bun.lock").read_bytes()).hexdigest() != lock_before or compiler_inputs() != inputs:
        raise RuntimeError("Reviewed compiler or frozen lock inputs changed during security checks")
    write_report("security-summary", {"status": "passed", "source_sha": sha, "toolchains": inputs,
                 "source_roots": ["brightcrm", "ops"], "nested_go_modules": ["brightcrm/voip"],
                 "policy": "existing Stage source/transport/PEM rules; HTML and SQL review remain advisory",
                 "shared_ops_security_coverage": "complete pinned ops execution root scanned with original source policy"})


if __name__ == "__main__":
    main()
