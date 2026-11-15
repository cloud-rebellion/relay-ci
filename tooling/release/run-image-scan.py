#!/usr/bin/env python3
"""Build one exact final image and scan its immutable archive without a socket."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import uuid

from common import (PRODUCT, POLICY, DockerSession, clean_environment,
                    compiler_inputs, output_directory, require_ephemeral,
                    require_zero, source_sha, origin_sha, validate_image_id, write_report)


def file_digest(path, limit):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        raise RuntimeError("Image evidence must be a bounded nonempty regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    require_ephemeral()
    inputs = compiler_inputs()
    sha = source_sha()
    release_origin = origin_sha()
    directory = output_directory()
    if POLICY["accepted_image_advisories"] or POLICY["trivy_severities"] != ["CRITICAL", "HIGH"] or not POLICY["trivy_ignore_unfixed"]:
        raise RuntimeError("Relay image security policy differs from the reviewed gate")
    owner = uuid.uuid4().hex
    tag = "relay-ci:scan-" + owner
    iid = directory / "final-image.id"
    archive = directory / "final-image.tar"
    image_id = None
    with DockerSession() as docker:
        try:
            require_zero(["docker", "buildx", "build", "--load", "--iidfile", str(iid), "-t", tag,
                          "--build-arg", "PUBLIC_FLARE_RELEASE=" + release_origin,
                          "--label", "relay.ci.image.owner=" + owner,
                          "--label", "org.opencontainers.image.revision=" + release_origin, str(PRODUCT)], "final-image-build", timeout=4500)
            file_digest(iid, 80)
            image_id = validate_image_id(iid.read_text().strip())
            binary = directory / "final-image-brightcrm.bin"
            binary_metadata = docker.read_relay_binary(image_id, binary)
            binary.unlink()
            require_zero(["docker", "image", "save", "--output", str(archive), image_id], "final-image-archive")
            digest = file_digest(archive, POLICY["trivy_max_archive_bytes"])
            scanner = docker.pull(POLICY["trivy_reference"], "trivy")
            for severity in POLICY["trivy_severities"]:
                command = ["image", "--input", "/image.tar", "--severity", severity,
                           "--ignore-unfixed", "--vuln-type", "os,library", "--scanners", "vuln",
                           "--ignorefile", "/dev/null", "--exit-code", "1", "--format", "json"]
                status, _ = docker.run("trivy-" + severity.lower(), scanner, command,
                                       mounts=[(archive, "/image.tar", True)], memory="768m")
                if status:
                    raise RuntimeError("Trivy " + severity + " findings or scanner failure; blocking release")
                if file_digest(archive, POLICY["trivy_max_archive_bytes"]) != digest:
                    raise RuntimeError("The exact image archive changed between scans")
            if compiler_inputs() != inputs:
                raise RuntimeError("Production compiler inputs changed during image qualification")
        finally:
            inspected = subprocess.run(["docker", "image", "inspect", tag], env=clean_environment(),
                                       text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            if inspected.returncode:
                if inspected.returncode != 1 or not ("No such " in inspected.stderr or "not found" in inspected.stderr):
                    raise RuntimeError("Cannot verify this run's private image tag for cleanup")
            else:
                items = json.loads(inspected.stdout)
                if len(items) != 1 or items[0]["Config"].get("Labels", {}).get("relay.ci.image.owner") != owner or (image_id is not None and items[0]["Id"] != image_id):
                    raise RuntimeError("Private image tag changed; preserved for review")
                require_zero(["docker", "image", "rm", tag], "final-image-tag-cleanup")
    # A success receipt is authoritative only after tag, scanner-container and
    # network cleanup has returned successfully; no passed report survives a refusal.
    write_report("image-summary", {"source_sha": sha, "origin_stage_commit": release_origin, "status": "passed", "image_id": image_id,
                 "binary_compiler": binary_metadata, "binary_image_path": "/usr/local/bin/brightcrm",
                 "archive_sha256": digest, "scanner_image_id": scanner,
                 "scanner_reference": POLICY["trivy_reference"], "blocking_severities": ["CRITICAL", "HIGH"],
                 "ignore_unfixed": True, "accepted_advisories": [], "scanner_daemon_socket_mounted": False})


if __name__ == "__main__":
    main()
