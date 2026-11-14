"""Strict artifact-security assessment; no ClamAV daemon or app is executed."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import tarfile

from registry import descriptor, document, require, Refusal, sha, MANIFEST_TYPES, INDEX_TYPES

TOOL_REFERENCE = "docker.io/aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
TOOL_VERSION = "0.74.0"


def utc(value):
    require(isinstance(value, str), "database-timestamp-missing")
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Refusal("database-timestamp-invalid") from None
    require(result.tzinfo is not None, "database-timestamp-zone")
    return result.astimezone(dt.timezone.utc)


def validate_database(metadata, *, now, started, maximum_age=86400, version=2):
    require(metadata.get("Version") == version, "database-schema")
    updated = utc(metadata.get("UpdatedAt"))
    downloaded = utc(metadata.get("DownloadedAt"))
    next_update = utc(metadata.get("NextUpdate"))
    require(dt.timedelta(0) <= now - updated <= dt.timedelta(seconds=maximum_age), "database-stale-or-future")
    require(started <= downloaded <= now and updated <= downloaded, "database-not-freshly-downloaded")
    require(updated < next_update and next_update > now, "database-update-overdue")
    return {key: metadata[key] for key in ("Version", "UpdatedAt", "DownloadedAt", "NextUpdate")}


def tree_fingerprint(root):
    result = []
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "artifact-symlink")
        if path.is_dir():
            continue
        require(path.is_file() and path.stat().st_nlink == 1, "artifact-nonregular-file")
        checksum = hashlib.sha256()
        with path.open("rb") as handle:
            while block := handle.read(1 << 20):
                checksum.update(block)
        result.append({"path": path.relative_to(root).as_posix(), "bytes": path.stat().st_size,
                       "sha256": checksum.hexdigest()})
    return result


def database_fingerprint(cache):
    return {name: tree_fingerprint(cache / name) for name in ("db", "java-db")}


def validate_report(value, profile):
    require(value.get("SchemaVersion") == 2 and value.get("ArtifactType") == "container_image",
            "trivy-report-schema")
    require(value.get("Trivy", {}).get("Version") == TOOL_VERSION, "trivy-report-tool-version")
    metadata = value.get("Metadata", {})
    require(metadata.get("ImageID") == profile["image"]["config_digest"], "trivy-scanned-config-mismatch")
    os = metadata.get("OS", {})
    require(os.get("Family") == "debian" and os.get("Name") == "13" and not os.get("EOSL"),
            "trivy-os-or-support-mismatch")
    config = metadata.get("ImageConfig", {})
    require(config.get("architecture") == "amd64" and config.get("os") == "linux", "trivy-platform-mismatch")
    require(metadata.get("DiffIDs") == profile["observed_diff_ids"], "trivy-rootfs-mismatch")
    rows = value.get("Results")
    require(isinstance(rows, list) and rows, "trivy-empty-results")
    require(any(x.get("Class") == "os-pkgs" and x.get("Type") == "debian" and x.get("Packages") for x in rows),
            "trivy-os-package-inventory-missing")
    findings = []
    packages = 0
    for row in rows:
        require(row.get("Class") in {"os-pkgs", "lang-pkgs"}, "trivy-unexpected-result-class")
        require(not row.get("ExperimentalModifiedFindings"), "trivy-modified-or-ignored-findings")
        require(isinstance(row.get("Packages", []), list), "trivy-package-shape")
        packages += len(row.get("Packages", []))
        for item in row.get("Vulnerabilities", []):
            severity = item.get("Severity")
            require(severity in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, "trivy-unknown-severity")
            require(isinstance(item.get("VulnerabilityID"), str) and item.get("VulnerabilityID"), "trivy-vulnerability-id")
            if severity in {"HIGH", "CRITICAL"}:
                # Includes unfixed findings. Never normalize these to accepted.
                findings.append({"id": item["VulnerabilityID"], "severity": severity,
                                 "package": item.get("PkgName", ""),
                                 "installed": item.get("InstalledVersion", ""),
                                 "fixed": item.get("FixedVersion", "")})
    return {"high": sum(x["severity"] == "HIGH" for x in findings),
            "critical": sum(x["severity"] == "CRITICAL" for x in findings),
            "packages": packages, "findings": findings,
            "verdict": "failed" if findings else "passed"}


def validate_tool_manifest(registry, reference):
    require(reference == TOOL_REFERENCE, "trivy-reviewed-tool-pin")
    digest = reference.split("@", 1)[1]
    raw = registry.get("manifests", digest)
    value = document(raw)
    if value.get("mediaType") in INDEX_TYPES:
        entries = value.get("manifests", [])
        candidates = [x for x in entries if x.get("platform", {}).get("os") == "linux" and
                      x.get("platform", {}).get("architecture") == "amd64"]
        require(len(candidates) == 1, "trivy-tool-platform-not-unique")
        entry = descriptor(candidates[0], MANIFEST_TYPES, 1 << 20)
        raw = registry.get("manifests", entry["digest"], maximum=entry["size"])
        require(len(raw) == entry["size"], "trivy-tool-manifest-size")
        value = document(raw)
    require(value.get("schemaVersion") == 2 and value.get("mediaType") in MANIFEST_TYPES,
            "trivy-tool-manifest-shape")
    config = descriptor(value.get("config"), {"application/vnd.oci.image.config.v1+json",
        "application/vnd.docker.container.image.v1+json"}, 256 << 10)
    raw_config = registry.get("blobs", config["digest"], maximum=config["size"])
    require(len(raw_config) == config["size"], "trivy-tool-config-size")
    actual = document(raw_config)
    require(actual.get("architecture") == "amd64" and actual.get("os") == "linux", "trivy-tool-config-platform")
    require(not any(x.startswith("TRIVY_") for x in actual.get("config", {}).get("Env", [])),
            "trivy-tool-baked-configuration")
    return {"reference": reference, "platform_manifest_digest": sha(raw), "config_digest": config["digest"]}


def scan_arguments():
    # Empty config, empty ignore file, allow no environment/config injection.
    # Read the verified OCI directory, not a registry tag or Docker daemon image.
    return ["image", "--config", "/input/empty.yaml", "--cache-dir", "/cache", "--input", "/input/oci",
            "--cache-backend", "memory",
            "--scanners", "vuln", "--pkg-types", "os,library", "--list-all-pkgs",
            "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "--ignore-unfixed=false",
            "--ignorefile", "/input/empty.ignore", "--skip-db-update", "--skip-java-db-update",
            "--offline-scan", "--timeout", "30m", "--format", "json", "--exit-code", "0"]


class Trivy:
    def __init__(self, daemon, tool, work, reports):
        self.daemon, self.tool, self.work, self.reports = daemon, tool, work, reports
        self.sequence = 0

    def invoke(self, arguments, *, network=False, timeout=1800):
        self.sequence += 1
        name = "relay-scanner-" + self.daemon.owner + "-trivy-" + str(self.sequence)
        # Only the reviewed tool runs. The candidate ClamAV image is never
        # installed in this daemon, started, or supplied as an entrypoint.
        result = self.daemon.docker(["run", "--rm", "--name", name,
            "--label", "relay.ci.owner=" + self.daemon.owner, "--network", "host" if network else "none",
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--memory=3g", "--cpus=2", "--pids-limit=256", "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m",
            "--mount", "type=bind,src=" + str(self.work) + ",dst=/input,readonly",
            "--mount", "type=bind,src=" + str(self.work / "cache") + ",dst=/cache",
            "--env", "HOME=/tmp", "--env", "TMPDIR=/cache/tmp",
            "--entrypoint", "/usr/local/bin/trivy", self.tool["config_digest"], *arguments], timeout=timeout,
            allow_failure=True)
        require(result.returncode == 0, "trivy-command-failed-" + str(self.sequence))
        require(len(result.stdout) <= 64 << 20 and len(result.stderr) <= 64 << 20, "trivy-report-size")
        # Unknown warnings can indicate unsupported/skipped analysis. Stop rather
        # than silently treating a partial package scan as a clear image.
        require(not re.search(rb"\b(WARN|ERROR|FATAL)\b", result.stderr), "trivy-warning-or-error")
        return result.stdout

    def assess(self, profile, *, now=lambda: dt.datetime.now(dt.timezone.utc)):
        started = now()
        self.daemon.docker(["pull", self.tool["reference"]], timeout=900)
        inspected = self.daemon.docker(["image", "inspect", self.tool["reference"]])
        rows = json.loads(inspected.stdout)
        require(len(rows) == 1 and rows[0].get("Id") == self.tool["config_digest"], "trivy-pulled-tool-identity")
        version = document(self.invoke(["version", "--format", "json"]))
        require(version.get("Version") == TOOL_VERSION, "trivy-runtime-version")
        self.invoke(["image", "--config", "/input/empty.yaml", "--cache-dir", "/cache",
                     "--download-db-only", "--db-repository", "ghcr.io/aquasecurity/trivy-db:2"], network=True)
        self.invoke(["image", "--config", "/input/empty.yaml", "--cache-dir", "/cache",
                     "--download-java-db-only", "--java-db-repository", "ghcr.io/aquasecurity/trivy-java-db:1"], network=True)
        cache = self.work / "cache"
        db = document((cache / "db/metadata.json").read_bytes())
        java = document((cache / "java-db/metadata.json").read_bytes())
        db_observation = validate_database(db, now=now(), started=started)
        # Java index has a different upstream update cadence; it must still be
        # downloaded in this run and not overdue. This is an explicit profile,
        # not an exemption for stale vulnerability data.
        java_observation = validate_database(java, now=now(), started=started, maximum_age=7 * 86400, version=1)
        before = database_fingerprint(cache)
        require(any(x["path"] == "trivy.db" and x["bytes"] > 0 for x in before["db"]) and
                any(x["path"] == "trivy-java.db" and x["bytes"] > 0 for x in before["java-db"]), "trivy-database-files-missing")
        raw = self.invoke(scan_arguments())
        (self.reports / "trivy-report.json").write_bytes(raw)
        verdict = validate_report(document(raw), profile)
        require(database_fingerprint(cache) == before, "trivy-database-changed-during-scan")
        # The JSON report with complete package inventory is retained even on
        # HIGH/CRITICAL. A failing image never advances to daemon qualification.
        if verdict["verdict"] == "failed":
            return {**verdict, "database": db_observation, "java_database": java_observation,
                    "database_files": before, "sbom_generated": False}
        args = scan_arguments()
        args[args.index("json")] = "cyclonedx"
        sbom = self.invoke(args)
        parsed = document(sbom)
        require(parsed.get("bomFormat") == "CycloneDX" and parsed.get("components"), "trivy-sbom-missing")
        (self.reports / "sbom.cdx.json").write_bytes(sbom)
        require(database_fingerprint(cache) == before, "trivy-database-changed-during-sbom")
        return {**verdict, "database": db_observation, "java_database": java_observation,
                "database_files": before, "sbom_generated": True}


def custody_tar(directory, target):
    entries = tree_fingerprint(directory)
    require(sum(x["bytes"] for x in entries) <= 1 << 30, "oci-custody-size")
    with tarfile.open(target, "x", format=tarfile.USTAR_FORMAT) as archive:
        for item in entries:
            path = directory / item["path"]
            info = tarfile.TarInfo(item["path"])
            info.size = item["bytes"]
            info.mode = 0o600
            with path.open("rb") as handle:
                archive.addfile(info, handle)
    checksum = hashlib.sha256()
    with target.open("rb") as handle:
        while block := handle.read(1 << 20):
            checksum.update(block)
    return {"files": entries, "archive_bytes": target.stat().st_size,
            "archive_sha256": checksum.hexdigest()}
