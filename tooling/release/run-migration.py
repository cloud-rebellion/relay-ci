#!/usr/bin/env python3
"""Rehearse the complete runtime SQL directory on one isolated synthetic DB."""
import hashlib
import re
import subprocess
import time

from common import (PRODUCT, POLICY, PINS, ROOT, DockerSession, clean_environment,
                    compiler_inputs, output_directory, require_ephemeral,
                    source_sha, write_report)


def inventory(directory):
    rows = []
    for path in sorted(directory.glob("*.sql")):
        match = re.fullmatch(r"([0-9]+)_[A-Za-z0-9_]+\.sql", path.name)
        if not match or path.is_symlink():
            raise RuntimeError("Unreviewed migration filename or linked input")
        rows.append({"name": path.name, "version": int(match[1]),
                     "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    if len(rows) < 4 or len({row["version"] for row in rows}) != len(rows):
        raise RuntimeError("Missing migration set, duplicate version or insufficient rollback cohort")
    return sorted(rows, key=lambda row: row["version"])


def validate_applied(raw, expected):
    try:
        versions = [int(line) for line in raw.splitlines() if line.strip()]
    except ValueError as error:
        raise RuntimeError("Invalid Goose history inventory") from error
    if versions != expected:
        raise RuntimeError("Actual database migration history differs from the required cohort")
    return versions


def applied_versions(docker, pg_name, expected, phase):
    item = docker._inspect("container", pg_name)
    cid = docker.container_ids[pg_name].read_text().strip()
    if not item or item["Id"] != cid or item["Config"]["Labels"].get("relay.ci.owner") != docker.owner:
        raise RuntimeError("Database ownership changed")
    command = ["docker", "exec", cid, "psql", "-U", "ci", "-d", "ci", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c",
               "SELECT DISTINCT version_id FROM public.goose_db_version WHERE is_applied AND version_id>0 ORDER BY version_id"]
    result = subprocess.run(command, env=clean_environment(), text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise RuntimeError("Cannot read the actual isolated Goose history")
    versions = validate_applied(result.stdout, expected)
    write_report("migration-history-" + phase, {"phase": phase, "versions": versions, "status": "passed"})


def main():
    require_ephemeral()
    inputs = compiler_inputs()
    sha = source_sha()
    directory = output_directory()
    migrations = PRODUCT / "internal/db/migrations"
    before = inventory(migrations)
    versions = [row["version"] for row in before]
    if POLICY["rollback_attempts"] != 3 or POLICY["goose_version"] != "v3.27.1":
        raise RuntimeError("The reviewed ordinary rollback/tool policy changed")
    tools = directory / "migration-tools"
    tools.mkdir()
    with DockerSession() as docker:
        go_image = docker.pull(inputs["go_image"], "migration-go")
        pg_image = docker.pull(PINS["images"]["postgres"]["reference"], "migration-postgres")
        install = "set -e; export GOTOOLCHAIN=local; cd /tmp; test \"$(go env GOVERSION)\" = go" + inputs["go"] + \
                  "; GOBIN=/tools go install github.com/pressly/goose/v3/cmd/goose@" + POLICY["goose_version"]
        status, _ = docker.run("migration-install", go_image, ["sh", "-c", install], mounts=[(tools, "/tools", False)])
        if status:
            raise RuntimeError("Source-free pinned Goose installation failed")
        tool_hash = hashlib.sha256((tools / "goose").read_bytes()).hexdigest()
        network = docker.network()
        status, pg_name = docker.run("migration-postgres", pg_image, [], network=network, detach=True,
                                     env=["POSTGRES_USER=ci", "POSTGRES_PASSWORD=ci", "POSTGRES_DB=ci"])
        if status:
            raise RuntimeError("Owned synthetic PostgreSQL failed to start")
        ready = False
        for _ in range(30):
            item = docker._inspect("container", pg_name)
            cid = docker.container_ids[pg_name].read_text().strip()
            if not item or item["Id"] != cid or item["Config"]["Labels"].get("relay.ci.owner") != docker.owner:
                raise RuntimeError("Synthetic database exited or ownership changed")
            if subprocess.run(["docker", "exec", cid, "pg_isready", "-U", "ci", "-d", "ci"],
                              env=clean_environment(), stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=5).returncode == 0:
                ready = True
                break
            time.sleep(1)
        if not ready:
            raise RuntimeError("Synthetic PostgreSQL never became ready")
        prelude = "set -e; export PATH=/tools:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; " \
                  "export GOOSE_DRIVER=postgres GOOSE_MIGRATION_DIR=/m GOOSE_TABLE=goose_db_version; " \
                  "export GOOSE_DBSTRING='host=" + pg_name + " port=5432 user=ci password=ci dbname=ci sslmode=disable'; cd /m; "
        mounts = [(tools, "/tools", True), (migrations, "/m", True), (ROOT / "goose-down.sh", "/goose-down.sh", True)]
        for phase, script, expected in [
            ("up", "goose --version; goose status; goose up; goose status", versions),
            ("down", ". /goose-down.sh; goose status", versions[:-3]),
            ("replay", "goose up; goose status", versions),
        ]:
            status, _ = docker.run("migration-" + phase, go_image, ["sh", "-c", prelude + script],
                                   mounts=mounts, network=network)
            if status:
                raise RuntimeError("Migration " + phase + " failed; an existing Down error is never waived")
            applied_versions(docker, pg_name, expected, phase)
            if inventory(migrations) != before or hashlib.sha256((tools / "goose").read_bytes()).hexdigest() != tool_hash:
                raise RuntimeError("Migration source or trusted Goose binary changed")
    if compiler_inputs() != inputs:
        raise RuntimeError("Compiler inputs changed during migration rehearsal")
    write_report("migration-summary", {"source_sha": sha, "status": "passed", "migrations": before,
                 "goose_cli": POLICY["goose_version"], "runtime_goose_library": POLICY["goose_runtime_library"],
                 "goose_sha256": tool_hash, "postgres_reference": PINS["images"]["postgres"]["reference"],
                 "rollback_versions": versions[-3:], "replayed_head": versions[-1],
                 "scope": POLICY["migration_scope"], "retained_data_restore_qualified": False,
                 "production_migration_authority_changed": False})


if __name__ == "__main__":
    main()
