#!/usr/bin/env python3
"""Run every core Go package against owned migrated PostgreSQL/Redis fixtures."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

from common import PRODUCT, PINS, capture, require_success, results_directory, source_sha, test_environment
from binding import inspect_go_binary

if os.environ.get("GITHUB_ACTIONS") != "true":
    raise RuntimeError("Backend fixture orchestration requires an ephemeral GitHub Actions runner")
directory = results_directory()
env = test_environment()
migrations = PRODUCT / "internal/db/migrations"
if not migrations.is_dir() or not list(migrations.glob("*.sql")):
    raise RuntimeError("Complete committed migration source is missing")
env["MIGRATIONS_DIR"] = str(migrations)
version = subprocess.check_output(["go", "env", "GOVERSION"], env=env, text=True).strip()
if version != "go" + PINS["go"]:
    raise RuntimeError("Go does not match the committed production compiler contract")
if not (PRODUCT / "cmd/server/frontend/build/index.html").is_file():
    raise RuntimeError("Build the actual frontend before backend compilation")
require_success(["docker", "info"], "docker-readiness", env=env)
require_success(["docker", "compose", "version"], "compose-readiness", env=env)
require_success(["go", "mod", "download"], "go-mod-download", env=env)
env.update(GOPROXY="off", CGO_ENABLED="1")
require_success(["go", "vet", "./..."], "go-vet", env=env)
binary = directory / "relay-core-server"
require_success(["go", "build", "-o", str(binary), "./cmd/server"], "core-server-build", env=env)
binary_metadata = inspect_go_binary(binary, results_root=directory)
binary.unlink()

owner = uuid.uuid4().hex
prefix = "relay-ci-" + owner
network = None
containers = []
images = []
outcomes = []
validator_spec = importlib.util.spec_from_file_location("go_results", Path(__file__).with_name("validate-go-results.py"))
validator = importlib.util.module_from_spec(validator_spec); validator_spec.loader.exec_module(validator)


def docker(*args):
    return subprocess.check_output(["docker", *args], env=env, text=True).strip()


def select_image(key, alias=None):
    reference = PINS["images"][key]["reference"]
    require_success(["docker", "pull", reference], "pull-" + key, env=env)
    selected = json.loads(docker("image", "inspect", reference))[0]
    image_id = selected["Id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise RuntimeError("Fixture image has no immutable local identity")
    if "@sha256:" in reference:
        digest = reference.split("@", 1)[1]
        if not any(item.endswith("@" + digest) for item in selected.get("RepoDigests", [])):
            raise RuntimeError("Pulled fixture descriptor differs from the committed pin")
    images.append({"key": key, "reference": reference, "id": image_id,
                   "repo_digests": selected.get("RepoDigests", [])})
    if alias:
        docker("tag", image_id, alias)
    return image_id


def start(name, image, *args):
    container = docker("run", "--rm", "-d", "--name", prefix + "-" + name,
                       "--label", "relay.ci.owner=" + owner,
                       "--network", network, *args, image,
                       *(["redis-server", "--requirepass", "ci", "--appendonly", "no"] if name == "redis" else []))
    if not re.fullmatch(r"[0-9a-f]{64}", container):
        raise RuntimeError("Owned fixture did not return an exact container ID")
    containers.append(container)
    return container


def sql(pg, statement, database="postgres"):
    return docker("exec", pg, "psql", "-U", "ci", "-d", database,
                  "-v", "ON_ERROR_STOP=1", "-Atc", statement)


def port(container, service_port):
    output = docker("port", container, service_port)
    match = re.fullmatch(r"127\.0\.0\.1:([0-9]+)", output)
    if not match:
        raise RuntimeError("Fixture port is not exclusively loopback-bound")
    return int(match[1])


cleanup_errors = []
try:
    pg_image = select_image("postgres")
    redis_image = select_image("redis")
    # These existing ciguards deliberately refuse implicit network pulls.
    select_image("alpine_guard", "alpine:3.21")
    select_image("prometheus_guard", "prom/prometheus:v3.4.0")
    network = docker("network", "create", "--label", "relay.ci.owner=" + owner, prefix)
    pg = start("postgres", pg_image, "--network-alias", "pg",
               "--publish", "127.0.0.1::5432", "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=1g",
               "--memory", "2g", "--pids-limit", "256",
               "-e", "POSTGRES_USER=ci", "-e", "POSTGRES_PASSWORD=ci", "-e", "POSTGRES_DB=relay_ci_template")
    redis = start("redis", redis_image, "--publish", "127.0.0.1::6379",
                  "--tmpfs", "/data:rw,nosuid,nodev,size=256m", "--memory", "512m", "--pids-limit", "128")
    for attempt in range(60):
        ready = subprocess.run(["docker", "exec", pg, "pg_isready", "-h", "127.0.0.1", "-U", "ci", "-d", "relay_ci_template"],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if ready.returncode == 0 and docker("exec", redis, "redis-cli", "--no-auth-warning", "-a", "ci", "PING") == "PONG":
                break
        except subprocess.CalledProcessError:
            pass
        time.sleep(1)
    else:
        raise RuntimeError("Owned PostgreSQL/Redis fixtures did not become ready")
    pg_port, redis_port = port(pg, "5432/tcp"), port(redis, "6379/tcp")
    env.update(DATABASE_URL=f"postgres://ci:ci@127.0.0.1:{pg_port}/relay_ci_template?sslmode=disable",
               BRIGHTCRM_TEST_REDIS_URL=f"redis://:ci@127.0.0.1:{redis_port}/0")
    require_success(["go", "run", "./cmd/migrate", "up"], "migrate-template", env=env)
    version_after_migration = sql(pg, "SELECT COALESCE(MAX(version_id),0) FROM goose_db_version WHERE is_applied", "relay_ci_template")
    expected_version = max(int(re.match(r"[0-9]+", path.name)[0]) for path in migrations.glob("*.sql"))
    if version_after_migration != str(expected_version):
        raise RuntimeError("Disposable template did not reach the complete committed schema")
    packages = subprocess.check_output(["go", "list", "./..."], cwd=PRODUCT, env=env, text=True).splitlines()
    if not packages or len(packages) != len(set(packages)):
        raise RuntimeError("Missing or duplicate Go package inventory")
    invitation_proved = False
    for index, package in enumerate(packages):
        metadata = json.loads(subprocess.check_output(["go", "list", "-json", package], cwd=PRODUCT, env=env, text=True))
        database = f"relay_ci_{index:03d}"
        sql(pg, f"CREATE DATABASE {database} TEMPLATE relay_ci_template")
        try:
            package_env = dict(env, BRIGHTCRM_TEST_DATABASE_URL=f"postgres://ci:ci@127.0.0.1:{pg_port}/{database}?sslmode=disable")
            package_env["BULKIMPORT_DSN"] = package_env["BRIGHTCRM_TEST_DATABASE_URL"]
            name = f"go-package-{index:03d}"
            status = capture(["go", "test", "-json", "-race", "-count=1", "-p=1", "-parallel=1", "-timeout=20m", package], name, env=package_env)
            events = [json.loads(line) for line in (directory / (name + ".stdout")).read_text().splitlines() if line.strip()]
            required = validator.INVITATION_REQUIREMENTS if package.endswith("/internal/handler") else []
            count = validator.validate(events, status, required,
                                       not metadata.get("TestGoFiles") and not metadata.get("XTestGoFiles"))
            invitation_proved |= bool(required)
            outcomes.append({"package": package, "status": "passed", "test_outcomes": count})
        finally:
            sql(pg, f"DROP DATABASE {database} WITH (FORCE)")
    if not invitation_proved:
        raise RuntimeError("Real invitation package was not exercised")
finally:
    # Stop only exact IDs created above, after proving this run's ownership.
    for container in reversed(containers):
        try:
            inspected = json.loads(docker("container", "inspect", container))[0]
            if inspected["Config"]["Labels"].get("relay.ci.owner") != owner:
                raise RuntimeError("Fixture container ownership changed")
            docker("stop", "--time", "10", container)
            if subprocess.run(["docker", "container", "inspect", container], env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                raise RuntimeError("Stopped --rm fixture still exists")
        except Exception as error:
            cleanup_errors.append(str(error))
    if network:
        try:
            inspected = json.loads(docker("network", "inspect", network))[0]
            if inspected["Labels"].get("relay.ci.owner") != owner:
                raise RuntimeError("Fixture network ownership changed")
            docker("network", "rm", network)
            if subprocess.run(["docker", "network", "inspect", network], env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                raise RuntimeError("Owned fixture network still exists")
        except Exception as error:
            cleanup_errors.append(str(error))
    (directory / "backend-fixtures.json").write_text(json.dumps({"owner": owner, "images": images,
                                                               "cleanup_errors": cleanup_errors}, indent=2) + "\n")
    if cleanup_errors:
        raise RuntimeError("Owned fixture cleanup was not verified")

(directory / "backend-summary.json").write_text(json.dumps({"source_sha": source_sha(), "go": version,
                                                           "server_binary": binary_metadata,
                                                           "schema": expected_version, "packages": outcomes,
                                                           "invitation_proved": True, "status": "passed"}, indent=2) + "\n")
print(f"Relay backend: {len(outcomes)} complete packages passed; real invitation proof present")
