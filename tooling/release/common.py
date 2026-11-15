"""Owned ephemeral execution helpers for the portable Relay release gates."""
from contextlib import AbstractContextManager
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import tarfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from binding import ACTIVE_GO_VERSION, compiler_contract, inspect_go_binary, private_product, source_sha, origin_sha, git, git_object, committed_tree
import uuid

ROOT = Path(__file__).resolve().parent
PRODUCT = private_product()
PINS = json.loads((ROOT.parent / "github/pins.json").read_text())
POLICY = json.loads((ROOT / "policy.json").read_text())
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
SOURCE_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def clean_environment():
    names = ("PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL",
             "GOCACHE", "GOMODCACHE", "GOPATH", "GOROOT", "CC", "CXX",
             "SSL_CERT_FILE", "SSL_CERT_DIR", "BUILD_SCRATCH_DIR")
    result = {name: os.environ[name] for name in names if name in os.environ}
    result.update(CI="true", GOTOOLCHAIN="local", GOWORK="off")
    return result


def output_directory():
    value = os.environ.get("RELAY_CI_RESULTS_DIR")
    if not value:
        scratch = os.environ.get("BUILD_SCRATCH_DIR")
        if not scratch:
            raise RuntimeError("An owned temporary results directory is required")
        value = str(Path(scratch) / "relay-release-results")
    path = Path(value)
    if not path.is_absolute() or path.resolve().is_relative_to(PRODUCT):
        raise RuntimeError("Results must be an absolute temporary path outside the image context")
    path.mkdir(parents=True, exist_ok=True)
    return path


def require_ephemeral():
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return
    scratch = os.environ.get("BUILD_SCRATCH_DIR")
    if not scratch or not PRODUCT.is_relative_to(Path(scratch).resolve()):
        raise RuntimeError("Export source into official build scratch before local execution")


def write_report(name, value):
    target = output_directory() / (name + ".json")
    target.write_text(json.dumps(value, indent=2) + "\n")
    return target


def execute(command, name, *, cwd=PRODUCT, env=None, timeout=2700):
    directory = output_directory()
    with (directory / (name + ".stdout")).open("w") as stdout, (directory / (name + ".stderr")).open("w") as stderr:
        status = subprocess.run(command, cwd=cwd, env=env or clean_environment(),
                                stdout=stdout, stderr=stderr, timeout=timeout).returncode
    print(name + ": exit " + str(status), flush=True)
    return status


def require_zero(command, name, **kwargs):
    status = execute(command, name, **kwargs)
    if status:
        raise RuntimeError(name + " failed; inspect its retained report")
    return status


def compiler_inputs():
    if PINS['go'] != ACTIVE_GO_VERSION:
        raise RuntimeError("The active compiler pin must remain exactly Go 1.26.11")
    active = compiler_contract(PRODUCT)
    dockerfile = (PRODUCT / "Dockerfile").read_text()
    module = (PRODUCT / "go.mod").read_text()
    if "FROM golang:" + PINS["go"] + "-alpine AS backend" not in dockerfile:
        raise RuntimeError("Go security compiler differs from the production builder")
    if not re.search(r"(?m)^toolchain go" + re.escape(PINS["go"]) + r"$", module):
        raise RuntimeError("Go module toolchain differs from the reviewed compiler")
    if "FROM oven/bun:" + PINS["bun"] + "-alpine AS frontend" not in dockerfile:
        raise RuntimeError("Bun checker differs from the production builder")
    return {"go": PINS["go"], "bun": PINS["bun"],
            "active_compiler_contract": active,
            "go_image": "golang:" + PINS["go"] + "-alpine",
            "bun_image": "oven/bun:" + PINS["bun"] + "-alpine",
            "dockerfile_sha256": hashlib.sha256(dockerfile.encode()).hexdigest(),
            "go_mod_sha256": hashlib.sha256(module.encode()).hexdigest()}


def module_export(module, destination):
    """Export exact committed compiler blobs, with a compile-only embed stub."""
    if destination.exists():
        raise RuntimeError("Module export must be fresh")
    repository = Path(git(module, "rev-parse", "--show-toplevel").decode().strip())
    prefix = module.relative_to(repository).as_posix() + "/"
    _, tree, _ = committed_tree(repository, source_sha())
    entries = []
    for path, row in tree.items():
        if not path.startswith(prefix):
            continue
        mode, kind, blob = row["mode"], row["type"], row["oid"]
        relative = Path(path[len(prefix):])
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("Invalid committed compiler path")
        entries.append((relative, mode, kind, blob))
    expected_modules = {"go.mod", "voip/go.mod"} if module == PRODUCT else {"go.mod"}
    actual_modules = {path.as_posix() for path, _, _, _ in entries if path.name == "go.mod"}
    if actual_modules != expected_modules:
        raise RuntimeError("Go module inventory changed; every nested module needs an explicit security lane")
    destination.mkdir()
    for relative, mode, kind, blob in entries:
        if module == PRODUCT and relative.parts[0] == "voip":
            continue
        if relative.name not in ("go.mod", "go.sum") and relative.suffix not in (".go", ".sql", ".yaml"):
            continue
        if kind != "blob" or mode not in ("100644", "100755"):
            raise RuntimeError("Linked or nonregular compiler input requires review")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(git_object(repository, "blob", blob))
    if module == PRODUCT:
        stub = destination / "cmd/server/frontend/build/index.html"
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text("<!-- compile-only embed stub; never an image or browser artifact -->\n")
    if not (destination / "go.mod").is_file():
        raise RuntimeError("The required complete module source is missing")
    return destination


def classify_vulncheck(status):
    if status == 0:
        return "passed"
    if status == 3:
        raise RuntimeError("govulncheck found reachable vulnerabilities; Relay has no accepted advisories")
    raise RuntimeError("govulncheck did not reach a verdict; scanner exit " + str(status))


def validate_image_id(value):
    if not isinstance(value, str) or not IMAGE_ID.fullmatch(value):
        raise RuntimeError("An immutable image ID is required")
    return value


class DockerSession(AbstractContextManager):
    """Own only newly created names, verify labels/IDs, and fail on cleanup errors."""
    def __init__(self):
        self.owner = uuid.uuid4().hex
        self.containers = []
        self.container_ids = {}
        self.networks = []
        self.network_ids = {}
        self.images = []
        self.graceful_containers = set()
        self.old_handlers = {}

    def __enter__(self):
        require_zero(["docker", "version"], "docker-version")
        for signum in (signal.SIGINT, signal.SIGTERM):
            self.old_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, lambda sig, frame: (_ for _ in ()).throw(SystemExit(128 + sig)))
        return self

    def _inspect(self, kind, name):
        result = subprocess.run(["docker", kind, "inspect", name], env=clean_environment(),
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if result.returncode:
            if result.returncode == 1 and ("No such " in result.stderr or "not found" in result.stderr):
                return None
            raise RuntimeError("Cannot verify owned Docker " + kind + " during cleanup")
        items = json.loads(result.stdout)
        if len(items) != 1:
            raise RuntimeError("Ambiguous Docker ownership")
        return items[0]

    def pull(self, reference, name):
        require_zero(["docker", "pull", reference], name + "-pull")
        item = self._inspect("image", reference)
        if not item:
            raise RuntimeError("Pulled image is missing")
        image = validate_image_id(item["Id"])
        self.images.append({"reference": reference, "image_id": image,
                            "repo_digests": item.get("RepoDigests", [])})
        return image

    def network(self):
        name = "relay-ci-" + self.owner
        self.networks.append(name)
        require_zero(["docker", "network", "create", "--label", "relay.ci.owner=" + self.owner,
                      "--internal", name], "network-create")
        item = self._inspect("network", name)
        if not item or item.get("Labels", {}).get("relay.ci.owner") != self.owner:
            raise RuntimeError("Owned network could not be verified")
        self.network_ids[name] = item["Id"]
        return name

    def run(self, leaf, image, command, *, mounts=(), env=(), network=None, detach=False, memory="3g"):
        validate_image_id(image)
        if not re.fullmatch(r"[a-z0-9-]+", leaf):
            raise RuntimeError("Invalid owned container label")
        name = "relay-ci-" + self.owner + "-" + leaf
        if name in self.containers:
            raise RuntimeError("Container name already used in this run")
        self.containers.append(name)
        cidfile = output_directory() / (name + ".cid")
        self.container_ids[name] = cidfile
        args = ["docker", "run", "--rm", "--name", name, "--cidfile", str(cidfile),
                "--label", "relay.ci.owner=" + self.owner, "--memory", memory,
                "--cpus", "2", "--pids-limit", "256"]
        if detach:
            args.append("-d")
        if network:
            args += ["--network", network]
        for host, target, readonly in mounts:
            host = Path(host).resolve()
            args += ["--mount", "type=bind,src=" + str(host) + ",dst=" + target + (",readonly" if readonly else "")]
        for value in env:
            args += ["-e", value]
        args += [image] + list(command)
        status = execute(args, leaf)
        if detach and status == 0:
            item = self._inspect("container", name)
            if not item or item["Config"]["Labels"].get("relay.ci.owner") != self.owner:
                raise RuntimeError("Started database ownership could not be verified")
        return status, name

    def read_relay_binary(self, image, output):
        """Read daemon filesystem bytes from an owned container that never starts."""
        validate_image_id(image)
        item = self._inspect("image", image)
        if not item or item["Id"] != image or item.get("Config", {}).get("Volumes"):
            raise RuntimeError("Binary readback requires the exact image with no volumes")
        directory = output_directory().resolve()
        output = Path(output)
        archive = directory / "image-binary-readback.tar"
        if output != directory / "final-image-brightcrm.bin" or any(path.exists() or path.is_symlink() for path in (output, archive)):
            raise RuntimeError("Image binary outputs must be fresh fixed private files")
        name = "relay-ci-" + self.owner + "-binary-readback"
        if name in self.containers:
            raise RuntimeError("Image binary readback cannot be repeated")
        self.containers.append(name)
        self.graceful_containers.add(name)
        cidfile = directory / (name + ".cid")
        self.container_ids[name] = cidfile
        limit = 128 * 1024 * 1024
        create = ["docker", "create", "--rm", "--pull=never", "--name", name, "--cidfile", str(cidfile),
                  "--label", "relay.ci.owner=" + self.owner, "--read-only", "--network", "none",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--no-healthcheck",
                  "--memory", "64m", "--cpus", "1", "--pids-limit", "32", "--stop-timeout", "5",
                  "--entrypoint", "/__relay_ci_never_start__", image]
        require_zero(create, "image-binary-create", timeout=30)
        identity = cidfile.read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", identity):
            raise RuntimeError("Image reader has no exact container identity")
        def owned_created():
            current = self._inspect("container", name)
            state = current.get("State", {}) if current else {}
            if not current or current["Id"] != identity or current["Name"] != "/" + name or current.get("Image") != image or \
                    current.get("Config", {}).get("Labels", {}).get("relay.ci.owner") != self.owner or \
                    state.get("Status") != "created" or state.get("Running") is not False or \
                    state.get("StartedAt") != "0001-01-01T00:00:00Z" or current.get("RestartCount") != 0:
                raise RuntimeError("Image reader changed identity or was started")
        owned_created()
        def output_limit():
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit + 1024 * 1024,) * 2)
        with archive.open("xb") as stdout, (directory / "image-binary-readback.stderr").open("xb") as stderr:
            archive.chmod(0o600)
            (directory / "image-binary-readback.stderr").chmod(0o600)
            try:
                result = subprocess.run(["docker", "cp", identity + ":/usr/local/bin/brightcrm", "-"],
                                        env=clean_environment(), stdout=stdout, stderr=stderr,
                                        timeout=30, preexec_fn=output_limit)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise RuntimeError("Owned image binary archive capture failed") from error
        owned_created()
        if result.returncode or not 0 < archive.stat().st_size <= limit + 1024 * 1024:
            raise RuntimeError("Owned image binary archive capture failed or exceeded its bound")
        try:
            with tarfile.open(archive, "r:") as bundle:
                member = bundle.next()
                if not member or member.name != "brightcrm" or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or \
                        member.linkname or member.sparse is not None or not 0 < member.size <= limit:
                    raise RuntimeError("Image archive must contain only the fixed bounded regular executable")
                source = bundle.extractfile(member)
                if source is None:
                    raise RuntimeError("Image binary archive body is missing")
                written = 0
                with source, output.open("xb") as destination:
                    output.chmod(0o600)
                    while block := source.read(min(1024 * 1024, member.size - written + 1)):
                        written += len(block)
                        if written > member.size:
                            raise RuntimeError("Image binary archive body exceeds its declared size")
                        destination.write(block)
                if written != member.size or bundle.next() is not None:
                    raise RuntimeError("Image binary archive is truncated or contains extra entries")
        except (tarfile.TarError, OSError, EOFError) as error:
            raise RuntimeError("Image binary archive is malformed or truncated") from error
        metadata = inspect_go_binary(output, results_root=directory)
        archive.unlink()
        return metadata

    def __exit__(self, exc_type, exc, tb):
        errors = []
        for name in reversed(self.containers):
            try:
                item = self._inspect("container", name)
                if not item:
                    continue
                expected = self.container_ids[name].read_text().strip()
                if not re.fullmatch(r"[0-9a-f]{64}", expected) or item["Id"] != expected or item["Name"] != "/" + name or item["Config"].get("Labels", {}).get("relay.ci.owner") != self.owner:
                    raise RuntimeError("Foreign or mismatched container state preserved")
                if name in self.graceful_containers and item.get("State", {}).get("Running"):
                    require_zero(["docker", "container", "stop", "--time", "5", item["Id"]],
                                 "stop-" + name, timeout=20)
                    item = self._inspect("container", name)
                    if item and (item["Id"] != expected or item["Name"] != "/" + name or item["Config"].get("Labels", {}).get("relay.ci.owner") != self.owner):
                        raise RuntimeError("Changed container state after graceful stop preserved")
                if item:
                    require_zero(["docker", "container", "rm", "-f", "-v", item["Id"]], "cleanup-" + name)
            except Exception as error:
                errors.append(str(error))
        for name in reversed(self.networks):
            try:
                item = self._inspect("network", name)
                if not item:
                    continue
                if item["Id"] != self.network_ids.get(name) or item.get("Labels", {}).get("relay.ci.owner") != self.owner:
                    raise RuntimeError("Foreign or mismatched network state preserved")
                require_zero(["docker", "network", "rm", item["Id"]], "cleanup-network")
            except Exception as error:
                errors.append(str(error))
        for signum, handler in self.old_handlers.items():
            signal.signal(signum, handler)
        write_report("docker-ownership-" + self.owner, {"owner": self.owner, "images": self.images,
                                                     "cleanup": "failed" if errors else "passed", "errors": errors})
        if errors:
            raise RuntimeError("Owned Docker cleanup did not complete: " + "; ".join(errors)) from exc
        return False
