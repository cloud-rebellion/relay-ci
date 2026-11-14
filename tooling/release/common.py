"""Owned ephemeral execution helpers for the portable Relay release gates."""
from contextlib import AbstractContextManager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from binding import private_product, source_sha, origin_sha
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
    dockerfile = (PRODUCT / "Dockerfile").read_text()
    module = (PRODUCT / "go.mod").read_text()
    if "FROM golang:" + PINS["go"] + "-alpine AS backend" not in dockerfile:
        raise RuntimeError("Go security compiler differs from the production builder")
    if not re.search(r"(?m)^toolchain go" + re.escape(PINS["go"]) + r"$", module):
        raise RuntimeError("Go module toolchain differs from the reviewed compiler")
    if "FROM oven/bun:" + PINS["bun"] + "-alpine AS frontend" not in dockerfile:
        raise RuntimeError("Bun checker differs from the production builder")
    return {"go": PINS["go"], "bun": PINS["bun"],
            "go_image": "golang:" + PINS["go"] + "-alpine",
            "bun_image": "oven/bun:" + PINS["bun"] + "-alpine",
            "dockerfile_sha256": hashlib.sha256(dockerfile.encode()).hexdigest(),
            "go_mod_sha256": hashlib.sha256(module.encode()).hexdigest()}


def module_export(module, destination):
    """Export exact committed compiler blobs, with a compile-only embed stub."""
    if destination.exists():
        raise RuntimeError("Module export must be fresh")
    repository = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=module, text=True).strip())
    prefix = module.relative_to(repository).as_posix() + "/"
    tree = subprocess.check_output(["git", "ls-tree", "-r", "-z", source_sha(), "--", prefix], cwd=repository)
    entries = []
    for raw in tree.split(b"\0"):
        if not raw:
            continue
        metadata, path = raw.decode().split("\t", 1)
        mode, kind, blob = metadata.split()
        if not path.startswith(prefix):
            raise RuntimeError("Committed compiler source escaped its module")
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
        target.write_bytes(subprocess.check_output(["git", "cat-file", "blob", blob], cwd=repository))
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
