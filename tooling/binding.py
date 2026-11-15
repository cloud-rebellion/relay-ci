"""Verify the three independent Relay CI identities without exposing source."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile

HARNESS = Path(__file__).resolve().parents[1]
PROFILE = HARNESS / "profiles/relay.json"
SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
ACTIVE_GO_VERSION = "1.26.11"


def inspect_go_binary(path, *, results_root, max_bytes=128 * 1024 * 1024):
    """Read embedded compiler metadata from an owned output; never execute it."""
    path, root = Path(path), Path(results_root)
    if not path.is_absolute() or not root.is_absolute() or root.resolve() != root or \
            path.resolve() != path or not path.is_relative_to(root) or path == root or \
            any(ord(c) < 32 or ord(c) == 127 for c in str(path)):
        raise RuntimeError("Binary readback requires a canonical private output")
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError("Binary readback requires a private owned output root")
    for parent in path.parents:
        if parent == root:
            break
        if parent.is_symlink() or not parent.is_dir():
            raise RuntimeError("Linked binary output parent refused")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or not 0 < before.st_size <= max_bytes:
        raise RuntimeError("Binary readback requires a bounded owned regular file")

    def fingerprint():
        value = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(block)
        return value.hexdigest()

    checksum = fingerprint()
    env = {name: os.environ[name] for name in ("PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH", "GOROOT") if name in os.environ}
    env.update(GOTOOLCHAIN="local", GOWORK="off", GOPROXY="off", GOSUMDB="off", GOENV="off")
    # Keep module paths and other private build information out of public logs.
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(["go", "version", "-m", str(path)], cwd=root, env=env,
                                    stdout=output, stderr=subprocess.PIPE, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("Embedded Go compiler readback failed") from error
        output.seek(0)
        raw = output.read(1024 * 1024 + 1)
    after = path.lstat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_uid")
    if any(getattr(before, name) != getattr(after, name) for name in fields) or fingerprint() != checksum:
        raise RuntimeError("Binary changed during compiler readback")
    if result.returncode or len(raw) > 1024 * 1024:
        raise RuntimeError("Embedded Go compiler metadata is missing or unbounded")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("Embedded Go compiler metadata is malformed") from error
    if not lines or lines[0] != str(path) + ": go" + ACTIVE_GO_VERSION or \
            not any(line.startswith("\tpath\t") and line[6:] for line in lines[1:]) or \
            "\tbuild\t-compiler=gc" not in lines[1:]:
        raise RuntimeError("Every active binary must embed the exact Go 1.26.11 compiler")
    return {"go_version": "go" + ACTIVE_GO_VERSION, "bytes": before.st_size, "sha256": checksum}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical_path(value):
    if not isinstance(value, str) or not value or "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise RuntimeError("Invalid manifest path")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(x in ("", ".", "..", ".git") for x in path.parts):
        raise RuntimeError("Noncanonical manifest path")
    return value


def git(root, *args):
    """Inert object/index reads after application code has run; never fetch."""
    # No inherited GIT_*, loader, shell or credential variables can redirect a
    # read. Fetch owns its separate short-lived SSH environment before app code.
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent-relay-ci-source", "LANG": "C", "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0",
           "GIT_TERMINAL_PROMPT": "0"}
    command = ["/usr/bin/git", "--no-replace-objects", "--literal-pathspecs",
               "-c", "core.commitGraph=false", "-c", "core.fsmonitor=false",
               "-c", "core.untrackedCache=false", "-c", "core.hooksPath=/dev/null", *args]
    try:
        return subprocess.check_output(command, cwd=root, env=env, stderr=subprocess.PIPE, timeout=60)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("Inert source Git read failed") from error


def object_digest(kind, body, oid):
    algorithm = hashlib.sha1 if len(oid) == 40 else hashlib.sha256
    return algorithm(kind.encode() + b" " + str(len(body)).encode() + b"\0" + body).hexdigest()


def git_object(root, kind, oid):
    if kind not in ("commit", "tree", "blob") or not SHA.fullmatch(oid):
        raise RuntimeError("Invalid committed object identity")
    body = git(root, "cat-file", kind, oid)
    if len(body) > 8 * 1024 * 1024 or object_digest(kind, body, oid) != oid:
        raise RuntimeError("Committed Git object bytes differ from their identity")
    return body


def committed_tree(root, commit):
    """Derive the listing from hash-checked objects, not mutable replace refs."""
    raw = git_object(root, "commit", commit)
    first = raw.split(b"\n", 1)[0]
    if not first.startswith(b"tree "):
        raise RuntimeError("Committed source has no root tree")
    tree = first[5:].decode()
    if len(tree) != len(commit) or not SHA.fullmatch(tree):
        raise RuntimeError("Invalid committed root tree")
    entries = {}
    visits = 0
    def walk(oid, prefix, depth):
        nonlocal visits
        if depth > 64:
            raise RuntimeError("Committed source exceeds its tree-depth bound")
        body = git_object(root, "tree", oid)
        offset, width = 0, len(oid) // 2
        names = set()
        while offset < len(body):
            space = body.find(b" ", offset); end = body.find(b"\0", space + 1)
            if space < offset or end < space or end + 1 + width > len(body):
                raise RuntimeError("Malformed committed tree")
            mode = body[offset:space].decode(); name = body[space + 1:end].decode()
            if not name or "/" in name or name in names:
                raise RuntimeError("Duplicate or invalid committed tree entry")
            names.add(name)
            path = canonical_path(prefix + name)
            if len(path.encode()) > 1024:
                raise RuntimeError("Committed source path exceeds its bound")
            child = body[end + 1:end + 1 + width].hex(); offset = end + 1 + width
            visits += 1
            if visits > 20000:
                raise RuntimeError("Committed source exceeds its tree-entry bound")
            if mode == "40000":
                walk(child, path + "/", depth + 1)
            elif mode in ("100644", "100755"):
                entries[path] = {"mode": mode, "type": "blob", "oid": child}
                if len(entries) > 3001:
                    raise RuntimeError("Committed source exceeds its file-entry bound")
            else:
                raise RuntimeError("Unsupported committed source entry type")
    walk(tree, "", 0)
    listing = b"".join((row["mode"] + " blob " + row["oid"] + "\t" + path).encode() + b"\0"
                       for path, row in sorted(entries.items(), key=lambda item: item[0].encode()))
    return tree, entries, listing


def verify_index(root, expected):
    # git status can execute an app-controlled clean filter. Index identities
    # need no worktree conversion; full raw working bytes/modes are checked above.
    actual = {}
    for raw in git(root, "ls-files", "--stage", "-z", "--full-name").split(b"\0"):
        if not raw:
            continue
        header, rawpath = raw.split(b"\t", 1)
        fields = header.decode().split()
        path = canonical_path(rawpath.decode())
        if len(fields) != 3 or fields[2] != "0" or path in actual:
            raise RuntimeError("Unmerged or duplicate source index entry")
        mode, oid, _ = fields
        actual[path] = {"mode": mode, "type": "blob", "oid": oid}
    if actual != expected:
        raise RuntimeError("Cached source index differs from the committed source")


def load_profile(path=PROFILE):
    g = verify_public()
    raw = path.read_bytes()
    _, inputs, _ = committed_tree(HARNESS, g)
    oid = inputs["profiles/relay.json"]["oid"]
    actual = hashlib.sha1() if len(oid) == 40 else hashlib.sha256()
    actual.update(b"blob " + str(len(raw)).encode() + b"\0" + raw)
    if actual.hexdigest() != oid:
        raise RuntimeError("Loaded profile bytes differ from trusted G")
    value = json.loads(raw)
    if value.get("schema") != 1 or value.get("status") != "pinned":
        raise RuntimeError("The CI profile is not pinned")
    for key in ("context_commit", "context_tree", "origin_stage_commit"):
        if not isinstance(value.get(key), str) or not SHA.fullmatch(value[key]):
            raise RuntimeError("Missing exact source identity")
    if not DIGEST.fullmatch(value.get("context_manifest_sha256", "")):
        raise RuntimeError("Missing exact context manifest identity")
    if value.get("private_repository") != "cloud-rebellion/relay" or value.get("private_repository_id") != 1447574877:
        raise RuntimeError("Unexpected private repository identity")
    if value.get("public_repository") != "cloud-rebellion/relay-ci":
        raise RuntimeError("Unexpected public repository identity")
    if type(value.get("public_repository_id")) is not int or value["public_repository_id"] <= 0:
        raise RuntimeError("Missing exact public repository ID")
    if value.get("execution_roots") != ["brightcrm", "ops"]:
        raise RuntimeError("Complete Relay source and ops scan roots are required")
    if any(type(value.get(key)) is not int or value[key] <= 0 for key in ("source_entry_count", "source_bytes")):
        raise RuntimeError("Missing pinned context inventory bounds")
    canonical_path(value["context_manifest_path"])
    return value


def private_product():
    expected = (HARNESS / "private-source/brightcrm").resolve()
    value = os.environ.get("RELAY_PRIVATE_SOURCE_ROOT")
    if not value or not Path(value).is_absolute() or Path(value).resolve() != expected:
        raise RuntimeError("Private source must use the fixed private-source checkout")
    return expected


def verify_public(harness=HARNESS, check_event=True):
    g = git(harness, "rev-parse", "HEAD").decode().strip()
    if not SHA.fullmatch(g) or (check_event and os.environ.get("GITHUB_SHA") != g):
        raise RuntimeError("Wrong public workflow commit")
    _, expected, _ = committed_tree(harness, g)
    for relative, row in expected.items():
        mode, kind, oid = row["mode"], row["type"], row["oid"]
        path = harness / relative
        if kind != "blob" or mode not in ("100644", "100755") or path.is_symlink() or not path.is_file():
            raise RuntimeError("Unsupported or missing trusted public tooling input")
        parent = path.parent
        while parent != harness:
            if parent.is_symlink():
                raise RuntimeError("Linked trusted tooling parent refused")
            parent = parent.parent
        body = path.read_bytes()
        actual = hashlib.sha1() if len(oid) == 40 else hashlib.sha256()
        actual.update(b"blob " + str(len(body)).encode() + b"\0" + body)
        actual_mode = "100755" if path.stat().st_mode & 0o111 else "100644"
        if actual.hexdigest() != oid or mode != actual_mode:
            raise RuntimeError("Trusted public tooling bytes or mode changed")
    verify_index(harness, expected)
    for args in (("ls-files", "--others", "--exclude-standard"),
                 ("ls-files", "--others", "--ignored", "--exclude-standard")):
        for rawpath in git(harness, *args).decode().splitlines():
            if not rawpath.startswith("private-source/"):
                raise RuntimeError("Untracked trusted-tooling input refused")
    return g


def verify(profile=None, *, harness=HARNESS, initial=True, check_event=True):
    profile = load_profile() if profile is None else profile
    private = harness / "private-source"
    if private.is_symlink() or not private.is_dir():
        raise RuntimeError("Private checkout is absent or linked")
    actual_root = Path(git(private, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if actual_root != private.resolve():
        raise RuntimeError("Private source is not an independent checkout")
    p = git(private, "rev-parse", "HEAD").decode().strip()
    private_tree, actual, _ = committed_tree(private, p)
    g = verify_public(harness, check_event)
    if p != profile["context_commit"] or not SHA.fullmatch(g):
        raise RuntimeError("Wrong private context or public workflow commit")
    if private_tree != profile["context_tree"]:
        raise RuntimeError("Private context tree differs from the pinned tree")
    if check_event:
        if os.environ.get("GITHUB_SHA") != g:
            raise RuntimeError("Public workflow commit differs from its event")
        if os.environ.get("GITHUB_REPOSITORY") != profile["public_repository"]:
            raise RuntimeError("Wrong public workflow repository")
        if str(os.environ.get("GITHUB_REPOSITORY_ID")) != str(profile["public_repository_id"]):
            raise RuntimeError("Wrong public workflow repository ID")
        if os.environ.get("GITHUB_REF") not in profile["allowed_workflow_refs"]:
            raise RuntimeError("Untrusted workflow ref")
        if os.environ.get("GITHUB_EVENT_NAME") not in ("push", "workflow_dispatch"):
            raise RuntimeError("Untrusted workflow event")
    manifest_path = private / canonical_path(profile["context_manifest_path"])
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise RuntimeError("Missing regular context manifest")
    raw = manifest_path.read_bytes()
    if digest(raw) != profile["context_manifest_sha256"]:
        raise RuntimeError("Context manifest differs from the pinned profile")
    manifest = json.loads(raw)
    if manifest.get("schema") != 1 or manifest.get("origin_stage_commit") != profile["origin_stage_commit"]:
        raise RuntimeError("Context origin differs from the pinned deployment source")
    if manifest.get("execution_roots") != profile["execution_roots"]:
        raise RuntimeError("Execution roots differ from the pinned contract")
    product_identity = manifest.get("product_identity")
    if not isinstance(product_identity, dict) or not product_identity:
        raise RuntimeError("Missing source product-policy identity")
    entries = manifest.get("source_entries")
    if not isinstance(entries, list) or not entries:
        raise RuntimeError("Missing complete context source inventory")
    if len(entries) != profile["source_entry_count"] or sum(row.get("size", -1) for row in entries) != profile["source_bytes"]:
        raise RuntimeError("Context inventory differs from the pinned bounds")
    metadata = {canonical_path(x) for x in profile.get("context_metadata_paths", [])}
    if profile["context_manifest_path"] not in metadata:
        raise RuntimeError("Manifest must be explicitly classified as context metadata")
    expected = {}
    for row in entries:
        path = canonical_path(row["path"])
        if path in expected or path in metadata or row.get("type") != "blob" or row.get("mode") not in ("100644", "100755"):
            raise RuntimeError("Duplicate, linked or unsupported source entry")
        if not SHA.fullmatch(row.get("oid", "")) or not DIGEST.fullmatch(row.get("sha256", "")) or type(row.get("size")) is not int or row["size"] < 0:
            raise RuntimeError("Malformed source entry identity")
        expected[path] = row
    if [x["path"] for x in entries] != sorted(expected, key=lambda x: x.encode()):
        raise RuntimeError("Source inventory must use canonical Git path order")
    if set(actual) != set(expected) | metadata:
        raise RuntimeError("Context tree added or removed an unmanifested path")
    for path, row in expected.items():
        if actual[path] != {k: row[k] for k in ("mode", "type", "oid")}:
            raise RuntimeError("Context tree mode, type or blob drifted")
        file = private / path
        parent = file.parent
        while parent != private:
            if parent.is_symlink():
                raise RuntimeError("Linked source parent directory refused")
            parent = parent.parent
        info = file.lstat()
        if not stat.S_ISREG(info.st_mode) or file.is_symlink() or not file.resolve().is_relative_to(private.resolve()):
            raise RuntimeError("Source input is missing, linked or outside the checkout")
        body = file.read_bytes()
        mode = "100755" if info.st_mode & 0o111 else "100644"
        object_hash = hashlib.sha1() if len(row["oid"]) == 40 else hashlib.sha256()
        object_hash.update(b"blob " + str(len(body)).encode() + b"\0" + body)
        if len(body) != row["size"] or digest(body) != row["sha256"] or object_hash.hexdigest() != row["oid"] or mode != row["mode"]:
            raise RuntimeError("Working source differs from the pinned Git source")
    for path in metadata:
        if actual[path]["type"] != "blob" or actual[path]["mode"] != "100644":
            raise RuntimeError("Unsupported context metadata type")
    verify_index(private, actual)
    if initial:
        if git(private, "ls-files", "--others", "--exclude-standard") or git(private, "ls-files", "--others", "--ignored", "--exclude-standard"):
            raise RuntimeError("Initial private checkout contains untracked inputs")
    for root in profile["execution_roots"]:
        root = canonical_path(root)
        if not (private / root).is_dir() or not any(path.startswith(root + "/") for path in expected):
            raise RuntimeError("A complete required execution root is missing")
    public_tree, _, public_listing = committed_tree(harness, g)
    return {"workflow_commit": g, "private_context_commit": p, "private_context_tree": private_tree,
            "workflow_tree": public_tree,
            "workflow_inputs_sha256": digest(public_listing),
            "origin_stage_commit": profile["origin_stage_commit"],
            "context_manifest_sha256": digest(raw), "source_entry_count": len(entries),
            "product_identity_manifest_sha256": digest(json.dumps(product_identity, sort_keys=True, separators=(",", ":")).encode()),
            "source_bytes": sum(x["size"] for x in entries),
            "profile_sha256": digest(PROFILE.read_bytes()) if harness == HARNESS else None}


def source_identity():
    # Revalidate tracked bytes even after a driver has generated ignored output.
    return verify(initial=False)


def source_sha():
    return source_identity()["private_context_commit"]


def origin_sha():
    return source_identity()["origin_stage_commit"]


def module_compiler(path, expected_module):
    raw = path.read_bytes()
    if not raw or len(raw) > 256 * 1024:
        raise RuntimeError("Go module compiler declarations exceed their bound")
    values = {}
    for line in raw.decode().splitlines():
        fields = line.split("//", 1)[0].split()
        if not fields or fields[0] not in ("module", "go", "toolchain"):
            continue
        if len(fields) != 2 or fields[0] in values:
            raise RuntimeError("Missing or duplicate Go compiler declaration")
        values[fields[0]] = fields[1]
    if values.get("module") != expected_module or values.get("toolchain") != "go" + ACTIVE_GO_VERSION:
        raise RuntimeError("Active module must declare the exact Go 1.26.11 toolchain")
    minimum = values.get("go", "")
    if not re.fullmatch(r"[1-9][0-9]*\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?", minimum):
        raise RuntimeError("Invalid Go module minimum")
    parts = tuple(int(x) for x in minimum.split("."))
    parts += (0,) * (3 - len(parts))
    if parts > (1, 26, 11):
        raise RuntimeError("Go module minimum exceeds the active SDK")
    return {"minimum": minimum, "toolchain": values["toolchain"], "sha256": digest(raw)}


def docker_instructions(raw):
    if len(raw) > 256 * 1024:
        raise RuntimeError("Docker compiler source exceeds its bound")
    pending = ""
    continued = False
    instructions = []
    allowed = set("FROM RUN CMD LABEL MAINTAINER EXPOSE ENV ADD COPY ENTRYPOINT VOLUME USER WORKDIR ARG ONBUILD STOPSIGNAL HEALTHCHECK SHELL".split())
    for line in raw.decode().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "<<" in line or line.endswith("\\\\"):
            raise RuntimeError("Ambiguous Docker compiler source requires review")
        more = line.endswith("\\")
        if more:
            line = line[:-1].strip()
            continued = True
        pending = (pending + " " + line).strip()
        if len(pending) > 256 * 1024:
            raise RuntimeError("Docker instruction exceeds its bound")
        if more:
            continue
        words = pending.split()
        if not words or words[0].upper() not in allowed:
            raise RuntimeError("Unsupported Docker compiler instruction")
        instructions.append((words, continued))
        pending, continued = "", False
    if pending or continued:
        raise RuntimeError("Unfinished Docker compiler continuation")
    return instructions


def compiler_contract(product, *, sdk_version=None):
    """Exact active SDK, both module toolchains, and every owned Go builder."""
    if sdk_version is None:
        env = {name: os.environ[name] for name in ("PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH", "GOROOT") if name in os.environ}
        env.update(GOTOOLCHAIN="local", GOWORK="off")
        sdk_version = subprocess.check_output(["go", "env", "GOVERSION"], cwd=product, env=env,
                                              stderr=subprocess.PIPE, text=True, timeout=30).strip()
    if sdk_version != "go" + ACTIVE_GO_VERSION:
        raise RuntimeError("Active host SDK must be exactly Go 1.26.11")
    modules, dockerfiles = [], []
    entries = 0
    for parent, directories, files in os.walk(product, followlinks=False):
        directories[:] = sorted(x for x in directories if x not in (".git", "node_modules", "vendor"))
        entries += len(directories) + len(files)
        if entries > 20000:
            raise RuntimeError("Compiler inventory exceeds its entry bound")
        for name in sorted(files):
            path = Path(parent) / name
            if name == "go.mod":
                modules.append(path.relative_to(product).as_posix())
            if name.startswith("Dockerfile") or name.endswith(".Dockerfile"):
                if path.is_symlink() or not path.is_file():
                    raise RuntimeError("Linked Docker compiler input refused")
                dockerfiles.append(path)
    if set(modules) != {"go.mod", "voip/go.mod"}:
        raise RuntimeError("Every nested Go module requires an explicit active compiler lane")
    module_inputs = {
        "brightcrm": module_compiler(product / "go.mod", "github.com/bright-interaction/brightcrm"),
        "brightcrm/voip": module_compiler(product / "voip/go.mod", "brightcrm-voip"),
    }
    if not dockerfiles or len(dockerfiles) > 32 or product / "Dockerfile" not in dockerfiles:
        raise RuntimeError("Compiler builder inventory refused")
    total = 0
    builders = []
    root_go = False
    for path in sorted(dockerfiles):
        raw = path.read_bytes(); total += len(raw)
        if total > 4 * 1024 * 1024:
            raise RuntimeError("Compiler inventory exceeds its byte bound")
        stages = {}; froms = 0
        for words, continued in docker_instructions(raw):
            if words[0].upper() != "FROM":
                continue
            froms += 1
            words = words[1:]
            while words and words[0].startswith("--"):
                if not words[0].startswith("--platform="):
                    raise RuntimeError("Unreviewed Docker FROM option")
                words = words[1:]
            if not words or continued or any(x in words[0] for x in ("$", "\\", "\"", "'")):
                raise RuntimeError("Nonliteral Docker compiler image refused")
            base, suffix = words[0], words[1:]
            if suffix and (len(suffix) != 2 or suffix[0].upper() != "AS"):
                raise RuntimeError("Unsupported Docker FROM form")
            ref, separator, pinned = base.partition("@")
            if separator and not re.fullmatch(r"sha256:[0-9a-f]{64}", pinned):
                raise RuntimeError("Noncanonical Docker compiler digest")
            if ref.lower() in stages and not separator:
                is_go = stages[ref.lower()]
            else:
                family = ref.rsplit(":", 1)[0] if ref.rfind(":") > ref.rfind("/") else ref
                if family not in ("golang", "alpine", "oven/bun", "clamav/clamav"):
                    raise RuntimeError("Unreviewed Docker builder base family")
                is_go = family == "golang"
                if is_go and ref != "golang:" + ACTIVE_GO_VERSION + "-alpine":
                    raise RuntimeError("Every active Docker Go builder must be exactly Go 1.26.11")
            if suffix:
                alias = suffix[1].lower()
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", suffix[1]) or alias in stages:
                    raise RuntimeError("Duplicate or invalid Docker compiler stage")
                stages[alias] = is_go
            if is_go:
                builders.append({"path": path.relative_to(product).as_posix(), "reference": ref})
                root_go |= path == product / "Dockerfile"
        if not froms:
            raise RuntimeError("Docker builder has no literal FROM")
    if not root_go:
        raise RuntimeError("Root Dockerfile has no admitted active Go compiler")
    return {"go_sdk": sdk_version, "go": ACTIVE_GO_VERSION, "modules": module_inputs,
            "docker_go_builders": builders, "dockerfile_count": len(dockerfiles)}
