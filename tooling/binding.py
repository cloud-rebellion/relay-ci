"""Verify the three independent Relay CI identities without exposing source."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

HARNESS = Path(__file__).resolve().parents[1]
PROFILE = HARNESS / "profiles/relay.json"
SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


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
    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.PIPE, timeout=60)


def load_profile(path=PROFILE):
    g = verify_public()
    raw = path.read_bytes()
    oid = git(HARNESS, "rev-parse", g + ":profiles/relay.json").decode().strip()
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
    for item in git(harness, "ls-tree", "-r", "-z", "--full-tree", g).split(b"\0"):
        if not item:
            continue
        header, rawpath = item.split(b"\t", 1)
        mode, kind, oid = header.decode().split()
        relative = canonical_path(rawpath.decode())
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
    private_tree = git(private, "rev-parse", p + "^{tree}").decode().strip()
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
    actual = {}
    for item in git(private, "ls-tree", "-r", "-z", "--full-tree", p).split(b"\0"):
        if not item:
            continue
        header, rawpath = item.split(b"\t", 1)
        mode, kind, oid = header.decode().split()
        path = canonical_path(rawpath.decode())
        actual[path] = {"mode": mode, "type": kind, "oid": oid}
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
    if git(private, "status", "--porcelain=v1", "--untracked-files=no"):
        raise RuntimeError("Tracked private checkout inputs changed")
    if initial:
        if git(private, "ls-files", "--others", "--exclude-standard") or git(private, "ls-files", "--others", "--ignored", "--exclude-standard"):
            raise RuntimeError("Initial private checkout contains untracked inputs")
    for root in profile["execution_roots"]:
        root = canonical_path(root)
        if not (private / root).is_dir() or not any(path.startswith(root + "/") for path in expected):
            raise RuntimeError("A complete required execution root is missing")
    return {"workflow_commit": g, "private_context_commit": p, "private_context_tree": private_tree,
            "workflow_tree": git(harness, "rev-parse", g + "^{tree}").decode().strip(),
            "workflow_inputs_sha256": digest(git(harness, "ls-tree", "-r", "-z", "--full-tree", g)),
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
