"""Refusal controls for portable security, image identity and real rollback checks."""
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import tarfile
import zlib
from types import SimpleNamespace
import unittest
from unittest import mock

import common


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


image = load("run-image-scan")
migration = load("run-migration")


class ReleaseRefusalTests(unittest.TestCase):
    def test_module_export_uses_committed_blobs_and_refuses_uncovered_nested_module(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            module = repository / "brightcrm/voip"
            module.mkdir(parents=True)
            (module / "implementation.go").write_text("uncommitted local bytes")
            blobs = {"a" * 40: b"module example.test/media\n", "b" * 40: b"package media\n", "c" * 40: b"do not import environment values"}
            rows = [("go.mod", "a" * 40), ("implementation.go", "b" * 40), (".env", "c" * 40)]
            def git_output(root, *arguments):
                self.assertEqual(arguments, ("rev-parse", "--show-toplevel"))
                return (str(repository) + "\n").encode()
            def source_tree(root, commit):
                self.assertEqual(commit, "d" * 40)  # Private context P, never G or S.
                return None, {"brightcrm/voip/" + path: {"mode": "100644", "type": "blob", "oid": blob}
                              for path, blob in rows}, None
            with mock.patch.object(common, "git", side_effect=git_output), \
                    mock.patch.object(common, "committed_tree", side_effect=source_tree), \
                    mock.patch.object(common, "git_object", side_effect=lambda root, kind, oid: blobs[oid]), \
                    mock.patch.object(common, "source_sha", return_value="d" * 40):
                exported = common.module_export(module, repository / "export")
                self.assertEqual((exported / "implementation.go").read_bytes(), b"package media\n")
                self.assertFalse((exported / ".env").exists())
                rows.append(("uncovered/go.mod", "a" * 40))
                with self.assertRaises(RuntimeError): common.module_export(module, repository / "other-export")

    def test_real_private_blob_replacement_cannot_change_module_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "source"; repository.mkdir()
            def command(*arguments, body=None):
                return subprocess.check_output(["/usr/bin/git", *arguments], cwd=repository, input=body,
                                               stderr=subprocess.PIPE)
            command("init", "--quiet")
            module = repository / "brightcrm/voip"; module.mkdir(parents=True)
            original = b"package media\nconst Original = true\n"
            (module / "go.mod").write_bytes(b"module media\ngo 1.26.3\n")
            (module / "implementation.go").write_bytes(original)
            command("add", "--all")
            command("-c", "user.name=Synthetic Relay control", "-c", "user.email=relay@example.test",
                    "commit", "--quiet", "-m", "synthetic private P")
            p = command("rev-parse", "HEAD").decode().strip()
            oid = command("rev-parse", p + ":brightcrm/voip/implementation.go").decode().strip()
            replacement = b"package media\nconst Replaced = true\n"
            alternate = command("hash-object", "-w", "--stdin", body=replacement).decode().strip()
            command("replace", oid, alternate)
            self.assertEqual(command("cat-file", "blob", oid), replacement)  # Active attack fixture.
            with mock.patch.object(common, "source_sha", return_value=p):
                exported = common.module_export(module, Path(temporary) / "export")
                self.assertEqual((exported / "implementation.go").read_bytes(), original)
            # Even a rewritten loose object under the original OID is refused.
            target = repository / ".git/objects" / oid[:2] / oid[2:]
            target.unlink()
            target.write_bytes(zlib.compress(b"blob " + str(len(replacement)).encode() + b"\0" + replacement))
            with mock.patch.object(common, "source_sha", return_value=p), self.assertRaises(RuntimeError):
                common.module_export(module, Path(temporary) / "forged-export")

    def test_only_clean_vulnerability_exit_passes(self):
        self.assertEqual(common.classify_vulncheck(0), "passed")
        for status in (3, 137, -9, 1, 2, 125):
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                common.classify_vulncheck(status)

    def test_image_identity_cannot_be_a_mutable_tag_or_malformed_hash(self):
        self.assertEqual(common.validate_image_id("sha256:" + "a" * 64), "sha256:" + "a" * 64)
        for value in ("relay:latest", "sha256:" + "a" * 63, "sha256:" + "A" * 64, "", None):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                common.validate_image_id(value)

    def test_archive_refuses_empty_oversize_and_linked_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "image.tar"
            regular.write_bytes(b"exact-image")
            original = image.file_digest(regular, 32)
            regular.write_bytes(b"other-image")
            self.assertNotEqual(image.file_digest(regular, 32), original)
            with self.assertRaises(RuntimeError): image.file_digest(regular, 1)
            link = root / "linked.tar"
            link.symlink_to(regular)
            with self.assertRaises(RuntimeError): image.file_digest(link, 32)
            regular.write_bytes(b"")
            with self.assertRaises(RuntimeError): image.file_digest(regular, 32)

    def test_final_image_gate_refuses_findings_and_scanner_failure(self):
        for critical, high, cleanup_failure, binary_failure, passes in [(1, 0, False, False, False), (0, 137, False, False, False), (0, 0, True, False, False), (0, 0, False, True, False), (0, 0, False, False, True)]:
            with self.subTest(critical=critical, high=high, cleanup_failure=cleanup_failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                exact_id = "sha256:" + "a" * 64
                owner = "f" * 32
                scans = []
                class FixtureDocker:
                    def __enter__(self): return self
                    def __exit__(self, *args):
                        if cleanup_failure: raise RuntimeError("cleanup refused")
                        return False
                    def pull(self, *args): return "sha256:" + "b" * 64
                    def read_relay_binary(self, selected, output):
                        self_outer.assertEqual(selected, exact_id)
                        if binary_failure: raise RuntimeError("embedded compiler refused")
                        output.write_bytes(b"only fixed image binary")
                        return {"go_version": "go1.26.11", "bytes": 23, "sha256": "e" * 64}
                    def run(self, leaf, scanner, command, **kwargs):
                        scans.append((leaf, kwargs["mounts"]))
                        return (critical if leaf.endswith("critical") else high), "fixture"
                self_outer = self
                def command(argv, name, **kwargs):
                    if name == "final-image-build":
                        self.assertIn("PUBLIC_FLARE_RELEASE=" + "d" * 40, argv)
                        self.assertIn("org.opencontainers.image.revision=" + "d" * 40, argv)
                        self.assertNotIn("PUBLIC_FLARE_RELEASE=" + "c" * 40, argv)
                        (root / "final-image.id").write_text(exact_id + "\n")
                    if name == "final-image-archive": (root / "final-image.tar").write_bytes(b"same exact image archive")
                inspected = subprocess.CompletedProcess([], 0, json.dumps([{"Id": exact_id, "Config": {"Labels": {"relay.ci.image.owner": owner}}}]), "")
                with mock.patch.object(image, "require_ephemeral"), mock.patch.object(image, "compiler_inputs", return_value={}), \
                        mock.patch.object(image, "source_sha", return_value="c" * 40), mock.patch.object(image, "origin_sha", return_value="d" * 40), mock.patch.object(image, "output_directory", return_value=root), \
                        mock.patch.object(image, "DockerSession", FixtureDocker), mock.patch.object(image, "require_zero", side_effect=command), \
                        mock.patch.object(image.subprocess, "run", return_value=inspected), \
                        mock.patch.object(image.uuid, "uuid4", return_value=SimpleNamespace(hex=owner)), \
                        mock.patch.object(image, "write_report") as report:
                    if passes:
                        image.main()
                        self.assertEqual(len(scans), 2)
                        self.assertEqual(scans[0][1], scans[1][1])
                        self.assertTrue(scans[0][1][0][2])
                        self.assertEqual(report.call_args.args[1]["image_id"], exact_id)
                        self.assertEqual(report.call_args.args[1]["source_sha"], "c" * 40)
                        self.assertEqual(report.call_args.args[1]["origin_stage_commit"], "d" * 40)
                        self.assertEqual(report.call_args.args[1]["binary_compiler"]["go_version"], "go1.26.11")
                        self.assertFalse((root / "final-image-brightcrm.bin").exists())
                    else:
                        with self.assertRaises(RuntimeError): image.main()
                        report.assert_not_called()

    def binary_archive(self, names=("brightcrm",), kind=tarfile.REGTYPE, size=None):
        if size is not None and size > len(b"synthetic binary"):
            # Only the declared oversized header is needed: the reader must
            # reject its bound before touching an absent/unbounded body.
            member = tarfile.TarInfo(names[0]); member.type = kind; member.size = size
            return member.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as bundle:
            for name in names:
                member = tarfile.TarInfo(name); member.type = kind
                body = b"synthetic binary"
                member.size = len(body) if size is None else size
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    member.linkname = "other"; member.size = 0
                bundle.addfile(member, io.BytesIO(body) if member.size == len(body) else None)
        return buffer.getvalue()

    def reader_fixtures(self, session, root, exact_id, payload):
        identity = "c" * 64
        def create(argv, name, **kwargs):
            self.assertEqual(argv[:2], ["docker", "create"])
            for flag in ("--rm", "--pull=never", "--read-only", "--no-healthcheck"):
                self.assertIn(flag, argv)
            for flag, value in (("--network", "none"), ("--cap-drop", "ALL"),
                                ("--security-opt", "no-new-privileges"), ("--memory", "64m"),
                                ("--pids-limit", "32"), ("--stop-timeout", "5"),
                                ("--entrypoint", "/__relay_ci_never_start__")):
                self.assertEqual(argv[argv.index(flag) + 1], value)
            self.assertFalse(any(flag in argv for flag in ("--mount", "-v", "--privileged", "-e", "-p", "run", "start", "exec")))
            self.assertEqual(argv[-1], exact_id)
            Path(argv[argv.index("--cidfile") + 1]).write_text(identity)
        def inspect(kind, name):
            if kind == "image": return {"Id": exact_id, "Config": {"Volumes": None}}
            return {"Id": identity, "Name": "/" + name, "Image": exact_id, "RestartCount": 0,
                    "Config": {"Labels": {"relay.ci.owner": session.owner}},
                    "State": {"Status": "created", "Running": False, "StartedAt": "0001-01-01T00:00:00Z"}}
        def copy(argv, **kwargs):
            self.assertEqual(argv, ["docker", "cp", identity + ":/usr/local/bin/brightcrm", "-"])
            self.assertEqual(kwargs["timeout"], 30)
            with mock.patch.object(common.resource, "setrlimit") as limit:
                kwargs["preexec_fn"]()
                limit.assert_called_once_with(common.resource.RLIMIT_FSIZE, (129 * 1024 * 1024,) * 2)
            kwargs["stdout"].write(payload); kwargs["stdout"].flush()
            return subprocess.CompletedProcess(argv, 0)
        return create, inspect, copy

    def test_image_binary_readback_is_fixed_never_started_owned_and_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); exact_id = "sha256:" + "a" * 64
            session = common.DockerSession(); output = root / "final-image-brightcrm.bin"
            create, inspect, copy = self.reader_fixtures(session, root, exact_id, self.binary_archive())
            with mock.patch.object(common, "output_directory", return_value=root), \
                    mock.patch.object(session, "_inspect", side_effect=inspect) as inspected, \
                    mock.patch.object(common, "require_zero", side_effect=create), \
                    mock.patch.object(common.subprocess, "run", side_effect=copy), \
                    mock.patch.object(common, "inspect_go_binary", return_value={"go_version": "go1.26.11"}) as readback:
                self.assertEqual(session.read_relay_binary(exact_id, output), {"go_version": "go1.26.11"})
                self.assertEqual(output.read_bytes(), b"synthetic binary")
                self.assertEqual(inspected.call_count, 3)
                self.assertFalse((root / "image-binary-readback.tar").exists())
                readback.assert_called_once_with(output, results_root=root)
                self.assertEqual(set(session.container_ids), session.graceful_containers)

    def test_image_binary_readback_refuses_image_volume_output_and_process_failures(self):
        exact_id = "sha256:" + "a" * 64
        for item in (None, {"Id": "sha256:" + "b" * 64, "Config": {}},
                     {"Id": exact_id, "Config": {"Volumes": {"/private": {}}}}):
            with tempfile.TemporaryDirectory() as temporary, self.subTest(item=item):
                root = Path(temporary).resolve(); session = common.DockerSession()
                with mock.patch.object(common, "output_directory", return_value=root), \
                        mock.patch.object(session, "_inspect", return_value=item), \
                        mock.patch.object(common, "require_zero") as create, self.assertRaises(RuntimeError):
                    session.read_relay_binary(exact_id, root / "final-image-brightcrm.bin")
                create.assert_not_called()
        for kind in ("existing", "linked", "wrong-path"):
            with tempfile.TemporaryDirectory() as temporary, self.subTest(output=kind):
                root = Path(temporary).resolve(); session = common.DockerSession()
                output = root / "final-image-brightcrm.bin"
                if kind == "existing": output.write_bytes(b"preserve existing evidence")
                elif kind == "linked": output.symlink_to(root / "missing")
                else: output = root / "unreviewed-path"
                with mock.patch.object(common, "output_directory", return_value=root), \
                        mock.patch.object(session, "_inspect", return_value={"Id": exact_id, "Config": {}}), \
                        mock.patch.object(common, "require_zero") as create, self.assertRaises(RuntimeError):
                    session.read_relay_binary(exact_id, output)
                create.assert_not_called()
        for failure in (subprocess.CompletedProcess([], 1), subprocess.TimeoutExpired("docker", 30)):
            with tempfile.TemporaryDirectory() as temporary, self.subTest(failure=type(failure).__name__):
                root = Path(temporary).resolve(); session = common.DockerSession()
                create, inspect, _ = self.reader_fixtures(session, root, exact_id, b"")
                with mock.patch.object(common, "output_directory", return_value=root), \
                        mock.patch.object(session, "_inspect", side_effect=inspect), \
                        mock.patch.object(common, "require_zero", side_effect=create), \
                        mock.patch.object(common.subprocess, "run", side_effect=failure if isinstance(failure, Exception) else None,
                                          return_value=failure), self.assertRaises(RuntimeError):
                    session.read_relay_binary(exact_id, root / "final-image-brightcrm.bin")

    def test_image_reader_refuses_started_or_replaced_container_before_and_after_copy(self):
        exact_id = "sha256:" + "a" * 64
        for mutate_after in (False, True):
            for field, value in (("Id", "d" * 64), ("Image", "sha256:" + "b" * 64),
                                 ("RestartCount", 1), ("Status", "running"), ("Running", True),
                                 ("StartedAt", "2026-11-14T00:00:00Z")):
                with tempfile.TemporaryDirectory() as temporary, self.subTest(after=mutate_after, field=field):
                    root = Path(temporary).resolve(); session = common.DockerSession()
                    create, inspect, copy = self.reader_fixtures(session, root, exact_id, self.binary_archive())
                    reads = 0
                    def changed(kind, name):
                        nonlocal reads
                        item = inspect(kind, name)
                        if kind == "container":
                            reads += 1
                            if reads == (2 if mutate_after else 1):
                                if field in item["State"]: item["State"][field] = value
                                else: item[field] = value
                        return item
                    with mock.patch.object(common, "output_directory", return_value=root), \
                            mock.patch.object(session, "_inspect", side_effect=changed), \
                            mock.patch.object(common, "require_zero", side_effect=create), \
                            mock.patch.object(common.subprocess, "run", side_effect=copy), \
                            mock.patch.object(common, "inspect_go_binary") as readback, self.assertRaises(RuntimeError):
                        session.read_relay_binary(exact_id, root / "final-image-brightcrm.bin")
                    readback.assert_not_called()

    def test_image_reader_refuses_nonfixed_linked_extra_empty_and_oversize_archive_members(self):
        exact_id = "sha256:" + "a" * 64
        payloads = [b"", b"not an archive", self.binary_archive()[:517],
                    self.binary_archive(names=("elsewhere",)), self.binary_archive(names=("../brightcrm",)),
                    self.binary_archive(names=("brightcrm", "extra")),
                    self.binary_archive(kind=tarfile.SYMTYPE), self.binary_archive(kind=tarfile.LNKTYPE),
                    self.binary_archive(kind=tarfile.DIRTYPE), self.binary_archive(size=0),
                    self.binary_archive(size=128 * 1024 * 1024 + 1)]
        for index, payload in enumerate(payloads):
            with tempfile.TemporaryDirectory() as temporary, self.subTest(archive=index):
                root = Path(temporary).resolve(); session = common.DockerSession()
                create, inspect, copy = self.reader_fixtures(session, root, exact_id, payload)
                with mock.patch.object(common, "output_directory", return_value=root), \
                        mock.patch.object(session, "_inspect", side_effect=inspect), \
                        mock.patch.object(common, "require_zero", side_effect=create), \
                        mock.patch.object(common.subprocess, "run", side_effect=copy), \
                        mock.patch.object(common, "inspect_go_binary") as readback, \
                        self.assertRaisesRegex(RuntimeError, "fixed bounded regular executable" if index == len(payloads) - 1 else ".*"):
                    session.read_relay_binary(exact_id, root / "final-image-brightcrm.bin")
                readback.assert_not_called()

    def test_binary_reader_cleanup_is_graceful_and_refuses_replaced_container(self):
        for replaced in (False, True):
            with tempfile.TemporaryDirectory() as temporary, self.subTest(replaced=replaced):
                root = Path(temporary); session = common.DockerSession(); name = "relay-ci-fixture"
                identity = "c" * 64; cid = root / "fixture.cid"; cid.write_text(identity)
                session.containers = [name]; session.container_ids[name] = cid; session.graceful_containers = {name}
                item = {"Id": identity, "Name": "/" + name, "Config": {"Labels": {"relay.ci.owner": session.owner}}, "State": {"Running": True}}
                after = {**item, "Id": "d" * 64} if replaced else None
                with mock.patch.object(session, "_inspect", side_effect=[item, after]), \
                        mock.patch.object(common, "require_zero") as command, mock.patch.object(common, "write_report"):
                    if replaced:
                        with self.assertRaises(RuntimeError): session.__exit__(None, None, None)
                    else: self.assertFalse(session.__exit__(None, None, None))
                    self.assertEqual(command.call_count, 1)
                    self.assertEqual(command.call_args.args[0], ["docker", "container", "stop", "--time", "5", identity])

    def test_scan_mount_is_readonly_and_container_is_ephemeral(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {"RELAY_CI_RESULTS_DIR": temporary}):
            tools = Path(temporary) / "tools"
            tools.mkdir()
            with mock.patch.object(common, "execute", return_value=0) as execute:
                session = common.DockerSession()
                session.run("scan", "sha256:" + "a" * 64, ["image", "--input", "/image.tar"],
                            mounts=[(tools, "/tools", True)])
                argv = execute.call_args.args[0]
                self.assertIn("--rm", argv)
                self.assertIn("--cidfile", argv)
                self.assertIn("type=bind,src=" + str(tools) + ",dst=/tools,readonly", argv)
                self.assertNotIn("/var/run/docker.sock", " ".join(argv))

    def test_cleanup_refuses_replacement_container_even_with_same_name_and_label(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {"RELAY_CI_RESULTS_DIR": temporary}):
            session = common.DockerSession()
            name = "relay-ci-" + session.owner + "-test"
            cidfile = Path(temporary) / "container.cid"
            cidfile.write_text("a" * 64)
            session.containers = [name]
            session.container_ids[name] = cidfile
            replacement = {"Id": "b" * 64, "Name": "/" + name,
                           "Config": {"Labels": {"relay.ci.owner": session.owner}}}
            with mock.patch.object(session, "_inspect", return_value=replacement), \
                    mock.patch.object(common, "require_zero") as removal:
                with self.assertRaises(RuntimeError): session.__exit__(None, None, None)
                removal.assert_not_called()

    def test_cleanup_refuses_foreign_network(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {"RELAY_CI_RESULTS_DIR": temporary}):
            session = common.DockerSession()
            session.networks = ["owned"]
            session.network_ids["owned"] = "a" * 64
            with mock.patch.object(session, "_inspect", return_value={"Id": "b" * 64, "Labels": {"relay.ci.owner": session.owner}}), \
                    mock.patch.object(common, "require_zero") as removal:
                with self.assertRaises(RuntimeError): session.__exit__(None, None, None)
                removal.assert_not_called()

    def test_cancellation_still_removes_only_exact_owned_container(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {"RELAY_CI_RESULTS_DIR": temporary}):
            session = common.DockerSession()
            name = "relay-ci-" + session.owner + "-test"
            cidfile = Path(temporary) / "container.cid"
            cidfile.write_text("a" * 64)
            session.containers = [name]
            session.container_ids[name] = cidfile
            item = {"Id": "a" * 64, "Name": "/" + name,
                    "Config": {"Labels": {"relay.ci.owner": session.owner}}}
            original = signal.getsignal(signal.SIGTERM)
            with mock.patch.object(session, "_inspect", return_value=item), \
                    mock.patch.object(common, "require_zero") as removal:
                with self.assertRaises(SystemExit):
                    with session:
                        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                self.assertIn(mock.call(["docker", "container", "rm", "-f", "-v", "a" * 64], "cleanup-" + name), removal.call_args_list)
            self.assertEqual(signal.getsignal(signal.SIGTERM), original)

    def test_migration_inventory_refuses_missing_duplicate_and_changed_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(RuntimeError): migration.inventory(root)
            for version in range(1, 5):
                (root / f"{version:03d}_fixture.sql").write_text("-- +goose Up\nSELECT 1;\n-- +goose Down\nSELECT 1;\n")
            initial = migration.inventory(root)
            self.assertEqual([row["version"] for row in initial], [1, 2, 3, 4])
            (root / "004_fixture.sql").write_text("different migration bytes")
            self.assertNotEqual(migration.inventory(root), initial)
            (root / "0001_duplicate.sql").write_text("duplicate version")
            with self.assertRaises(RuntimeError): migration.inventory(root)

    def test_migration_history_requires_every_expected_version_and_real_down_progress(self):
        self.assertEqual(migration.validate_applied("1\n2\n3\n4\n", [1, 2, 3, 4]), [1, 2, 3, 4])
        for raw, expected in [("1\n4\n", [1, 2, 3, 4]), ("1\n2\n3\n4\n", [1]),
                              ("1\n2\n2\n", [1, 2]), ("not a verdict", [1])]:
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                migration.validate_applied(raw, expected)

    def test_existing_down_error_and_tool_failure_are_never_waived(self):
        script = Path(__file__).with_name("goose-down.sh")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            goose = root / "goose"
            goose.write_text("#!/bin/sh\ncase \"$MODE\" in\n"
                             "broken) echo 'syntax error in existing Down'; exit 1;;\n"
                             "killed) exit 137;;\n"
                             "empty) echo 'no current version found'; exit 1;;\n"
                             "ok) echo attempt >> \"$COUNTER\"; exit 0;;\nesac\nexit 2\n")
            goose.chmod(0o700)
            for mode, passed in [("broken", False), ("killed", False), ("empty", True), ("ok", True)]:
                counter = root / (mode + ".count")
                env = {"PATH": str(root) + ":/usr/bin:/bin", "MODE": mode, "COUNTER": str(counter)}
                result = subprocess.run(["/bin/sh", "-ec", '. "$1"', "rehearsal", str(script)],
                                        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(result.returncode == 0, passed, mode)
                if mode == "ok": self.assertEqual(len(counter.read_text().splitlines()), 3)

    def test_no_unreviewed_security_exemptions_are_configured(self):
        self.assertEqual(common.POLICY["accepted_go_advisories"], [])
        self.assertEqual(common.POLICY["accepted_image_advisories"], [])
        self.assertEqual(common.POLICY["trivy_severities"], ["CRITICAL", "HIGH"])
        self.assertTrue(common.POLICY["trivy_ignore_unfixed"])


if __name__ == "__main__":
    unittest.main()
