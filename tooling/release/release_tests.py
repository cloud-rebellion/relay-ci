"""Refusal controls for portable security, image identity and real rollback checks."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
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
            def git_output(command, **kwargs):
                if command[1] == "rev-parse": return str(repository) + "\n"
                if command[1] == "ls-tree":
                    self.assertEqual(command[4], "d" * 40)  # Actual private context P, never G or S.
                    return b"".join(("100644 blob " + blob + "\tbrightcrm/voip/" + path).encode() + b"\0" for path, blob in rows)
                if command[1] == "cat-file": return blobs[command[-1]]
                raise AssertionError(command)
            with mock.patch.object(common.subprocess, "check_output", side_effect=git_output), \
                    mock.patch.object(common, "source_sha", return_value="d" * 40):
                exported = common.module_export(module, repository / "export")
                self.assertEqual((exported / "implementation.go").read_bytes(), b"package media\n")
                self.assertFalse((exported / ".env").exists())
                rows.append(("uncovered/go.mod", "a" * 40))
                with self.assertRaises(RuntimeError): common.module_export(module, repository / "other-export")

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
        for critical, high, cleanup_failure, passes in [(1, 0, False, False), (0, 137, False, False), (0, 0, True, False), (0, 0, False, True)]:
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
                    def run(self, leaf, scanner, command, **kwargs):
                        scans.append((leaf, kwargs["mounts"]))
                        return (critical if leaf.endswith("critical") else high), "fixture"
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
                    else:
                        with self.assertRaises(RuntimeError): image.main()
                        report.assert_not_called()

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
