"""Adversarial controls for full-tree identity and public diagnostic boundaries."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import unittest
from unittest import mock

import binding


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


seal = load("seal-reports")
fetch = load("fetch-private")
gate = load("run-gate")


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.harness = Path(self.temporary.name)
        self.private = self.harness / "private-source"
        self.private.mkdir()
        self.command(self.harness, "init", "--quiet")
        (self.harness / ".gitignore").write_text("/private-source/\n__pycache__/\n*.pyc\n")
        self.commit(self.harness)
        self.g = self.command(self.harness, "rev-parse", "HEAD").strip()
        self.command(self.private, "init", "--quiet")
        for path, body in [("brightcrm/go.mod", "module example.test/relay\n"),
                           ("ops/scripts/fixture.py", "print('synthetic')\n")]:
            target = self.private / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(body)
        self.commit(self.private)
        entries = []
        for raw in self.command(self.private, "ls-tree", "-r", "HEAD").splitlines():
            header, path = raw.split("\t"); mode, kind, oid = header.split(); body = (self.private / path).read_bytes()
            entries.append({"path": path, "mode": mode, "type": kind, "oid": oid,
                            "size": len(body), "sha256": hashlib.sha256(body).hexdigest()})
        self.manifest = {"schema": 1, "origin_stage_commit": "a" * 40,
                         "product_identity": {"program": "brightcrm", "policy_digest": "synthetic"},
                         "execution_roots": ["brightcrm", "ops"], "source_entries": entries}
        self.profile = {"schema": 1, "context_manifest_path": "relay-ci-context.json",
                        "context_metadata_paths": ["relay-ci-context.json"], "origin_stage_commit": "a" * 40,
                        "execution_roots": ["brightcrm", "ops"], "public_repository": "cloud-rebellion/relay-ci",
                        "public_repository_id": 900, "allowed_workflow_refs": ["refs/heads/main"]}
        self.update_manifest()

    def command(self, root, *args):
        return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.PIPE)

    def commit(self, root):
        self.command(root, "add", "--all")
        self.command(root, "-c", "user.name=Relay synthetic control", "-c", "user.email=relay-control@example.test",
                     "commit", "--quiet", "--allow-empty", "-m", "synthetic control")

    def refresh_context_commit(self):
        self.profile["context_commit"] = self.command(self.private, "rev-parse", "HEAD").strip()
        self.profile["context_tree"] = self.command(self.private, "rev-parse", "HEAD^{tree}").strip()

    def update_manifest(self):
        raw = (json.dumps(self.manifest, sort_keys=True) + "\n").encode()
        (self.private / "relay-ci-context.json").write_bytes(raw)
        self.profile["context_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        self.commit(self.private)
        self.refresh_context_commit()
        self.profile["source_entry_count"] = len(self.manifest["source_entries"])
        self.profile["source_bytes"] = sum(row["size"] for row in self.manifest["source_entries"])

    def verify(self, **kwargs):
        return binding.verify(self.profile, harness=self.harness, check_event=False, **kwargs)


class Identity(Fixture):
    def test_public_private_and_origin_are_distinct(self):
        result = self.verify()
        self.assertEqual(result["workflow_commit"], self.g)
        self.assertEqual(result["private_context_commit"], self.profile["context_commit"])
        self.assertEqual(result["origin_stage_commit"], "a" * 40)
        self.assertEqual(len({result[x] for x in ("workflow_commit", "private_context_commit", "origin_stage_commit")}), 3)

    def test_working_byte_drift_refuses(self):
        (self.private / "brightcrm/go.mod").write_text("module changed.test/relay\n")
        with self.assertRaises(RuntimeError): self.verify()

    def test_missing_added_mode_and_linked_inputs_refuse(self):
        path = self.private / "ops/scripts/fixture.py"
        path.unlink(); self.commit(self.private)
        self.refresh_context_commit()
        with self.assertRaises(RuntimeError): self.verify()

    def test_new_file_under_execution_root_cannot_escape_manifest(self):
        (self.private / "ops/new-wildcard-input.py").write_text("synthetic = True\n")
        self.commit(self.private); self.refresh_context_commit()
        with self.assertRaises(RuntimeError): self.verify()

    def test_mode_change_cannot_escape_byte_hashes(self):
        (self.private / "ops/scripts/fixture.py").chmod(0o755)
        self.commit(self.private); self.refresh_context_commit()
        with self.assertRaises(RuntimeError): self.verify()

    def test_symlink_cannot_replace_regular_input(self):
        path = self.private / "ops/scripts/fixture.py"; path.unlink(); path.symlink_to("../../brightcrm/go.mod")
        self.commit(self.private); self.refresh_context_commit()
        with self.assertRaises(RuntimeError): self.verify()

    def test_initial_ignored_input_refuses_but_generated_output_is_allowed_afterward(self):
        (self.private / "extra-output").write_text("generated only after build")
        with self.assertRaises(RuntimeError): self.verify()
        self.verify(initial=False)

    def test_changed_manifest_or_origin_refuses(self):
        manifest = self.private / "relay-ci-context.json"
        manifest.write_text(manifest.read_text() + " ")
        with self.assertRaises(RuntimeError): self.verify()
        self.manifest["origin_stage_commit"] = "b" * 40; self.update_manifest()
        with self.assertRaises(RuntimeError): self.verify()

    def test_incomplete_ops_inventory_and_duplicate_refuse(self):
        self.manifest["source_entries"] = self.manifest["source_entries"][:1]; self.update_manifest()
        with self.assertRaises(RuntimeError): self.verify()
        self.manifest["source_entries"] *= 2; self.update_manifest()
        with self.assertRaises(RuntimeError): self.verify()

    def test_private_commit_cannot_substitute_github_sha(self):
        env = {"GITHUB_SHA": self.profile["context_commit"], "GITHUB_REPOSITORY": "cloud-rebellion/relay-ci",
               "GITHUB_REPOSITORY_ID": "900", "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push"}
        with mock.patch.dict(os.environ, env):
            with self.assertRaises(RuntimeError):
                binding.verify(self.profile, harness=self.harness, check_event=True)

    def test_public_tooling_byte_drift_refuses_even_when_head_is_unchanged(self):
        (self.harness / ".gitignore").write_text("altered trusted input\n")
        with self.assertRaises(RuntimeError): self.verify()

    def test_public_tooling_mode_drift_refuses(self):
        (self.harness / ".gitignore").chmod(0o755)
        with self.assertRaises(RuntimeError): self.verify()

    def test_untracked_python_bytecode_cannot_override_trusted_code(self):
        cache = self.harness / "__pycache__"; cache.mkdir()
        (cache / "binding.cpython-314.pyc").write_bytes(b"untrusted executable input")
        with self.assertRaises(RuntimeError): self.verify()

    def test_loaded_profile_bytes_are_bound_to_public_git_blob(self):
        profile = dict(self.profile, status="pinned", private_repository="cloud-rebellion/relay",
                       private_repository_id=1447574877)
        directory = self.harness / "profiles"; directory.mkdir()
        path = directory / "relay.json"; path.write_text(json.dumps(profile))
        self.commit(self.harness); g = self.command(self.harness, "rev-parse", "HEAD").strip()
        with mock.patch.object(binding, "HARNESS", self.harness), mock.patch.object(binding, "verify_public", return_value=g):
            self.assertEqual(binding.load_profile(path)["context_commit"], self.profile["context_commit"])
            profile["origin_stage_commit"] = "f" * 40; path.write_text(json.dumps(profile))
            with self.assertRaises(RuntimeError): binding.load_profile(path)


class Diagnostics(Fixture):
    def setUp(self):
        super().setUp()
        self.diagnostics_temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.diagnostics_temporary.cleanup)
        self.results = Path(self.diagnostics_temporary.name)
        profiles = self.harness / "profiles"; profiles.mkdir()
        (profiles / "relay.json").write_text(json.dumps(self.profile))
        self.commit(self.harness)
        self.g = self.command(self.harness, "rev-parse", "HEAD").strip()
        self.sentinel = "PRIVATE_DIAGNOSTIC_SENTINEL_NEVER_PUBLIC"

    def test_only_approved_diagnostics_are_packaged(self):
        (self.results / "run.stdout").write_text(self.sentinel)
        (self.results / "image.tar").write_text(self.sentinel)
        nested = self.results / "vet-source-crm"; nested.mkdir(); (nested / "private.go").write_text(self.sentinel)
        paths, total = seal.report_paths(self.results)
        self.assertEqual([x.name for x in paths], ["run.stdout"])
        self.assertEqual(total, len(self.sentinel))

    def test_linked_diagnostic_refuses(self):
        (self.results / "leak.stdout").symlink_to(self.private / "brightcrm/go.mod")
        with self.assertRaises(RuntimeError): seal.report_paths(self.results)

    def test_public_summary_never_copies_advisories_or_errors(self):
        raw = {"gate": "source-security", "status": "passed", "binding_verified": True,
               "workflow_commit": self.g, "private_context_commit": self.profile["context_commit"],
               "private_context_tree": self.profile["context_tree"],
               "origin_stage_commit": self.profile["origin_stage_commit"],
               "context_manifest_sha256": self.profile["context_manifest_sha256"], "private_error": self.sentinel}
        (self.results / "gate-execution.json").write_text(json.dumps(raw))
        (self.results / "security-summary.json").write_text(json.dumps({"status": "passed", "private": self.sentinel}))
        for root in ["brightcrm", "ops"]:
            (self.results / ("source-scan-" + root + ".json")).write_text(json.dumps({"status": "passed", "blocking": [], "advisory": [{"location": self.sentinel}]}))
        env = {"GITHUB_SHA": self.g, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_REPOSITORY": "cloud-rebellion/relay-ci", "GITHUB_REPOSITORY_ID": "900",
               "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push"}
        with mock.patch.object(seal, "HARNESS", self.harness), mock.patch.dict(os.environ, env):
            summary = seal.safe_summary(self.profile, "source-security", self.results)
        self.assertNotIn(self.sentinel, json.dumps(summary))
        self.assertEqual(summary["counts"], {"brightcrm_blocking": 0, "brightcrm_advisory": 1, "ops_blocking": 0, "ops_advisory": 1})

    def test_false_green_private_summary_refuses(self):
        raw = {"gate": "core", "status": "passed", "binding_verified": True,
               "workflow_commit": self.g, "private_context_commit": "f" * 40}
        (self.results / "gate-execution.json").write_text(json.dumps(raw))
        with mock.patch.object(seal, "HARNESS", self.harness), mock.patch.dict(os.environ, {"GITHUB_SHA": self.g, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}):
            with self.assertRaises(RuntimeError): seal.safe_summary(self.profile, "core", self.results)


class ProcessPermissions(Fixture):
    def test_real_git_checkout_preserves_modes_inside_private_root_and_removes_key(self):
        source = self.harness / "local-source"
        source.mkdir(); self.command(source, "init", "--quiet")
        config = source / "brightcrm/deploy/cluster/prometheus.yml"
        config.parent.mkdir(parents=True); config.write_text("global: {}\n"); config.chmod(0o644)
        executable = source / "brightcrm/synthetic-tool.sh"
        executable.write_text("#!/bin/sh\nexit 0\n"); executable.chmod(0o755)
        self.commit(source); commit = self.command(source, "rev-parse", "HEAD").strip()
        harness = self.harness / "fetch-harness"; harness.mkdir(mode=0o700)
        runner = self.harness / "runner"; runner.mkdir(mode=0o700)
        results = runner / "diagnostics"
        hosts = "github.com ssh-ed25519 synthetic-public-host-identity\n"
        profile = {"private_repository": "cloud-rebellion/relay", "context_commit": commit,
                   "github_ssh_known_hosts": hosts,
                   "github_ssh_known_hosts_sha256": hashlib.sha256(hosts.encode()).hexdigest()}
        actual_run = subprocess.run
        def local_git(command, **kwargs):
            command = list(command)
            if command[:4] == ["git", "remote", "add", "origin"]:
                self.assertEqual(command[-1], "git@github.com:cloud-rebellion/relay.git")
                command[-1] = str(source)
            if "checkout" in command:
                keys = list(runner.glob("relay-read-key-*"))
                self.assertEqual(len(keys), 1)
                self.assertEqual(stat.S_IMODE(keys[0].stat().st_mode), 0o700)
                for name in ["key", "known_hosts"]:
                    self.assertEqual(stat.S_IMODE((keys[0] / name).stat().st_mode), 0o600)
            return actual_run(command, **kwargs)
        env = {"RUNNER_TEMP": str(runner), "RELAY_CI_RESULTS_DIR": str(results),
               "RELAY_SOURCE_READ_KEY": "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-only-never-used-for-network\n"}
        previous = os.umask(0o077)
        try:
            with mock.patch.object(fetch, "HARNESS", harness), mock.patch.object(fetch, "load_profile", return_value=profile), \
                    mock.patch.object(fetch.subprocess, "run", side_effect=local_git), mock.patch.dict(os.environ, env):
                fetch.main()
            private = harness / "private-source"
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((private / ".git").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((private / "brightcrm/deploy/cluster/prometheus.yml").stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE((private / "brightcrm/synthetic-tool.sh").stat().st_mode), 0o755)
            self.assertEqual((private / "brightcrm/deploy/cluster/prometheus.yml").read_bytes(), config.read_bytes())
            self.assertEqual(self.command(private, "rev-parse", "HEAD").strip(), commit)
            self.assertEqual(stat.S_IMODE(results.stat().st_mode), 0o700)
            for name in ["private-fetch.stdout", "private-fetch.stderr"]:
                self.assertEqual(stat.S_IMODE((results / name).stat().st_mode), 0o600)
            self.assertEqual(list(runner.glob("relay-read-key-*")), [])
        finally:
            os.umask(previous)

    def test_real_build_child_gets_normal_modes_while_capture_stays_private(self):
        directory = self.harness / "mode-control"; directory.mkdir(mode=0o700)
        diagnostics = directory / "diagnostics"; diagnostics.mkdir(mode=0o700)
        config = directory / "container-config.yml"
        child_report = diagnostics / "child.json"
        program = "import os,sys; [os.close(os.open(p,os.O_WRONLY|os.O_CREAT,0o644)) for p in sys.argv[1:]]"
        previous = os.umask(0o077)
        try:
            with (diagnostics / "capture.stdout").open("w") as stdout:
                gate.physical_process([sys.executable, "-B", "-c", program, str(config), str(child_report)],
                                      stdout=stdout, stderr=subprocess.DEVNULL, check=True, timeout=30)
            # Child umask must not alter the private capture parent's umask.
            parent_control = directory / "parent-control"
            fd = os.open(parent_control, os.O_WRONLY | os.O_CREAT, 0o644); os.close(fd)
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(parent_control.stat().st_mode), 0o600)
            gate.protect_reports(diagnostics)
            self.assertEqual(stat.S_IMODE(diagnostics.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((diagnostics / "capture.stdout").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(child_report.stat().st_mode), 0o600)
        finally:
            os.umask(previous)

    def test_private_diagnostic_protection_refuses_linked_reports(self):
        directory = self.harness / "diagnostic-link-control"; directory.mkdir()
        (directory / "foreign.stdout").symlink_to(self.harness / ".gitignore")
        with self.assertRaises(RuntimeError): gate.protect_reports(directory)


if __name__ == "__main__":
    unittest.main()
