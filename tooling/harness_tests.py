"""Adversarial controls for full-tree identity and public diagnostic boundaries."""
import copy
import hashlib
import importlib.util
import json
import os
import shlex
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import unittest
import zlib
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

    def write_object(self, kind, body):
        return subprocess.check_output(["/usr/bin/git", "hash-object", "-t", kind, "-w", "--stdin"],
                                       cwd=self.harness, input=body, stderr=subprocess.PIPE).decode().strip()

    def forged_public_tree(self):
        body = b"forged trusted-tooling bytes\n"
        blob = self.write_object("blob", body)
        raw = b"100644 .gitignore\0" + bytes.fromhex(blob)
        return body, blob, raw, self.write_object("tree", raw)

    def test_public_commit_replacement_cannot_forge_trusted_tooling(self):
        body, blob, _, tree = self.forged_public_tree()
        raw = ("tree " + tree + "\nauthor Synthetic <relay@example.test> 1 +0000\n"
               "committer Synthetic <relay@example.test> 1 +0000\n\nsynthetic replacement\n").encode()
        replacement = self.write_object("commit", raw)
        self.command(self.harness, "replace", self.g, replacement)
        (self.harness / ".gitignore").write_bytes(body)
        self.assertIn(blob, self.command(self.harness, "ls-tree", "-r", self.g))
        with self.assertRaises(RuntimeError): self.verify()

    def test_public_tree_replacement_cannot_forge_trusted_tooling(self):
        original = self.command(self.harness, "rev-parse", self.g + "^{tree}").strip()
        body, blob, _, tree = self.forged_public_tree()
        self.command(self.harness, "replace", original, tree)
        (self.harness / ".gitignore").write_bytes(body)
        self.assertIn(blob, self.command(self.harness, "ls-tree", "-r", self.g))
        with self.assertRaises(RuntimeError): self.verify()

    def test_loose_public_tree_forgery_under_trusted_oid_refuses(self):
        original = self.command(self.harness, "rev-parse", self.g + "^{tree}").strip()
        body, _, raw, _ = self.forged_public_tree()
        target = self.harness / ".git/objects" / original[:2] / original[2:]
        target.unlink()
        target.write_bytes(zlib.compress(b"tree " + str(len(raw)).encode() + b"\0" + raw))
        (self.harness / ".gitignore").write_bytes(body)
        with self.assertRaises(RuntimeError): self.verify()

    def test_hostile_git_environment_cannot_redirect_identity_or_execute_commands(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        foreign = Path(temporary.name); self.command(foreign, "init", "--quiet"); self.commit(foreign)
        marker = foreign / "executed"
        binary = foreign / "git"
        binary.write_text("#!/bin/sh\nprintf hostile > " + shlex.quote(str(marker)) + "\nexit 1\n")
        binary.chmod(0o700)
        env = {"GIT_DIR": str(foreign / ".git"), "GIT_WORK_TREE": str(foreign),
               "GIT_COMMON_DIR": str(foreign / ".git"), "GIT_INDEX_FILE": str(foreign / "wrong-index"),
               "GIT_OBJECT_DIRECTORY": str(foreign / ".git/objects"), "GIT_NAMESPACE": "forged",
               "GIT_REPLACE_REF_BASE": "refs/forged/", "GIT_CONFIG_COUNT": "1",
               "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": str(binary),
               "GIT_CONFIG_PARAMETERS": "'core.fsmonitor=true'", "GIT_SSH_COMMAND": str(binary),
               "PATH": str(foreign) + ":" + os.environ.get("PATH", "")}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(self.verify()["workflow_commit"], self.g)
        self.assertFalse(marker.exists())

    def test_public_staged_extra_input_cannot_hide_as_tracked(self):
        (self.harness / "forged.py").write_text("unexpected executable input\n")
        self.command(self.harness, "add", "forged.py")
        with self.assertRaises(RuntimeError): self.verify()

    def test_private_staged_extra_input_cannot_hide_as_tracked(self):
        (self.private / "brightcrm/forged.py").write_text("unexpected application input\n")
        self.command(self.private, "add", "brightcrm/forged.py")
        with self.assertRaises(RuntimeError): self.verify()

    def test_source_verification_never_executes_configured_fsmonitor(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        marker = Path(temporary.name) / "fsmonitor-executed"
        hook = self.private / ".git/hooks/synthetic-fsmonitor"
        hook.write_text("#!/bin/sh\nprintf called > " + shlex.quote(str(marker)) + "\nprintf '1\\0'\n")
        hook.chmod(0o700)
        self.command(self.private, "config", "core.fsmonitor", ".git/hooks/synthetic-fsmonitor")
        self.verify()
        self.assertFalse(marker.exists())
        # Prove the configured command is live on the removed ordinary-status path.
        subprocess.run(["/usr/bin/git", "status", "--porcelain=v1", "--untracked-files=no"],
                       cwd=self.private, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        self.assertTrue(marker.exists())

    def test_source_verification_never_executes_configured_clean_filter(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        marker = Path(temporary.name) / "filter-executed"
        script = self.private / ".git/hooks/synthetic-clean"
        script.write_text("#!/bin/sh\nprintf called > " + shlex.quote(str(marker)) + "\n/bin/cat\n")
        script.chmod(0o700)
        (self.private / ".git/info/attributes").write_text("brightcrm/go.mod filter=synthetic\n")
        self.command(self.private, "config", "filter.synthetic.clean", shlex.quote(str(script)))
        module = self.private / "brightcrm/go.mod"; module.write_bytes(module.read_bytes())
        self.verify()
        self.assertFalse(marker.exists())
        subprocess.run(["/usr/bin/git", "status", "--porcelain=v1", "--untracked-files=no"],
                       cwd=self.private, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        self.assertTrue(marker.exists())

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


class ActiveCompilerContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.product = Path(self.temporary.name) / "brightcrm"; self.product.mkdir()
        self.write_module("go.mod", "github.com/bright-interaction/brightcrm")
        self.write_module("voip/go.mod", "brightcrm-voip")
        (self.product / "Dockerfile").write_text("FROM oven/bun:1.4.3-alpine AS frontend\nFROM golang:1.26.11-alpine AS backend\nRUN go build ./cmd/server\nFROM alpine:3.21\n")

    def write_module(self, path, name, compiler="1.26.11", minimum="1.26.3"):
        path = self.product / path; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"module {name}\n\ngo {minimum}\n\ntoolchain go{compiler}\n")

    def verify(self, sdk="go1.26.11"):
        return binding.compiler_contract(self.product, sdk_version=sdk)

    def test_active_sdk_module_and_builder_contract_passes(self):
        value = self.verify()
        self.assertEqual(value["go_sdk"], "go1.26.11")
        self.assertEqual(value["go"], "1.26.11")
        self.assertEqual({x["toolchain"] for x in value["modules"].values()}, {"go1.26.11"})
        self.assertEqual(value["docker_go_builders"], [{"path": "Dockerfile", "reference": "golang:1.26.11-alpine"}])

    def test_older_newer_or_nonrelease_host_sdk_refuses(self):
        for sdk in ("go1.26.6", "go1.26.10", "go1.26.12", "go1.27.0", "devel go1.26.11", ""):
            with self.subTest(sdk=sdk), self.assertRaises(RuntimeError): self.verify(sdk)

    def test_real_sdk_probe_rejects_old_sdk_despite_active_pin(self):
        tools = Path(self.temporary.name) / "bin"; tools.mkdir()
        executable = tools / "go"
        executable.write_text("#!/bin/sh\nprintf 'go1.26.10\\n'\n"); executable.chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": str(tools) + os.pathsep + os.environ["PATH"]}):
            with self.assertRaises(RuntimeError): binding.compiler_contract(self.product)
            executable.write_text("#!/bin/sh\nprintf 'go1.26.11\\n'\n")
            self.assertEqual(binding.compiler_contract(self.product)["go_sdk"], "go1.26.11")

    def test_both_module_toolchains_must_be_exactly_active(self):
        for path, module, old in [("go.mod", "github.com/bright-interaction/brightcrm", "1.26.10"),
                                  ("voip/go.mod", "brightcrm-voip", "1.26.6")]:
            with self.subTest(path=path):
                self.write_module(path, module, old)
                with self.assertRaises(RuntimeError): self.verify()
                self.write_module(path, module)

    def test_every_secondary_docker_go_builder_must_be_active(self):
        path = self.product / "tools/helper.Dockerfile"; path.parent.mkdir()
        path.write_text("FROM golang:1.26.11-alpine AS helper\nFROM helper AS inherited\n")
        self.assertEqual(len(self.verify()["docker_go_builders"]), 3)
        for compiler in ("1.26.7", "1.26.10", "1.26.12"):
            with self.subTest(compiler=compiler):
                path.write_text(f"FROM golang:{compiler}-alpine AS hidden\n")
                with self.assertRaises(RuntimeError): self.verify()

    def test_fake_variable_or_ambiguous_builder_cannot_satisfy_contract(self):
        for source in ("FROM alpine:3.21\nRUN echo safe \\\nFROM golang:1.26.11-alpine\n",
                       "FROM golang:${GO_VERSION}-alpine AS backend\n", "FROM private/compiler:1.26.11\n",
                       "FROM golang:1.26.11-alpine AS same\nFROM alpine:3.21 AS same\n",
                       "FROM golang:1.26.11-alpine\nRUN <<EOF\nFROM golang:1.26.10-alpine\nEOF\n"):
            with self.subTest(source_hash=hashlib.sha256(source.encode()).hexdigest()):
                (self.product / "Dockerfile").write_text(source)
                with self.assertRaises(RuntimeError): self.verify()

    def test_unknown_module_duplicate_toolchain_and_excessive_minimum_refuse(self):
        self.write_module("extra/go.mod", "example.test/unregistered")
        with self.assertRaises(RuntimeError): self.verify()
        (self.product / "extra/go.mod").unlink()
        with (self.product / "go.mod").open("a") as stream: stream.write("toolchain go1.26.11\n")
        with self.assertRaises(RuntimeError): self.verify()
        self.write_module("go.mod", "github.com/bright-interaction/brightcrm", minimum="1.27.0")
        with self.assertRaises(RuntimeError): self.verify()


class EmbeddedCompilerControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.binary = self.root / "fixture"
        self.binary.write_bytes(b"synthetic bounded binary")

    def output(self, version="go1.26.11", body=None, code=0, mutate=False):
        def run(command, **kwargs):
            self.assertEqual(command, ["go", "version", "-m", str(self.binary)])
            self.assertEqual(kwargs["timeout"], 30)
            self.assertEqual(kwargs["env"]["GOTOOLCHAIN"], "local")
            raw = body if body is not None else (str(self.binary) + ": " + version +
                  "\n\tpath\texample.invalid/synthetic\n\tbuild\t-compiler=gc\n").encode()
            kwargs["stdout"].write(raw)
            if mutate: self.binary.write_bytes(b"changed output")
            return subprocess.CompletedProcess(command, code, b"", b"private diagnostic")
        return run

    def inspect(self, **kwargs):
        return binding.inspect_go_binary(self.binary, results_root=self.root, **kwargs)

    def test_exact_embedded_compiler_passes_without_executing_output(self):
        with mock.patch.object(binding.subprocess, "run", side_effect=self.output()):
            result = self.inspect()
        self.assertEqual(result, {"go_version": "go1.26.11", "bytes": self.binary.stat().st_size,
                                  "sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest()})

    def test_old_future_devel_missing_malformed_and_unbounded_metadata_refuse(self):
        outputs = [self.output(version) for version in ("go1.26.10", "go1.26.12", "devel go1.26.11", "")]
        outputs += [self.output(body=b"not a Go executable\n"), self.output(body=b"\xff"),
                    self.output(body=b"x" * (1024 * 1024 + 1)), self.output(code=1)]
        for output in outputs:
            with self.subTest(), mock.patch.object(binding.subprocess, "run", side_effect=output), self.assertRaises(RuntimeError):
                self.inspect()

    def test_changed_binary_and_probe_timeout_refuse(self):
        with mock.patch.object(binding.subprocess, "run", side_effect=self.output(mutate=True)), self.assertRaises(RuntimeError):
            self.inspect()
        with mock.patch.object(binding.subprocess, "run", side_effect=subprocess.TimeoutExpired("go", 30)), self.assertRaises(RuntimeError):
            self.inspect()

    def test_linked_empty_oversized_nonprivate_or_outside_output_refuses(self):
        with self.assertRaises(RuntimeError): self.inspect(max_bytes=1)
        self.binary.write_bytes(b"")
        with self.assertRaises(RuntimeError): self.inspect()
        self.binary.unlink(); self.binary.symlink_to(self.root / "missing")
        with self.assertRaises(RuntimeError): self.inspect()
        self.binary.unlink(); self.binary.write_bytes(b"synthetic")
        self.root.chmod(0o755)
        with self.assertRaises(RuntimeError): self.inspect()
        self.root.chmod(0o700)
        with self.assertRaises(RuntimeError): binding.inspect_go_binary(self.binary, results_root=self.root / "elsewhere")

    def test_real_go_output_metadata_is_read_without_running_the_binary(self):
        source = self.root / "fixture.go"
        source.write_text('package main\nfunc main(){ panic("must never execute") }\n')
        # The other controls use a non-object placeholder. Go deliberately
        # refuses to overwrite that file, so the real build needs a fresh path.
        self.binary.unlink()
        env = {name: os.environ[name] for name in ("PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH", "GOROOT") if name in os.environ}
        env.update(GOTOOLCHAIN="local", GOWORK="off", GOPROXY="off", GOSUMDB="off", GOENV="off")
        built = subprocess.run(["go", "build", "-o", str(self.binary), str(source)], cwd=self.root, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        self.assertEqual(built.returncode, 0, "Synthetic Go readback fixture must compile: " +
                         built.stderr.decode(errors="replace")[-8192:])
        self.assertEqual(self.inspect()["go_version"], "go1.26.11")


if __name__ == "__main__":
    unittest.main()
