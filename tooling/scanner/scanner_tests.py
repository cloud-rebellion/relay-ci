"""Adversarial controls use synthetic bytes only. No network, Docker or provider."""
import copy
import datetime as dt
import io
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error

import artifact
import profile
import registry
import storage

NOW = dt.datetime(2026, 11, 14, 22, tzinfo=dt.timezone.utc)
START = NOW - dt.timedelta(minutes=10)
DIGEST = "sha256:" + "a" * 64
CONFIG = "sha256:" + "b" * 64


def metadata():
    return {"Version": 2, "UpdatedAt": (NOW - dt.timedelta(hours=2)).isoformat(),
            "DownloadedAt": (NOW - dt.timedelta(minutes=5)).isoformat(),
            "NextUpdate": (NOW + dt.timedelta(hours=4)).isoformat()}


def report():
    return {"SchemaVersion": 2, "ArtifactType": "container_image", "Trivy": {"Version": "0.74.0"},
            "Metadata": {"ImageID": CONFIG, "OS": {"Family": "alpine", "Name": "3.24.4"},
                         "ImageConfig": {"os": "linux", "architecture": "amd64"}, "DiffIDs": [DIGEST]},
            "Results": [{"Target": "synthetic", "Class": "os-pkgs", "Type": "alpine",
                         "Packages": [{"Name": "synthetic", "Version": "1"}]}]}


def scan_profile():
    return {"image": {"config_digest": CONFIG}, "observed_diff_ids": [DIGEST]}


def desc(digest=DIGEST, **kw):
    return {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest, "size": 100, **kw}


def index():
    return {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
        desc(platform={"os": "linux", "architecture": "amd64"}),
        desc("sha256:" + "c" * 64, annotations={"vnd.docker.reference.type": "attestation-manifest",
                                               "vnd.docker.reference.digest": DIGEST})]}


class Response(io.BytesIO):
    status = 200
    def __init__(self, raw, headers=None):
        super().__init__(raw)
        self.headers = headers or {}


class ScannerControls(unittest.TestCase):
    def test_json_duplicate_key_refused(self):
        with self.assertRaisesRegex(registry.Refusal, "duplicate-json-key"):
            registry.document(b'{"subject":1,"subject":2}')

    def test_descriptor_external_urls_and_size_refused(self):
        for change in ({"urls": ["https://elsewhere.invalid/blob"]}, {"size": True}, {"size": 1025}):
            with self.subTest(change=change), self.assertRaises(registry.Refusal):
                registry.descriptor({**desc(), **change}, registry.MANIFEST_TYPES, 1024)

    def test_registry_repository_and_mutable_reference_refused(self):
        with self.assertRaises(registry.Refusal):
            registry.Registry("unreviewed/tool")
        with self.assertRaisesRegex(registry.Refusal, "fixed-digest"):
            registry.Registry("clamav/clamav").get("manifests", "latest")

    def test_registry_foreign_host_refused_before_request(self):
        opener = mock.Mock()
        instance = registry.Registry("clamav/clamav", opener=opener)
        for url in ("http://registry-1.docker.io/a", "https://registry-1.docker.io.evil/a",
                    "https://user@registry-1.docker.io/a", "https://registry-1.docker.io:444/a"):
            with self.subTest(url=url), self.assertRaises(registry.Refusal):
                instance._open(url)
        opener.open.assert_not_called()

    def test_refused_route_receipt_is_bounded_and_contains_no_url_or_credentials(self):
        opener = mock.Mock()
        instance = registry.Registry("clamav/clamav", opener=opener)
        instance.token = "synthetic-authorization-do-not-retain"
        with self.assertRaisesRegex(registry.Refusal, "registry-host"):
            instance._open("https://usernameSentinel:passwordSentinel@untrusted.example:8443/private-path-sentinel?signed-query-sentinel=opaque", cdn=True)
        self.assertEqual(instance.refused_routes, [{"hostname": "untrusted.example", "scheme": "https", "port": 8443,
                                                   "credentials_present": True}])
        raw = json.dumps(instance.refused_routes)
        for forbidden in ("usernameSentinel", "passwordSentinel", "private-path-sentinel", "signed-query-sentinel", instance.token, "https://"):
            self.assertNotIn(forbidden, raw)
        with self.assertRaisesRegex(registry.Refusal, "registry-host"):
            instance._open("https://untrusted.example:not-a-port/other?not-retained", cdn=True)
        self.assertEqual(instance.refused_routes[-1]["port"], "invalid")
        for _ in range(8):
            with self.assertRaises(registry.Refusal): instance._open("https://" + "a" * 64 + ".example/path", cdn=True)
        self.assertEqual(len(instance.refused_routes), 4)
        self.assertEqual(instance.refused_routes[-1]["hostname"], "invalid")
        self.assertTrue(all(set(row) == {"hostname", "scheme", "port", "credentials_present"} for row in instance.refused_routes))
        opener.open.assert_not_called()

    def test_unknown_cdn_stays_refused_without_request_or_bearer_forwarding(self):
        calls = []
        def open_request(request, **_):
            calls.append(request)
            raise urllib.error.HTTPError(request.full_url, 307, "redirect", {
                "Location": "https://unknown.cdn.example/blob?signature=synthetic-private-query"}, None)
        instance = registry.Registry("clamav/clamav", opener=mock.Mock(open=open_request))
        instance.token = "synthetic-authorization-not-exported"
        with self.assertRaisesRegex(registry.Refusal, "registry-host"):
            instance.get("blobs", DIGEST)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].full_url.startswith("https://registry-1.docker.io/v2/clamav/clamav/blobs/"))
        self.assertIsNotNone(calls[0].get_header("Authorization"))
        self.assertEqual(registry.CDN_HOSTS, {"production.cloudflare.docker.com", "production.cloudfront.docker.com"})
        self.assertEqual(instance.refused_routes, [{"hostname": "unknown.cdn.example", "scheme": "https", "port": 443,
                                                   "credentials_present": False}])
        self.assertNotIn("signature", json.dumps(instance.refused_routes))
        self.assertNotIn(instance.token, json.dumps(instance.refused_routes))

    def test_blob_redirect_strips_bearer_and_retains_no_signed_url(self):
        calls = []
        def open_request(request, **_):
            calls.append(request)
            if len(calls) == 1:
                raise urllib.error.HTTPError(request.full_url, 307, "redirect", {
                    "Location": "https://production.cloudflare.docker.com/blob?synthetic_signed=do-not-retain"}, None)
            return Response(b"synthetic")
        instance = registry.Registry("clamav/clamav", opener=mock.Mock(open=open_request))
        instance.token = "synthetic-memory-only-authorization"
        value = instance.get("blobs", registry.sha(b"synthetic"))
        self.assertEqual(value, b"synthetic")
        self.assertIsNotNone(calls[0].get_header("Authorization"))
        self.assertIsNone(calls[1].get_header("Authorization"))
        self.assertNotIn("synthetic_signed", json.dumps(instance.receipts))
        self.assertNotIn(instance.token, json.dumps(instance.receipts))
        instance.close()
        self.assertIsNone(instance.token)

    def test_blob_foreign_redirect_refused(self):
        error = urllib.error.HTTPError("https://registry-1.docker.io/a", 307, "redirect",
                                     {"Location": "https://evil.invalid/blob"}, None)
        instance = registry.Registry("clamav/clamav", opener=mock.Mock(open=mock.Mock(side_effect=error)))
        instance.token = "synthetic"
        with self.assertRaisesRegex(registry.Refusal, "registry-host"):
            instance.get("blobs", DIGEST)

    def test_registry_digest_size_and_total_bounds(self):
        for raw, digest, maximum, total in ((b"wrong", DIGEST, 100, 100),
                (b"large", registry.sha(b"large"), 4, 100), (b"large", registry.sha(b"large"), 100, 4)):
            opener = mock.Mock(open=lambda *_, **__: Response(raw))
            instance = registry.Registry("clamav/clamav", opener=opener, max_bytes=total)
            instance.token = "synthetic"
            with self.subTest(raw=raw, maximum=maximum, total=total), self.assertRaises(registry.Refusal):
                instance.get("blobs", digest, maximum=maximum)

    def test_index_subject_platform_and_attestation_required(self):
        selected, attestations = registry.select_image(index(), DIGEST)
        self.assertEqual(selected["digest"], DIGEST)
        self.assertEqual(len(attestations), 1)
        for mutate in (lambda v: v["manifests"].append(copy.deepcopy(v["manifests"][0])),
                       lambda v: v["manifests"][0]["platform"].update(architecture="arm64"),
                       lambda v: v["manifests"].pop()):
            value = index(); mutate(value)
            with self.assertRaises(registry.Refusal):
                registry.select_image(value, DIGEST)

    def test_attestation_subject_mismatch_and_unsigned_trust(self):
        value = {"_type": "https://in-toto.io/Statement/v0.1", "subject": [{"name": "synthetic", "digest": {"sha256": "a" * 64}}],
                 "predicateType": "https://slsa.dev/provenance/v0.2", "predicate": {}}
        actual = registry.inspect_attestation(json.dumps(value).encode(), DIGEST)
        self.assertTrue(actual["subject_verified"])
        self.assertFalse(actual["publisher_signature_verified"])
        for change in ({"subject": [{"name": "synthetic", "digest": {"sha256": "d" * 64}}]},
                       {"predicateType": "https://unknown.invalid/type"}):
            with self.assertRaises(registry.Refusal):
                registry.inspect_attestation(json.dumps({**value, **change}).encode(), DIGEST)

    def test_observed_ten_same_image_alias_subjects_are_accepted(self):
        # Count/digests and these four aliases come from fixed public SPDX
        # a2fe0686.., observed 2026-11-14. Six withheld upstream names are
        # represented by unique synthetic labels; no raw body replay is claimed.
        target = "sha256:2d901d81cbd1ed6556edfde8e20391bf81a13365d8f3ad9460d1c0340470ad89"
        names = ["pkg:docker/clamav/clamav@" + tag + "?platform=linux%2Famd64" for tag in
                 ("1.5.4_base-debian", "1.5.4_base-debian13-slim", "1.5_base-debian", "1.5_base-debian13-slim")]
        names += ["synthetic-redacted-upstream-alias-" + str(i) for i in range(6)]
        value = {"_type": "https://in-toto.io/Statement/v0.1", "subject": [
                    {"name": name, "digest": {"sha256": target[7:]}} for name in names],
                 "predicateType": "https://spdx.dev/Document", "predicate": {}}
        actual = registry.inspect_attestation(json.dumps(value).encode(), target)
        self.assertEqual(actual["subject_count"], 10)
        self.assertTrue(actual["subject_verified"])
        self.assertFalse(actual["publisher_signature_verified"])

    def test_attestation_alias_count_bounds_are_closed(self):
        value = {"_type": "https://in-toto.io/Statement/v1", "subject": [],
                 "predicateType": "https://spdx.dev/Document", "predicate": {}}
        with self.assertRaisesRegex(registry.Refusal, "attestation-subject-count"):
            registry.inspect_attestation(json.dumps(value).encode(), DIGEST)
        value["subject"] = [{"name": "alias-" + str(i), "digest": {"sha256": DIGEST[7:]}} for i in range(32)]
        self.assertEqual(registry.inspect_attestation(json.dumps(value).encode(), DIGEST)["subject_count"], 32)
        value["subject"].append({"name": "alias-32", "digest": {"sha256": DIGEST[7:]}})
        with self.assertRaisesRegex(registry.Refusal, "attestation-subject-count"):
            registry.inspect_attestation(json.dumps(value).encode(), DIGEST)

    def test_attestation_alias_mixed_digest_duplicate_type_and_name_refused(self):
        good = {"name": "first", "digest": {"sha256": DIGEST[7:]}}
        invalid = [None, "not-an-object", {}, {"name": "first", "digest": good["digest"]},
                   {"name": "other", "digest": {"sha256": "d" * 64}},
                   {"name": "other", "digest": {"sha256": DIGEST[7:], "sha1": "b" * 40}},
                   {"name": "other", "digest": []}, {"name": "", "digest": good["digest"]},
                   {"name": 1, "digest": good["digest"]},
                   {"name": "nul\u0000name", "digest": good["digest"]},
                   {"name": "unicode\u0085control", "digest": good["digest"]},
                   {"name": "hidden\u200bformat", "digest": good["digest"]},
                   {"name": "x" * 4097, "digest": good["digest"]}]
        for bad in invalid:
            value = {"_type": "https://in-toto.io/Statement/v1", "subject": [good, bad],
                     "predicateType": "https://spdx.dev/Document", "predicate": {}}
            with self.subTest(bad=bad), self.assertRaises(registry.Refusal):
                registry.inspect_attestation(json.dumps(value).encode(), DIGEST)

    def test_database_fresh_positive_and_no_prior_download_credit(self):
        actual = artifact.validate_database(metadata(), now=NOW, started=START)
        self.assertEqual(actual["Version"], 2)
        value = metadata(); value["DownloadedAt"] = (START - dt.timedelta(seconds=1)).isoformat()
        with self.assertRaisesRegex(registry.Refusal, "not-freshly"):
            artifact.validate_database(value, now=NOW, started=START)

    def test_database_stale_future_missing_overdue_and_schema_refused(self):
        for change in ({"UpdatedAt": (NOW - dt.timedelta(days=2)).isoformat()},
                       {"UpdatedAt": (NOW + dt.timedelta(seconds=1)).isoformat()},
                       {"NextUpdate": (NOW - dt.timedelta(seconds=1)).isoformat()},
                       {"DownloadedAt": None}, {"Version": 3}):
            with self.subTest(change=change), self.assertRaises(registry.Refusal):
                artifact.validate_database({**metadata(), **change}, now=NOW, started=START)

    def test_empty_and_wrong_image_scan_reports_refused(self):
        for change in ({"Results": []}, {"SchemaVersion": 1}, {"Trivy": {"Version": "future"}},
                       {"Metadata": {**report()["Metadata"], "ImageID": DIGEST}},
                       {"Metadata": {**report()["Metadata"], "DiffIDs": []}},
                       {"Metadata": {**report()["Metadata"], "OS": {"Family": "alpine", "Name": "3.24"}}}):
            with self.subTest(change=change), self.assertRaises(registry.Refusal):
                artifact.validate_report({**report(), **change}, scan_profile())

    def test_alpine_os_family_release_support_and_package_type_are_exact(self):
        self.assertEqual(artifact.validate_report(report(), scan_profile())["verdict"], "passed")
        for os_value in ({"Family": "debian", "Name": "13.7"},
                         {"Family": "alpine", "Name": "3.24"},
                         {"Family": "alpine", "Name": "3.24.3"},
                         {"Family": "alpine", "Name": "3.24.5"},
                         {"Family": "alpine", "Name": "3.25.0"},
                         {"Family": "alpine", "Name": "3.24.4", "EOSL": True}):
            value = report(); value["Metadata"]["OS"] = os_value
            with self.subTest(os=os_value), self.assertRaisesRegex(registry.Refusal, "os-or-support-mismatch"):
                artifact.validate_report(value, scan_profile())
        value = report(); value["Results"][0]["Type"] = "debian"
        with self.assertRaisesRegex(registry.Refusal, "package-inventory-missing"):
            artifact.validate_report(value, scan_profile())

    def test_rejected_debian_profile_is_exact_historical_and_cannot_be_active(self):
        import hashlib
        path = Path(__file__).resolve().parents[2] / "profiles/historical/scanner-artifact-debian-2d901d81-rejected.json"
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "8aabce18e32b4a83687276fecef75779027163d6a4e4f84c440404f2a68cde27")
        with self.assertRaisesRegex(registry.Refusal, "profile-subject-or-policy"):
            profile.load(path)
        self.assertEqual(profile.IMAGE["manifest_digest"],
                         "sha256:b2c2f5c9a557dc1c1249e09448a84c59c3e414bb3bbbac0a9d065236c779842c")

    def test_unfixed_high_and_critical_both_block(self):
        value = report()
        value["Results"][0]["Vulnerabilities"] = [
            {"VulnerabilityID": "CVE-2099-1001", "Severity": "HIGH", "FixedVersion": ""},
            {"VulnerabilityID": "CVE-2099-1002", "Severity": "CRITICAL", "FixedVersion": "2"}]
        actual = artifact.validate_report(value, scan_profile())
        self.assertEqual((actual["verdict"], actual["high"], actual["critical"]), ("failed", 1, 1))

    def test_zero_finding_report_requires_real_os_package_inventory(self):
        self.assertEqual(artifact.validate_report(report(), scan_profile())["verdict"], "passed")
        value = report(); value["Results"][0]["Packages"] = []
        with self.assertRaisesRegex(registry.Refusal, "package-inventory-missing"):
            artifact.validate_report(value, scan_profile())

    def test_modified_findings_and_unknown_severity_refused(self):
        for change in ({"ExperimentalModifiedFindings": [{"ID": "synthetic"}]},
                       {"Vulnerabilities": [{"VulnerabilityID": "CVE-2099-1003", "Severity": "UNREVIEWED"}]}):
            value = report(); value["Results"][0].update(change)
            with self.assertRaises(registry.Refusal):
                artifact.validate_report(value, scan_profile())

    def test_scan_command_has_no_unfixed_ignore_or_coverage_omissions(self):
        arguments = artifact.scan_arguments()
        self.assertIn("--ignore-unfixed=false", arguments)
        self.assertEqual(arguments[arguments.index("--input") + 1], "/input/oci")
        self.assertEqual(arguments[arguments.index("--pkg-types") + 1], "os,library")
        self.assertEqual(arguments[arguments.index("--ignorefile") + 1], "/input/empty.ignore")
        for flag in ("--skip-files", "--skip-dirs", "--ignore-status", "--vex", "--ignore-policy"):
            self.assertNotIn(flag, arguments)

    def test_database_mutation_and_links_change_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "db").write_bytes(b"one")
            before = artifact.tree_fingerprint(root)
            (root / "db").write_bytes(b"two")
            self.assertNotEqual(artifact.tree_fingerprint(root), before)
            (root / "linked").symlink_to(root / "db")
            with self.assertRaisesRegex(registry.Refusal, "symlink"):
                artifact.tree_fingerprint(root)

    def test_public_vm_and_event_boundary_refuses_selfhosted_private_and_pr(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
               "RUNNER_ARCH": "X64", "GITHUB_REPOSITORY": "cloud-rebellion/relay-ci",
               "GITHUB_REPOSITORY_ID": "1457664829", "GITHUB_EVENT_NAME": "push",
               "GITHUB_REF": "refs/heads/scanner/assessment-20261114"}
        storage.public_runner(env)
        for change in ({"RUNNER_ENVIRONMENT": "self-hosted"}, {"GITHUB_EVENT_NAME": "pull_request"},
                       {"GITHUB_REF": "refs/heads/main"}, {"GITHUB_REPOSITORY_ID": "1"},
                       {"RELAY_SOURCE_READ_KEY": "synthetic-no-real-key"}, {"RELAY_PRIVATE_SOURCE_ROOT": "/tmp/private"}):
            with self.subTest(change=change), self.assertRaises(registry.Refusal):
                storage.public_runner({**env, **change})

    def test_loop_ownership_rejects_wrong_device_and_backing_path(self):
        expected = Path("/synthetic/owned.ext4")
        storage.owned_loop([{"name": "/dev/loop7", "back-file": str(expected)}], "/dev/loop7", expected)
        for rows in ([], [{"name": "/dev/loop8", "back-file": str(expected)}],
                     [{"name": "/dev/loop7", "back-file": "/synthetic/someone-else.ext4"}]):
            with self.assertRaises(registry.Refusal):
                storage.owned_loop(rows, "/dev/loop7", expected)

    def test_tool_pin_cannot_be_mutated(self):
        with self.assertRaisesRegex(registry.Refusal, "reviewed-tool-pin"):
            artifact.validate_tool_manifest(mock.Mock(), "docker.io/aquasec/trivy:latest")

    def test_profile_exact_base_policy_and_unknown_keys_refused(self):
        value = json.loads((Path(__file__).resolve().parents[2] / "profiles/scanner-artifact.json").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "profile.json"
            target.write_text(json.dumps(value))
            self.assertEqual(profile.load(target)[0]["public_base_identity"]["commit"],
                             "ecb76187a2851abe163f3a501e22dcde3264184c")
            for mutate in (lambda v: v.update(unknown_allowance=True),
                           lambda v: v["vulnerability_policy"].update(ignore_unfixed=True),
                           lambda v: v["public_base_identity"].update(commit="a" * 40)):
                altered = copy.deepcopy(value); mutate(altered); target.write_text(json.dumps(altered))
                with self.assertRaises(registry.Refusal):
                    profile.load(target)

    def test_owned_command_cannot_fall_back_to_inherited_docker_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); results = root / "results"; results.mkdir()
            observed = []
            def run(args, **kwargs):
                observed.append((args, kwargs["env"]))
                kwargs["stdout"].write(b"synthetic-result")
                return mock.Mock(returncode=0)
            with mock.patch.object(storage, "public_runner"), mock.patch.dict(os.environ,
                    {"RUNNER_TEMP": str(root), "DOCKER_HOST": "tcp://unrelated.invalid:2375", "DOCKER_CONTEXT": "unrelated"}):
                daemon = storage.BoundedDaemon(results, run=run)
                daemon.root.mkdir()
                daemon.daemon_id = "synthetic-owned-daemon"
                daemon.docker(["info"])
            self.assertEqual(observed[0][0], ["docker", "info"])
            self.assertEqual(observed[0][1]["DOCKER_HOST"], "unix://" + str(daemon.root / "docker.sock"))
            self.assertNotIn("DOCKER_CONTEXT", observed[0][1])
            self.assertNotIn("tcp://", json.dumps(observed))

    def test_ambiguous_loop_cleanup_refuses_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); results = root / "results"; results.mkdir()
            run = mock.Mock()
            with mock.patch.object(storage, "public_runner"), mock.patch.dict(os.environ, {"RUNNER_TEMP": str(root)}):
                daemon = storage.BoundedDaemon(results, run=run)
            daemon.device = "/dev/loop7"
            with mock.patch.object(daemon, "verify_loop", side_effect=registry.Refusal("loop-ownership-mismatch")):
                with self.assertRaisesRegex(registry.Refusal, "loop-ownership-mismatch"):
                    daemon.__exit__(None, None, None)
            run.assert_not_called()

    def test_lost_mount_response_is_resolved_before_unmount_detach_unlink(self):
        with cleanup_fixture() as (daemon, state, commands):
            daemon.mount_attempted = True
            daemon.mounted = False  # mount succeeded, Python never got response
            daemon.__exit__(None, None, None)
            self.assertFalse(state["mounted"])
            self.assertFalse(state["loop"])
            self.assertFalse(daemon.backing.exists())
            mutations = [x for x in commands if "umount" in x or "--detach" in x]
            self.assertEqual(len(mutations), 2)
            first_mutation = commands.index(mutations[0])
            self.assertTrue(any("findmnt" in x for x in commands[:first_mutation]))
            self.assertTrue(any("--associated" in x for x in commands[:first_mutation]))

    def test_failed_mount_inventory_preserves_backing_without_mutation(self):
        with cleanup_fixture() as (daemon, state, commands):
            state["inventory_failure"] = True
            daemon.mount_attempted = True
            with self.assertRaisesRegex(registry.Refusal, "synthetic-inventory-unavailable"):
                daemon.__exit__(None, None, None)
            self.assertTrue(daemon.backing.exists())
            self.assertTrue(state["loop"])
            self.assertFalse(any("umount" in x or "--detach" in x for x in commands))

    def test_wrong_mount_identity_preserves_backing_without_mutation(self):
        with cleanup_fixture() as (daemon, state, commands):
            state["wrong_source"] = True
            daemon.mount_attempted = True
            with self.assertRaisesRegex(registry.Refusal, "bounded-mount-identity"):
                daemon.__exit__(None, None, None)
            self.assertTrue(daemon.backing.exists())
            self.assertFalse(any("umount" in x or "--detach" in x for x in commands))

    def test_proven_mount_and_loop_absence_allows_only_owned_backing_unlink(self):
        with cleanup_fixture() as (daemon, state, commands):
            state.update(loop=False, mounted=False)
            daemon.device = None
            daemon.mount_attempted = True
            daemon.__exit__(None, None, None)
            self.assertFalse(daemon.backing.exists())
            self.assertFalse(any("umount" in x or "--detach" in x for x in commands))

    def test_lost_loop_response_resolves_exact_backing_before_detach(self):
        with cleanup_fixture() as (daemon, state, commands):
            daemon.device = None  # losetup succeeded, stdout was lost
            state["mounted"] = False
            daemon.__exit__(None, None, None)
            self.assertFalse(state["loop"])
            self.assertFalse(daemon.backing.exists())
            detach = next(x for x in commands if "--detach" in x)
            self.assertEqual(detach[-1], "/dev/loop7")
            self.assertGreaterEqual(sum("--associated" in x for x in commands), 2)

    def test_canonical_oci_custody_archive_preserves_fixed_bytes(self):
        import tarfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); oci = root / "oci"; oci.mkdir()
            (oci / "oci-layout").write_bytes(b'{"imageLayoutVersion":"1.0.0"}')
            receipt = artifact.custody_tar(oci, root / "custody.tar")
            with tarfile.open(root / "custody.tar") as bundle:
                self.assertEqual(bundle.getnames(), ["oci-layout"])
                self.assertEqual(bundle.extractfile("oci-layout").read(), (oci / "oci-layout").read_bytes())
            self.assertEqual(receipt["files"][0]["bytes"], len((oci / "oci-layout").read_bytes()))

    def test_artifact_summary_cannot_claim_daemon_app_or_production_acceptance(self):
        sealer = load_sealer()
        source_profile = {"image": profile.IMAGE}
        raw = {"schema": 1, "kind": "relay-public-scanner-artifact-assessment-v1", "workflow_commit": "a" * 40,
               "profile_sha256": "b" * 64, "image": profile.IMAGE, "status": "passed-artifact-security-only",
               "artifact_security": {"verdict": "passed", "high": 0, "critical": 0, "packages": 1, "sbom_generated": True},
               "candidate_image_executed": False, **{key: False for key in ("full_scanner_qualified", "daemon_qualification_started",
                   "private_app_source_used", "app_six_job_qualification", "deployment_authorized")}}
        actual = sealer.summary(source_profile, "b" * 64, raw, "a" * 40)
        self.assertEqual(actual["status"], "passed-artifact-security-only")
        for key in ("full_scanner_qualified", "daemon_qualification_started", "private_app_source_used",
                    "app_six_job_qualification", "deployment_authorized"):
            with self.subTest(key=key), self.assertRaises(registry.Refusal):
                sealer.summary(source_profile, "b" * 64, {**raw, key: True}, "a" * 40)

    def test_artifact_summary_high_critical_and_mismatched_identity_refused(self):
        sealer = load_sealer()
        raw = {"schema": 1, "kind": "relay-public-scanner-artifact-assessment-v1", "workflow_commit": "a" * 40,
               "profile_sha256": "b" * 64, "image": profile.IMAGE, "status": "passed-artifact-security-only",
               "artifact_security": {"verdict": "passed", "high": 1, "critical": 0, "packages": 1, "sbom_generated": True},
               "candidate_image_executed": False, **{key: False for key in ("full_scanner_qualified", "daemon_qualification_started",
                   "private_app_source_used", "app_six_job_qualification", "deployment_authorized")}}
        with self.assertRaises(registry.Refusal):
            sealer.summary({"image": profile.IMAGE}, "b" * 64, raw, "a" * 40)
        raw["status"] = "failed"
        actual = sealer.summary({"image": profile.IMAGE}, "b" * 64, raw, "a" * 40)
        self.assertEqual(actual["status"], "failed")
        with self.assertRaises(registry.Refusal):
            sealer.summary({"image": profile.IMAGE}, "b" * 64, raw, "c" * 40)

    def test_high_critical_verdict_stops_before_sbom_or_daemon(self):
        value = report(); value["Results"][0]["Vulnerabilities"] = [
            {"VulnerabilityID": "CVE-2099-1004", "Severity": "HIGH", "FixedVersion": ""}]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); private_tool_inputs(root); cache = root / "cache"
            for name, version in (("db", 2), ("java-db", 1)):
                directory = cache / name; directory.mkdir()
                (directory / "metadata.json").write_text(json.dumps({**metadata(), "Version": version}))
                (directory / ("trivy.db" if version == 2 else "trivy-java.db")).write_bytes(b"synthetic-db")
            daemon = mock.Mock()
            daemon.docker.return_value = mock.Mock(returncode=0, stdout=json.dumps([{"Id": CONFIG}]).encode())
            scanner = artifact.Trivy(daemon, {"reference": artifact.TOOL_REFERENCE, "config_digest": CONFIG}, root, root)
            # Version, DB download, Java download, actual structured verdict.
            responses = [b'{"Version":"0.74.0"}', b"", b"", json.dumps(value).encode()]
            moments = iter([START, NOW, NOW])
            with mock.patch.object(scanner, "invoke", side_effect=responses) as invoke:
                result = scanner.assess(scan_profile(), now=lambda: next(moments))
            self.assertEqual(result["verdict"], "failed")
            self.assertFalse(result["sbom_generated"])
            self.assertEqual(invoke.call_count, 4)
            self.assertEqual(daemon.docker.call_count, 2)

    def test_tool_user_matches_private_inputs_and_cache_without_privilege_relaxation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); private_tool_inputs(root)
            daemon = mock.Mock(); daemon.owner = "synthetic-owner"
            daemon.docker.return_value = mock.Mock(returncode=0, stdout=b"{}", stderr=b"")
            scanner = artifact.Trivy(daemon, {"config_digest": CONFIG}, root, root)
            scanner.invoke(["version"])
            args = daemon.docker.call_args.args[0]
            self.assertEqual(args[args.index("--user") + 1], str(os.geteuid()) + ":" + str(os.getegid()))
            for required in ("--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true"):
                self.assertIn(required, args)
            self.assertIn("type=bind,src=" + str(root) + ",dst=/input,readonly", args)
            self.assertIn("type=bind,src=" + str(root / "cache") + ",dst=/cache", args)
            self.assertNotIn("--privileged", args); self.assertFalse(any(x.startswith("--cap-add") for x in args))
            code = "from pathlib import Path; import sys; p=Path(sys.argv[1]); assert (p/'empty.yaml').read_bytes()==b'{}\\n'; (p/'cache/probe').write_bytes(b'synthetic'); print('owned-input-cache-ok')"
            completed = subprocess.run([sys.executable, "-B", "-c", code, str(root)], capture_output=True, text=True, timeout=15)
            self.assertEqual((completed.returncode, completed.stdout.strip()), (0, "owned-input-cache-ok"))
            self.assertEqual((root / "empty.yaml").stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / "cache").stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / "cache/probe").stat().st_uid, os.geteuid())

    def test_tool_refuses_root_mismatched_or_foreign_owner_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); private_tool_inputs(root); daemon = mock.Mock()
            for real, effective in ((0, 0), (os.getuid(), 0), (os.getuid() + 1, os.getuid() + 1)):
                with self.subTest(real=real, effective=effective), mock.patch.object(artifact.os, "getuid", return_value=real), \
                     mock.patch.object(artifact.os, "geteuid", return_value=effective), self.assertRaises(registry.Refusal):
                    artifact.Trivy(daemon, {"config_digest": CONFIG}, root, root)
            daemon.docker.assert_not_called()

    def test_tool_refuses_input_cache_modes_links_and_changed_config_before_execution(self):
        for damage in ("input-mode", "input-symlink", "input-hardlink", "cache-mode", "cache-tmp-symlink", "changed-config"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); private_tool_inputs(root); daemon = mock.Mock()
                if damage == "input-mode": (root / "empty.yaml").chmod(0o644)
                elif damage == "input-symlink":
                    (root / "other").write_text("{}\n"); (root / "empty.yaml").unlink(); (root / "empty.yaml").symlink_to(root / "other")
                elif damage == "input-hardlink": os.link(root / "empty.ignore", root / "second-link")
                elif damage == "cache-mode": (root / "cache").chmod(0o755)
                elif damage == "cache-tmp-symlink":
                    (root / "other-cache").mkdir(); (root / "cache/tmp").rmdir(); (root / "cache/tmp").symlink_to(root / "other-cache", target_is_directory=True)
                else: (root / "empty.yaml").write_text("unexpected: true\n")
                with self.assertRaises(registry.Refusal): artifact.Trivy(daemon, {"config_digest": CONFIG}, root, root)
                daemon.docker.assert_not_called()


def load_sealer():
    spec = spec_from_file_location("scanner_public_summary_controls", Path(__file__).with_name("seal-public.py"))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_tool_inputs(root):
    for name in ("oci", "cache", "cache/tmp"):
        (root / name).mkdir(mode=0o700, exist_ok=True)
    for name, raw in (("empty.yaml", b"{}\n"), ("empty.ignore", b"")):
        (root / name).write_bytes(raw); (root / name).chmod(0o600)


from contextlib import contextmanager


@contextmanager
def cleanup_fixture():
    """Synthetic successful inventory, not an actual mount/loop qualification."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary); results = root / "results"; results.mkdir()
        with mock.patch.object(storage, "public_runner"), mock.patch.dict(os.environ, {"RUNNER_TEMP": str(root)}):
            daemon = storage.BoundedDaemon(results)
        daemon.root.mkdir()
        daemon.backing.write_bytes(b"synthetic-owned-backing")
        daemon.loop_attempted = True
        daemon.device = "/dev/loop7"
        state = {"loop": True, "mounted": True, "wrong_source": False, "inventory_failure": False}
        commands = []
        def command(args, **_):
            commands.append(args)
            if "--associated" in args:
                value = {"loopdevices": [{"name": "/dev/loop7", "back-file": str(daemon.backing)}] if state["loop"] else []}
            elif args[0] == "findmnt":
                if state["inventory_failure"]:
                    raise registry.Refusal("synthetic-inventory-unavailable")
                rows = [{"source": "/dev/root", "target": "/", "fstype": "ext4"}]
                if state["mounted"]:
                    rows.append({"source": "/dev/loop8" if state["wrong_source"] else "/dev/loop7",
                                 "target": str(daemon.mount), "fstype": "ext4"})
                value = {"filesystems": rows}
            elif "umount" in args:
                state["mounted"] = False; value = {}
            elif "--detach" in args:
                if state["mounted"]:
                    raise AssertionError("must not detach mounted filesystem")
                state["loop"] = False; value = {}
            else:
                raise AssertionError("unexpected synthetic command")
            return mock.Mock(returncode=0, stdout=json.dumps(value).encode())
        with mock.patch.object(daemon, "command", side_effect=command), mock.patch.object(daemon, "verify_loop"), \
             mock.patch.object(daemon, "verify_mount"):
            yield daemon, state, commands


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ScannerControls)
    # This closed inventory deliberately changes only with reviewed source.
    if suite.countTestCases() != 42:
        raise SystemExit("Closed scanner control inventory changed")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    destination = os.environ.get("RELAY_SCANNER_RESULTS_DIR")
    if destination:
        (Path(destination) / "scanner-controls-summary.json").write_text(json.dumps({"schema": 1,
            "tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
            "skips": len(result.skipped), "status": "passed" if result.wasSuccessful() and not result.skipped else "failed"}) + "\n")
    if result.skipped or result.testsRun != 42 or not result.wasSuccessful():
        raise SystemExit(1)


if __name__ == "__main__":
    main()
