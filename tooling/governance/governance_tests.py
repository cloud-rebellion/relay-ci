import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("relay_governance_driver", Path(__file__).with_name("run-governance.py"))
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class GovernanceDriverControls(unittest.TestCase):
    def events(self):
        events = []
        for name in sorted(DRIVER.REQUIRED_CONTROLS):
            events += [{"Action": "run", "Test": name}, {"Action": "pass", "Test": name}]
        return events + [{"Action": "pass", "Package": "relay-ci-governance"}]

    def validate(self, events):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text("".join(json.dumps(event) + "\n" for event in events))
            return DRIVER.validate_controls(path)

    def test_complete_controls_have_real_counts(self):
        self.assertEqual(self.validate(self.events()), {"top_level": 13, "outcomes": 13, "skipped": 0})

    def test_missing_skipped_failed_duplicate_or_nonterminal_is_refused(self):
        events = self.events()
        mutations = [events[2:], events[:-1], events + [events[0]],
                     events + [{"Action": "skip", "Test": "planted"}],
                     events + [{"Action": "fail", "Test": "planted"}],
                     events + [{"Action": "run", "Test": "unfinished"}],
                     events + [events[1]]]
        for mutated in mutations:
            with self.subTest(mutation=len(mutated)):
                with self.assertRaises(RuntimeError):
                    self.validate(mutated)

    def test_compiler_provenance_is_explicit_and_cannot_claim_native_go11(self):
        report = {"status": "passed", "selected_guard_count": 10,
                  "assertions": [{"name": str(index), "status": "passed"} for index in range(10)],
                  "native_controller_profile": DRIVER.NATIVE_PROFILE,
                  "native_go11_admitted": False, "public_go11_required": True}
        DRIVER.validate_helper_report(report)
        for key, value in (("native_controller_profile", "native11-or-auto"),
                           ("native_go11_admitted", True), ("native_go11_admitted", None),
                           ("public_go11_required", False), ("public_go11_required", None)):
            candidate = dict(report, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                DRIVER.validate_helper_report(candidate)
        for key in ("native_controller_profile", "native_go11_admitted", "public_go11_required"):
            candidate = dict(report)
            del candidate[key]
            with self.subTest(omitted=key), self.assertRaises(RuntimeError):
                DRIVER.validate_helper_report(candidate)

    def test_output_stays_outside_trusted_and_private_source(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = Path(directory) / "harness"
            harness.mkdir()
            for path in (harness, harness / "tooling/results", harness / "private-source/results"):
                with self.assertRaises(RuntimeError):
                    DRIVER.output_directory(str(path), harness)
            with self.assertRaises(RuntimeError):
                DRIVER.output_directory("relative-output", harness)
            target = Path(directory) / "private-results"
            self.assertEqual(DRIVER.output_directory(str(target), harness), target)
            alias = Path(directory) / "alias"
            alias.symlink_to(harness)
            with self.assertRaises(RuntimeError):
                DRIVER.output_directory(str(alias / "results"), harness)
