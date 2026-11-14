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
        self.assertEqual(self.validate(self.events()), {"top_level": 10, "outcomes": 10, "skipped": 0})

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
