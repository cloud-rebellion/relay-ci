"""False-green regression tests for the structured CI result validators."""
import copy
import importlib.util
from pathlib import Path
import unittest


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


browser = load("validate-browser-results")
go = load("validate-go-results")


class BrowserResults(unittest.TestCase):
    def setUp(self):
        self.manifest = {"expectedTests": 1, "cases": [{"file": "invite.spec.ts", "title": "accept"}]}
        self.report = {"config": {"projects": [{"timeout": 30000, "retries": 0}]},
                       "suites": [{"specs": [{"file": "invite.spec.ts", "title": "accept", "tests": [
                           {"expectedStatus": "passed", "results": [{"status": "passed", "retry": 0}]}]}]}],
                       "stats": {"expected": 1, "skipped": 0, "unexpected": 0, "flaky": 0}}

    def test_complete_original_outcome_passes(self):
        self.assertEqual(browser.validate(self.report, self.manifest, 0), 1)

    def test_zero_missing_duplicate_and_substituted_cases_fail(self):
        for mode in ["zero", "missing", "duplicate", "substitute"]:
            with self.subTest(mode=mode):
                report = copy.deepcopy(self.report)
                if mode in ["zero", "missing"]:
                    report["suites"] = []
                elif mode == "duplicate":
                    report["suites"] *= 2
                else:
                    report["suites"][0]["specs"][0]["title"] = "another test"
                with self.assertRaises(ValueError):
                    browser.validate(report, self.manifest, 0)

    def test_skip_retry_expected_failure_and_changed_timeout_fail(self):
        for mode in ["skip", "retry", "expected-failure", "timeout", "flaky"]:
            with self.subTest(mode=mode):
                report = copy.deepcopy(self.report)
                test = report["suites"][0]["specs"][0]["tests"][0]
                if mode == "skip": test["results"][0]["status"] = "skipped"
                if mode == "retry": test["results"][0]["retry"] = 1
                if mode == "expected-failure": test["expectedStatus"] = "failed"
                if mode == "timeout": report["config"]["projects"][0]["timeout"] = 60000
                if mode == "flaky": report["stats"]["flaky"] = 1
                with self.assertRaises(ValueError):
                    browser.validate(report, self.manifest, 0)

    def test_failed_process_cannot_be_rescued_by_passing_json(self):
        with self.assertRaises(ValueError): browser.validate(self.report, self.manifest, 1)


class GoResults(unittest.TestCase):
    def events(self):
        return [{"Package": "relay/internal/handler", "Action": "pass", "Test": name}
                for name in go.INVITATION_REQUIREMENTS] + [
                    {"Package": "relay/internal/handler", "Action": "pass"}]

    def test_real_invitation_names_are_required(self):
        self.assertEqual(go.validate(self.events(), 0, go.INVITATION_REQUIREMENTS), 5)
        with self.assertRaises(ValueError):
            go.validate(self.events()[1:], 0, go.INVITATION_REQUIREMENTS)

    def test_skipped_subtest_duplicate_and_failed_process_fail(self):
        events = self.events()
        events[0]["Action"] = "skip"
        with self.assertRaises(ValueError): go.validate(events, 0)
        with self.assertRaises(ValueError): go.validate(self.events() + self.events()[:1], 0)
        with self.assertRaises(ValueError): go.validate(self.events(), 1)

    def test_empty_output_or_zero_test_success_fails(self):
        with self.assertRaises(ValueError): go.validate([], 0)
        with self.assertRaises(ValueError): go.validate([{"Package": "relay", "Action": "pass"}], 0)

    def test_no_test_file_package_requires_explicit_inventory_admission(self):
        events = [{"Package": "relay/constants", "Action": "skip"}]
        with self.assertRaises(ValueError): go.validate(events, 0)
        self.assertEqual(go.validate(events, 0, allow_no_tests=True), 0)


if __name__ == "__main__":
    unittest.main()
