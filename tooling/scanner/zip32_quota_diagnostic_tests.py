"""Three offline ordinary-ZIP32 observation controls; no daemon or network."""
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest

from daemon_policy import stream_chunks
from registry import Refusal
import zip32_quota_diagnostics as diagnostic


class Zip32QuotaObservationControls(unittest.TestCase):
    def test_five_actual_input_shapes_have_real_ZIP32_headers_and_decoded_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            rows = diagnostic.build_quota_matrix(Path(temporary).resolve() / "inputs")
            self.assertEqual(tuple(row["name"] for row in rows), diagnostic.NAMES)
            for row in rows:
                self.assertEqual(diagnostic.identity(row["path"]), row["input"])
                self.assertFalse(row["accepted"])
                self.assertFalse(row["qualification_credit"])
            for row in rows[:4]:
                self.assertEqual(row["proof"]["format_bits"], 32)
                self.assertTrue(row["proof"]["all_members_decoded_hashes_match"])
                self.assertTrue(row["proof"]["all_sizes_real_ZIP32"])
                self.assertFalse(row["proof"]["ZIP64_extra_or_sentinel"])
                self.assertFalse(row["proof"]["data_descriptor"])
                self.assertFalse(row["proof"]["compressed_literal_marker_present"])
            self.assertEqual(rows[0]["proof"]["largest_member_bytes"], 25 * diagnostic.MIB + 1)
            self.assertEqual(rows[1]["proof"]["member_count"], 5)
            self.assertEqual(rows[1]["proof"]["expanded_bytes"], 105 * diagnostic.MIB)
            self.assertEqual(rows[1]["proof"]["largest_member_bytes"], 21 * diagnostic.MIB)
            self.assertEqual(rows[2]["nesting"], 18)
            self.assertEqual(len(rows[2]["nested_layer_proofs"]), 18)
            self.assertTrue(all(row["member_count"] == 1 and row["all_sizes_real_ZIP32"]
                                for row in rows[2]["nested_layer_proofs"]))
            self.assertEqual(rows[3]["proof"]["member_count"], 10001)
            self.assertEqual(len(rows[3]["proof"]["header_samples"]), 3)
            self.assertEqual(rows[4]["input"]["bytes"], 24 * diagnostic.MIB)
            self.assertEqual(rows[4]["input"]["sha256"], rows[4]["proof"]["generated_sha256"])
            self.assertLessEqual(sum(path.stat().st_size for path in Path(rows[0]["path"]).parent.iterdir()),
                                 48 * diagnostic.MIB)

    def test_header_sentinels_descriptors_counts_and_decoded_hash_mismatch_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / "tiny.zip"
            value = b"Relay harmless tiny member\n"
            proof = diagnostic.write_zip32(path, [("small.txt", value)])
            expected = [("small.txt", len(value), hashlib.sha256(value).hexdigest())]
            raw = path.read_bytes()
            central = struct.unpack_from("<L", raw, len(raw) - 6)[0]
            for label, offset, packing, value in (
                ("local-sentinel", 18, "<L", 0xffffffff),
                ("central-sentinel", central + 24, "<L", 0xffffffff),
                ("descriptor-flag", 6, "<H", 8),
                ("central-offset", central + 42, "<L", 1),
                ("EOCD-count", len(raw) - 12, "<H", 2),
                ("extra-region", 28, "<H", 1),
            ):
                with self.subTest(label=label):
                    changed = bytearray(raw)
                    struct.pack_into(packing, changed, offset, value)
                    other = root / (label + ".zip")
                    other.write_bytes(changed)
                    with self.assertRaises(Refusal):
                        diagnostic.prove_zip32(other, expected)
            with self.assertRaisesRegex(Refusal, "decoded-size-and-generated-hash"):
                diagnostic.prove_zip32(path, [("small.txt", expected[0][1], "0" * 64)])
            self.assertEqual(proof["member_count"], 1)
            for name in ("../escape", "duplicate/name", "bad\nname"):
                with self.subTest(name=name), self.assertRaises(Refusal):
                    diagnostic.write_zip32(root / (str(len(name)) + "-invalid.zip"), [(name, b"x")])
            with self.assertRaises(Refusal):
                list(diagnostic.seed_blocks("safe.txt", 27 * diagnostic.MIB))

    def test_responses_errors_stream_custody_and_replay_never_gain_credit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            rows = []
            for index, name in enumerate(diagnostic.NAMES):
                path = root / (name + ".txt")
                path.write_bytes(("synthetic-control-%d\n" % index).encode())
                rows.append({"name": name, "path": str(path), "input": diagnostic.identity(path),
                    "synthetic_control_only": True, "accepted": False, "qualification_credit": False})
                self.assertEqual(list(diagnostic.file_stream(path, rows[-1]["input"])),
                                 list(stream_chunks(path.read_bytes())))
            results = root / "results"
            results.mkdir(mode=0o700)
            replies = iter([b"stream: OK\x00", b"stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\x00",
                b"stream: unrelated ERROR\x00", OSError("synthetic transport failure"), b"x" * 4097])

            def exchange(blocks):
                frames = list(blocks)
                self.assertEqual(frames[0], b"zINSTREAM\x00")
                self.assertEqual(frames[-1], b"\x00" * 4)
                reply = next(replies)
                if isinstance(reply, Exception):
                    raise reply
                return reply

            candidate = SimpleNamespace(cid="c" * 64, exchange=exchange)
            observed = diagnostic.observe_quota_matrix(candidate, rows, results)
            self.assertEqual(len(observed), 5)
            report = json.loads((results / "zip32-quota-observations-before-strict-corpus.json").read_text())
            self.assertTrue(report["before_original_strict_corpus"])
            for field in ("qualification_credit", "accepted", "full_scanner_qualified",
                          "application_acceptance", "deployment_authorized"):
                self.assertFalse(report[field])
            self.assertTrue(all(row["accepted"] is False and row["qualification_credit"] is False for row in observed))
            self.assertEqual(observed[0]["observation"], "clean-observed-not-accepted")
            self.assertEqual(observed[1]["observation"], "limit-alert-observed-not-accepted")
            self.assertEqual(observed[2]["observation"], "other-response-observed-not-accepted")
            self.assertEqual(observed[3]["observation"], "transport-or-response-error-no-credit")
            self.assertEqual(observed[4]["observation"], "transport-or-response-error-no-credit")
            with self.assertRaisesRegex(Refusal, "once-exact"):
                diagnostic.observe_quota_matrix(candidate, rows, results)
            other = root / "other"
            other.mkdir(mode=0o700)
            with self.assertRaisesRegex(Refusal, "once-exact"):
                diagnostic.observe_quota_matrix(candidate, [{**row, "accepted": True} for row in rows], other)
            path = Path(rows[0]["path"])
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(Refusal, "changed-before-send"):
                list(diagnostic.file_stream(path, rows[0]["input"]))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Zip32QuotaObservationControls)
    if suite.countTestCases() != diagnostic.CONTROL_COUNT:
        raise RuntimeError("Closed ordinary ZIP32 diagnostic controls changed")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    value = {"schema": 1, "tests": result.testsRun, "failures": len(result.failures),
             "errors": len(result.errors), "skips": len(result.skipped),
             "status": "passed" if result.wasSuccessful() and not result.skipped else "failed"}
    root = os.environ.get("RELAY_SCANNER_PHASE1_RESULTS_DIR")
    if root:
        (Path(root) / "zip32-quota-diagnostics-controls-summary.json").write_text(json.dumps(value, sort_keys=True) + "\n")
    raise SystemExit(0 if value["status"] == "passed" else 1)
