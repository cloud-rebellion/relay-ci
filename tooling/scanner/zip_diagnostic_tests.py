"""Three offline controls; generated archives only, no daemon/process/network."""
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest

import zip_diagnostics as diagnostic
from registry import Refusal


class ZipDiagnosticControls(unittest.TestCase):
    def test_six_real_zip_headers_decoded_hashes_and_marker_offsets_are_proven(self):
        with tempfile.TemporaryDirectory() as temporary:
            rows=diagnostic.build_matrix(Path(temporary).resolve()/"matrix")
            self.assertEqual({row["name"] for row in rows},{row[0] for row in diagnostic.SPECS})
            for row in rows:
                self.assertEqual(row["decoded"]["bytes"],row["member_bytes"])
                self.assertEqual(row["decoded"]["marker_offsets"],[row["marker_offset"]])
                self.assertEqual(row["decoded"]["sha256"],row["generated_payload_sha256"])
                self.assertFalse(row["headers"]["compressed_literal_marker_present"])
                self.assertFalse(row["accepted"]);self.assertFalse(row["qualification_credit"])
                if row["format_bits"]==64:
                    self.assertEqual(row["headers"]["local_uncompressed_size_field"],0xffffffff)
                    self.assertEqual(row["headers"]["local_compressed_size_field"],0xffffffff)
                    self.assertEqual(row["headers"]["ZIP64_extra_uncompressed_size"],row["member_bytes"])
                else:
                    self.assertEqual(row["headers"]["local_uncompressed_size_field"],row["member_bytes"])
                if "after" in row["name"]:self.assertGreater(row["marker_offset"],diagnostic.LIMIT)
                else:self.assertLess(row["marker_offset"],diagnostic.LIMIT)

    def test_header_sentinel_size_flag_CRC_and_payload_mutations_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            rows=diagnostic.build_matrix(Path(temporary).resolve()/"matrix")
            for row in rows[:2]:
                raw=Path(row["path"]).read_bytes()
                variants=[]
                for offset,value in ((6,1),(14,0),(18,1),(22,1)):
                    body=bytearray(raw)
                    if offset==6:struct.pack_into("<H",body,offset,value)
                    else:struct.pack_into("<L",body,offset,
                        struct.unpack_from("<L",raw,offset)[0]^1 if offset==14 else value)
                    variants.append(bytes(body))
                for body in variants:
                    with self.subTest(bits=row["format_bits"]),self.assertRaises(Refusal):
                        diagnostic.headers(body,row["format_bits"],row["member_bytes"])
                with self.assertRaises(Refusal):
                    diagnostic.decoded(Path(row["path"]),row["member_bytes"],row["marker_offset"]+1,row["decoded"]["sha256"])
                with self.assertRaises(Refusal):
                    diagnostic.headers(raw,row["format_bits"]+1,row["member_bytes"])
            with self.assertRaises(Refusal):list(diagnostic.payload_blocks(27*diagnostic.MIB,0))

    def test_every_response_and_transport_error_stays_nonqualifying(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();rows=diagnostic.build_matrix(root/"matrix")
            results=root/"results";results.mkdir(mode=0o700)
            replies=iter([b"stream: OK\x00",b"stream: Relay.CI.Controlled.UNOFFICIAL FOUND\x00",
                          b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\x00",b"stream: parser ERROR\x00",
                          OSError("synthetic transport refusal"),b"x"*4097])
            def exchange(blocks):
                body=list(blocks);self.assertEqual(body[0],b"zINSTREAM\x00");self.assertEqual(body[-1],b"\x00"*4)
                reply=next(replies)
                if isinstance(reply,Exception):raise reply
                return reply
            observed=diagnostic.observe_matrix(SimpleNamespace(exchange=exchange,cid="c"*64),rows,results)
            self.assertEqual(len(observed),6)
            report=json.loads((results/"zip-limit-diagnostics-before-strict-corpus.json").read_text())
            self.assertTrue(report["before_original_strict_corpus"])
            for field in ("qualification_credit","accepted","full_scanner_qualified","application_acceptance","deployment_authorized"):
                self.assertFalse(report[field])
            self.assertTrue(all(row["qualification_credit"] is False and row["accepted"] is False for row in observed))
            self.assertEqual(observed[0]["observation"],"clean-observed-not-accepted")
            self.assertEqual(observed[1]["observation"],"controlled-observed-not-accepted")
            self.assertEqual(observed[2]["observation"],"limit-alert-observed-not-accepted")
            self.assertEqual(observed[4]["observation"],"transport-or-response-error-no-credit")
            with self.assertRaisesRegex(Refusal,"once-exact-matrix"):
                diagnostic.observe_matrix(SimpleNamespace(exchange=exchange,cid="c"*64),rows,results)
            other=root/"no-credit";other.mkdir(mode=0o700)
            with self.assertRaisesRegex(Refusal,"once-exact-matrix"):
                diagnostic.observe_matrix(SimpleNamespace(exchange=exchange,cid="c"*64),
                    [{**row,"accepted":True} for row in rows],other)


if __name__=="__main__":
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(ZipDiagnosticControls)
    if suite.countTestCases()!=diagnostic.CONTROL_COUNT:raise RuntimeError("Closed ZIP diagnostic controls changed")
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    value={"schema":1,"tests":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),
           "skips":len(result.skipped),"status":"passed" if result.wasSuccessful() and not result.skipped else "failed"}
    root=os.environ.get("RELAY_SCANNER_PHASE1_RESULTS_DIR")
    if root:(Path(root)/"zip-diagnostics-controls-summary.json").write_text(json.dumps(value,sort_keys=True)+"\n")
    raise SystemExit(0 if value["status"]=="passed" else 1)
