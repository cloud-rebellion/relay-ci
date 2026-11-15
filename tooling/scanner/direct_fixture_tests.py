"""Eight synthetic controls. No apt, executable, socket, Docker or provider calls."""
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile
import zlib

import direct_fixtures as fixture
from daemon_policy import MARKER
from registry import Refusal


class DirectFixtureControls(unittest.TestCase):
    def test_pdf_has_real_xref_objects_and_deflated_content(self):
        for payload in (b"Relay ordinary PDF utility", MARKER):
            raw = fixture.pdf_bytes(payload)
            self.assertTrue(raw.startswith(b"%PDF-1.5\n"))
            self.assertTrue(raw.endswith(b"%%EOF\n"))
            xref = int(re.search(rb"startxref\n([0-9]+)\n", raw)[1])
            self.assertEqual(raw[xref:xref+4], b"xref")
            rows = raw[xref:].splitlines()[3:8]
            self.assertEqual(len(rows), 5)
            for number, row in enumerate(rows, 1):
                self.assertTrue(raw[int(row[:10]):].startswith(str(number).encode()+b" 0 obj\n"))
            stream = raw.split(b"\nstream\n", 1)[1].split(b"\nendstream", 1)[0]
            self.assertIn(payload, zlib.decompress(stream))
            self.assertNotIn(payload, stream)
            if payload == MARKER:
                self.assertNotIn(MARKER, raw)
        with self.assertRaises(Refusal):
            fixture.pdf_bytes(b"x"*4097)

    def test_docx_is_complete_deflated_office_xml_with_compressed_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for index, payload in enumerate((b"Relay clean Office utility", MARKER)):
                path = root/(str(index)+".docx")
                fixture.docx(path, payload)
                self.assertNotIn(payload, path.read_bytes())
                with zipfile.ZipFile(path) as archive:
                    self.assertEqual(set(archive.namelist()), {"[Content_Types].xml", "_rels/.rels", "word/document.xml"})
                    self.assertIsNone(archive.testzip())
                    self.assertTrue(all(row.compress_type == zipfile.ZIP_DEFLATED for row in archive.infolist()))
                    for name in archive.namelist():
                        ET.fromstring(archive.read(name))
                    self.assertIn(payload, archive.read("word/document.xml"))
            with self.assertRaises(Refusal):
                fixture.docx(root/"unsafe.docx", b"<injected>")

    def test_actual_generated_limits_have_distinct_expansion_recursion_and_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); rows = {}
            def add(name, path, expected, **shape):
                rows[name] = {"path": path, "expected": expected, **shape}
            fixture.add_quota_cases(root, add)
            self.assertEqual(set(rows), {"individual-size", "expanded-size", "recursion", "file-count", "clean-csv-near-ceiling"})
            with zipfile.ZipFile(rows["individual-size"]["path"]) as archive:
                self.assertEqual(archive.infolist()[0].file_size, 25*fixture.MIB+1)
                self.assertEqual(len(archive.read("large.txt")), 25*fixture.MIB+1)
            with zipfile.ZipFile(rows["expanded-size"]["path"]) as archive:
                self.assertEqual(len(archive.infolist()), 5)
                self.assertEqual(sum(row.file_size for row in archive.infolist()), 105*fixture.MIB)
                self.assertEqual(max(row.file_size for row in archive.infolist()), 21*fixture.MIB)
                prefixes = set()
                for row in archive.infolist():
                    with archive.open(row) as stream:
                        prefixes.add(stream.read(128))
                self.assertEqual(len(prefixes), 5)
            nested = rows["recursion"]["path"].read_bytes()
            for depth in range(18):
                with zipfile.ZipFile(io.BytesIO(nested)) as archive:
                    self.assertEqual(len(archive.namelist()), 1)
                    nested = archive.read(archive.namelist()[0])
            self.assertEqual(nested, b"Relay clean nested content\n")
            with zipfile.ZipFile(rows["file-count"]["path"]) as archive:
                self.assertEqual(len(archive.namelist()), 10001)
                self.assertEqual(len(set(archive.namelist())), 10001)
                self.assertNotEqual(archive.read("file-00000.txt"), archive.read("file-10000.txt"))
            self.assertEqual(rows["clean-csv-near-ceiling"]["path"].stat().st_size, 24*fixture.MIB)
            self.assertLess(sum(p.stat().st_size for p in root.iterdir()), 64*fixture.MIB)
            self.assertTrue(all(row["path"].stat().st_size <= 25*fixture.MIB for row in rows.values()))

    def test_only_each_exact_named_alert_clears_its_category(self):
        self.assertEqual(len(fixture.CASE_NAMES), 11)
        self.assertEqual(set(fixture.ALERTS), {"encrypted-zip", "encrypted-pdf", "individual-size", "expanded-size", "recursion", "file-count"})
        for kind, alert in fixture.ALERTS.items():
            correct = ("stream: "+alert+" FOUND").encode()
            self.assertEqual(fixture.specific_alert(correct+b"\x00", kind)["alert"], alert)
            for bad in (b"stream: OK\x00", b"stream: ERROR\x00", b"stream: parser failed ERROR",
                        b"stream: scan timed out ERROR", b"stream: Different FOUND", correct+b"\nstream: OK",
                        correct[:-1], correct+b" garbage", b"x"*4097):
                with self.subTest(kind=kind, bad=bad), self.assertRaises(Refusal):
                    fixture.specific_alert(bad, kind)
        with self.assertRaises(Refusal):
            fixture.specific_alert(b"stream: ERROR", "time-or-queue")

    def test_scan_keeps_original_bytes_and_generic_errors_fail_the_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); path = root/"synthetic.zip"; path.write_bytes(b"synthetic control only")
            row = {"name": "individual-size", "path": str(path), "bytes": path.stat().st_size,
                   "sha256": fixture.sha(path.read_bytes()), "expected": "individual-size", "expanded_bytes": 25*fixture.MIB+1}
            sent = []
            def exchange(blocks):
                sent.extend(blocks)
                return b"stream: parser failed ERROR\x00"
            candidate = SimpleNamespace(exchange=exchange)
            with self.assertRaisesRegex(Refusal, "direct-specific-individual-size-not-proven"):
                fixture.scan_corpus(candidate, [row], root, "synthetic-failure")
            self.assertEqual(sent[0], b"zINSTREAM\x00")
            self.assertEqual(sent[-1], b"\x00"*4)
            self.assertEqual(b"".join(block[4:] for block in sent[1:-1]), path.read_bytes())
            report = json.loads((root/"direct-fixtures-synthetic-failure.json").read_text())
            self.assertEqual(report["cases"][0]["status"], "failed")
            self.assertFalse(report["full_scanner_qualified"])
            candidate.exchange = mock.Mock(return_value=b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\x00")
            passed = fixture.scan_corpus(candidate, [row], root, "synthetic-exact-alert")
            self.assertEqual(passed[0]["status"], "passed")
            path.write_bytes(b"changed")
            candidate.exchange.reset_mock()
            with self.assertRaisesRegex(Refusal, "synthetic-fixture-changed"):
                fixture.scan_corpus(candidate, [row], root, "changed")
            candidate.exchange.assert_not_called()

    def test_host_tools_need_private_metadata_and_exact_binary_before_and_after(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            identity = {"sha256": "a"*64, "uid": 0, "mode": 0o755}
            metadata = {"os": {"ID": "ubuntu", "VERSION_ID": "24.04"}, "installed_on_host_only": True,
                        "authenticated_ubuntu_apt_only": True, "cache_in_owned8GiB": True,
                        "release_selection_sha256": fixture.sha(fixture.APT_PREFERENCES.encode()),
                        "tools": {name: {"file": identity} for name in ("qpdf", "zip")}}
            path = root/"fixture-host-tools.json"; path.write_text(json.dumps(metadata)); path.chmod(0o600)
            tools = fixture.HostTools(root)
            with mock.patch.object(fixture, "fingerprint", return_value={"changed": True}), \
                    mock.patch.object(fixture.subprocess, "run") as run:
                with self.assertRaisesRegex(Refusal, "tool-changed"):
                    tools.run("qpdf", ["--check", "clean.pdf"], root)
                run.assert_not_called()
            with mock.patch.object(fixture, "fingerprint", side_effect=[identity, {"changed": True}]), \
                    mock.patch.object(fixture.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
                with self.assertRaisesRegex(Refusal, "generator-failed"):
                    tools.run("qpdf", ["--check", "clean.pdf"], root)
                self.assertEqual(run.call_args.args[0], ["/usr/bin/qpdf", "--check", "clean.pdf"])
                self.assertEqual(run.call_args.kwargs["timeout"], 45)
                self.assertEqual(run.call_args.kwargs["env"]["PATH"], "/usr/bin:/bin")
            path.chmod(0o644)
            with self.assertRaisesRegex(Refusal, "metadata-custody"):
                fixture.HostTools(root)

    def test_authenticated_apt_flags_and_cache_are_fixed_to_owned_private_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); work = root/"apt"; work.mkdir(mode=0o700)
            (work/"ubuntu-publisher.pref").write_text(fixture.APT_PREFERENCES)
            (work/"ubuntu-publisher.pref").chmod(0o600)
            (work/"preferences.d").mkdir(mode=0o700)
            options = fixture.authenticated_apt_options(work)
            values = options[1::2]
            for name in ("APT::Get::AllowUnauthenticated", "Acquire::AllowInsecureRepositories", "Acquire::AllowDowngradeToInsecureRepositories"):
                self.assertIn(name+"=false", values)
            self.assertIn("Acquire::Check-Valid-Until=true", values)
            paths = [value.split("=", 1)[1] for value in values if value.startswith("Dir::")]
            self.assertEqual(len(paths), 6)
            self.assertTrue(all(Path(path).parent == work for path in paths))
            (work/"ubuntu-publisher.pref").write_text(fixture.APT_PREFERENCES.replace("Ubuntu", "Other"))
            with self.assertRaisesRegex(Refusal, "host-apt-ubuntu-publisher-selection"):
                fixture.authenticated_apt_options(work)
            (work/"ubuntu-publisher.pref").write_text(fixture.APT_PREFERENCES)
            work.chmod(0o755)
            with self.assertRaisesRegex(Refusal, "host-apt-owned-work"):
                fixture.authenticated_apt_options(work)
            work.chmod(0o700); link = root/"alias"; link.symlink_to(work, target_is_directory=True)
            with self.assertRaisesRegex(Refusal, "host-apt-owned-work"):
                fixture.authenticated_apt_options(link)

            class Child:
                def __init__(self,pid,code=0,timeout=False,writer=True):
                    self.pid,self.code,self.timeout=pid,code,timeout
                    self.returncode=None;self.stdin=io.BytesIO() if writer else None
                def wait(self,timeout):
                    if self.timeout:
                        raise fixture.subprocess.TimeoutExpired("synthetic owned child",timeout)
                    self.returncode=self.code;return self.code
                def poll(self):return self.returncode
                def terminate(self):self.timeout=False;self.code=-15
                def kill(self):self.timeout=False;self.code=-9
            identity={"uid":0,"mode":0o755,"sha256":"a"*64}
            for index,outcome in enumerate(("passed","writer-limit","root-timeout")):
                results=root/("capture"+str(index));results.mkdir(mode=0o700)
                daemon=SimpleNamespace(fixture_processes=[])
                children=[Child(2001+index*3,code=1 if outcome=="writer-limit" else 0),
                          Child(2002+index*3),Child(2003+index*3,timeout=outcome=="root-timeout",writer=False)]
                with mock.patch.object(fixture,"fingerprint",return_value=identity), \
                        mock.patch.object(fixture.subprocess,"Popen",side_effect=children) as launch:
                    if outcome=="passed":
                        self.assertEqual(fixture.capture_apt_operation(daemon,results,"update",options,identity)["status"],"passed")
                    else:
                        with self.assertRaises((Refusal,fixture.subprocess.TimeoutExpired)):
                            fixture.capture_apt_operation(daemon,results,"update",options,identity)
                    self.assertEqual(launch.call_count,3)
                    writer_calls=launch.call_args_list[:2];apt_call=launch.call_args_list[2]
                    self.assertEqual(apt_call.args[0][:7],["sudo","-n","/usr/bin/timeout","--signal=TERM","--kill-after=10s","240s","apt-get"])
                    self.assertNotIn("preexec_fn",apt_call.kwargs)  # Apt downloads are not capped at1MiB.
                    for call in writer_calls:
                        with mock.patch.object(fixture.resource,"setrlimit") as limit:
                            call.kwargs["preexec_fn"]()
                        limit.assert_called_once_with(fixture.resource.RLIMIT_FSIZE,(fixture.MIB,fixture.MIB))
                    receipt=json.loads((results/"fixture-apt-update.json").read_text())
                    self.assertTrue(all(row["reaped"] for row in receipt["writers"]))
                    self.assertEqual(receipt["root_timeout_reaped"],outcome!="root-timeout")
                    if outcome=="root-timeout":
                        guarded=object.__new__(fixture.FixtureDaemon)
                        guarded.results=results;guarded.fixture_processes=daemon.fixture_processes
                        with mock.patch.object(fixture.BoundedDaemon,"__exit__") as cleanup:
                            self.assertFalse(guarded.__exit__(RuntimeError,RuntimeError("synthetic primary"),None))
                            cleanup.assert_not_called()
                    with self.assertRaisesRegex(Refusal,"already-attempted-no-retry"):
                        fixture.capture_apt_operation(daemon,results,"update",options,identity)

            guarded=object.__new__(fixture.FixtureDaemon)
            guarded.results=root;guarded.fixture_processes=[]
            with mock.patch.object(Path,"write_text",side_effect=OSError("synthetic receipt refusal")), \
                    mock.patch.object(fixture.BoundedDaemon,"__exit__") as cleanup:
                self.assertFalse(guarded.__exit__(RuntimeError,RuntimeError("original primary"),None))
                cleanup.assert_not_called()
                with self.assertRaises(OSError):
                    guarded.__exit__(None,None,None)
                cleanup.assert_not_called()

    def test_fixture_archive_names_types_sizes_and_duplicates_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            invalid = [("../outside", b"x"), ("/absolute", b"x"), ("bad\nname", b"x"),
                       ("oversize", 26*fixture.MIB+1), ("notbytes", True), ("toolarge", b"x"*(fixture.MIB+1))]
            for index, entry in enumerate(invalid):
                with self.subTest(entry=entry[0]), self.assertRaises(Refusal):
                    fixture.write_zip(root/(str(index)+".zip"), [entry])
            with self.assertRaises(Refusal):
                fixture.write_zip(root/"duplicate.zip", [("same.txt", b"first"), ("same.txt", b"second")])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DirectFixtureControls)
    if suite.countTestCases() != fixture.CONTROL_COUNT:
        raise RuntimeError("Closed direct-fixture controls changed")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    value = {"schema": 1, "tests": result.testsRun, "failures": len(result.failures),
             "errors": len(result.errors), "skips": len(result.skipped),
             "status": "passed" if result.wasSuccessful() and not result.skipped else "failed"}
    output = os.environ.get("RELAY_SCANNER_PHASE1_RESULTS_DIR")
    if output:
        (Path(output)/"direct-fixtures-controls-summary.json").write_text(json.dumps(value, sort_keys=True)+"\n")
    sys.exit(0 if value["status"] == "passed" else 1)
