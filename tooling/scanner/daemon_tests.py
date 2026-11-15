"""Synthetic controls only: no socket, registry, Docker, provider or host calls."""
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import daemon_policy as policy
import storage
from daemon_runtime import PrivateEgress, Candidate, OwnedTrace, owned_inventory, rule_identity
from registry import Refusal

NOW = dt.datetime(2026, 11, 15, 15, tzinfo=dt.timezone.utc)


def configuration(extra=""):
    return ("\n".join(k + " " + v for k, v in policy.SETTINGS.items()) + "\n" + extra).encode()


def parsed():
    return ("Checking configuration files in /etc/clamav\nConfig file: clamd.conf\n" +
            "\n".join(k + ' = "' + v + '"' for k, v in policy.SETTINGS.items()) +
            "\nConfig file: freshclam.conf\nChecks = 4\n").encode()


def trace(pid=123):
    return (str(pid) + ' execve("/usr/local/sbin/clamd", ["clamd", "--foreground"], 0x1 /* 24 vars */) = 0\n' +
            str(pid) + ' openat(AT_FDCWD, "/etc/clamav/clamd.conf", O_RDONLY) = 4\n').encode()


def resources():
    return {"memory.max": str(policy.MEMORY), "memory.swap.max": "0", "memory.peak": "2400000000",
            "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
            "cpu.max": "200000 100000", "cpu.stat": "usage_usec 123\n", "pids.max": "256", "pids.current": "8"}


class DaemonControls(unittest.TestCase):
    def test_policy_is_finite_22_existing_values(self):
        self.assertEqual(len(policy.SETTINGS), 22)
        self.assertEqual(policy.SETTINGS["StreamMaxLength"], "25M")
        self.assertEqual(policy.SETTINGS["MaxScanSize"], "100M")
        self.assertEqual(policy.SETTINGS["MaxThreads"], "2")
        self.assertEqual(policy.SETTINGS["MaxQueue"], "8")
        self.assertEqual(policy.MEMORY, 4 << 30)
        self.assertTrue(policy.REFERENCE.endswith("b2c2f5c9a557dc1c1249e09448a84c59c3e414bb3bbbac0a9d065236c779842c"))

    def test_all_values_need_actual_parser_section(self):
        proof = policy.config_witness(configuration(), parsed())
        self.assertEqual(len(proof["loaded_settings"]), 22)
        self.assertFalse(proof["identical_duplicates"])

    def test_conflicting_duplicate_refused(self):
        with self.assertRaisesRegex(Refusal, "conflicting"):
            policy.config_witness(configuration("MaxThreads 4\n"), parsed())

    def test_missing_directive_refused_even_if_parser_has_default(self):
        raw = configuration().replace(b"ScanPDF yes\n", b"")
        with self.assertRaisesRegex(Refusal, "missing"):
            policy.config_witness(raw, parsed())

    def test_include_and_exclusions_refuse_without_guessing(self):
        for extra in ("Include /elsewhere\n", "ExcludePath .*\n", "ExcludePUA Packed\n"):
            with self.subTest(extra=extra), self.assertRaisesRegex(Refusal, "include-or-exclusion"):
                policy.config_witness(configuration(extra), parsed())

    def test_identical_duplicates_still_need_exact_parser_values(self):
        self.assertTrue(policy.config_witness(configuration("MaxThreads 2\n"), parsed())["identical_duplicates"])
        with self.assertRaises(Refusal):
            policy.config_witness(configuration("MaxThreads 2\n"), parsed().replace(b'MaxThreads = "2"', b'MaxThreads = "4"'))

    def test_wrong_omitted_or_duplicate_parser_value_refused(self):
        for value in (parsed().replace(b'ScanPDF = "yes"\n', b""),
                      parsed().replace(b'ScanPDF = "yes"', b'ScanPDF = "no"'),
                      parsed().replace(b'ScanPDF = "yes"', b'ScanPDF = "yes"\nScanPDF = "yes"')):
            with self.subTest(value=value), self.assertRaises(Refusal):
                policy.config_witness(configuration(), value)

    def test_other_config_file_cannot_clear_policy(self):
        with self.assertRaisesRegex(Refusal, "exact-config-section"):
            policy.config_witness(configuration(), parsed().replace(b"Config file: clamd.conf", b"Config file: other.conf"))

    def test_actual_pid_exec_and_successful_config_open(self):
        self.assertTrue(policy.trace_witness(trace(), 123)["successful_read_open"])

    def test_foreign_pid_or_failed_open_cannot_clear_witness(self):
        for raw, pid in ((trace(124), 123), (trace().replace(b"= 4", b"= -1 ENOENT (No such file)"), 123),
                         (trace().replace(b"/etc/clamav/clamd.conf", b"/tmp/other.conf"), 123)):
            with self.subTest(raw=raw), self.assertRaises(Refusal):
                policy.trace_witness(raw, pid)

    def test_daemon_writing_loaded_config_refused(self):
        with self.assertRaisesRegex(Refusal, "for-write"):
            policy.trace_witness(trace() + b'123 openat(AT_FDCWD, "/etc/clamav/clamd.conf", O_RDWR) = 5\n', 123)

    def test_fresh_loaded_signature_date(self):
        self.assertEqual(policy.fresh_version(b"ClamAV 1.5.4/28258/Sun Nov 15 14:00:00 2026\x00", NOW)["age_seconds"], 3600)

    def test_stale_future_or_wrong_engine_refuses(self):
        for value in (b"ClamAV 1.5.4/28258/Fri Nov 13 14:00:00 2026", b"ClamAV 1.5.4/28258/Sun Nov 15 16:00:00 2026",
                      b"ClamAV 1.5.3/28258/Sun Nov 15 14:00:00 2026", b"ClamAV 1.5.4"):
            with self.subTest(value=value), self.assertRaises((Refusal, ValueError)):
                policy.fresh_version(value, NOW)

    def test_clean_is_exact_complete_response(self):
        policy.verdict(b"stream: OK\x00", "clean")
        for value in (b"stream: OK\nstream: ERROR", b"stream: partial OK", b"", b"stream: FOUND"):
            with self.subTest(value=value), self.assertRaises(Refusal):
                policy.verdict(value, "clean")

    def test_controlled_signature_never_accepts_eicar_or_clean(self):
        policy.verdict(b"stream: Relay.CI.Controlled.UNOFFICIAL FOUND\x00", "controlled")
        for value in (b"stream: Eicar-Test-Signature FOUND", b"stream: OK", b"stream: Unknown FOUND"):
            with self.subTest(value=value), self.assertRaises(Refusal):
                policy.verdict(value, "controlled")

    def test_limit_refusal_never_accepts_partial_clean(self):
        policy.verdict(b"INSTREAM size limit exceeded. ERROR\x00", "refuse")
        with self.assertRaises(Refusal):
            policy.verdict(b"stream: OK\x00", "refuse")

    def test_stream_framing_has_exact_chunks_and_final_zero(self):
        data = b"x" * 65537
        blocks = list(policy.stream_chunks(data))
        self.assertEqual(blocks[0], b"zINSTREAM\x00")
        self.assertEqual(blocks[-1], b"\x00" * 4)
        self.assertEqual(struct.unpack("!I", blocks[1][:4])[0], 65536)
        self.assertEqual(struct.unpack("!I", blocks[2][:4])[0], 1)
        self.assertEqual(b"".join(x[4:] for x in blocks[1:-1]), data)

    def test_actual_cgroup_limits_and_oom_are_mandatory(self):
        self.assertEqual(policy.resource_witness(resources())["hard_memory_bytes"], 4 << 30)
        for key, value in (("memory.max", "max"), ("memory.swap.max", "1"), ("pids.max", "max"),
                           ("cpu.max", "max 100000"), ("memory.events", "oom 1\noom_kill 0"),
                           ("memory.events", "oom 0\noom_kill 1")):
            with self.subTest(key=key), self.assertRaises(Refusal):
                policy.resource_witness({**resources(), key: value})

    def test_scoped_rule_intent_precedes_mutation_and_never_flushes(self):
        daemon = SimpleNamespace(owner="a" * 32)
        network = PrivateEgress(daemon)
        def command(args):
            self.assertEqual(len(network.rules), 1)
            self.assertNotIn("-F", args)
            self.assertNotIn("-P", args)
            self.assertIn(network.name, args)
            raise Refusal("synthetic-unknown")
        daemon.command = command
        with self.assertRaisesRegex(Refusal, "synthetic-unknown"):
            network.rule("filter", "FORWARD", ["-i", network.bridge, "-j", "DROP"])
        self.assertEqual(len(network.rules), 1)
        first = ["-A", "FORWARD", "-i", "owned", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]
        other = ["-A", "FORWARD", "-i", "owned", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]
        self.assertEqual(rule_identity(first), rule_identity(other))
        with self.assertRaisesRegex(Refusal, "unknown-option"):
            rule_identity(first + ["--unreviewed", "yes"])

    def test_ambiguous_rule_inventory_preserves_network(self):
        daemon = SimpleNamespace(owner="a" * 32, command=mock.Mock(return_value=SimpleNamespace(returncode=4)), docker=mock.Mock())
        network = PrivateEgress(daemon)
        network.rules = [["-t", "filter", "FORWARD", "-i", network.bridge, "-j", "DROP"]]
        with self.assertRaisesRegex(Refusal, "inventory-unknown"):
            network.__exit__(None, None, None)
        daemon.docker.assert_not_called()
        self.assertEqual(daemon.command.call_count, 1)

    def test_populated_network_cleanup_preserves_rules_and_network(self):
        daemon = SimpleNamespace(owner="a" * 32, command=mock.Mock(), docker=mock.Mock())
        network = PrivateEgress(daemon)
        network.network_attempted = True
        network.verify = mock.Mock(return_value={"Containers": {"foreign": {}}})
        with self.assertRaisesRegex(Refusal, "populated"):
            network.__exit__(None, None, None)
        daemon.command.assert_not_called()
        daemon.docker.assert_not_called()

    def test_candidate_create_does_not_override_inherited_startup_or_publish(self):
        daemon = SimpleNamespace(owner="a" * 32, docker=mock.Mock(return_value=SimpleNamespace(stdout=("b" * 64 + "\n").encode())))
        candidate = Candidate(daemon, SimpleNamespace(name="owned-network"), {})
        candidate.create()
        args = daemon.docker.call_args.args[0]
        self.assertEqual(args[-1], policy.REFERENCE)
        self.assertNotIn("--entrypoint", args)
        self.assertNotIn("--user", args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--publish", args)
        self.assertIn("--memory=4g", args)
        self.assertIn("--memory-swap=4g", args)
        self.assertIn("--security-opt=no-new-privileges:true", args)
        self.assertEqual(sum(x.startswith("CLAMD_CONF_") for x in args), 22)

    def trace_fixture(self, root):
        daemon = SimpleNamespace(unit="relay-scanner-" + "a" * 32, mount=root, results=root,
            command=mock.Mock(return_value=SimpleNamespace(stdout=trace(), returncode=0)))
        owned = OwnedTrace(daemon)
        owned.attempted = True
        active = {"LoadState": "loaded", "ActiveState": "active", "MainPID": "222", "ControlPID": "0",
                  "ExecStart": "strace -o " + str(owned.path),
                  "ControlGroup": "/system.slice/" + owned.unit + ".service", "InvocationID": "b" * 32}
        owned.prior = {key: active[key] for key in ("MainPID", "ExecStart", "ControlGroup", "InvocationID")}
        owned.prior["start_ticks"] = "111"
        def probe(mode, *arguments):
            if mode == "settled":
                return {"status": "absent", "pid": 222}
            self.assertEqual(mode, "identity")
            return {"status": "present", "pid": 222, "start_ticks": "111", "exe": "/usr/bin/strace",
                    "cmdline": ["strace", "-o", str(owned.path)]}
        owned.probe = mock.Mock(side_effect=probe)
        return owned, active

    def test_foreign_active_trace_is_preserved_without_stop(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned, active = self.trace_fixture(Path(temporary))
            for field, value in (("MainPID", "333"), ("InvocationID", "c" * 32),
                                 ("ControlGroup", "/system.slice/foreign.service"), ("ExecStart", "strace /foreign")):
                with self.subTest(field=field):
                    owned._raw_state = mock.Mock(return_value={**active, field: value})
                    with self.assertRaises(Refusal):
                        owned._settle()
                    owned.d.command.assert_not_called()
                    owned.probe.assert_not_called()

    def test_trace_stopped_or_unloaded_uses_prior_identity_and_process_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            for load in ("loaded", "not-found"):
                with self.subTest(load=load):
                    owned, active = self.trace_fixture(Path(temporary))
                    retired = {**active, "LoadState": load, "ActiveState": "inactive", "MainPID": "0",
                               "ControlPID": "0", "ExecStart": "", "ControlGroup": "", "InvocationID": ""}
                    owned._raw_state = mock.Mock(side_effect=[active, retired])
                    value = owned._settle()
                    self.assertTrue(value["settled"])
                    self.assertEqual(value["prior_process"], "absent")
                    self.assertFalse(value["final_trace_changes_witness_verdict"])
                    self.assertEqual(sum("stop" in call.args[0] for call in owned.d.command.call_args_list), 1)
                    self.assertEqual((Path(temporary) / "actual-clamd-config-trace-poststop.stdout").read_bytes(), trace())

    def test_trace_reused_pid_proves_only_prior_process_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned, active = self.trace_fixture(Path(temporary))
            retired = {**active, "ActiveState": "inactive", "MainPID": "0"}
            owned._raw_state = mock.Mock(return_value=retired)
            owned.probe = mock.Mock(return_value={"pid": 222, "status": "present", "start_ticks": "112"})
            self.assertEqual(owned._settle()["prior_process"], "pid-reused-prior-process-absent")
            owned.probe.assert_called_once_with("settled", "222")
            self.assertFalse(any("stop" in call.args[0] for call in owned.d.command.call_args_list))
            for value in ({"pid": 222, "status": "present", "start_ticks": "111"},
                          {"pid": 222, "status": "unknown"}, {"pid": 333, "status": "absent"}):
                with self.subTest(value=value), self.assertRaises(Refusal):
                    owned.probe.return_value = value
                    owned._settle()

    def test_ambiguous_trace_stop_is_not_repeated_or_reported_settled(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned, active = self.trace_fixture(Path(temporary))
            owned._raw_state = mock.Mock(return_value=active)
            owned.d.command.side_effect = Refusal("synthetic-stop-response-unknown")
            with self.assertRaisesRegex(Refusal, "not-settled"):
                owned._settle()
            with self.assertRaisesRegex(Refusal, "already-attempted"):
                owned._settle()
            self.assertEqual(owned.d.command.call_count, 1)
            self.assertTrue(owned.stop_attempted)

    def test_trace_cleanup_error_does_not_mask_primary_witness_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned, _ = self.trace_fixture(Path(temporary))
            owned._settle = mock.Mock(side_effect=Refusal("synthetic-cleanup-unknown"))
            primary = Refusal("actual-clamd-exec-not-witnessed")
            with mock.patch.object(OwnedTrace, "__enter__", return_value=owned):
                with self.assertRaises(Refusal) as raised:
                    with owned:
                        raise primary
            self.assertIs(raised.exception, primary)
            receipt = json.loads((Path(temporary) / "owned-trace-cleanup.json").read_bytes())
            self.assertFalse(receipt["settled"])
            self.assertEqual(receipt["primary_error"], "actual-clamd-exec-not-witnessed")
            self.assertEqual(receipt["cleanup_error"], "synthetic-cleanup-unknown")

    def test_trace_cleanup_without_primary_refuses_instead_of_passing(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned, _ = self.trace_fixture(Path(temporary))
            owned._settle = mock.Mock(side_effect=Refusal("synthetic-cleanup-unknown"))
            with self.assertRaisesRegex(Refusal, "cleanup-unknown"):
                owned.__exit__(None, None, None)
            receipt = json.loads((Path(temporary) / "owned-trace-cleanup.json").read_bytes())
            self.assertIsNone(receipt["primary_error"])
            self.assertFalse(receipt["settled"])

    def test_recursive_inventory_is_owned_bounded_and_nonduplicated(self):
        group = "/system.slice/relay-scanner-" + "a" * 32 + ".service"
        def row(pid, directory):
            return {"status": "present", "pid": pid, "start_ticks": "111", "cgroup": directory,
                    "threads": [{"tid": pid, "tracer_pid": 222}]}
        value = {"cgroup": group, "directories": [group, group + "/child", group + "/child/grandchild"],
                 "processes": [row(10, group), row(20, group + "/child/grandchild")]}
        self.assertEqual(owned_inventory(value, group, 10)[0], [10, 20])
        bad = []
        for path in ("/system.slice/foreign.service", group + "/../foreign"):
            item = copy.deepcopy(value); item["directories"].append(path); bad.append(item)
        item = copy.deepcopy(value); item["processes"][1]["cgroup"] = "/foreign"; bad.append(item)
        item = copy.deepcopy(value); item["processes"].append(item["processes"][0]); bad.append(item)
        item = copy.deepcopy(value); item["processes"][1]["threads"] = [{"tid": 10, "tracer_pid": 222}]; bad.append(item)
        item = copy.deepcopy(value); item["processes"][0]["threads"] = [{"tid": i + 100, "tracer_pid": 222} for i in range(513)]; bad.append(item)
        item = copy.deepcopy(value); item["directories"] += [group + "/c" + str(i) for i in range(65)]; bad.append(item)
        item = copy.deepcopy(value); item["processes"] = [row(i + 10, group) for i in range(33)]; bad.append(item)
        for item in bad:
            with self.subTest(item=item), self.assertRaises(Refusal):
                owned_inventory(item, group, 10)

    def test_actual_diagnostics_precede_strict_trace_refusal_without_clearing_it(self):
        path = Path(__file__).with_name("run-daemon.py")
        spec = importlib.util.spec_from_file_location("relay_scanner_daemon_driver", path)
        driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = SimpleNamespace(cid="c" * 64)
            candidate.inspect = mock.Mock(return_value={"Id": candidate.cid, "Image": policy.CONFIG,
                "State": {"Running": True, "Pid": 100, "OOMKilled": False}})
            candidate.process_metadata = mock.Mock(return_value={"pid": 123, "start_ticks": "111",
                "cmdline": ["clamd", "--foreground"], "exe": "/usr/local/sbin/clamd", "nspid": [123, 9],
                "tracer_pid": 222, "cgroup": "/owned/" + candidate.cid})
            def docker(args, **kwargs):
                if args[0] == "top":
                    return SimpleNamespace(stdout=b"PID COMMAND\n123 clamd\n", stderr=b"", returncode=0)
                self.assertEqual(args[:2], ["exec", candidate.cid])
                if args[2:] == ["cat", "/init"]: output = b"#!/bin/sh\nexec clamd\n"
                elif args[2:] == ["cat", policy.CONFIG_PATH]: output = configuration()
                elif args[2] == "stat": output = b"1:2:0:0:644:128:1:1\n"
                elif args[2] == "clamconf": output = parsed()
                else: self.fail("unexpected diagnostic command")
                return SimpleNamespace(stdout=output, stderr=b"", returncode=0)
            candidate.d = SimpleNamespace(docker=mock.Mock(side_effect=docker))
            candidate.execute = mock.Mock(); candidate.exchange = mock.Mock()
            def snapshot():
                for leaf in ("init", "clamd-config", "clamd-config-stat", "clamconf"):
                    self.assertTrue((root / ("initial-load-" + leaf + ".stdout")).exists())
                captured = json.loads((root / "initial-load-diagnostic-capture.json").read_bytes())
                self.assertEqual(captured["actual_clamd_process"]["nspid"], [123, 9])
                self.assertEqual(captured["status"], "captured-not-qualified")
                return b'2411 openat(AT_FDCWD, "/etc/clamav/clamd.conf", O_RDONLY) = 4\n'
            with self.assertRaisesRegex(Refusal, "actual-clamd-exec-not-witnessed"):
                driver.witness(candidate, SimpleNamespace(snapshot=snapshot), root, "initial-load")
            report = json.loads((root / "initial-load-diagnostic-capture.json").read_bytes())
            self.assertEqual(report["primary_error"], "actual-clamd-exec-not-witnessed")
            self.assertFalse((root / "initial-load-witness.json").exists())
            candidate.execute.assert_not_called(); candidate.exchange.assert_not_called()

    def runtime_fixture(self, root, selector=None):
        environment = {"GITHUB_ACTIONS":"true", "RUNNER_ENVIRONMENT":"github-hosted", "RUNNER_OS":"Linux",
            "RUNNER_ARCH":"X64", "GITHUB_REPOSITORY":"cloud-rebellion/relay-ci", "GITHUB_REPOSITORY_ID":"1457664829",
            "GITHUB_EVENT_NAME":"push", "GITHUB_REF":"refs/heads/scanner/assessment-20261114", "RUNNER_TEMP":str(root)}
        with mock.patch.dict(os.environ, environment, clear=True):
            daemon = storage.BoundedDaemon(root / "results", **({"private_containerd":selector} if selector is not None else {}))
        daemon.results.mkdir(mode=0o700, exist_ok=True)
        daemon.root.mkdir(mode=0o700); daemon.mount.mkdir(mode=0o700)
        return daemon

    def test_loaded_service_and_unloaded_generic_unit_are_distinct_no_fake_pid(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned, active = self.trace_fixture(Path(temporary))
            encoded = lambda value: ("\n".join(key+"="+item for key,item in value.items())+"\n").encode()
            self.assertEqual(storage.unit_state(encoded(active)), active)
            unloaded = b"LoadState=not-found\nActiveState=inactive\n"
            parsed = storage.unit_state(unloaded, allow_unloaded=True)
            self.assertNotIn("MainPID", parsed); self.assertNotIn("ControlPID", parsed)
            variants = [unloaded, encoded({k:v for k,v in active.items() if k!="InvocationID"}),
                encoded(active)+b"MainPID=222\n", encoded(active)+b"Foreign=value\n"]
            for raw in variants:
                with self.subTest(raw=raw), self.assertRaises(Refusal): storage.unit_state(raw)
            for raw in (b"LoadState=not-found\nActiveState=active\n", unloaded+b"MainPID=222\n",
                        unloaded+b"MainPID=\n", unloaded+b"ExecStart=strace foreign\n", unloaded+b"Foreign=value\n",
                        encoded({k:v for k,v in active.items() if k!="MainPID"})):
                with self.subTest(raw=raw), self.assertRaises(Refusal): storage.unit_state(raw, allow_unloaded=True)
            owned.d.command.return_value = SimpleNamespace(returncode=0,stdout=unloaded)
            self.assertEqual(owned._raw_state(allow_unloaded=True), parsed)
            with self.assertRaises(Refusal): owned._raw_state()
            shape=json.loads((Path(temporary)/"owned-trace-state-shape-2.json").read_bytes())
            self.assertIn("MainPID",shape["missing"])
            # A failure after stop preserves the attempted boundary and original witness.
            owned._raw_state=mock.Mock(side_effect=[active,Refusal("synthetic-after-stop-shape")])
            owned._settle_call = None
            owned.__exit__(Refusal,Refusal("actual-clamd-exec-not-witnessed"),None)
            receipt=json.loads((Path(temporary)/"owned-trace-cleanup.json").read_bytes())
            self.assertTrue(receipt["stop_attempted"])
            self.assertEqual(receipt["cleanup_phase"],"read-after-stop")
            self.assertEqual(receipt["prior_identity"]["MainPID"],"222")
            self.assertEqual(receipt["primary_error"],"actual-clamd-exec-not-witnessed")

    def test_private_containerd_is_opt_in_hard_bounded_and_has_no_shared_listeners(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            default=self.runtime_fixture(root)
            self.assertFalse(default.private_containerd)
            default.command=mock.Mock()
            with self.assertRaises(Refusal): default.start_private_runtime()
            default.command.assert_not_called()
            daemon=self.runtime_fixture(root,True)
            def command(args,**kwargs):
                self.assertTrue(daemon.runtime_started)
                return SimpleNamespace(returncode=0,stdout=b"")
            daemon.command=mock.Mock(side_effect=command)
            daemon.verify_runtime_unit=mock.Mock(return_value=224)
            with mock.patch.object(Path,"exists",return_value=True), mock.patch.object(Path,"lstat",return_value=SimpleNamespace(st_mode=stat.S_IFSOCK)):
                daemon.start_private_runtime()
            args=daemon.command.call_args.args[0]
            self.assertIn("--unit="+daemon.runtime_unit,args)
            for item in ("--property=MemoryMax=256M","--property=CPUQuota=100%","--property=TasksMax=128",
                         "--property=RuntimeMaxSec=7200","--property=KillMode=control-group",
                         "--address="+str(daemon.runtime_socket),"--root="+str(daemon.runtime_root),"--state="+str(daemon.runtime_state)):
                self.assertIn(item,args)
            self.assertNotIn("/run/containerd/containerd.sock"," ".join(args))
            self.assertTrue(daemon.runtime_root.is_relative_to(daemon.mount)); self.assertTrue(daemon.runtime_state.is_relative_to(daemon.mount))
            text=daemon.runtime_config.read_text()
            for plugin in ("io.containerd.grpc.v1.cri","io.containerd.cri.v1.images","io.containerd.cri.v1.runtime","io.containerd.nri.v1.nri"):
                self.assertIn('"'+plugin+'"',text)
            self.assertIn('[debug]\naddress = ""',text); self.assertIn('[metrics]\naddress = ""',text)
            self.assertNotIn("/run/containerd",text)
            with self.assertRaisesRegex(Refusal,"start-once"): daemon.start_private_runtime()
            self.assertEqual(daemon.command.call_count,1)
            with self.assertRaisesRegex(Refusal,"selector"): self.runtime_fixture(root,"true")

    def test_tracer_attaches_both_verified_owned_service_trees_with_combined_caps(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned,_=self.trace_fixture(Path(temporary)); daemon=owned.d
            daemon.private_containerd=True; daemon.runtime_unit=daemon.unit+"-containerd"
            daemon.verify_unit=mock.Mock(return_value=10); daemon.verify_runtime_unit=mock.Mock(return_value=20)
            started=[]
            def command(args,**kwargs):
                if "systemd-run" in args:
                    self.assertGreater(daemon.verify_runtime_unit.call_count,0)
                    self.assertEqual([args[i+1] for i,x in enumerate(args) if x=="-p"],["10","20"])
                    started.append(True)
                return SimpleNamespace(returncode=0,stdout=b"")
            daemon.command=mock.Mock(side_effect=command)
            def probe(mode,group):
                self.assertEqual(mode,"tree")
                pid=20 if group.endswith("-containerd.service") else 10
                return {"cgroup":group,"directories":[group],"processes":[{"pid":pid,"status":"present","start_ticks":"111",
                    "cgroup":group,"threads":[{"tid":pid,"tracer_pid":222 if started else 0}]}]}
            owned.probe=mock.Mock(side_effect=probe); owned.state=mock.Mock(return_value={"MainPID":"222"})
            self.assertIs(owned.__enter__(),owned)
            self.assertEqual(len(started),1)
            inventory=json.loads((Path(temporary)/"owned-trace-initial-inventory.json").read_bytes())
            self.assertEqual(len(inventory["services"]),2)
            # Each tree can be valid alone while their union exceeds the global cap.
            def large(mode,group):
                values=probe(mode,group); base=20 if group.endswith("-containerd.service") else 10
                values["processes"][0]["threads"]=[{"tid":base*1000+i,"tracer_pid":222} for i in range(300)]
                return values
            owned.probe.side_effect=large
            with self.assertRaisesRegex(Refusal,"combined-bound"): owned.inventory(10)

    def test_private_runtime_identity_and_stop_are_exact_and_never_repeat(self):
        with tempfile.TemporaryDirectory() as temporary:
            daemon=self.runtime_fixture(Path(temporary),True); daemon.runtime_started=True
            active={"LoadState":"loaded","ActiveState":"active","MainPID":"224","ControlPID":"0",
                "ControlGroup":"/system.slice/"+daemon.runtime_unit+".service","InvocationID":"b"*32,
                "ExecStart":"containerd --address="+str(daemon.runtime_socket)+" --root="+str(daemon.runtime_root)+
                    " --state="+str(daemon.runtime_state)+" --config="+str(daemon.runtime_config)}
            encoded=lambda value:("\n".join(key+"="+item for key,item in value.items())+"\n").encode()
            daemon.runtime_process=mock.Mock(return_value={"pid":224,"status":"present","start_ticks":"111"})
            daemon.command=mock.Mock(return_value=SimpleNamespace(returncode=0,stdout=encoded(active)))
            self.assertEqual(daemon.verify_runtime_unit(),224)
            for field,value in (("ExecStart",active["ExecStart"].replace(str(daemon.runtime_socket),"/run/containerd/containerd.sock")),
                                ("ControlGroup","/system.slice/containerd.service"),("InvocationID","c"*32)):
                daemon.command.return_value.stdout=encoded({**active,field:value})
                with self.subTest(field=field),self.assertRaises(Refusal):daemon.stop_private_runtime()
                self.assertFalse(daemon.runtime_stop_attempted)
                self.assertFalse(any("stop" in call.args[0] for call in daemon.command.call_args_list))
            calls=[]
            def command(args,**kwargs):
                calls.append(args)
                if "show" in args:
                    body=encoded(active) if not daemon.runtime_stop_attempted else b"LoadState=not-found\nActiveState=inactive\n"
                else:body=b""
                return SimpleNamespace(returncode=0,stdout=body)
            daemon.command=mock.Mock(side_effect=command)
            daemon.runtime_process.side_effect=[{"pid":224,"status":"present","start_ticks":"111"},{"pid":224,"status":"absent"}]
            daemon.stop_private_runtime()
            self.assertFalse(daemon.runtime_started)
            self.assertEqual(sum("stop" in args for args in calls),1)
            receipt=json.loads((daemon.results/"owned-containerd-cleanup.json").read_bytes())
            self.assertTrue(receipt["settled"]);self.assertTrue(receipt["unloaded_service_pid_fields_inapplicable"])
            self.assertNotIn("MainPID",receipt["state_readback"])
            with self.assertRaises(Refusal):daemon.stop_private_runtime()
            self.assertEqual(sum("stop" in args for args in calls),1)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DaemonControls)
    count = suite.countTestCases()
    if count != 34:
        raise RuntimeError("Closed daemon controls changed")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    value = {"schema": 1, "tests": result.testsRun, "failures": len(result.failures),
             "errors": len(result.errors), "skips": len(result.skipped),
             "status": "passed" if result.wasSuccessful() and not result.skipped else "failed"}
    output = os.environ.get("RELAY_SCANNER_PHASE1_RESULTS_DIR")
    if output:
        (Path(output) / "daemon-controls-summary.json").write_text(json.dumps(value, sort_keys=True) + "\n")
    sys.exit(0 if value["status"] == "passed" else 1)
