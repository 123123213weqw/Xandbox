"""Pure synthetic parser/environment tests; NEVER compile or launch Go/VMs."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

import runtime_cpu_diagnostic as diagnostic


class RuntimeCPUDiagnosticTests(unittest.TestCase):
    marker = 'PRIVATE_SYNTHETIC_SENTINEL'

    def events(self):
        result = [{'Action': 'start', 'Package': diagnostic.PACKAGE}]
        result += [{'Action': 'run', 'Package': diagnostic.PACKAGE, 'Test': diagnostic.TARGET}]
        for name in tuple(diagnostic.TARGET + '/' + c for c in diagnostic.CUTS):
            result += [{'Action': 'run', 'Package': diagnostic.PACKAGE, 'Test': name},
                       {'Action': 'output', 'Package': diagnostic.PACKAGE,
                        'Test': name, 'Output': self.marker},
                       {'Action': 'pass', 'Package': diagnostic.PACKAGE,
                        'Test': name, 'Elapsed': 0.25}]
        result += [{'Action': 'pass', 'Package': diagnostic.PACKAGE,
                    'Test': diagnostic.TARGET, 'Elapsed': 1.5},
                   {'Action': 'pass', 'Package': diagnostic.PACKAGE, 'Elapsed': 1.5}]
        return result

    def encode(self, events):
        return b'\n'.join(json.dumps(e).encode() for e in events)

    def test_whole_existing16_cut_roster_once_and_output_never_exported(self):
        result = diagnostic.test_summary(self.encode(self.events()))
        self.assertEqual(len(diagnostic.CUTS), 16)
        self.assertEqual(len(result['cut_elapsed_seconds']), 16)
        self.assertNotIn(self.marker, json.dumps(result))

    def test_missing_duplicate_extra_skip_fail_package_or_reorder_fail_closed(self):
        variants = []
        events = self.events(); variants.append(events[:-1])
        events = self.events(); variants.append(events + [events[1]])
        for key, value in [('Action', 'skip'), ('Action', 'fail'), ('Package', 'unknown'),
                           ('Test', 'foreign'), ('Elapsed', float('nan'))]:
            events = self.events(); events[4][key] = value; variants.append(events)
        events = self.events(); events[2], events[4] = events[4], events[2]; variants.append(events)
        for events in variants:
            with self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.test_summary(self.encode(events))

    def test_race_warning_malformed_or_oversized_capture_fail_closed(self):
        events = self.events(); events[3]['Output'] = 'WARNING: DATA RACE'
        for raw in (self.encode(events), b'{}', b'invalid', b'', b'x'*(diagnostic.MAX_CAPTURE + 1)):
            with self.assertRaises((diagnostic.DiagnosticError, ValueError)):
                diagnostic.test_summary(raw)

    def profile(self, symbol=None):
        return ('File: ' + self.marker + '\nType: cpu\nTime: ' + self.marker + '\n'
                'Duration: 1s, Total samples = 100ms (10%)\n'
                'Showing nodes accounting for 100ms, 100% of 100ms total\n'
                ' flat flat% sum% cum cum%\n'
                ' 40ms 40% 40% 100ms 100% __tsan_read\n'
                ' 20ms 20% 60% 90ms 90% runtime.mallocgc\n'
                ' 10ms 10% 70% 80ms 80% encoding/json.Unmarshal\n'
                ' 10ms 10% 80% 70ms 70% regexp.(*Regexp).MatchString\n'
                ' 10ms 10% 90% 60ms 60% github.com/123123213weqw/Xandbox/internal/installtxn.x\n'
                ' 10ms 10% 100% 50ms 50% ' + (symbol or self.marker) + '\n').encode()

    def test_complete_flat_categories_do_not_add_cumulative_or_emit_symbols(self):
        result = diagnostic.cpu_summary(self.profile())
        self.assertEqual(sum(result['flat_CPU_ms_by_closed_category'].values()), 100)
        self.assertEqual(result['flat_CPU_ms_by_closed_category']['race_instrumentation'], 40)
        self.assertNotIn(self.marker, json.dumps(result))

    def test_arbitrary_profile_text_in_symbol_is_only_closed_other_category(self):
        result = diagnostic.cpu_summary(self.profile('/private/path with arbitrary text'))
        self.assertEqual(result['flat_CPU_ms_by_closed_category']['other_or_unattributed'], 10)
        self.assertNotIn('/private/', json.dumps(result))

    def test_pprof_unitless_zero_is_valid_but_unitless_nonzero_is_not(self):
        raw = self.profile() + b' 0 0% 100% 10ms 10% fixed\n'
        self.assertEqual(diagnostic.cpu_summary(raw)['total_sampled_CPU_ms'], 100)
        for wrong in (b' 1 0% 100% 10ms 10% fixed\n', b' 0 0% 100% 1 10% fixed\n'):
            with self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.cpu_summary(self.profile() + wrong)

    def test_dropped_missing_bad_unit_nonfinite_incomplete_or_duplicate_table_refused(self):
        raw = self.profile()
        variants = [b'', raw.replace(b'Type: cpu', b'Type: heap'),
                    raw.replace(b' flat flat%', b'Dropped 1 node\n flat flat%'),
                    raw.replace(b'40ms 40%', b'41ms 40%'),
                    raw.replace(b'40ms 40%', b'nanms 40%'),
                    raw.replace(b'40ms 40%', b'40s 40%'), raw + b'garbage\n',
                    raw + b' flat flat% sum% cum cum%\n']
        for value in variants:
            with self.assertRaises((diagnostic.DiagnosticError, ValueError)):
                diagnostic.cpu_summary(value)

    def test_only_nonroot_disposable_hosted_linux(self):
        env = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux'}
        diagnostic.hosted_linux_only(env, 'Linux', 1001)
        for e, system, uid in [(env, 'Darwin', 1001), (env, 'Linux', 0), ({}, 'Linux', 1001),
                               ({**env, 'RUNNER_ENVIRONMENT': 'self-hosted'}, 'Linux', 1001)]:
            with self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.hosted_linux_only(e, system, uid)

    def test_environment_removes_credentials_and_ambient_go_configuration(self):
        with patch.dict(os.environ, {'PATH': '/fixed', 'HOME': '/synthetic',
                                    'GITHUB_TOKEN': self.marker, 'GOFLAGS': self.marker,
                                    'GOEXPERIMENT': self.marker, 'GODEBUG': self.marker}, clear=True):
            env = diagnostic.environment()
        self.assertNotIn(self.marker, json.dumps(env))
        self.assertEqual(env['GOTOOLCHAIN'], 'go1.27.3')
        self.assertEqual(env['GOFLAGS'], '-p=1')
        self.assertEqual(env['GOMAXPROCS'], '2')
        self.assertEqual(env['GOMEMLIMIT'], '512MiB')

    def test_failures_cannot_export_exception_text_or_claim_pass(self):
        for error in (RuntimeError(self.marker), KeyboardInterrupt(self.marker)):
            output = io.StringIO()
            with patch.object(diagnostic, 'main', side_effect=error), contextlib.redirect_stdout(output):
                self.assertEqual(diagnostic.entrypoint(), 1)
            result = json.loads(output.getvalue())
            self.assertFalse(result['diagnostic_complete'])
            self.assertFalse(result['native_qualification'])
            self.assertNotIn(self.marker, output.getvalue())

    def test_deadline_and_unknown_label_fail_before_launch(self):
        with tempfile.TemporaryDirectory() as root, patch.object(diagnostic.subprocess, 'Popen') as launch:
            for label, deadline in [('test', -1), ('arbitrary', 10**20)]:
                with self.assertRaises(diagnostic.DiagnosticError):
                    diagnostic.bounded([], root, {}, Path(root), label, deadline)
            launch.assert_not_called()

    def test_nonhost_main_refuses_before_priority_temp_or_process_work(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(diagnostic.sys, 'argv', ['fixed']), \
                patch.object(diagnostic.os, 'setpriority', create=True) as priority, \
                patch.object(diagnostic.tempfile, 'TemporaryDirectory') as temporary, \
                patch.object(diagnostic.subprocess, 'Popen') as launch:
            with self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.main()
            priority.assert_not_called(); temporary.assert_not_called(); launch.assert_not_called()

    def test_optimized_python_refuses_before_any_host_or_process_work(self):
        with patch.object(diagnostic.sys, 'argv', ['fixed']), \
                patch.object(diagnostic.sys, 'flags', SimpleNamespace(optimize=1)), \
                patch.object(diagnostic, 'hosted_linux_only') as host:
            with self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.main()
            host.assert_not_called()

    def test_timeout_only_signals_newly_launched_session_and_reaps(self):
        process = Mock(pid=424242); process.poll.return_value = None
        with tempfile.TemporaryDirectory() as root, \
                patch.object(diagnostic.subprocess, 'Popen', return_value=process) as launch, \
                patch.object(diagnostic.os, 'killpg') as kill, \
                patch.object(diagnostic.time, 'monotonic', side_effect=[0, 2]):
            with self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.bounded(['fixed'], root, {}, Path(root), 'test', 1)
            self.assertTrue(launch.call_args.kwargs['start_new_session'])
            kill.assert_called_once_with(424242, diagnostic.signal.SIGKILL)
            process.wait.assert_called_once()

    def test_failed_completed_child_never_signals_other_pids(self):
        process = Mock(pid=424242); process.poll.return_value = 2
        with tempfile.TemporaryDirectory() as root, \
                patch.object(diagnostic.subprocess, 'Popen', return_value=process), \
                patch.object(diagnostic.os, 'killpg') as kill:
            with self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.bounded(['fixed'], root, {}, Path(root), 'test', 10**20)
            kill.assert_not_called()

    def test_number_types_and_nonfinite_or_negative_are_rejected(self):
        for value in (True, '1', None, float('inf'), float('nan'), -1, 600001):
            with self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.number(value)

    def test_all_cut_order_matters_not_just_set_counts(self):
        events = self.events(); events[2:5], events[5:8] = events[5:8], events[2:5]
        with self.assertRaises(diagnostic.DiagnosticError):
            diagnostic.test_summary(self.encode(events))


if __name__ == '__main__':
    unittest.main()
