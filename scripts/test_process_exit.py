import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import unittest
from unittest.mock import patch
from process_exit import project_view, failure_summary, require_clean_exit, project_cycle, MAX_VIEW


class ClosedProcessExitTests(unittest.TestCase):
    def test_projection_never_exports_extra_values_or_record_identity(self):
        value={'version':1,'private':'do-not-export','records':[{'sequence':99,'event':{'kind':'process_failed','reason':'deadline','time_ns':123,'private':'do-not-export'}}]}
        self.assertEqual(project_view(json.dumps(value).encode()),[{'kind':'process_failed','reason':'deadline'}])

    def test_unknown_enum_or_malformed_view_is_not_rendered(self):
        for value in ({'version':1,'records':[{'event':{'kind':'private-token','reason':'other'}}]},
                      {'version':1,'records':[{'event':{'kind':'process_failed','reason':'private-path'}}]},
                      {'version':1,'records':[None]},[],{'version':2,'records':[]},{'version':True,'records':[]}):
            with self.assertRaises(ValueError):project_view(json.dumps(value).encode())
        with self.assertRaises(ValueError):project_view(b'x'*(MAX_VIEW+1))

    def test_tail_is_bounded(self):
        rows=[{'event':{'kind':'process_stopped','reason':'other'}}]*128
        self.assertEqual(len(project_view(json.dumps({'version':1,'records':rows}).encode())),6)

    def test_tool_error_cannot_leak_third_party_text(self):
        with patch('process_exit.subprocess.run',side_effect=OSError('private-path-token')):
            value=failure_summary(-15,'/unexecuted','/private-state')
        self.assertEqual(value['exit_status'],-15);self.assertNotIn('private',json.dumps(value))

    def test_nonzero_status_stays_failure_and_is_recorded(self):
        with patch('process_exit.failure_summary',return_value={'exit_status':1,'closed_records':[]}):
            with self.assertRaisesRegex(AssertionError,'"exit_status": 1'):
                require_clean_exit(SimpleNamespace(wait=lambda timeout:1),'/unexecuted','/private')
        require_clean_exit(SimpleNamespace(wait=lambda timeout:0),'/unexecuted','/private')

    def test_wait_timeout_is_not_treated_as_clean(self):
        def pending(timeout):raise subprocess.TimeoutExpired('unexecuted',timeout)
        with self.assertRaisesRegex(AssertionError,'wait_timeout'):require_clean_exit(SimpleNamespace(wait=pending),'/unexecuted','/private')

    def test_diagnostic_restart_keeps_nonzero_assertion_and_cycle_context(self):
        from diagnostics_smoke import terminate_cleanly
        calls=[]
        process=SimpleNamespace(terminate=lambda:calls.append('terminate'),wait=lambda timeout:1)
        with patch('process_exit.failure_summary',return_value={'exit_status':1,'closed_records':[]}):
            with self.assertRaisesRegex(AssertionError,'diagnostics restart cycle 44:.*"exit_status": 1'):
                terminate_cleanly(process,'/unexecuted','/private',44)
        self.assertEqual(calls,['terminate'])
        process=SimpleNamespace(terminate=lambda:None,wait=lambda timeout:0)
        terminate_cleanly(process,'/unexecuted','/private',0)

    def test_diagnostic_restart_keeps_original_cycles_pipe_and_record_gates(self):
        import inspect
        import diagnostics_smoke
        source=inspect.getsource(diagnostics_smoke.main)
        for gate in ('range(45)',"os.set_blocking(write_fd, True)","stdout=write_fd, stderr=write_fd",'terminate_cleanly(proc, node, state, cycle)',"observed['observed_sequence'] == (cycle + 1) * 3","observed['observed_sequence'] == 135",'assert total == filled'):
            self.assertIn(gate,source)
        self.assertNotIn('assert proc.wait(timeout=10) == 0',source)


class CurrentCycleObservationTests(unittest.TestCase):
    def raw(self,observed,kinds):
        return json.dumps({'version':1,'observed_sequence':observed,'private':'do-not-export',
            'records':[{'sequence':observed-i,'event':{'kind':kind,'reason':'other','time_ns':123,'private':'do-not-export'}} for i,kind in enumerate(kinds)]}).encode()
    def test_previous_clean_tail_is_not_current_cycle(self):
        raw=self.raw(78,['service_mock','process_stopped','collector_closed']*2)
        v=project_cycle(raw,78)
        self.assertEqual(v,{'cycle_observation':'unchanged','cycle_new_events':0,'cycle_events':[],'cycle_collector_closed':False})
    def test_current_events_are_relative_and_redacted(self):
        v=project_cycle(self.raw(81,['service_mock','process_stopped','collector_closed']*2),78)
        self.assertEqual(v['cycle_new_events'],3);self.assertTrue(v['cycle_collector_closed'])
        self.assertEqual(v['cycle_events'],[{'kind':k,'reason':'other'} for k in ('service_mock','process_stopped','collector_closed')])
        for value in ('sequence','time_ns','do-not-export','81','78'):
            self.assertNotIn(value,json.dumps(v))
    def test_partial_behind_overflow_and_invalid_are_distinct(self):
        self.assertEqual(project_cycle(self.raw(79,['service_mock']),78)['cycle_new_events'],1)
        self.assertEqual(project_cycle(self.raw(77,[]),78)['cycle_observation'],'behind')
        self.assertEqual(project_cycle(self.raw(90,['service_mock']*12),78)['cycle_observation'],'more_than_six')
        for previous,observed in ((True,78),(136,78),(-1,78),(78,True),(78,-1),(78,1<<64)):
            with self.assertRaises(ValueError):project_cycle(self.raw(observed,[]),previous)
        with self.assertRaises(ValueError):project_cycle(self.raw(81,[]),78)
    def test_nonzero_failure_uses_closed_cycle_summary_without_streams(self):
        process=SimpleNamespace(wait=lambda timeout:1)
        with patch('process_exit.failure_summary',return_value={'exit_status':1,'cycle_observation':'unchanged'}) as summary:
            with self.assertRaisesRegex(AssertionError,'unchanged'):require_clean_exit(process,'/unexecuted','/private',previous_sequence=78)
            summary.assert_called_once_with(1,'/unexecuted','/private',78)
    def test_restart_passes_exact_prior_success_count_not_untrusted_record_identity(self):
        from diagnostics_smoke import terminate_cleanly
        with patch('diagnostics_smoke.require_clean_exit') as clean:
            terminate_cleanly(SimpleNamespace(terminate=lambda:None),'/unexecuted','/private',26)
            self.assertEqual(clean.call_args.kwargs,{'previous_sequence':78})


class MetadataStopEvidenceTests(unittest.TestCase):
    marker = 'SYNTHETIC_PRIVATE_ERROR_AND_PATH_SENTINEL'

    def process(self, status=0, signal_error=None, wait_error=None):
        calls = []
        def signal(name):
            calls.append(name)
            if signal_error is not None:
                raise signal_error
        def wait(timeout):
            calls.append(('wait', timeout))
            if wait_error is not None:
                raise wait_error
            return status
        return SimpleNamespace(terminate=lambda: signal('terminate'), kill=lambda: signal('kill'), wait=wait), calls

    def failed(self, process, *, phase='imported_2048_stop', crash=False, summary=None, directory='/owned-imported'):
        import metadata_smoke as metadata
        if summary is None:
            summary = {'view_exit_status': 0, 'diagnostic_view': 'closed',
                       'closed_records': [{'kind': 'collector_closed', 'reason': 'other'}]}
        with patch.object(metadata, 'failure_summary', return_value=summary) as collect:
            with self.assertRaises(AssertionError) as raised:
                metadata.stop_metadata_process(process, '/unexecuted-node', directory, phase, crash=crash)
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertNotIn(self.marker, str(raised.exception))
        return json.loads(str(raised.exception)), collect

    def test_all_nine_success_policies_keep_exact_signal_wait15_and_no_diagnostic_io(self):
        import metadata_smoke as metadata
        self.assertEqual(len(metadata.STOP_PHASES), 9)
        for phase, crash in metadata.STOP_PHASES.items():
            for status in ((-9, 1) if crash else (0,)):
                process, calls = self.process(status)
                with patch.object(metadata, 'failure_summary') as collect:
                    metadata.stop_metadata_process(process, '/unexecuted', '/owned', phase, crash=crash)
                    collect.assert_not_called()
                self.assertEqual(calls, ['kill' if crash else 'terminate', ('wait', 15)])

    def test_unexpected_status_never_passes_even_with_earlier_collector_closed_tail(self):
        for phase, crash, status in [('imported_2048_stop', False, 1), ('tenant_capacity_stop', False, -15),
                                     ('partial_migration_kill', True, 0)]:
            process, calls = self.process(status)
            result, collect = self.failed(process, phase=phase, crash=crash)
            self.assertEqual(result['exit_status'], status)
            self.assertEqual(result['phase'], phase)
            self.assertEqual(result['failure'], 'unexpected_exit_status')
            self.assertEqual(result['wait_limit_seconds'], 15)
            self.assertTrue(result['persisted_tail_is_not_current_process_proof'])
            collect.assert_called_once_with(status, '/unexecuted-node', '/owned-imported')
            self.assertEqual(calls[-1], ('wait', 15))

    def test_each_failure_collects_only_explicit_actual_directory(self):
        import metadata_smoke as metadata
        for phase, directory in [('imported_2048_stop', Path('/owned/interrupted')),
                                 ('historical_recovery_stop', Path('/owned/historical')),
                                 ('tenant_capacity_stop', Path('/owned/state'))]:
            process, _ = self.process(1)
            result, collect = self.failed(process, phase=phase, directory=directory)
            collect.assert_called_once_with(1, '/unexecuted-node', directory)
            self.assertNotIn(str(directory), json.dumps(result))
            self.assertEqual(result['diagnostic_view'], 'closed')

    def test_projection_drops_extra_private_fields_and_uses_only_closed_enums(self):
        row = {'kind': 'process_failed', 'reason': 'deadline', 'path': self.marker, 'sequence': 99}
        summary = {'view_exit_status': 0, 'diagnostic_view': 'closed', 'closed_records': [row],
                   'exit_status': self.marker, 'raw': self.marker, 'time_ns': 123}
        result, _ = self.failed(self.process(1)[0], summary=summary)
        self.assertEqual(result['closed_records'], [{'kind': 'process_failed', 'reason': 'deadline'}])
        self.assertEqual(result['exit_status'], 1)
        for key in ('path', 'sequence', 'raw', 'time_ns'):
            self.assertNotIn(key, result)

    def test_malformed_unknown_or_overlong_tail_cannot_export_a_partial_prefix(self):
        good = {'kind': 'collector_closed', 'reason': 'other'}
        bads = [None, [], {'diagnostic_view': self.marker},
                {'view_exit_status': self.marker, 'diagnostic_view': 'closed', 'closed_records': [good]},
                {'view_exit_status': 0, 'diagnostic_view': 'closed', 'closed_records': [good]*7},
                {'view_exit_status': 0, 'diagnostic_view': 'closed', 'closed_records': [good, None]},
                {'view_exit_status': 0, 'diagnostic_view': 'closed', 'closed_records': [good, {'kind': self.marker, 'reason': 'other'}]},
                {'view_exit_status': 0, 'diagnostic_view': 'closed', 'closed_records': [good, {'kind': 'unknown', 'reason': self.marker}]}]
        for summary in bads:
            # None is a malformed collector result here, not failed()'s default.
            import metadata_smoke as metadata
            with patch.object(metadata, 'failure_summary', return_value=summary):
                with self.assertRaises(AssertionError) as raised:
                    metadata.stop_metadata_process(self.process(1)[0], '/unexecuted', '/owned', 'imported_2048_stop')
            result = json.loads(str(raised.exception))
            self.assertEqual(result['closed_records'], [])
            self.assertEqual(result['diagnostic_view'], 'unavailable')
            self.assertNotIn(self.marker, str(raised.exception))

    def test_collector_exception_is_not_relayed_or_converted_to_success(self):
        import metadata_smoke as metadata
        for exception in (OSError(self.marker), ValueError(self.marker), RuntimeError(self.marker)):
            with patch.object(metadata, 'failure_summary', side_effect=exception):
                with self.assertRaises(AssertionError) as raised:
                    metadata.stop_metadata_process(self.process(1)[0], '/unexecuted', '/owned', 'imported_2048_stop')
            result = json.loads(str(raised.exception))
            self.assertEqual(result['exit_status'], 1)
            self.assertEqual(result['diagnostic_view'], 'unavailable')
            self.assertNotIn(self.marker, str(raised.exception))

    def test_signal_errors_fail_before_wait_and_do_not_collect_live_process(self):
        process, calls = self.process(signal_error=OSError(self.marker))
        result, collect = self.failed(process)
        self.assertEqual(result['failure'], 'signal_failed')
        self.assertEqual(calls, ['terminate'])
        collect.assert_not_called()
        self.assertIsNone(result['exit_status'])

    def test_wait_timeout_error_and_invalid_status_fail_without_extra_diagnostic_wait(self):
        variants = [(None, subprocess.TimeoutExpired(self.marker, 15), 'wait_timeout'),
                    (None, OSError(self.marker), 'wait_failed')]
        variants += [(status, None, 'invalid_exit_status') for status in (True, self.marker, None, -129, 256)]
        for status, exception, expected in variants:
            process, calls = self.process(status, wait_error=exception)
            result, collect = self.failed(process)
            self.assertEqual(result['failure'], expected)
            self.assertIsNone(result['exit_status'])
            self.assertEqual(result['diagnostic_view'], 'not_requested')
            self.assertEqual(calls, ['terminate', ('wait', 15)])
            collect.assert_not_called()

    def test_invalid_policy_and_optimized_python_refuse_before_process_work(self):
        import metadata_smoke as metadata
        for phase, crash in [(self.marker, False), ([], False), ('imported_2048_stop', True),
                             ('partial_migration_kill', False), ('imported_2048_stop', 0)]:
            process, calls = self.process()
            result, collect = self.failed(process, phase=phase, crash=crash)
            self.assertEqual(result['failure'], 'invalid_policy')
            self.assertEqual(result['phase'], 'unavailable')
            self.assertEqual(calls, [])
            collect.assert_not_called()
        process, calls = self.process()
        with patch.object(metadata.sys, 'flags', SimpleNamespace(optimize=1)):
            result, collect = self.failed(process)
            self.assertEqual(result['failure'], 'optimized_python')
            self.assertEqual(calls, [])
            collect.assert_not_called()
            with patch.object(metadata.argparse, 'ArgumentParser') as parser:
                with self.assertRaises(AssertionError): metadata.main()
                parser.assert_not_called()

    def test_main_all_nine_stops_have_fixed_phase_actual_root_and_original_fixtures(self):
        import ast
        import inspect
        import metadata_smoke as metadata
        tree = ast.parse(inspect.getsource(metadata.main))
        calls = sorted((n for n in ast.walk(tree) if isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Name) and n.func.id == 'stopped'), key=lambda n: n.lineno)
        observed = []
        for call in calls:
            fields = {k.arg: k.value for k in call.keywords}
            observed.append((ast.literal_eval(fields['phase']), fields['directory'].id,
                             ast.literal_eval(fields['crash']) if 'crash' in fields else False))
        self.assertEqual(observed, [(p, d, c) for (p, c), d in zip(metadata.STOP_PHASES.items(),
                         ['state']*5 + ['interrupted']*2 + ['historical']*2)])
        source = inspect.getsource(metadata.main)
        for gate in ('count = 2048', "seconds=30", '0 < upgraded < count',
                     "resumed = migrate(interrupted)", "['upgraded'] == count - upgraded",
                     "'NODE_DRAINING'", "'METADATA_CAPACITY'", "['control']['admission_open']"):
            self.assertIn(gate, source)
        self.assertIn('process.kill(); process.wait(timeout=15)', source)


if __name__=='__main__':unittest.main()
