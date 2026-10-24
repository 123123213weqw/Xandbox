import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import unittest
from unittest.mock import patch
from process_exit import project_view, failure_summary, require_clean_exit, MAX_VIEW


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


if __name__=='__main__':unittest.main()
