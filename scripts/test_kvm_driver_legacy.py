import copy
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from kvm_driver_smoke import resume_legacy_fixture


class LegacyAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.committed = {'version': 1, 'epoch': 'a' * 32, 'revision': 1,
                          'mode': 'drained', 'last_request_id': '', 'last_expected_revision': 0}
        self.opened = dict(self.committed, revision=2, mode='open',
                           last_request_id='b' * 32, last_expected_revision=1)

    def reply(self, state, opened):
        return {'control': {'version': 1, 'committed': state, 'phase': 'ready',
                            'desired_mode': state['mode'], 'admission_open': opened,
                            'pending_session_reservations': 0},
                'resource_observation': {'backend': 'firecracker', 'records': 1,
                                         'record_capacity': 1, 'tenant_record_capacity': 1,
                                         'active': 0, 'recovering': 0}}

    def run_helper(self, replies, disk=None):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            (state / 'admission').mkdir()
            (state / 'admission/state.json').write_text(json.dumps(self.opened if disk is None else disk))
            responses = [subprocess.CompletedProcess([], 0, json.dumps(r).encode()) for r in replies]
            with patch('kvm_driver_smoke.subprocess.run', side_effect=responses) as run, \
                    patch('kvm_driver_smoke.secrets.token_hex', return_value='b' * 32):
                result = resume_legacy_fixture('/trusted/node', state, self.committed, io.BytesIO())
                commands = [call.args[0] for call in run.call_args_list]
                self.assertEqual(commands, [
                    ['/trusted/node', '-state-dir', str(state), 'status'],
                    ['/trusted/node', '-state-dir', str(state), '-epoch', 'a' * 32,
                     '-revision', '1', '-request-id', 'b' * 32, 'resume'],
                    ['/trusted/node', '-state-dir', str(state), 'status']])
                for call in run.call_args_list:
                    self.assertEqual(call.kwargs['timeout'], 10)
                    self.assertIs(call.kwargs['stdout'], subprocess.PIPE)
                    self.assertIsNotNone(call.kwargs['stderr'])
                self.assertNotIn('a' * 32, json.dumps(result))
                self.assertNotIn('b' * 32, json.dumps(result))
                return result

    def test_drained_fixture_explicit_cas_keeps_one_tombstone(self):
        replies = [self.reply(self.committed, False), self.reply(self.opened, True),
                   self.reply(self.opened, True)]
        self.assertEqual(self.run_helper(replies)['retained_destroyed_records'], 1)

    def test_wrong_control_or_resources_rejected(self):
        for field, value in [('admission_open', True), ('phase', 'pending'),
                             ('desired_mode', 'open'), ('pending_session_reservations', 1)]:
            with self.subTest(field=field):
                initial = self.reply(self.committed, False)
                initial['control'][field] = value
                with self.assertRaises(AssertionError): self.run_helper([initial])
        for field, value in [('backend', 'mock'), ('records', 0), ('active', 1),
                             ('recovering', 1), ('record_capacity', 2), ('tenant_record_capacity', 2)]:
            with self.subTest(field=field):
                initial = self.reply(self.committed, False)
                initial['resource_observation'][field] = value
                with self.assertRaises(AssertionError): self.run_helper([initial])

    def test_epoch_revision_and_durable_readback_must_match(self):
        for index, mutate in [(0, {'epoch': 'c' * 32}), (0, {'revision': 2}),
                              (1, {'last_request_id': 'c' * 32}), (2, {'revision': 3})]:
            replies = [self.reply(copy.deepcopy(self.committed), False),
                       self.reply(copy.deepcopy(self.opened), True), self.reply(copy.deepcopy(self.opened), True)]
            replies[index]['control']['committed'].update(mutate)
            with self.subTest(index=index, mutate=mutate), self.assertRaises(AssertionError):
                self.run_helper(replies)
        with self.assertRaises(AssertionError):
            self.run_helper([self.reply(self.committed, False), self.reply(self.opened, True),
                             self.reply(self.opened, True)], disk=self.committed)

    def test_nonzero_exit_and_oversized_reply_fail_without_retry(self):
        for reply in [subprocess.CompletedProcess([], 1, b''),
                      subprocess.CompletedProcess([], 0, b' ' * 8193)]:
            with patch('kvm_driver_smoke.subprocess.run', return_value=reply) as run:
                with self.assertRaises(AssertionError):
                    resume_legacy_fixture('/trusted/node', Path('/unused'), self.committed, io.BytesIO())
                self.assertEqual(run.call_count, 1)

    def test_unexpected_initial_state_rejected_before_cli(self):
        for change in [{'revision': 2}, {'mode': 'open'}, {'epoch': 'not-an-epoch'},
                       {'last_request_id': 'b' * 32}, {'last_expected_revision': 1}]:
            with patch('kvm_driver_smoke.subprocess.run') as run, self.assertRaises(AssertionError):
                resume_legacy_fixture('/trusted/node', Path('/unused'),
                                      dict(self.committed, **change), io.BytesIO())
            run.assert_not_called()


if __name__ == '__main__': unittest.main()
