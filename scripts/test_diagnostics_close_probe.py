import inspect
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import diagnostics_close_probe as probe
import diagnostics_smoke


class DiagnosticProbeTests(unittest.TestCase):
    def test_closed_receipt_rejects_extra_or_unknown_data(self):
        for code, name in enumerate(probe.CODES):
            self.assertEqual(probe.decode_receipt(bytes((ord('X'), code))), name)
        for raw in (b'', b'X', b'X\xff', b'X\x00secret', b'Y\x00'):
            with self.assertRaises(ValueError):
                probe.decode_receipt(raw)

    def test_receipt_never_masks_nonzero_exit_and_is_consumed_once(self):
        r, w = os.pipe()
        os.write(w, b'X\x01'); os.close(w)
        receipts = []
        process = probe.ObservedProcess(SimpleNamespace(wait=lambda timeout: 1), r, receipts)
        self.assertEqual(process.wait(timeout=10), 1)
        self.assertEqual(process.wait(timeout=10), 1)
        self.assertEqual(receipts, [{'exit_status': 1, 'close_result': 'pending'}])

    def test_missing_frame_does_not_wait_for_unclosed_writer(self):
        r, w = os.pipe(); os.set_blocking(r, False)
        try:
            receipts = []
            process = probe.ObservedProcess(SimpleNamespace(wait=lambda timeout: 1), r, receipts)
            self.assertEqual(process.wait(timeout=10), 1)
            self.assertEqual(receipts, [{'exit_status': 1, 'close_result': 'unavailable'}])
        finally:
            os.close(w)

    def test_spawn_error_closes_both_owned_fds(self):
        r, w = os.pipe()
        with patch.object(probe.os, 'pipe', return_value=(r, w)), patch.object(
                probe.subprocess, 'Popen', side_effect=OSError('private-not-exported')):
            with self.assertRaises(OSError):
                probe.observed_popen(['/not-executed'], receipts=[], stdout=7, stderr=7)
        for fd in (r, w):
            with self.assertRaises(OSError): os.fstat(fd)

    def test_fixture_preserves_streams_arguments_and_private_fd_custody(self):
        calls = []
        def spawn(command, **kwargs):
            calls.append((command, kwargs.copy()))
            self.assertFalse(os.get_blocking(kwargs['pass_fds'][0]))
            return SimpleNamespace(wait=lambda timeout: 0)
        with patch.object(probe.subprocess, 'Popen', side_effect=spawn):
            process = probe.observed_popen(['/fixture', '-backend', 'mock'], receipts=[], stdout=7, stderr=7)
        process.wait(timeout=10)
        command, kwargs = calls[0]
        self.assertEqual(command, ['/fixture', '-test.run=^TestDiagnosticsProbeProcessHelper$', '--', '-backend', 'mock'])
        self.assertEqual((kwargs['stdout'], kwargs['stderr']), (7, 7))
        self.assertEqual(len(kwargs['pass_fds']), 1)
        self.assertEqual(kwargs['env'][probe.FD_ENV], str(kwargs['pass_fds'][0]))

    def test_original_harness_protocol_not_replaced_or_shortened(self):
        source = inspect.getsource(diagnostics_smoke.main)
        for text in ('range(45)', 'stdout=write_fd, stderr=write_fd',
                     'terminate_cleanly(proc, node, state, cycle)',
                     "observed['observed_sequence'] == 135", 'assert total == filled'):
            self.assertIn(text, source)
        fixture = Path(__file__).parents[1] / 'cmd/sandboxd/diagnostics_probe_fixture_test.go'
        code = fixture.read_text()
        self.assertTrue(code.startswith('//go:build xandbox_diagnostics_fixture && (linux || darwin)'))
        self.assertIn('err = runArgs(args)', code)
        self.assertIn('os.Exit(processExitCode(err))', code)
        self.assertNotIn('.Error()', code)


if __name__ == '__main__':
    unittest.main()
