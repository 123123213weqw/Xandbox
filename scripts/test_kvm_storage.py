import errno
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from kvm_storage import BoundedExt4, require_private_namespace
from kvm_storage_faults import validate_host_stop_guard, validate_failed_fault_restart, no_unix_listener


class BoundedStorageTests(unittest.TestCase):
    def test_only_fresh_empty_lost_found_is_removed_from_ledger_volume(self):
        with tempfile.TemporaryDirectory() as root:
            volume = BoundedExt4(root, 'ledger'); volume.mount.mkdir()
            lost = volume.mount / 'lost+found'; lost.mkdir()
            (lost / 'unexpected').touch()
            with patch.object(volume, '_check'), self.assertRaises(OSError): volume._prepare_empty_ledger()
            self.assertTrue((lost / 'unexpected').exists())
            (lost / 'unexpected').unlink()
            with patch.object(volume, '_check'): volume._prepare_empty_ledger()
            self.assertEqual(list(volume.mount.iterdir()), [])

    def test_unowned_ledger_cannot_remove_lost_found(self):
        with tempfile.TemporaryDirectory() as root:
            volume = BoundedExt4(root, 'ledger'); volume.mount.mkdir()
            lost = volume.mount / 'lost+found'; lost.mkdir()
            with self.assertRaises(RuntimeError): volume._prepare_empty_ledger()
            self.assertTrue(lost.exists())

    def test_fault_mount_layout_is_not_an_arbitrary_path(self):
        self.assertEqual(BoundedExt4('/exclusive', 'ledger').mount, Path('/exclusive/ledger'))
        for name in ('/', '../ledger', 'firecracker', '/srv', ''):
            with self.assertRaises(ValueError): BoundedExt4('/exclusive', name)

    def test_no_readonly_mutation_on_unmounted_or_unowned_volume(self):
        with tempfile.TemporaryDirectory() as root, patch('kvm_storage.subprocess.run') as run:
            volume = BoundedExt4(root)
            with self.assertRaises(RuntimeError): volume.fill('readonly')
            with self.assertRaises(RuntimeError): volume._remount(True)
            # A failed exact-binding check also forbids restoration, not just
            # injection. Do not change a reused device to make cleanup pass.
            volume.mounted = True
            with self.assertRaises(RuntimeError): volume.release()
            run.assert_not_called()

    def test_readonly_probe_checks_prefault_directory_fd_and_exact_errno(self):
        volume = BoundedExt4('/exclusive')
        with patch.object(volume, '_check'), patch('kvm_storage.os.open', side_effect=OSError(errno.EROFS, 'fixture')) as op:
            self.assertEqual(volume.probe(errno.EROFS, dir_fd=73), {'errno': errno.EROFS, 'phase': 'open'})
            self.assertEqual(op.call_args.args[0], '.enospc-probe')
            self.assertEqual(op.call_args.kwargs['dir_fd'], 73)
        for actual in (errno.ENOSPC, errno.EACCES, errno.EIO):
            with patch.object(volume, '_check'), patch('kvm_storage.os.open', side_effect=OSError(actual, 'fixture')):
                with self.assertRaises(OSError) as error: volume.probe(errno.EROFS)
                self.assertEqual(error.exception.errno, actual)

    def test_readonly_injection_keeps_directory_open_across_remount(self):
        volume = BoundedExt4('/exclusive')
        usage = SimpleNamespace(f_flag=0, f_blocks=1024, f_frsize=4096, f_bavail=512, f_favail=400)
        seen = []
        def remount(ro):
            seen.append(('remount', ro)); usage.f_flag = os.ST_RDONLY
        def probe(expected_errno, **kw):
            self.assertEqual(expected_errno, errno.EROFS)
            seen.append(('probe', kw)); return {'errno': errno.EROFS, 'phase': 'open'}
        def op(*args): seen.append(('open', args)); return 73
        with patch.object(volume, '_check', return_value=usage), patch.object(volume, '_remount', side_effect=remount):
            with patch.object(volume, 'probe', side_effect=probe), patch('kvm_storage.os.open', side_effect=op), patch('kvm_storage.os.close') as close:
                value = volume.fill('readonly')
                self.assertTrue(value['statvfs_readonly']); close.assert_called_once_with(73)
        self.assertEqual([row[0] for row in seen], ['open', 'remount', 'probe', 'probe'])
        self.assertEqual(seen[-1][1], {'dir_fd': 73})

    def test_release_reads_kernel_flags_even_without_injection_completion(self):
        volume = BoundedExt4('/exclusive'); volume.mounted = True
        with patch.object(volume, '_check', return_value=SimpleNamespace(f_flag=os.ST_RDONLY)):
            with patch.object(volume, '_remount') as remount, patch.object(volume, 'probe') as probe:
                volume.release()
                remount.assert_called_once_with(False); probe.assert_called_once_with(expected_errno=0)

    def test_remount_checks_identity_before_and_flags_after_mutation(self):
        volume = BoundedExt4('/exclusive')
        with patch.object(volume, '_check', side_effect=[SimpleNamespace(f_flag=0), SimpleNamespace(f_flag=os.ST_RDONLY)]):
            with patch('kvm_storage.subprocess.run') as run:
                volume._remount(True)
                self.assertEqual(run.call_args.args[0], ['mount', '-n', '-o', 'remount,ro,nosuid,nodev,noexec', '/exclusive/m'])
                self.assertEqual(run.call_args.kwargs, {'check': True, 'timeout': 15})
        with patch.object(volume, '_check', return_value=SimpleNamespace(f_flag=0)):
            with patch('kvm_storage.subprocess.run'), self.assertRaises(RuntimeError): volume._remount(True)

    def test_finite_observation_guard_not_unbounded_or_nan(self):
        for value in (0, 100, 1500, 4000):
            self.assertEqual(validate_host_stop_guard(value), value)
        for value in (-1, 99, 4001, float('nan'), float('inf')):
            with self.assertRaises(ValueError): validate_host_stop_guard(value)

    def test_no_fill_on_plain_directory_or_unmounted_volume(self):
        with tempfile.TemporaryDirectory() as root:
            volume = BoundedExt4(root)
            for mode in ('blocks', 'inodes'):
                with self.assertRaises(RuntimeError): volume.fill(mode)
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_same_namespace_cannot_mount_or_fill(self):
        with patch('os.readlink', return_value='mnt:[123]'):
            with self.assertRaises(RuntimeError): require_private_namespace('mnt:[123]')

    def test_propagating_mount_namespace_is_rejected(self):
        with patch('os.readlink', side_effect=['mnt:[456]', 'mnt:[123]']):
            with patch.object(Path, 'read_text', return_value='10 1 8:1 / / rw shared:1 - ext4 /dev/fake rw\n'):
                with self.assertRaises(RuntimeError): require_private_namespace('mnt:[123]')


if __name__ == '__main__':
    unittest.main()

class ClosedStorageRestartTests(unittest.TestCase):
    def test_expected_errno_and_no_output_are_not_durable_log_ack(self):
        for code, line in ((errno.EROFS, b'sandboxd: read-only file system\n'),
                           (errno.ENOSPC, b'sandboxd: no space left on device\n')):
            probe={'errno':code,'phase':'open'}
            self.assertEqual(validate_failed_fault_restart(1,b'',line,code,probe,probe),'closed_errno_stderr')
            self.assertEqual(validate_failed_fault_restart(1,b'',b'',code,probe,probe),'no_inherited_output')
            for exit_code, out, error in ((0,b'',line),(-9,b'',line),(2,b'',line),(1,b'secret',line),
                                          (1,b'',b'sandboxd: configuration or bootstrap failure\n'),
                                          (1,b'',b'private raw path: '+line)):
                with self.assertRaises(AssertionError):validate_failed_fault_restart(exit_code,out,error,code,probe,probe)
            for bad in ({'errno':errno.EIO,'phase':'open'}, {'errno':True,'phase':'open'},
                        {'errno':code,'phase':'unknown'}, {'errno':code,'phase':'open','unrecognized':1}):
                with self.assertRaises(AssertionError):validate_failed_fault_restart(1,b'',b'',code,probe,bad)
    def test_live_socket_is_not_absence_and_unrelated_errno_does_not_pass(self):
        import socket
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'s';self.assertTrue(no_unix_listener(path))
            s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                s.bind(str(path));s.listen(1)
                with self.assertRaises(AssertionError):no_unix_listener(path)
            finally:s.close()
            self.assertTrue(no_unix_listener(path))
