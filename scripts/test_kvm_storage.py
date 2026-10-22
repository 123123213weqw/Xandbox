import errno
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from kvm_storage import BoundedExt4, require_private_namespace
from kvm_storage_faults import validate_host_stop_guard


class BoundedStorageTests(unittest.TestCase):
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
