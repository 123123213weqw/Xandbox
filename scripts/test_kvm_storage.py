from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from kvm_storage import BoundedExt4, require_private_namespace
from kvm_storage_faults import validate_host_stop_guard


class BoundedStorageTests(unittest.TestCase):
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
