from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from kvm_storage import BoundedExt4, require_private_namespace


class BoundedStorageTests(unittest.TestCase):
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
