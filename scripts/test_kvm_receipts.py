import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from kvm_driver_smoke import private_resource_receipt, same_owned_directory


class PrivateResourceReceiptTests(unittest.TestCase):
    def test_only_our_successful_mkdir_identity_allows_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'group'; path.mkdir()
            identity = path.lstat()
            self.assertFalse(same_owned_directory(path, None))
            self.assertTrue(same_owned_directory(path, identity))
            original = Path(folder) / 'original'; path.rename(original); path.mkdir()
            self.assertFalse(same_owned_directory(path, identity))
            path.rmdir(); path.symlink_to(original, target_is_directory=True)
            self.assertFalse(same_owned_directory(path, identity))
            path.unlink()
            self.assertFalse(same_owned_directory(path, identity))

    def test_private_exact_bytes_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'receipt.json'
            value = {'version': 1, 'source_revision': 'a' * 40, 'root': '/srv/owned-test-only'}
            before = os.umask(0)
            try: private_resource_receipt(path, value)
            finally: os.umask(before)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text()), value)
            original = path.read_bytes()
            with self.assertRaises(FileExistsError): private_resource_receipt(path, {'replacement': True})
            self.assertEqual(path.read_bytes(), original)

    def test_receipt_symlink_and_size_rejected_without_writing_target(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'target'; target.write_text('unchanged')
            link = Path(folder) / 'link'; link.symlink_to(target)
            with self.assertRaises(OSError): private_resource_receipt(link, {'overwrite': True})
            self.assertEqual(target.read_text(), 'unchanged')
            oversized = Path(folder) / 'oversized'
            with self.assertRaises(ValueError): private_resource_receipt(oversized, {'data': 'x' * 8192})
            self.assertFalse(oversized.exists())


if __name__ == '__main__': unittest.main()
