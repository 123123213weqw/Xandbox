import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

from build_guest_image import safe_guest_filter


@unittest.skipUnless(hasattr(tarfile, "data_filter"), "requires security-patched tarfile")
class GuestImageExtractionTests(unittest.TestCase):
    def test_absolute_guest_link_is_rewritten_inside_tree(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            link = tarfile.TarInfo("usr/bin/yes")
            link.type, link.linkname = tarfile.SYMTYPE, "/bin/busybox"
            archive.addfile(link)
            payload = b"not-an-executable"
            binary = tarfile.TarInfo("bin/busybox")
            binary.size = len(payload)
            archive.addfile(binary, io.BytesIO(payload))
        data.seek(0)
        with tempfile.TemporaryDirectory() as root, tarfile.open(fileobj=data) as archive:
            archive.extractall(root, filter=safe_guest_filter)
            link = Path(root) / "usr/bin/yes"
            self.assertFalse(os.path.isabs(os.readlink(link)))
            self.assertEqual(link.read_bytes(), b"not-an-executable")

    def test_rejects_parent_and_indirect_symlink_escape(self):
        with tempfile.TemporaryDirectory() as root:
            for name, target in (("escape", "../../outside"), ("dir/link", "../../../outside")):
                link = tarfile.TarInfo(name)
                link.type, link.linkname = tarfile.SYMTYPE, target
                with self.assertRaises(ValueError):
                    safe_guest_filter(link, root)
            os.symlink("/", Path(root) / "host")
            link = tarfile.TarInfo("link")
            link.type, link.linkname = tarfile.SYMTYPE, "host/etc"
            with self.assertRaises(ValueError):
                safe_guest_filter(link, root)

    def test_rejects_special_and_hardlink_escape(self):
        with tempfile.TemporaryDirectory() as root:
            device = tarfile.TarInfo("device")
            device.type = tarfile.CHRTYPE
            with self.assertRaises(ValueError):
                safe_guest_filter(device, root)
            link = tarfile.TarInfo("hard")
            link.type, link.linkname = tarfile.LNKTYPE, "../outside"
            with self.assertRaises(tarfile.FilterError):
                safe_guest_filter(link, root)


if __name__ == "__main__":
    unittest.main()
