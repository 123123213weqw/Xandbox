import copy
import io
import json
from pathlib import Path
import unittest

from build_nested_host import validate_manifest
from kvm_nested_host import JSONSocket


class NestedFixtureTests(unittest.TestCase):
    def test_manifest_cannot_copy_an_arbitrary_host_file_or_kernel(self):
        good=json.loads(Path(__file__).with_name('nested_host_assets.json').read_text())
        validate_manifest(good)
        variants=[]
        for key,value in (('test_only',False),('architecture','arm64'),('l1_kernel_release','../../etc'),('qemu_sha256','unverified')):
            bad=copy.deepcopy(good);bad[key]=value;variants.append(bad)
        bad=copy.deepcopy(good);bad['modules_sha256']['/etc/shadow']='a'*64;variants.append(bad)
        bad=copy.deepcopy(good);bad['modules_sha256']=dict(reversed(list(bad['modules_sha256'].items())));variants.append(bad)
        for bad in variants:
            with self.assertRaises(ValueError):validate_manifest(bad)

    def test_private_control_frame_is_bounded_and_not_eof_success(self):
        control=JSONSocket.__new__(JSONSocket)
        control.file=io.BytesIO(b'{"ok":true}\n')
        self.assertEqual(control.read(),{'ok':True})
        for raw in (b'',b'x'*65537):
            control.file=io.BytesIO(raw)
            with self.assertRaises(AssertionError):control.read()


if __name__=='__main__':unittest.main()
