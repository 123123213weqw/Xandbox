import copy
import io
import json
import stat
import tempfile
from pathlib import Path
import unittest

from build_nested_host import init_scripts, validate_manifest
from kvm_nested_host import JSONSocket, replace_private_json


class NestedFixtureTests(unittest.TestCase):
    def test_state_io_profile_cannot_mount_backing_disk_bypassing_l1_mapper(self):
        bootstrap,service=init_scripts([],state_io=True)
        self.assertIn('switch_root',bootstrap)
        self.assertNotIn('mount -t ext4',service)
        self.assertTrue(service.endswith('exec /usr/bin/xandbox-host-fixture -mode node-io >/dev/console 2>&1\n'))
    def test_root_private_receipt_and_policy_can_be_replaced_for_next_incarnation(self):
        with tempfile.TemporaryDirectory() as temporary:
            p=Path(temporary)/'policy.json'
            replace_private_json(p,{'generation':1})
            first=p.stat().st_ino
            replace_private_json(p,{'generation':2})
            self.assertEqual(json.loads(p.read_text()),{'generation':2})
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
            self.assertNotEqual(first,p.stat().st_ino)
            self.assertEqual(list(Path(temporary).iterdir()),[p])

    def test_l1_switches_off_special_rootfs_before_mounting_or_launching_services(self):
        bootstrap,service=init_scripts(['kvm.ko'])
        self.assertIn('size=256m',bootstrap)
        self.assertIn('[ "$entry" = /newroot ] || cp -a',bootstrap)
        self.assertTrue(bootstrap.endswith('exec switch_root -c /dev/console /newroot /sbin/xandbox-host-init\n'))
        self.assertNotIn('insmod',bootstrap)
        self.assertNotIn('cgroup2',bootstrap)
        self.assertLess(service.index('mount -t devtmpfs'),service.index('insmod /lib/fixture/kvm.ko'))
        self.assertLess(service.index('mount -t ext4 -o rw,nosuid'),service.index('exec /usr/bin/xandbox-host-fixture'))
        self.assertNotIn('nodev',service)

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
