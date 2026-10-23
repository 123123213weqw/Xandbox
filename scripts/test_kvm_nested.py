import copy
import io
import json
import stat
import tempfile
from pathlib import Path
import unittest

from build_nested_host import init_scripts, validate_manifest
from kvm_nested_host import JSONSocket, replace_private_json, quota_format_options, validate_negative_setup


class NestedFixtureTests(unittest.TestCase):
    def test_negative_report_requires_every_case_and_no_false_success(self):
        rows=[]
        for name in ('cap','uuid','unknown','binding','block','inode'):
            row={'case':name,'ordinary_daemon':True,'all_fixed_project_records_cleared':True,'owned_cgroup_root_removed':True}
            if name in ('cap','uuid','unknown'):row.update(specific_startup_rejection_checked=True,no_api_socket_after_rejection=True)
            if name=='unknown':row['unknown_record_unchanged_before_owned_fixture_cleanup']=True
            if name=='binding':row['changed_policy_rejected_original_binding_unchanged']=True
            if name in ('block','inode'):
                for key in ('actual_prepare_edquot_private_log_checked','create_refused500','durable_destroyed_and_exact_resources_absent','old_create_key_refused410','same_binding_restart_destroyed_key410_checked','released_capacity_reused_second_edquot_cleaned'):row[key]=True
                row.update(hard_bytes=(16<<20 if name=='block' else 192<<20),hard_inodes=(128 if name=='block' else 1))
            rows.append(row)
        good={'all_fixed_negative_projects_cleared':True,'positive_backend_not_yet_bound':True,'ordinary_daemon_negative_cases':rows}
        validate_negative_setup(good)
        variants=[]
        for key in ('all_fixed_negative_projects_cleared','positive_backend_not_yet_bound'):
            bad=copy.deepcopy(good);bad[key]=False;variants.append(bad)
        bad=copy.deepcopy(good);bad['ordinary_daemon_negative_cases'].pop();variants.append(bad)
        for index,row in enumerate(rows):
            for key,value in row.items():
                if value is True:
                    bad=copy.deepcopy(good);bad['ordinary_daemon_negative_cases'][index][key]=False;variants.append(bad)
        bad=copy.deepcopy(good);bad['ordinary_daemon_negative_cases'][-1]['hard_inodes']=2;variants.append(bad)
        for bad in variants:
            with self.assertRaises(AssertionError):validate_negative_setup(bad)

    def test_snapshot_quota_profile_is_separate_from_cold_and_never_loads_on_l0(self):
        _,service=init_scripts(['quota_tree.ko','quota_v2.ko'],quota_snapshot=True)
        self.assertIn('mount -t ext4 -o rw,nosuid,prjquota /dev/vda /srv',service)
        self.assertTrue(service.endswith('exec /usr/bin/xandbox-host-fixture -mode node-quota-snapshot >/dev/console 2>&1\n'))
        for flags in ({'quota_snapshot':True,'quota_driver':True},{'quota_snapshot':True,'quota_probe':True},{'quota_snapshot':True,'state_io':True}):
            with self.assertRaises(ValueError):init_scripts([],**flags)

    def test_driver_quota_profile_loads_only_inside_owned_l1_and_is_exclusive(self):
        _,service=init_scripts(['quota_tree.ko','quota_v2.ko'],quota_driver=True)
        self.assertIn('mount -t ext4 -o rw,nosuid,prjquota /dev/vda /srv',service)
        self.assertTrue(service.endswith('exec /usr/bin/xandbox-host-fixture -mode node-quota-driver >/dev/console 2>&1\n'))
        for flags in ({'state_io':True,'quota_driver':True},{'quota_probe':True,'quota_driver':True}):
            with self.assertRaises(ValueError):init_scripts([],**flags)

    def test_quota_format_uses_installed_e2fsprogs_extended_option_not_unknown_flag(self):
        self.assertEqual(quota_format_options(False),[])
        self.assertEqual(quota_format_options(True),['-O','project,quota','-E','quotatype=prjquota','-I','256','-b','4096'])

    def test_quota_profile_is_explicit_enforcing_and_mutually_exclusive(self):
        _,service=init_scripts(['quota_tree.ko','quota_v2.ko'],quota_probe=True)
        self.assertIn('mount -t ext4 -o rw,nosuid,prjquota /dev/vda /srv',service)
        self.assertTrue(service.endswith('exec /usr/bin/xandbox-host-fixture -mode node-quota >/dev/console 2>&1\n'))
        self.assertLess(service.index('insmod /lib/fixture/quota_tree.ko'),service.index('insmod /lib/fixture/quota_v2.ko'))
        _,ordinary=init_scripts([])
        self.assertNotIn('prjquota',ordinary)
        self.assertNotIn('quota-drop',ordinary)
        with self.assertRaises(ValueError):init_scripts([],state_io=True,quota_probe=True)

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
        for key,value in (('/etc/shadow','a'*64),('kernel/fs/quota/quota_v2.ko','not-a-digest')):
            bad=copy.deepcopy(good);bad['quota_modules_sha256'][key]=value;variants.append(bad)
        bad=copy.deepcopy(good);bad['quota_modules_sha256']=dict(reversed(list(bad['quota_modules_sha256'].items())));variants.append(bad)
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
