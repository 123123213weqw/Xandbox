import copy
import io
import json
import stat
import tempfile
from pathlib import Path
import unittest

from build_nested_host import init_scripts, validate_manifest
from kvm_nested_host import JSONSocket, replace_private_json, quota_format_options, validate_negative_setup, validate_unenforced_setup, validate_quota_clear_checkpoint, validate_quota_clear_recovery, validate_quota_syscall_setup, validate_quota_barrier_checkpoint, validate_quota_barrier_recovery


class NestedFixtureTests(unittest.TestCase):
    def test_quota_barrier_requires_actual_filesystem_stack_and_prefork_cold_recovery(self):
        checkpoint=('checkpoint_receipt_fsynced_before_set','pre_fork_namespace_absent_before_suspend','durable_attempted_owner_before_set','installed_limits_checked_before_suspend','ordinary_qsync_returned_before_syncfs','notification_continued_into_real_kernel','actual_syncfs_syscall_D_filesystem_stack_not_seccomp','actual_kernel_hold_rechecked_three_times','no_create_ack_while_commit_held','capacity_retained_new_create503','no_quota_or_srv_reads_after_suspend','mapper_still_suspended_until_power_cut','no_l2_vm_born_at_checkpoint')
        recovery=('l1_boot_changed','attempted_owner_bytes_policy_and_absent_namespace_before_daemon','unreturned_commit_empty_or_known_limits_checked','no_assigned_guest_restore','old_durable_destroyed','old_resources_absent','old_key_refused410','fresh_real_kvm_uid_exec_destroy_uninstrumented_launch','all_fixed_project_records_cleared','owned_cgroup_root_removed')
        for fn,keys,extra in ((validate_quota_barrier_checkpoint,checkpoint,{'fixed_project_zero_dirty_bytes':4<<20}),(validate_quota_barrier_recovery,recovery,{'cold_quota_record_empty':True})):
            good={'phase':'reserve-quota-syncfs-held',**{k:True for k in keys},**extra};fn(good)
            for k in keys:
                bad=dict(good);bad[k]=False
                with self.assertRaises(AssertionError):fn(bad)
                bad=dict(good);del bad[k]
                with self.assertRaises(KeyError):fn(bad)
            with self.assertRaises(AssertionError):fn(dict(good,phase='running'))
            for k in extra:
                with self.assertRaises(AssertionError):fn(dict(good,**{k:0}))

    def test_quota_syscall_setup_requires_each_exact_errno_and_ordinary_recovery_proof(self):
        common=('test_only_seccomp_errno','fixed_child_thread_and_anchor_verified','durable_attempted_owner_before_injection','kernel_limits_and_zero_usage_checked_at_boundary','no_execution_namespace_at_injected_boundary','real_kernel_continue_not_emulated_success','durable_destroyed_resources_absent_key410','capacity_reused_fresh_real_kvm_guest_uid_exec_destroy','all_thread_caps_nnp_observer_and_ordinary_vmm_filters_checked','all_fixed_projects_cleared','owned_cgroup_root_removed')
        good={k:True for k in ('test_only_syscall_errno_injection','ordinary_daemon_elf_unchanged','not_physical_media_fault','all_fixed_projects_cleared')}
        good['all_fixed_syscall_cases']=[]
        for name in ('reserve-set-eio','reserve-read-erofs','reserve-sync-eio','clear-set-eio','clear-sync-erofs','clear-read-eio'):
            r={'case':name,'injected_calls':1,'continued_kernel_calls':20,**{k:True for k in common}}
            if name.startswith('reserve-'):r['prepare_refused500']=True
            else:r.update(reclaiming_owner_and_capacity_retained_while_errno_armed=True,new_create_refused503_during_clear_failure=True)
            good['all_fixed_syscall_cases'].append(r)
        validate_quota_syscall_setup(good)
        for i,r in enumerate(good['all_fixed_syscall_cases']):
            for k,v in r.items():
                if v is True:
                    bad=copy.deepcopy(good);bad['all_fixed_syscall_cases'][i][k]=False
                    with self.assertRaises(AssertionError):validate_quota_syscall_setup(bad)
                    bad=copy.deepcopy(good);del bad['all_fixed_syscall_cases'][i][k]
                    with self.assertRaises(KeyError):validate_quota_syscall_setup(bad)
            for k in ('injected_calls','continued_kernel_calls'):
                for value in (0,False,-1):
                    bad=copy.deepcopy(good);bad['all_fixed_syscall_cases'][i][k]=value
                    with self.assertRaises(AssertionError):validate_quota_syscall_setup(bad)
        for records in ([],good['all_fixed_syscall_cases'][:-1],list(reversed(good['all_fixed_syscall_cases']))):
            with self.assertRaises(AssertionError):validate_quota_syscall_setup(dict(good,all_fixed_syscall_cases=records))
        bad=copy.deepcopy(good);bad['all_fixed_syscall_cases'][0]['injected_calls']=2
        with self.assertRaises(AssertionError):validate_quota_syscall_setup(bad)

    def test_quota_clear_report_rejects_every_missing_boundary_or_recovery_proof(self):
        checkpoint=('real_nested_kvm','guest_uid_checked','checkpoint_receipt_fsynced','two_simultaneous_ordinary_snapshot_clones','private_projects_distinct','catalog_pins_two_checked_before_barrier','ordinary_post_quota_sync_catalog_fd_observed','victim_quota_zero_namespace_absent_owner_retained','victim_durable_reclaiming_not_destroyed','zero_quota_did_not_release_capacity_503','keeper_real_vm_data_execution_survived','only_two_known_shared_links_removed','no_observer_quota_sync_after_clear_boundary','pid1_lock_retained_until_l1_power_cut')
        recovery=('l1_boot_changed','old_durable_destroyed','old_resources_absent','old_key_refused_410','fresh_real_kvm_exec_destroy','fresh_guest_boot_changed','cleared_victim_quota_zero_before_daemon_recovery','both_durable_owners_and_two_pins_retained_across_cold_boot','keeper_quota_namespace_and_shared_content_checked_before_recovery','keeper_old_destroyed_resources_absent_key410','both_old_pins_released_active_template_unchanged','all_private_project_ids_cleared')
        for function,keys in ((validate_quota_clear_checkpoint,checkpoint),(validate_quota_clear_recovery,recovery)):
            good={'phase':'quota-cleared-owner-pinned',**{key:True for key in keys}}
            function(good)
            for key in keys:
                bad=dict(good);bad[key]=False
                with self.assertRaises(AssertionError):function(bad)
                bad=dict(good);del bad[key]
                with self.assertRaises(KeyError):function(bad)
            with self.assertRaises(AssertionError):function(dict(good,phase='destroyed'))

    def test_quota_io_profile_loads_quota_but_never_mounts_backing_bypassing_mapper(self):
        _,service=init_scripts(['quota_tree.ko','quota_v2.ko'],quota_state_io=True)
        self.assertNotIn('mount -t ext4',service)
        self.assertIn('insmod /lib/fixture/quota_v2.ko',service)
        self.assertTrue(service.endswith('exec /usr/bin/xandbox-host-fixture -mode node-quota-io >/dev/console 2>&1\n'))
        for other in ('state_io','quota_probe','quota_driver','quota_snapshot','quota_unenforced'):
            with self.assertRaises(ValueError):init_scripts([],quota_state_io=True,**{other:True})

    def test_unenforced_profile_is_fresh_ext4_not_quotaoff_or_fake_kvm_acceptance(self):
        _,service=init_scripts(['quota_tree.ko','quota_v2.ko'],quota_unenforced=True)
        self.assertIn('mount -t ext4 -o rw,nosuid /dev/vda /srv',service)
        self.assertNotIn('prjquota',service)
        self.assertTrue(service.endswith('exec /usr/bin/xandbox-host-fixture -mode node-quota-unenforced >/dev/console 2>&1\n'))
        for other in ('state_io','quota_probe','quota_driver','quota_snapshot'):
            with self.assertRaises(ValueError):init_scripts([],quota_unenforced=True,**{other:True})
        good={key:True for key in ('ordinary_daemon','fresh_writable_ext4_without_project_enforcement','specific_enforcement_startup_rejection_checked','no_api_or_backend_ownership_or_generation_domain','fixed_child_reaped','no_quota_on_off_or_mount_policy_mutation')}
        good['l2_vms_started']=0
        validate_unenforced_setup(good)
        variants=[{},dict(good,l2_vms_started=False),dict(good,l2_vms_started=1)]
        for key,value in good.items():
            if value is True:variants.append(dict(good,**{key:False}))
        for bad in variants:
            with self.assertRaises(AssertionError):validate_unenforced_setup(bad)

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
