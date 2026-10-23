import copy
import io
import json
import stat
import tempfile
from pathlib import Path
import unittest

from build_nested_host import init_scripts, validate_manifest
from kvm_nested_host import JSONSocket, replace_private_json, quota_format_options, validate_negative_setup, validate_unenforced_setup, validate_quota_clear_checkpoint, validate_quota_clear_recovery, validate_quota_syscall_setup, validate_quota_barrier_checkpoint, validate_quota_barrier_recovery, validate_quota_commit_checkpoint, validate_quota_commit_recovery, COMMIT_PROFILES, validate_quota_listener_checkpoint, validate_quota_listener_recovery, LISTENER_PROFILES, nested_resources, QUOTA_SWITCH_MAX_FRAME, validate_quota_switch_setup, validate_quota_switch_run, validate_quota_switch_recovery, validate_quota_switch_checkpoint


class NestedFixtureTests(unittest.TestCase):
    def test_explicit_switch_resources_and_image_preserve_legacy_bounds(self):
        self.assertEqual(nested_resources(False),{'profile':'','memory_mib':2048,'disk_bytes':2<<30,'cgroup_memory_max':3<<30})
        self.assertEqual(nested_resources(True),{'profile':'quota-switch-v1','memory_mib':3072,'disk_bytes':4<<30,'cgroup_memory_max':4<<30})
        for v in (1,None,'switch'):
            with self.assertRaises(AssertionError):nested_resources(v)
        _,service=init_scripts(['quota_tree.ko','quota_v2.ko'],quota_switch=True)
        self.assertIn('rw,nosuid,prjquota',service)
        self.assertTrue(service.endswith('exec /usr/bin/xandbox-host-fixture -mode node-quota-switch >/dev/console 2>&1\n'))
        for other in ('state_io','quota_probe','quota_driver','quota_snapshot','quota_unenforced','quota_state_io'):
            with self.assertRaises(ValueError):init_scripts([],quota_switch=True,**{other:True})

    def test_large_control_reply_is_opt_in_not_a_global_bound_change(self):
        conn=JSONSocket.__new__(JSONSocket)
        raw=json.dumps({'sample':'x'*70000}).encode()+b'\n';conn.file=io.BytesIO(raw)
        with self.assertRaises(AssertionError):conn.read()
        conn.max_frame=QUOTA_SWITCH_MAX_FRAME;conn.file=io.BytesIO(raw);self.assertEqual(len(conn.read()['sample']),70000)
        conn.file=io.BytesIO(b'x'*(QUOTA_SWITCH_MAX_FRAME+1))
        with self.assertRaises(AssertionError):conn.read()

    def test_switch_setup_and_cold_recovery_require_every_explicit_boundary(self):
        pre=('four_simultaneous_real_kvm_quota_guests','four_distinct_private_projects_and_shared_readonly_project_zero_inodes','independent_named_inode_accounting_before_benchmark','alpha_fourth429_with_spare_node_slot_beta_still_executes','node_fifth503_below_beta_tenant_quota','authentication401_and_cross_tenant404','old_key410_resources_absent_quota_zero_before_controlled_slot_reuse','same_uid_project_reused_only_as_fresh_ref_boot_and_workspace','beta_execution_and_data_survived_alpha_recycle','all_eight_projects_zero_and_active_catalog_pins_zero')
        base=('genuine_l1_unassigned_template_built','l1_host_abi_checked','builder_two_independent_clones_checked','builder_runtime_reclaimed','ordinary_catalog_published_and_activated')
        good={'fixed_node_capacity':4,'fixed_tenant_capacity':3,'fixed_uid_project_slots':8,'ordinary_production_no_test_observer':True,'genuine_l1_snapshot_setup':{**{k:True for k in base},'snapshot_memory_bytes':512<<20},'preflight':{k:True for k in pre}}
        validate_quota_switch_setup(good)
        for k in pre:
            bad=copy.deepcopy(good);bad['preflight'][k]=False
            with self.assertRaises(AssertionError):validate_quota_switch_setup(bad)
        flags=('l1_boot_changed','two_exact_owners_policy_shared_backing_and_independent_quota_checked_before_daemon','two_old_execution_domains_absent','two_pins_retained_before_ordinary_recovery','old_sessions_closed_exec_and_create_keys410_no_old_job_resume','both_old_generations_destroyed_resources_absent','two_fresh_real_kvm_guest_uids_workspaces_and_boots_checked','all_eight_project_records_zero_and_active_template_pins_zero','controller_reaped_and_owned_cgroup_root_removed','no_assigned_guest_restored_or_exported')
        checkpoint=('real_nested_kvm','checkpoint_receipt_fsynced','two_live_tenant_sessions_and_running_old_jobs','distinct_private_projects_with_named_inode_accounting','two_active_template_pins_checked','ordinary_quota_ready_owners_saved_privately','checkpoint_after_measured_load_not_an_inflight_commit_fault')
        cp={'phase':'quota-enabled-two-tenant-switching',**{k:True for k in checkpoint}};validate_quota_switch_checkpoint(cp)
        for k in checkpoint:
            with self.assertRaises(AssertionError):validate_quota_switch_checkpoint(dict(cp,**{k:False}))
        rec={'phase':'quota-enabled-two-tenant-switching' ,**{k:True for k in flags}};validate_quota_switch_recovery(rec)
        for k in flags:
            with self.assertRaises(AssertionError):validate_quota_switch_recovery(dict(rec,**{k:False}))
            with self.assertRaises(KeyError):validate_quota_switch_recovery({a:b for a,b in rec.items() if a!=k})

    def test_full_switch_validator_cannot_pass_fewer_idle_or_unmeasured_rows(self):
        keys=('request_to_binding_response_ms','request_to_first_new_command_success_ms','request_to_old_host_stopped_observed_ms','request_to_old_durable_destroyed_observed_ms')
        checkpoint=('real_nested_kvm','checkpoint_receipt_fsynced','two_live_tenant_sessions_and_running_old_jobs','distinct_private_projects_with_named_inode_accounting','two_active_template_pins_checked','ordinary_quota_ready_owners_saved_privately','checkpoint_after_measured_load_not_an_inflight_commit_fault')
        resource={k:0 for k in ('allocated','stop_queued','cleanup_queued','stop_running','cleanup_running','owned_cgroup_count','durable_owner_files','nontransactional_nonempty_quota_slots','nontransactional_quota_space_bytes','nontransactional_quota_inodes')};resource['l1_root_free_bytes']=1<<30
        workers=[]
        labels=('binding','first_new_command','old_host_stopped','old_durable_destroyed')
        for tenant in ('alpha','beta'):
            rows=[{'iteration':i+1,'session_ordinal':i//48+1,'completed':True,'busy_old_job_running_at_switch_request':True,'busy_old_guest_write_progress_checked':True,'old_job_earliest_timeout_budget_ms_at_switch_request':59000,'old_job_terminal':'HISTORY_DROPPED_AFTER_RECLAIM','workload_start_ms':i*1500,'workload_end_ms':i*1500+10,'switch_start_ms':i*1500+10,'switch_end_ms':i*1500+50,**{k:20 for k in keys},'server_phase_observations':{'measured':True}} for i in range(120)]
            workers.append({'tenant':tenant,'samples':rows,'summary_ms':{label:{'count':120,'p50':20,'p95':20,'p99':20,'p100':20} for label in labels}})
        good={'phase':'quota-enabled-two-tenant-switching','load':{'passed':True,'cycles_per_tenant':120,'minimum_paced_seconds':180,'fixed_run_budget_seconds':720,'duration_seconds':180.1,'busy_old_writer_each_switch':True,'no_operator_quota_sync_during_measured_switches':True,'same_initial_session_key_isolated_between_tenants':True,'workers':workers,'cross_tenant_overlapping_switch_interval_pairs':120,'resources':[dict(resource) for _ in range(3)],'checkpoint':{k:True for k in checkpoint}}}
        validate_quota_switch_run(good)
        for field,value in [('fixed_run_budget_seconds',600),('cycles_per_tenant',119),('duration_seconds',179),('cross_tenant_overlapping_switch_interval_pairs',0),('busy_old_writer_each_switch',False),('no_operator_quota_sync_during_measured_switches',False)]:
            bad=copy.deepcopy(good);bad['load'][field]=value
            with self.assertRaises(AssertionError):validate_quota_switch_run(bad)
        for field,value in [('completed',False),('busy_old_job_running_at_switch_request',False),('busy_old_guest_write_progress_checked',False),('old_job_terminal','TIMED_OUT'),('old_job_earliest_timeout_budget_ms_at_switch_request',20),('old_job_earliest_timeout_budget_ms_at_switch_request',float('nan')),('request_to_first_new_command_success_ms',float('nan'))]:
            bad=copy.deepcopy(good);bad['load']['workers'][0]['samples'][10][field]=value
            with self.assertRaises(AssertionError):validate_quota_switch_run(bad)
        bad=copy.deepcopy(good);bad['load']['workers'][0]['samples'].pop()
        with self.assertRaises(AssertionError):validate_quota_switch_run(bad)
        bad=copy.deepcopy(good);bad['load']['resources'][-1]['nontransactional_quota_space_bytes']=4096
        with self.assertRaises(AssertionError):validate_quota_switch_run(bad)
        bad=copy.deepcopy(good);bad['load']['workers'][1]['summary_ms']['binding']['p99']=21
        with self.assertRaises(AssertionError):validate_quota_switch_run(bad)

    def test_listener_loss_requires_last_close_actual_enosys_and_retained_state(self):
        common=('fixed_owned_thread_anchor_owner_checked','receipt_fsynced_before_target_set','last_listener_closed_without_notification_response','selected_quotactl_fd_kernel_exit_observed','target_set_not_continued_or_errno_emulated','quota_and_absent_namespace_checked_before_listener_close','durable_reclaiming_stopped_owner_and_admission503_rechecked_three_times','quota_unchanged_while_listener_absent','no_false_destroy_confirmation','listener_never_reattached_before_power_cut')
        for phase,_ in LISTENER_PROFILES.values():
            reserve=phase.startswith('reserve-')
            good={'phase':phase,**{k:True for k in common},'selected_set_kernel_errno':38,'first_return_latch_seen':1,'prepare_refused500':reserve,'checkpoint_has_no_old_l2_vm':reserve,'old_real_kvm_uid_exec_quota_filters_checked':not reserve,'delete_acceptance_allowed_not_destroy_confirmation':not reserve}
            validate_quota_listener_checkpoint(good,phase)
            for k,v in good.items():
                bad=dict(good);del bad[k]
                with self.assertRaises(KeyError):validate_quota_listener_checkpoint(bad,phase)
                values=(not v,0,'true') if type(v) is bool else ('running',) if k=='phase' else (0,False,-1,5,2)
                for x in values:
                    with self.assertRaises(AssertionError):validate_quota_listener_checkpoint(dict(good,**{k:x}),phase)
            with self.assertRaises(AssertionError):validate_quota_listener_checkpoint(good,'untrusted')

    def test_listener_cold_recovery_never_fabricates_old_reserve_guest(self):
        common=('l1_boot_changed','exact_owner_bytes_policy_and_absent_namespace_before_daemon','unexecuted_set_quota_state_checked_before_daemon','old_durable_destroyed_resources_absent_key410','fresh_real_kvm_uid_exec_destroy_uninstrumented_launch','all_fixed_project_records_cleared','owned_cgroup_root_removed','listener_not_recreated_for_recovery')
        for phase,_ in LISTENER_PROFILES.values():
            good={'phase':phase,**{k:True for k in common},'cold_quota_record_empty':phase.startswith('reserve-'),'old_real_guest_boot_changed':phase.startswith('release-')}
            validate_quota_listener_recovery(good,phase)
            for k,v in good.items():
                bad=dict(good);del bad[k]
                with self.assertRaises(KeyError):validate_quota_listener_recovery(bad,phase)
                with self.assertRaises(AssertionError):validate_quota_listener_recovery(dict(good,**{k:('running' if k=='phase' else not v)}),phase)

    def test_repeated_clear_requires_three_replies_and_distinct_post_set_attempts(self):
        common=('test_only_seccomp_errno','fixed_child_thread_and_anchor_verified','durable_attempted_owner_before_injection','kernel_limits_and_zero_usage_checked_at_boundary','no_execution_namespace_at_injected_boundary','real_kernel_continue_not_emulated_success','durable_destroyed_resources_absent_key410','capacity_reused_fresh_real_kvm_guest_uid_exec_destroy','all_thread_caps_nnp_observer_and_ordinary_vmm_filters_checked','all_fixed_projects_cleared','owned_cgroup_root_removed')
        repeat=('at_least_three_clear_error_replies_before_disarm','same_owner_namespace_and_kernel_record_checked_each_reply','clear_target_rearmed_each_cleanup_attempt','durable_reclaiming_ledger_checked_while_errors_armed')
        good={k:True for k in ('test_only_syscall_errno_injection','ordinary_daemon_elf_unchanged','not_physical_media_fault','all_fixed_projects_cleared')};good.update(repeated_clear_minimum=3,all_fixed_syscall_cases=[])
        for name in ('reserve-set-eio','reserve-read-erofs','reserve-sync-eio','clear-set-eio','clear-sync-erofs','clear-read-eio'):
            r={'case':name,'continued_kernel_calls':20,'injected_calls':1 if name.startswith('reserve-') else 3,**{k:True for k in common}}
            if name.startswith('reserve-'):r['prepare_refused500']=True
            else:r.update({k:True for k in repeat},successful_set_continues_before_disarm=1 if name=='clear-set-eio' else 4,reclaiming_owner_and_capacity_retained_while_errno_armed=True,new_create_refused503_during_clear_failure=True)
            good['all_fixed_syscall_cases'].append(r)
        validate_quota_syscall_setup(good,require_repeated=True)
        for v in (True,0,2,4):
            with self.assertRaises(AssertionError):validate_quota_syscall_setup(dict(good,repeated_clear_minimum=v),require_repeated=True)
        for i in range(3,6):
            for k in repeat:
                bad=copy.deepcopy(good);bad['all_fixed_syscall_cases'][i][k]=False
                with self.assertRaises(AssertionError):validate_quota_syscall_setup(bad,require_repeated=True)
            for k,v in [('injected_calls',2),('successful_set_continues_before_disarm',True),('successful_set_continues_before_disarm',2)]:
                bad=copy.deepcopy(good);bad['all_fixed_syscall_cases'][i][k]=v
                with self.assertRaises(AssertionError):validate_quota_syscall_setup(bad,require_repeated=True)
        # Historical verifier defaults retain their original >=1 semantics.
        old=copy.deepcopy(good);del old['repeated_clear_minimum']
        for r in old['all_fixed_syscall_cases'][3:]:r['injected_calls']=1
        validate_quota_syscall_setup(old)

    def test_real_commit_eio_requires_direct_kernel_errno_and_retained_owner(self):
        phase='reserve-quota-syncfs-real-eio'
        flags=('checkpoint_receipt_fsynced_before_set','durable_attempted_owner_before_set','installed_limits_checked_before_fault','ordinary_qsync_returned_before_syncfs','notification_continued_no_errno_or_success_emulation','selected_syncfs_kernel_exit_observed','ordinary_prepare_eio_diagnostic_in_tmpfs','create_refused500','no_false_ready_stop_destroy_confirmation','exact_owner_receipt_persisted_before_eio_for_cold_recheck','admission_new_create503','no_observer_quota_or_srv_reads_after_eio','own_mapper_error_retained_until_power_cut_no_rw_remount','no_l2_vm_born_at_checkpoint')
        good={'phase':phase,**{k:True for k in flags},'fixed_project_zero_dirty_bytes':4<<20,'selected_syncfs_kernel_errno':5,'selected_syncfs_exit_observations':1}
        validate_quota_commit_checkpoint(good,phase)
        for key in good:
            bad=dict(good);del bad[key]
            with self.assertRaises(KeyError):validate_quota_commit_checkpoint(bad,phase)
            values=(False,0,'true') if key in flags else ('running',) if key=='phase' else (False,0,-1,6)
            for v in values:
                with self.assertRaises(AssertionError):validate_quota_commit_checkpoint(dict(good,**{key:v}),phase)
        with self.assertRaises(AssertionError):validate_quota_commit_checkpoint(good,'untrusted')

    def test_release_commit_hold_requires_exact_ordinal_usage_and_fresh_guest_recovery(self):
        flags=('checkpoint_receipt_fsynced_before_delete','old_real_kvm_guest_uid_exec_and_quota_checked','same_durable_owner_checked_at_release_boundary','namespace_and_cgroup_absent_before_suspend','ordinary_qsync_returned_before_selected_syncfs','notification_continued_into_real_kernel','actual_syncfs_syscall_D_filesystem_stack_not_seccomp','actual_kernel_hold_rechecked_three_times','durable_reclaiming_stopped_not_destroyed','capacity_retained_new_create503','no_quota_or_srv_reads_after_suspend','no_observer_sync_after_delete','mapper_still_suspended_until_power_cut')
        recovery=('l1_boot_changed','attempted_owner_bytes_policy_and_absent_namespace_before_daemon','unreturned_commit_empty_or_known_limits_checked','no_assigned_guest_restore','old_durable_destroyed','old_resources_absent','old_key_refused410','fresh_real_kvm_uid_exec_destroy_uninstrumented_launch','all_fixed_project_records_cleared','owned_cgroup_root_removed')
        for phase,_ in COMMIT_PROFILES.values():
            release=phase.startswith('release-')
            rec={'phase':phase,**{k:True for k in recovery},'cold_quota_record_empty':False,'old_real_guest_boot_changed':release}
            validate_quota_commit_recovery(rec,phase)
            with self.assertRaises(AssertionError):validate_quota_commit_recovery(dict(rec,old_real_guest_boot_changed=not release),phase)
            with self.assertRaises(KeyError):validate_quota_commit_recovery({k:v for k,v in rec.items() if k!='old_real_guest_boot_changed'},phase)
            if not release:continue
            post='postclear' in phase
            good={'phase':phase,**{k:True for k in flags},'fixed_project_zero_dirty_bytes':4<<20,'selected_syncfs_ordinal':3 if post else 2,'quota_record_empty_before_suspend':post,'quota_space_before_suspend':0 if post else 4096,'quota_inodes_before_suspend':0 if post else 1}
            validate_quota_commit_checkpoint(good,phase)
            for key in good:
                bad=dict(good);del bad[key]
                with self.assertRaises(KeyError):validate_quota_commit_checkpoint(bad,phase)
            for key in flags:
                with self.assertRaises(AssertionError):validate_quota_commit_checkpoint(dict(good,**{key:False}),phase)
            for key,values in {'selected_syncfs_ordinal':(True,0,2 if post else 3),'quota_record_empty_before_suspend':(not post,0,1),'quota_space_before_suspend':(False,-1,1 if post else (193<<20)),'quota_inodes_before_suspend':(False,-1,1 if post else 129),'fixed_project_zero_dirty_bytes':(True,0,1)}.items():
                for v in values:
                    with self.assertRaises(AssertionError):validate_quota_commit_checkpoint(dict(good,**{key:v}),phase)

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
