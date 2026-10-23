#!/usr/bin/env python3
"""TEST ONLY: power-cut OWN L1 service host with real L2 KVM. Never reboot L0."""
import argparse
import datetime
import json
import math
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import subprocess
import time
import traceback
import uuid
import re

from build_nested_host import build_initrd, digest, validate_manifest
from kvm_resources import cgroup_empty
from kvm_driver_smoke import wait
from kvm_snapshot_smoke import private_json, sync_dir

DISK_BYTES = 2 << 30
QUOTA_SWITCH_MAX_FRAME = 2 << 20


def quota_format_options(enabled):
    # e2fsprogs 1.46.5 uses the extended quotatype option, NOT a -Q flag.
    return ['-O','project,quota','-E','quotatype=prjquota','-I','256','-b','4096'] if enabled else []



class JSONSocket:
    def __init__(self, path, timeout=90, quota_switch=False):
        assert type(quota_switch) is bool
        self.max_frame=QUOTA_SWITCH_MAX_FRAME if quota_switch else 65536
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.sock.settimeout(timeout)
        self.sock.connect(str(path)); self.file = self.sock.makefile('rb')
    def read(self):
        bound=getattr(self,"max_frame",65536)
        line = self.file.readline(bound+1)
        assert line and len(line) <= bound, 'bounded private control frame required'
        return json.loads(line)
    def send(self, value): self.sock.sendall(json.dumps(value,separators=(',',':')).encode() + b'\n')
    def close(self): self.file.close(); self.sock.close()


def qmp_probe(path, memory_mib=None):
    conn = JSONSocket(path, 5)
    try:
        assert 'QMP' in conn.read()
        def command(op):
            conn.send({'execute': op})
            for _ in range(16):
                value = conn.read()
                if 'return' in value: return value['return']
                assert 'error' not in value
            raise AssertionError('QMP event bound exceeded')
        command('qmp_capabilities')
        assert command('query-kvm') == {'enabled': True, 'present': True}
        assert command('query-status')['running']
        if memory_mib is not None:
            view=command('query-memory-size-summary')
            assert view['base-memory']==memory_mib<<20 and view.get('plugged-memory',0)==0
    finally: conn.close()


def private_group_counters(group):
    values = {}
    for name in ('memory.current', 'memory.peak', 'memory.events', 'pids.current', 'pids.events', 'cgroup.events'):
        try: values[name] = (group/name).read_text()[:4096]
        except OSError: values[name] = 'unavailable'
    return values


def replace_private_json(path, value):
    temporary = path.with_name(path.name + '.new-' + secrets.token_hex(8))
    try:
        private_json(temporary, value)
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        if temporary.exists(): temporary.unlink()


def validate_negative_setup(value):
    assert value['all_fixed_negative_projects_cleared'] is True and value['positive_backend_not_yet_bound'] is True
    rows=value['ordinary_daemon_negative_cases']
    assert [r['case'] for r in rows]==['cap','uuid','unknown','binding','block','inode']
    for r in rows:
        assert all(r[k] is True for k in ('ordinary_daemon','all_fixed_project_records_cleared','owned_cgroup_root_removed'))
        if r['case'] in ('cap','uuid','unknown'):
            assert r['specific_startup_rejection_checked'] is True and r['no_api_socket_after_rejection'] is True
        if r['case']=='unknown': assert r['unknown_record_unchanged_before_owned_fixture_cleanup'] is True
        if r['case']=='binding': assert r['changed_policy_rejected_original_binding_unchanged'] is True
        if r['case'] in ('block','inode'):
            assert all(r[k] is True for k in ('actual_prepare_edquot_private_log_checked','create_refused500','durable_destroyed_and_exact_resources_absent','old_create_key_refused410','same_binding_restart_destroyed_key410_checked','released_capacity_reused_second_edquot_cleaned'))
            assert (r['hard_bytes'],r['hard_inodes'])==((16<<20,128) if r['case']=='block' else (192<<20,1))


def validate_unenforced_setup(value):
    flags=('ordinary_daemon','fresh_writable_ext4_without_project_enforcement','specific_enforcement_startup_rejection_checked','no_api_or_backend_ownership_or_generation_domain','fixed_child_reaped','no_quota_on_off_or_mount_policy_mutation')
    assert set(value)==set(flags)|{'l2_vms_started'}
    assert all(value[key] is True for key in flags)
    assert type(value['l2_vms_started']) is int and value['l2_vms_started']==0


def validate_quota_clear_checkpoint(value):
    assert value['phase']=='quota-cleared-owner-pinned'
    for key in ('real_nested_kvm','guest_uid_checked','checkpoint_receipt_fsynced','two_simultaneous_ordinary_snapshot_clones','private_projects_distinct','catalog_pins_two_checked_before_barrier','ordinary_post_quota_sync_catalog_fd_observed','victim_quota_zero_namespace_absent_owner_retained','victim_durable_reclaiming_not_destroyed','zero_quota_did_not_release_capacity_503','keeper_real_vm_data_execution_survived','only_two_known_shared_links_removed','no_observer_quota_sync_after_clear_boundary','pid1_lock_retained_until_l1_power_cut'): assert value[key] is True


def validate_quota_clear_recovery(value):
    assert value['phase']=='quota-cleared-owner-pinned'
    for key in ('l1_boot_changed','old_durable_destroyed','old_resources_absent','old_key_refused_410','fresh_real_kvm_exec_destroy','fresh_guest_boot_changed','cleared_victim_quota_zero_before_daemon_recovery','both_durable_owners_and_two_pins_retained_across_cold_boot','keeper_quota_namespace_and_shared_content_checked_before_recovery','keeper_old_destroyed_resources_absent_key410','both_old_pins_released_active_template_unchanged','all_private_project_ids_cleared'): assert value[key] is True


def validate_quota_syscall_setup(value, require_repeated=False):
    if require_repeated: assert type(value["repeated_clear_minimum"]) is int and value["repeated_clear_minimum"]==3
    for key in ('test_only_syscall_errno_injection','ordinary_daemon_elf_unchanged','not_physical_media_fault','all_fixed_projects_cleared'): assert value[key] is True
    cases=value['all_fixed_syscall_cases']
    assert [r['case'] for r in cases]==['reserve-set-eio','reserve-read-erofs','reserve-sync-eio','clear-set-eio','clear-sync-erofs','clear-read-eio']
    for r in cases:
        for key in ('test_only_seccomp_errno','fixed_child_thread_and_anchor_verified','durable_attempted_owner_before_injection','kernel_limits_and_zero_usage_checked_at_boundary','no_execution_namespace_at_injected_boundary','real_kernel_continue_not_emulated_success','durable_destroyed_resources_absent_key410','capacity_reused_fresh_real_kvm_guest_uid_exec_destroy','all_thread_caps_nnp_observer_and_ordinary_vmm_filters_checked','all_fixed_projects_cleared','owned_cgroup_root_removed'): assert r[key] is True
        assert type(r['injected_calls']) is int and r['injected_calls']>=1
        assert type(r['continued_kernel_calls']) is int and r['continued_kernel_calls']>=1
        if r['case'].startswith('reserve-'): assert r['prepare_refused500'] is True and r['injected_calls']==1
        else:
            if require_repeated:
                assert r['injected_calls']>=3
                assert type(r['successful_set_continues_before_disarm']) is int
                assert r['successful_set_continues_before_disarm']==1 if r['case']=='clear-set-eio' else r['successful_set_continues_before_disarm']>=4
                for k in ('at_least_three_clear_error_replies_before_disarm','same_owner_namespace_and_kernel_record_checked_each_reply','clear_target_rearmed_each_cleanup_attempt','durable_reclaiming_ledger_checked_while_errors_armed'): assert r[k] is True
            assert r['reclaiming_owner_and_capacity_retained_while_errno_armed'] is True
            assert r['new_create_refused503_during_clear_failure'] is True


def validate_quota_barrier_checkpoint(value):
    assert value['phase']=='reserve-quota-syncfs-held'
    for key in ('checkpoint_receipt_fsynced_before_set','pre_fork_namespace_absent_before_suspend','durable_attempted_owner_before_set','installed_limits_checked_before_suspend','ordinary_qsync_returned_before_syncfs','notification_continued_into_real_kernel','actual_syncfs_syscall_D_filesystem_stack_not_seccomp','actual_kernel_hold_rechecked_three_times','no_create_ack_while_commit_held','capacity_retained_new_create503','no_quota_or_srv_reads_after_suspend','mapper_still_suspended_until_power_cut','no_l2_vm_born_at_checkpoint'): assert value[key] is True
    assert type(value['fixed_project_zero_dirty_bytes']) is int and value['fixed_project_zero_dirty_bytes']==4<<20


def validate_quota_barrier_recovery(value, phase='reserve-quota-syncfs-held'):
    assert value['phase']==phase
    for key in ('l1_boot_changed','attempted_owner_bytes_policy_and_absent_namespace_before_daemon','unreturned_commit_empty_or_known_limits_checked','no_assigned_guest_restore','old_durable_destroyed','old_resources_absent','old_key_refused410','fresh_real_kvm_uid_exec_destroy_uninstrumented_launch','all_fixed_project_records_cleared','owned_cgroup_root_removed'): assert value[key] is True
    assert type(value['cold_quota_record_empty']) is bool


COMMIT_PROFILES = {
    'quota_commit_eio': ('reserve-quota-syncfs-real-eio', 'quota-commit-eio'),
    'quota_release_preclear_hang': ('release-preclear-quota-syncfs-held', 'quota-preclear-hold'),
    'quota_release_postclear_hang': ('release-postclear-quota-syncfs-held', 'quota-postclear-hold'),
}


def validate_quota_commit_checkpoint(value, phase):
    assert phase in {v[0] for v in COMMIT_PROFILES.values()} and value['phase']==phase
    assert type(value['fixed_project_zero_dirty_bytes']) is int and value['fixed_project_zero_dirty_bytes']==4<<20
    if phase=='reserve-quota-syncfs-real-eio':
        flags=('checkpoint_receipt_fsynced_before_set','durable_attempted_owner_before_set','installed_limits_checked_before_fault','ordinary_qsync_returned_before_syncfs','notification_continued_no_errno_or_success_emulation','selected_syncfs_kernel_exit_observed','ordinary_prepare_eio_diagnostic_in_tmpfs','create_refused500','no_false_ready_stop_destroy_confirmation','exact_owner_receipt_persisted_before_eio_for_cold_recheck','admission_new_create503','no_observer_quota_or_srv_reads_after_eio','own_mapper_error_retained_until_power_cut_no_rw_remount','no_l2_vm_born_at_checkpoint')
        assert type(value['selected_syncfs_kernel_errno']) is int and value['selected_syncfs_kernel_errno']==5
        assert type(value['selected_syncfs_exit_observations']) is int and value['selected_syncfs_exit_observations']==1
    else:
        flags=('checkpoint_receipt_fsynced_before_delete','old_real_kvm_guest_uid_exec_and_quota_checked','same_durable_owner_checked_at_release_boundary','namespace_and_cgroup_absent_before_suspend','ordinary_qsync_returned_before_selected_syncfs','notification_continued_into_real_kernel','actual_syncfs_syscall_D_filesystem_stack_not_seccomp','actual_kernel_hold_rechecked_three_times','durable_reclaiming_stopped_not_destroyed','capacity_retained_new_create503','no_quota_or_srv_reads_after_suspend','no_observer_sync_after_delete','mapper_still_suspended_until_power_cut')
        post=phase=='release-postclear-quota-syncfs-held'
        assert type(value['selected_syncfs_ordinal']) is int and value['selected_syncfs_ordinal']==(3 if post else 2)
        assert value['quota_record_empty_before_suspend'] is post
        for key,bound in (('quota_space_before_suspend',192<<20),('quota_inodes_before_suspend',128)):
            assert type(value[key]) is int and 0<=value[key]<=(0 if post else bound)
    for key in flags: assert value[key] is True


def validate_quota_commit_recovery(value, phase):
    assert phase in {v[0] for v in COMMIT_PROFILES.values()}
    validate_quota_barrier_recovery(value, phase)
    assert value['old_real_guest_boot_changed'] is phase.startswith('release-')


LISTENER_PROFILES = {
    'quota_listener_reserve_loss': ('reserve-quota-listener-loss','quota-listener-reserve'),
    'quota_listener_release_loss': ('release-quota-listener-loss','quota-listener-release'),
}


def validate_quota_listener_checkpoint(value, phase):
    assert phase in {v[0] for v in LISTENER_PROFILES.values()} and value['phase']==phase
    for k in ('fixed_owned_thread_anchor_owner_checked','receipt_fsynced_before_target_set','last_listener_closed_without_notification_response','selected_quotactl_fd_kernel_exit_observed','target_set_not_continued_or_errno_emulated','quota_and_absent_namespace_checked_before_listener_close','durable_reclaiming_stopped_owner_and_admission503_rechecked_three_times','quota_unchanged_while_listener_absent','no_false_destroy_confirmation','listener_never_reattached_before_power_cut'): assert value[k] is True
    assert type(value['selected_set_kernel_errno']) is int and value['selected_set_kernel_errno']==38
    assert type(value['first_return_latch_seen']) is int and value['first_return_latch_seen']==1
    reserve=phase=='reserve-quota-listener-loss'
    for k in ('prepare_refused500','checkpoint_has_no_old_l2_vm'): assert value[k] is reserve
    for k in ('old_real_kvm_uid_exec_quota_filters_checked','delete_acceptance_allowed_not_destroy_confirmation'): assert value[k] is (not reserve)


def validate_quota_listener_recovery(value, phase):
    assert phase in {v[0] for v in LISTENER_PROFILES.values()} and value['phase']==phase
    for k in ('l1_boot_changed','exact_owner_bytes_policy_and_absent_namespace_before_daemon','unexecuted_set_quota_state_checked_before_daemon','old_durable_destroyed_resources_absent_key410','fresh_real_kvm_uid_exec_destroy_uninstrumented_launch','all_fixed_project_records_cleared','owned_cgroup_root_removed','listener_not_recreated_for_recovery'): assert value[k] is True
    assert value['cold_quota_record_empty'] is phase.startswith('reserve-')
    assert value['old_real_guest_boot_changed'] is phase.startswith('release-')


def nested_resources(quota_switch):
    assert type(quota_switch) is bool
    return {'profile':'quota-switch-v1' if quota_switch else '', 'memory_mib':3072 if quota_switch else 2048,
            'disk_bytes':(4 if quota_switch else 2)<<30,'cgroup_memory_max':4<<30 if quota_switch else 3<<30}


def nested_copy_resources():
    return {'profile':'quota-copy-v1','memory_mib':3072,'disk_bytes':4<<30,'cgroup_memory_max':4<<30}


def validate_quota_copy_setup(value):
    setup=value['genuine_l1_snapshot_setup']
    for k in ('genuine_l1_unassigned_template_built','l1_host_abi_checked','builder_two_independent_clones_checked','builder_runtime_reclaimed','ordinary_catalog_published_and_activated'):assert setup[k] is True
    assert setup['snapshot_memory_bytes']==512<<20
    v=value['partial_copy']
    for k in ('test_only_write_errno_not_physical_eio','exact_child_thread_fd_owner_and_project_checked','actual_positive_partial_prefix_before_shared_links_and_vmm_birth','healthy_observer_sync_for_stable_prefix_not_latency_measurement','independent_named_inode_quota_accounting','durable_creating_and_exec409_and_capacity503_while_held','retired_template_pins_two_and_gc_zero_at_partial_boundary','live_keeper_data_and_execution_survived','ordinary_prepare500_and_private_eio_diagnostic_checked','victim_destroyed_resources_absent_quota_zero_key410','same_uid_project_reused_only_after_clear_with_new_ref_template_and_clean_guest','new_declaration_only_from_never_assigned_export','retired_backing_survived_until_last_keeper_release','last_pin_gc_removed_exact_old_template','all_four_project_records_zero_controller_reaped_parent_removed'):assert v[k] is True
    assert type(v['partial_workspace_bytes']) is int and v['partial_workspace_bytes']==16<<20
    assert type(v['partial_project_space_bytes']) is int and 16<<20<=v['partial_project_space_bytes']<128<<20 and v['partial_project_space_bytes']%4096==0
    assert type(v['partial_project_inodes']) is int and v['partial_project_inodes']==3
    assert type(v['fixed_write_error_replies']) is int and v['fixed_write_error_replies']==1
    assert type(v['real_kernel_write_continue_replies']) is int and 256<=v['real_kernel_write_continue_replies']<8192


def validate_quota_switch_setup(value):
    assert (value['fixed_node_capacity'],value['fixed_tenant_capacity'],value['fixed_uid_project_slots'])==(4,3,8)
    assert value['ordinary_production_no_test_observer'] is True
    setup=value['genuine_l1_snapshot_setup']
    for k in ('genuine_l1_unassigned_template_built','l1_host_abi_checked','builder_two_independent_clones_checked','builder_runtime_reclaimed','ordinary_catalog_published_and_activated'):assert setup[k] is True
    assert setup['snapshot_memory_bytes']==512<<20
    for k in ('four_simultaneous_real_kvm_quota_guests','four_distinct_private_projects_and_shared_readonly_project_zero_inodes','independent_named_inode_accounting_before_benchmark','alpha_fourth429_with_spare_node_slot_beta_still_executes','node_fifth503_below_beta_tenant_quota','authentication401_and_cross_tenant404','old_key410_resources_absent_quota_zero_before_controlled_slot_reuse','same_uid_project_reused_only_as_fresh_ref_boot_and_workspace','beta_execution_and_data_survived_alpha_recycle','all_eight_projects_zero_and_active_catalog_pins_zero'):assert value['preflight'][k] is True


def validate_quota_switch_run(value):
    assert value['phase']=='quota-enabled-two-tenant-switching'
    load=value['load'];assert load['passed'] is True and load['cycles_per_tenant']==120 and load['minimum_paced_seconds']==180 and load['fixed_run_budget_seconds']==720 and 180<=load['duration_seconds']<=720
    for k in ('busy_old_writer_each_switch','no_operator_quota_sync_during_measured_switches','same_initial_session_key_isolated_between_tenants'):assert load[k] is True
    workers=load['workers'];assert [w['tenant'] for w in workers]==['alpha','beta']
    fields={'binding':'request_to_binding_response_ms','first_new_command':'request_to_first_new_command_success_ms','old_host_stopped':'request_to_old_host_stopped_observed_ms','old_durable_destroyed':'request_to_old_durable_destroyed_observed_ms'}
    for worker in workers:
        rows=worker['samples'];assert len(rows)==120 and not worker.get('failure_stage')
        for i,row in enumerate(rows):
            assert row['iteration']==i+1 and row['session_ordinal']==i//48+1 and row['completed'] is True and row['busy_old_job_running_at_switch_request'] is True
            assert row['old_job_terminal'] in ('CANCELLED','FAILED','EXITED','HISTORY_DROPPED_AFTER_RECLAIM')
            assert row['busy_old_guest_write_progress_checked'] is True
            assert type(row['old_job_earliest_timeout_budget_ms_at_switch_request']) in (int,float) and math.isfinite(row['old_job_earliest_timeout_budget_ms_at_switch_request'])
            assert 0<=row['request_to_old_host_stopped_observed_ms']<row['old_job_earliest_timeout_budget_ms_at_switch_request']<=60000
            assert 0<=row['workload_start_ms']<=row['workload_end_ms']<=row['switch_start_ms']<=row['switch_end_ms']
            for k in fields.values():assert type(row[k]) in (int,float) and math.isfinite(row[k]) and row[k]>=0
            assert row['request_to_first_new_command_success_ms']>=row['request_to_binding_response_ms']
            assert row['request_to_old_durable_destroyed_observed_ms']>=row['request_to_old_host_stopped_observed_ms']
            assert row['server_phase_observations']['measured'] is True
        for label,key in fields.items():
            vals=sorted(r[key] for r in rows);q=worker['summary_ms'][label];assert q['count']==120
            for percentile in (50,95,99,100):assert q['p'+str(percentile)]==vals[math.ceil(120*percentile/100)-1]
    overlaps=sum(a['switch_start_ms']<b['switch_end_ms'] and b['switch_start_ms']<a['switch_end_ms'] for a in workers[0]['samples'] for b in workers[1]['samples'])
    assert load['cross_tenant_overlapping_switch_interval_pairs']==overlaps and overlaps>0
    resources=load['resources'];assert 3<=len(resources)<=1452
    for row in resources:
        assert 0<=row['allocated']<=4 and 0<=row['nontransactional_nonempty_quota_slots']<=8 and row['l1_root_free_bytes']>=256<<20
    final=resources[-1]
    for k in ('allocated','stop_queued','cleanup_queued','stop_running','cleanup_running','owned_cgroup_count','durable_owner_files','nontransactional_nonempty_quota_slots','nontransactional_quota_space_bytes','nontransactional_quota_inodes'):assert final[k]==0


def validate_quota_switch_checkpoint(value):
    assert value['phase']=='quota-enabled-two-tenant-switching'
    for k in ('real_nested_kvm','checkpoint_receipt_fsynced','two_live_tenant_sessions_and_running_old_jobs','distinct_private_projects_with_named_inode_accounting','two_active_template_pins_checked','ordinary_quota_ready_owners_saved_privately','checkpoint_after_measured_load_not_an_inflight_commit_fault','receipts_sampled_after_both_bindings_ready','two_shared_inode_link_counts_captured_consistently'):assert value[k] is True


def validate_quota_switch_recovery(value):
    assert value['phase']=='quota-enabled-two-tenant-switching'
    for k in ('l1_boot_changed','two_exact_owners_policy_shared_backing_and_independent_quota_checked_before_daemon','two_old_execution_domains_absent','two_pins_retained_before_ordinary_recovery','old_sessions_closed_exec_and_create_keys410_no_old_job_resume','both_old_generations_destroyed_resources_absent','two_fresh_real_kvm_guest_uids_workspaces_and_boots_checked','all_eight_project_records_zero_and_active_template_pins_zero','controller_reaped_and_owned_cgroup_root_removed','no_assigned_guest_restored_or_exported'):assert value[k] is True



COPY_CUT_RECEIPT_MAX = 7000
COPY_CUT_CHECKPOINT_FLAGS = ('real_keeper_kvm_uid_data_and_filters_checked', 'attempted_uninitialized_victim_no_vmm_or_shared_links', 'two_durable_owner_pins_read_without_catalog_sync', 'durable_creating_and_request_still_pending', 'zero_selected_write_error_or_continue_reply', 'no_observer_l1_sync_or_receipt_write_after_prefix', 'keeper_baseline_synced_only_before_victim_creation', 'private_receipt_only_over_control_not_l1_disk', 'held_notification_not_actual_filesystem_D')
COPY_CUT_RECOVERY_FLAGS = ('l1_boot_changed', 'private_control_receipt_revalidated_not_l1_disk_receipt', 'exact_attempted_owners_policy_and_pristine_abi_checked_before_daemon', 'old_execution_domains_absent_before_daemon', 'keeper_full_namespace_and_shared_inodes_accounted', 'partial_namespace_subset_policy_and_actual_kernel_quota_accounted', 'two_durable_template_pins_retained_before_recovery', 'ordinary_unobserved_recovery_both_destroyed_resources_absent_keys410_exec409', 'two_fresh_real_guest_uids_boots_and_workspaces_checked', 'retired_backing_two_then_one_pin_gc_and_surviving_exec_checked', 'last_pin_exact_gc_all_four_projects_zero_controller_reaped_parent_removed')


def validate_quota_copy_cut_checkpoint(value):
    setup=value['genuine_l1_snapshot_setup']
    for k in ('genuine_l1_unassigned_template_built','l1_host_abi_checked','builder_two_independent_clones_checked','builder_runtime_reclaimed','ordinary_catalog_published_and_activated'): assert setup[k] is True
    assert setup['snapshot_memory_bytes']==512<<20
    for k in COPY_CUT_CHECKPOINT_FLAGS: assert value[k] is True
    assert type(value['actual_live_workspace_prefix_bytes']) is int and value['actual_live_workspace_prefix_bytes']==16<<20
    for k in ('live_kernel_quota_space_bytes','live_named_allocated_bytes'):
        assert type(value[k]) is int and 0<=value[k]<=192<<20
    for k in ('live_quota_inodes','live_named_inodes'): assert type(value[k]) is int and value[k]==3
    # Delayed allocation is not forced stable or compared to pre-cut quota.


def validate_quota_copy_cut_recovery(value):
    for k in COPY_CUT_RECOVERY_FLAGS: assert value[k] is True
    for k,high in (('cold_partial_entries',3),('cold_partial_workspace_size_bytes',16<<20),('cold_partial_project_space_bytes',192<<20),('cold_partial_project_inodes',3)):
        assert type(value[k]) is int and 0<=value[k]<=high
    assert value['cold_partial_entries']==value['cold_partial_project_inodes']


def copy_cut_recovery_packet(receipt):
    assert type(receipt) is dict and type(receipt.get('version')) is int and receipt['version']==1
    wire=json.dumps(receipt,separators=(',',':')).encode()
    assert 0<len(wire)<=COPY_CUT_RECEIPT_MAX, 'private cut receipt must fit unchanged control scanner'
    packet={'version':1,'operation':'quota-copy-cut-recover','receipt':receipt}
    assert len(json.dumps(packet,separators=(',',':')).encode())+1<8192
    return packet


def detach_copy_cut_checkpoint(out,private_path):
    # OUTER L0 storage only. Never write this receipt into the L1 disk, or
    # attach it to the public result/report/archive. Exclusive0600 file.
    assert out['ok'] is True
    receipt=out.pop('private_receipt')
    copy_cut_recovery_packet(receipt)
    validate_quota_copy_cut_checkpoint(out['result'])
    assert 'private_receipt' not in out['result']
    private_json(private_path,receipt)
    return out['result'],receipt



OWNER_CUT_CHECKPOINT_FLAGS = ('two_real_initialized_guest_uids_boots_data_and_filters_checked','exact_daemon_directory_fd_inode_and_post_unlink_fsync_checked','victim_jail_cgroup_absent_and_quota_policy_usage_times_zero_before_owner_commit','victim_owner_unlink_visible_but_directory_fsync_has_not_returned','catalog_interprocess_lock_still_held_during_directory_commit','ledger_and_api_reclaiming_stopped_not_destroyed_exec409_capacity503','keeper_actual_kvm_domain_retained_and_post_cleanup_links_accounted','keeper_post_target_guest_command_not_issued','no_observer_sync_admin_or_l1_receipt_after_selected_unlink','private_receipt_only_control_to_outer_l0','zero_target_error_or_continue_reply_notification_wait_not_filesystem_D','delete202_was_intent_only_not_a_pending_http_request')
OWNER_CUT_RECOVERY_FLAGS = ('l1_boot_changed','exact_policy_export_abi_index_and_reclaiming_ledger_checked_before_daemon','victim_namespace_absent_and_completed_quota_clear_remained_zero','keeper_post_cleanup_full_metadata_shared_inodes_and_quota_accounted','cold_known_owners_only_no_fixture_owner_restore_or_unknown_quota_adoption','old_execution_domains_absent_before_daemon','ordinary_unobserved_recovery_both_destroyed_resources_absent_keys410_exec409','two_fresh_real_guest_uids_boots_and_workspaces_checked','retired_backing_two_then_one_pin_gc_and_surviving_exec_checked','last_pin_exact_gc_all_four_projects_zero_controller_reaped_parent_removed')


def validate_quota_owner_cut_checkpoint(value):
    setup=value['genuine_l1_snapshot_setup']
    for k in ('genuine_l1_unassigned_template_built','l1_host_abi_checked','builder_two_independent_clones_checked','builder_runtime_reclaimed','ordinary_catalog_published_and_activated'): assert setup[k] is True
    assert setup['snapshot_memory_bytes']==512<<20
    for k in OWNER_CUT_CHECKPOINT_FLAGS: assert value[k] is True
    count=value['other_fsync_continue_reply_submissions']
    assert type(count) is int and 0<count<8192


def validate_quota_owner_cut_recovery(value):
    for k in OWNER_CUT_RECOVERY_FLAGS: assert value[k] is True
    assert type(value['cold_victim_owner_present']) is bool
    assert type(value['cold_durable_owner_pins']) is int and value['cold_durable_owner_pins']==(2 if value['cold_victim_owner_present'] else 1)


def owner_cut_recovery_packet(receipt):
    packet=copy_cut_recovery_packet(receipt)
    packet['operation']='quota-owner-cut-recover'
    assert len(json.dumps(packet,separators=(',',':')).encode())+1<8192
    return packet


def detach_owner_cut_checkpoint(out,private_path):
    assert out['ok'] is True
    receipt=out.pop('private_receipt')
    owner_cut_recovery_packet(receipt)
    validate_quota_owner_cut_checkpoint(out['result'])
    assert 'private_receipt' not in out['result']
    private_json(private_path,receipt)
    return out['result'],receipt



NODE_BUDGET_CHECKPOINT_FLAGS = ('real_nested_kvm','checkpoint_receipt_fsynced','node_schema3_exact_frontend_counts_and_parent_control_placement_enforced','wrong_limits_and_wrong_control_subtree_rejected_before_binding_and_api','four_simultaneous_actual_kvm_guests_uid_data_and_filters_checked','fifth_create503_then_full_quota_reclaim_checked','parent_limit_drift_refused_new_preparation_without_fallback','stop_cleanup_and_existing_exec_continue_during_stricter_parent_drift','failed_prepare_key410_and_same_policy_restored_before_fresh_guest','healthy_synced_checkpoint_not_inflight_metadata_fault')
NODE_BUDGET_RECOVERY_FLAGS = ('l1_boot_changed','exact_node_policy_and_owner_quota_metadata_checked_before_daemon','old_execution_absent_and_ordinary_recovery_destroyed_resources_absent','old_key410_all_four_projects_zero_before_reuse','fresh_actual_guest_uid_boot_workspace_checked','all_four_projects_zero_controller_reaped_entire_node_subtree_removed','no_assigned_guest_restore_and_no_node_policy_retargeted')


def nested_node_resources():
    return {'profile':'node-budget-v1','memory_mib':8192,'disk_bytes':12<<30,'cgroup_memory_max':10<<30}


def validate_node_budget_checkpoint(value):
    for k in NODE_BUDGET_CHECKPOINT_FLAGS: assert value[k] is True
    for k,want in {'guest_memory_touched_bytes_each':8<<20,'node_memory_max_bytes':7<<30,'controller_memory_max_bytes':1<<30,'node_cpu_quota_us':800000,'node_pids_max':384,'prepare_workers':1,'node_io_bytes_per_second':256<<20,'node_io_operations_per_second':8192}.items(): assert type(value[k]) is int and value[k]==want


def validate_node_budget_recovery(value):
    for k in NODE_BUDGET_RECOVERY_FLAGS: assert value[k] is True


def node_budget_policy():
    return {'version':1,'cgroup_root':'/sys/fs/cgroup/xandbox','max_instances':4,'max_records':1024,'max_sessions':32,'prepare_workers':1,'memory_max':7<<30,'controller_memory_max':1<<30,'host_memory_reserve':512<<20,'pids_max':384,'controller_pids_max':128,'cpu_quota':800000,'io_bytes_per_second':256<<20,'io_operations_per_second':8192,'disk_bytes':10<<30,'disk_inodes':100000,'external_disk_bytes':2<<30,'external_inodes':2048,'min_free_bytes':256<<20,'min_free_inodes':2048}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('fixture', 'daemon', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd', 'workspace', 'alpine',
                 'source-revision', 'report', 'log-dir'):
        parser.add_argument('--' + name, required=True)
    for name in ('admin','snapshot-builder','snapshot-seed-manifest'): parser.add_argument('--'+name)
    profiles = parser.add_mutually_exclusive_group()
    profiles.add_argument("--node-budget",action="store_true",help="TEST ONLY: schema3 aggregate node envelope, explicit8GiB RAM/12GiB disk/10GiB outerCG/CPU8; new parent-limit refusal and healthy same-disk cold recovery")
    profiles.add_argument("--quota-owner-cut",action="store_true",help="TEST ONLY: fixed post-unlink unreturned owner-directory fsync and original-disk cold recovery; private outer-L0 receipt only, not filesystem D or physical media fault")
    profiles.add_argument("--quota-partial-copy-cut",action="store_true",help="TEST ONLY: unsynced partial-copy held notification and same-disk cold recovery; private receipt on outer L0 only; not physical media error or filesystem D")
    profiles.add_argument("--quota-partial-copy",action="store_true",help="TEST ONLY: fixed partial workspace write errno with real keeper/pins; explicit3GiB/4GiB resource and4entry/2GiB catalog bounds; not physical EIO or cold-cut acceptance")
    profiles.add_argument("--quota-switch",action="store_true",help="TEST ONLY: explicit 3GiB RAM/4GiB disk profile, node4/tenant3/slots8, two tenants120 switches each with running old jobs, then cold recovery")
    for flag in LISTENER_PROFILES:
        profiles.add_argument("--"+flag.replace("_","-"),action="store_true",help="TEST ONLY: close last fixed own-child listener at reserve or clear SET; real ENOSYS and cold recovery")
    for flag in COMMIT_PROFILES:
        profiles.add_argument('--'+flag.replace('_','-'), action='store_true', help='TEST ONLY: fixed real quota filesystem commit fault and owned L1 cold recovery')
    profiles.add_argument('--quota-barrier-hang', action='store_true', help='TEST ONLY: actual ordinary quota syncfs kernel hold and pre-fork crash')
    profiles.add_argument('--quota-syscalls', action='store_true', help='TEST ONLY: fixed own-child quotactl_fd errno injection, NOT physical media failure')
    profiles.add_argument('--quota-clear-crash', action='store_true', help='TEST ONLY: power cut after ordinary quota clear, before durable owner/pin release')
    profiles.add_argument('--quota-state-io', action='store_true', help='TEST ONLY: whole owned state disk EIO/held I/O with ordinary driver quota enabled')
    profiles.add_argument('--quota-unenforced', action='store_true', help='TEST ONLY: fresh ext4 without project quota must reject startup; no L2 VM expected')
    profiles.add_argument('--quota-negatives', action='store_true', help='TEST ONLY: ordinary driver EDQUOT and startup rejection cases before cold recovery')
    profiles.add_argument('--quota-snapshot', action='store_true', help='TEST ONLY: genuinely L1-built pristine snapshot with ordinary driver quota')
    profiles.add_argument('--quota-driver', action='store_true', help='TEST ONLY: ordinary-driver quota lifecycle and coldboot')
    profiles.add_argument('--quota-probe', action='store_true', help='TEST ONLY: ext4 project quota kernel prerequisites, NOT production enforcement')
    profiles.add_argument('--state-io', action='store_true', help='TEST ONLY: whole owned L1 disk EIO/suspended-IO matrix')
    args = parser.parse_args(); os.umask(0o077)
    selected=[v for flag,v in COMMIT_PROFILES.items() if getattr(args,flag)]
    commit_phase,commit_operation=selected[0] if selected else (None,None)
    commit_profile=bool(selected)
    losses=[v for flag,v in LISTENER_PROFILES.items() if getattr(args,flag)]
    listener_phase,listener_operation=losses[0] if losses else (None,None)
    listener_profile=bool(losses)
    private_cut_profile=args.quota_partial_copy_cut or args.quota_owner_cut
    copy_profile=args.quota_partial_copy or private_cut_profile
    resources=nested_node_resources() if args.node_budget else nested_copy_resources() if copy_profile else nested_resources(args.quota_switch)
    disk_bytes=resources["disk_bytes"]
    snapshot_profile = args.quota_snapshot or args.quota_clear_crash or args.quota_switch or copy_profile
    state_io_profile = args.state_io or args.quota_state_io
    driver_profile = args.node_budget or args.quota_driver or snapshot_profile or args.quota_negatives or args.quota_syscalls or args.quota_unenforced or args.quota_state_io or args.quota_barrier_hang or commit_profile or listener_profile
    if snapshot_profile: assert args.admin and args.snapshot_builder and args.snapshot_seed_manifest
    else: assert not args.admin and not args.snapshot_builder and not args.snapshot_seed_manifest
    assert os.geteuid() == 0 and os.uname().sysname == 'Linux' and os.uname().machine == 'x86_64'
    assert len(bytes.fromhex(args.source_revision)) == 20
    report, logs = Path(args.report).resolve(), Path(args.log_dir).resolve()
    assert not report.exists() and not logs.exists(); logs.mkdir(mode=0o700, parents=True)
    policy = json.loads(Path(__file__).with_name('nested_host_assets.json').read_text())
    validate_manifest(policy)
    assert digest('/usr/bin/qemu-system-x86_64') == policy['qemu_sha256']
    l1kernel = Path('/boot/vmlinuz-' + policy['l1_kernel_release'])
    assert digest(l1kernel) == policy['l1_kernel_sha256']
    assert Path('/sys/module/kvm_intel/parameters/nested').read_text().strip() in ('Y', '1')
    assert os.statvfs('/srv').f_bavail * os.statvfs('/srv').f_frsize > (24 if args.node_budget else 12 if (args.quota_switch or copy_profile) else 8) << 30
    if args.node_budget or args.quota_switch or copy_profile:
        available=[int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')]
        assert len(available)==1 and available[0]>=(32 if args.node_budget else 8)<<30, 'explicit profile requires its fixed L0 memory headroom'
    suffix = secrets.token_hex(3)
    root = Path('/srv/nh-' + suffix); control = Path('/var/lib/xandbox-nested-proof-' + suffix)
    parent_group = Path('/sys/fs/cgroup/xandbox-nested-proof-' + suffix); group = parent_group / secrets.token_hex(32)
    assert not any(p.exists() for p in (root, control, parent_group))
    sources = {n: Path(getattr(args,n)).resolve() for n in ('fixture','daemon','warden','firecracker','jailer','kernel','initrd','workspace','alpine')}
    if snapshot_profile:
        sources.update({n:Path(getattr(args,n)).resolve() for n in ('admin','snapshot_builder')})
        seed=json.loads(Path(args.snapshot_seed_manifest).read_text())
        assert seed['assignment']=='UNASSIGNED' and re.fullmatch('[0-9a-f]{64}',seed['agent_sha256'])
        for n in ('firecracker','jailer','kernel','initrd','workspace'): assert seed[n+'_sha256']==digest(sources[n])
    phases = ('node-envelope-healthy-checkpoint',) if args.node_budget else ('owner-unlink-directory-fsync-pending',) if args.quota_owner_cut else ('partial-copy-inflight-cut',) if args.quota_partial_copy_cut else () if args.quota_partial_copy else ('quota-enabled-two-tenant-switching',) if args.quota_switch else (listener_phase,) if listener_profile else (commit_phase,) if commit_profile else ('reserve-quota-syncfs-held',) if args.quota_barrier_hang else ('quota-cleared-owner-pinned',) if args.quota_clear_crash else () if args.quota_unenforced else ('quota-prerequisites',) if args.quota_probe else ('eio-busy','eio-idle','hang-busy','hang-idle') if state_io_profile else ('running','stopped','destroyed')
    result = {'test':'owned_l1_schema3_node_envelope_admission_and_healthy_cold_recovery' if args.node_budget else 'owned_l1_owner_unlink_directory_fsync_pending_cut_with_keeper' if args.quota_owner_cut else 'owned_l1_unsynced_partial_workspace_copy_cut_with_keeper' if args.quota_partial_copy_cut else 'owned_l1_partial_workspace_write_errno_with_live_keeper' if args.quota_partial_copy else 'owned_l1_quota_two_tenant_busy_switching' if args.quota_switch else 'owned_l1_last_quota_listener_loss' if listener_profile else 'owned_l1_fixed_real_quota_commit_fault' if commit_profile else 'owned_l1_actual_quota_syncfs_hold_prefork_crash' if args.quota_barrier_hang else 'owned_l1_fixed_quota_syscall_errno_real_l2_kvm' if args.quota_syscalls else 'owned_l1_quota_cleared_owner_pinned_power_cut_real_l2_kvm' if args.quota_clear_crash else 'owned_l1_quota_whole_state_io_failure_real_l2_kvm' if args.quota_state_io else 'owned_l1_ordinary_driver_unenforced_ext4_startup_rejection' if args.quota_unenforced else 'owned_l1_ordinary_driver_quota_negative_real_l2_kvm' if args.quota_negatives else 'owned_l1_snapshot_driver_quota_real_l2_kvm' if args.quota_snapshot else 'owned_l1_ordinary_driver_quota_real_l2_kvm' if args.quota_driver else 'owned_l1_project_quota_prerequisites_real_l2_kvm' if args.quota_probe else 'owned_l1_whole_state_io_failure_real_l2_kvm' if args.state_io else 'owned_l1_host_power_cut_real_l2_kvm',
        'production_ready':False,'passed':False,'state_io_profile':state_io_profile,'quota_state_io_profile':args.quota_state_io,'quota_prerequisite_profile':args.quota_probe,
        'production_driver_quota':driver_profile,'quota_snapshot_profile':snapshot_profile,'quota_clear_crash_profile':args.quota_clear_crash,'quota_negative_profile':args.quota_negatives,'quota_unenforced_profile':args.quota_unenforced,
        'quota_syscall_errno_profile':args.quota_syscalls,'quota_barrier_hang_profile':args.quota_barrier_hang,
        'quota_commit_fault_phase':commit_phase,'quota_listener_loss_phase':listener_phase,'quota_switch_profile':args.quota_switch,'quota_partial_copy_profile':args.quota_partial_copy,'quota_partial_copy_cut_profile':args.quota_partial_copy_cut,'quota_owner_cut_profile':args.quota_owner_cut,'node_budget_profile':args.node_budget,
        'source_revision':args.source_revision,'validated_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'harness_sha256':digest(__file__),'builder_sha256':digest(Path(__file__).with_name('build_nested_host.py')),
        'l0_kernel':os.uname().release,'l1_kernel':policy['l1_kernel_release'],'qemu_package_version':policy['qemu_package_version'],
        'qemu_sha256':policy['qemu_sha256'],'l1_kernel_sha256':policy['l1_kernel_sha256'],
        'modules_sha256':policy['modules_sha256'],'artifacts_sha256':{n:digest(p) for n,p in sources.items()},
        'l1_memory_mib':resources['memory_mib'],'l0_cgroup_memory_max':resources['cgroup_memory_max'],'l1_vcpus':8 if args.node_budget else 4,'l1_disk_bytes':disk_bytes,'launch_profile':resources['profile'],
        'l1_business_network_interfaces':0,'l2_guest_memory_mib':512,'l2_vcpus':2,'l2_workspace_bytes':128<<20,
        'outer_disk_format':'raw','outer_disk_cache':'none','outer_disk_aio':'native','cases':[],
        'l1_boots_completed':0,'checkpoint_progress':[],
        'limitations':['Forced loss of our isolated L1 service-host VM, not physical L0 power/media failure.',
            'No TCG fallback, outer QEMU migration/snapshot save/restore, or shared L0 host reboot; this does not prohibit real L2 Firecracker snapshot operations.',
            'Fixed trusted test control operations, not tenant commands executed on a host.',
            'Finite checkpoint cases, not every in-flight fsync/prepare window, production SLO or independent operator acceptance.']}
    if args.node_budget:
        result['limitations'] += ['NEW explicit8GiB L1 RAM/12GiB raw disk/10GiB outerCG/CPU8/pids256/noNIC/900; QMP memory verified. Old2GiB and3GiB profiles unchanged; larger resources are not performance improvement evidence.', 'Schema3 node aggregate planning and kernel parent/control ceilings with exact frontend limits, quota/IO and bounded preparation. Disk/inodes use conservative full-allocation plus full-free admission reserve, NOT a node-wide project quota or unique RAM billing. Operator assets/exports/logs require external bounds; pressure checks do not guarantee media availability.', 'Each of four guests touches8MiB memory, not full512MiB. Parent memory.max tightened only4KiB with explicit safe headroom; rejection proves immutable readback enforcement, not OOM/saturation or the full set of node resource-pressure faults.', 'Healthy synced checkpoint/cold recovery only, not an in-flight metadata commit. Preparation concurrency is unit/race bounded and wired to real staging; this case does not claim a hardware trace of concurrent copy permits, unique-page attribution, fairness or production SLO.', 'New production ELF requires full DEFAULT/quota-enabled240/dual-cold/failure requalification separately; legacy frozen522 reports cannot certify this ELF. FullM1-M4/production/operator acceptance remains incomplete.']
    if args.quota_owner_cut:
        result['limitations'] += ['Fixed quota-copy-v1 resource and catalog bounds; owner commit window only, not a production aggregate node budget.', 'One known victim unlink after ordinary jail/cgroup removal and successful complete quota clear. Exact original daemon FSYNC directory FD/inode is held WITHOUT target reply; notification wait is NOT filesystem D or physical media fault. Other notifications CONTINUE real kernel, not all completions or latency counts.', 'After target no observer quota-sync/syncfs/fsync/catalog-admin or L1 receipt write. Keeper data/UID/boot command and baseline sync BEFORE DELETE; after target only actual host KVM domain and exact post-victim-cleanup keeper links/quota are checked, NOT a fresh keeper guest command that would fsync its job ledger.', 'Private bounded receipt only over control and outer-L0 exclusive0600 storage; original8KiB scanner unchanged. Natural filesystem/background persistence allowed: cold victim owner may be present or absent, but no fixture owner restoration, unknown quota adoption or blanket clear.', 'DELETE202 acknowledged intent before the checkpoint, NOT a pending synchronous DELETE response. RECLAIMING/StoppedAt/noDestroyed/exec409/capacity503 retain capacity while catalog interprocess lock remains held. The held syscall is not a claim that other catalog operations are globally nonblocking.', 'One metadata window, not every owner commit/error/pin combination, physical power loss, node budgets, open-loop/fairness/operator/SLO or fullM1-M4.']
    if args.quota_partial_copy_cut:
        result['limitations'] += ['Fixed quota-copy-v1 resources and immutable catalog4 entries/2GiB before binding, not production aggregate admission.', 'No observer quota sync, syncfs, fsync, catalog-admin scan or receipt write in L1 after the16MiB target. Keeper baseline is synced BEFORE victim creation. Private receipt travels over control and is saved only on outer L0, outside the guest filesystem; natural background persistence is allowed.', 'Selected next128KiB WRITE remains a TEST notification wait without reply until owned outer cut, not actual filesystem D or physical media failure. No tracee buffers read. Cold prefix may disappear or truncate; actual namespace and kernel quota are independently checked before ordinary uninstrumented recovery.', 'One fixed partial-copy window only; arbitrary media errors, owner unlink/dirsync and other pin persistence windows, open-loop/fairness/SLO and independent operator remain incomplete.']
    if args.quota_partial_copy:
        result['limitations'][0]='One owned L1 isolates this TEST errno profile; no host cold-cut or physical media error is exercised.'
        result['limitations'] += ['Explicit fixed3GiB RAM/4GiB disk/4GiB outer cgroup/CPU4/pids128/noNIC/900s; immutable catalog4 retained entries/2GiB max bytes to republish a never-assigned declaration while old keeper pin remains. Not a production node budget.', 'Extra TEST ONLY inherited write notification/NNP layer holds the next128KiB write after actual16MiB prefix; healthy observer sync stabilizes prefix accounting before one EIO reply. This notification wait is NOT actual filesystem D-state or physical EIO. No tracee buffers read; other writes CONTINUE real kernel. Counts are successful reply submissions, not all write completions or latency.', 'Only stable partial Prepare failure/keeper pin/retirement/GC/slot-reuse is accepted here; arbitrary partial copies, in-flight host power cuts and owner unlink/dirfsync persistence windows remain incomplete.']
    if args.quota_switch:
        result['limitations'] += ['EXPLICIT larger fixed experiment:3GiB L1 RAM/4GiB disk/4GiB outer cgroup, CPU4/pids128/noNIC/hard15min; not the old2GiB resource profile or a production node-budget policy.', 'Two paced closed-loop workers120 each with a RUNNING old guest writer per switch; not open-loop saturation, scheduler fairness, unique-RAM billing, every failure window or a production SLO.', 'Resource samples500ms target are nontransactional and miss peaks; summed quota slots, cgroup memory and controller RSS are different overlapping views. No operator quota sync during measured switches; stable preflight/crash checkpoint may sync.']
    if args.quota_probe or driver_profile:
        result['quota_modules_sha256'] = policy['quota_modules_sha256']
    if args.quota_clear_crash:
        result['limitations'].append('Healthy catalog lock is deliberately held by L1 PID1 after ordinary quota clear, until outer L1 power cut. This tests that precise clear-before-owner-delete window, not arbitrary quota syscall errors or latency under a held catalog lock.')
    if args.quota_barrier_hang:
        result['limitations'].append('Additional TEST ONLY seccomp/NNP launch observer locates quota syncfs, then CONTINUE enters actual suspended-mapper filesystem IO. No old L2 VM is born at this pre-fork checkpoint. Fixed 4MiB project-zero dirty data ensures filesystem-wide writeback; not per-project IO or physical media failure. Receipt is synced BEFORE SET, with no observer sync after SET; unreturned commit is not assumed durable.')
    if commit_profile:
        result['limitations'].append('Additional TEST ONLY seccomp/NNP observer locates a fixed ordinary commit. CONTINUE enters the real kernel. One owned L1 mapper only: no physical L0 media failure or bounded filesystem IO guarantee. Fixed 4MiB project-zero dirty data is filesystem-wide. Reserve EIO uses an exact owned-thread, first-syncfs-return eBPF observer only inside L1; no tracee payloads or persistent hook. Release holds allow DELETE acceptance but never confirm DESTROYED/capacity before commit. Receipts sync before SET or DELETE; no observer sync after the selected mutation.')
    if listener_profile:
        result['limitations'].append('TEST ONLY inherited seccomp/NNP layer, not a production listener dependency. Close only our last listener FD at a fixed SET without responding; actual owned-L1 raw sys_exit BPF must observe ENOSYS. Quota SET does not execute. Healthy filesystem permits independent durable-owner/ledger readback while listener absent; no listener reattach or synthesized success. Fresh ordinary uninstrumented launch after own L1 cold boot recovers. Frontend503 is not a direct backend allocator probe.')
    if args.quota_syscalls:
        result['limitations'].append('ELF-unchanged ordinary child has an additional inherited TEST ONLY seccomp notification/NNP launch layer. Six fixed errno cases, not physical media EIO/EROFS, held Q_SYNC, in-flight crash or snapshot pin acceptance. Clear cases require at least3 validated error replies with the selected post-SET target rearmed each cleanup attempt and durable RECLAIMING/owner/admission checks before disarm. Other calls execute the real kernel via CONTINUE; no synthetic successful quota response.')
    if args.quota_state_io:
        result['limitations'].append('Quota enabled during whole-filesystem faults. The injected blocking point is state fsync, not a claim of every Q_SET/Q_SYNC/readback/clear syscall persistence window.')
    if args.quota_unenforced:
        result.update(startup_rejection_only=True,l2_guest_memory_mib=0,l2_vcpus=0,l2_workspace_bytes=0)
        result['limitations'].append('Separate fresh ext4 startup rejection only: no L2 VM, tenant execution, cold recovery or quota-zero readback claimed in this profile.')
    if args.quota_probe:
        result['limitations'].append('Kernel prerequisite probe only: ordinary sandboxd has NO project quota integration or per-generation physical disk enforcement.')
    process = None; lifetime = None; channel = None; launcher_log = None; owned_groups = []
    l0_boot = Path('/proc/sys/kernel/random/boot_id').read_bytes()
    try:
        root.mkdir(mode=0o700); control.mkdir(mode=0o700)
        private_json(logs/'resource-receipt.json',{'version':1,'root':str(root),'control':str(control),'cgroup_parent':str(parent_group),'cgroup':str(group)})
        uid = 850000 + secrets.randbelow(30000)
        try: pwd.getpwuid(uid)
        except KeyError: pass
        else: raise AssertionError('reserved fixture UID is assigned')
        fixture = control/'fixture'; warden = control/'warden'
        shutil.copyfile(sources['fixture'],fixture); fixture.chmod(0o555)
        shutil.copyfile(sources['warden'],warden); warden.chmod(0o555)
        shutil.copyfile(l1kernel,root/'kernel'); (root/'kernel').chmod(0o444)
        build_initrd(alpine=sources['alpine'],fixture=fixture,manifest=policy,output=root/'initrd.cpio.gz',state_io=args.state_io,quota_probe=args.quota_probe,quota_driver=(args.quota_driver or args.quota_negatives or args.quota_syscalls or listener_profile),quota_snapshot=(snapshot_profile and not args.quota_switch),quota_switch=args.quota_switch,node_budget=args.node_budget,quota_unenforced=args.quota_unenforced,quota_state_io=(args.quota_state_io or args.quota_barrier_hang or commit_profile))
        result['l1_initrd_sha256']=digest(root/'initrd.cpio.gz')
        staging = control/'disk-root'; (staging/'assets').mkdir(mode=0o755,parents=True); (staging/'config').mkdir(mode=0o700)
        backend = {'version':1,'runtime_root':'/srv/r','cgroup_root':'/sys/fs/cgroup/xandbox','uid_start':400000,'uid_count':8 if args.quota_switch else 4,'reserved_uid_range':True}
        filesystem_uuid = uuid.uuid4()
        if driver_profile:
            backend['quota'] = {'version':1,'filesystem_uuid':filesystem_uuid.hex,'project_start':1300000,'max_bytes':192<<20,'max_inodes':128}
        for name in ('daemon','warden','firecracker','jailer','kernel','initrd','workspace'):
            target=staging/'assets'/('sandboxd' if name=='daemon' else name)
            shutil.copyfile(sources[name],target); target.chmod(0o555 if name in ('daemon','warden','firecracker','jailer') else 0o444)
            if name!='daemon': backend[name]={'path':'/srv/assets/'+name,'sha256':digest(target)}
        if snapshot_profile:
            backend['version']=2
            backend['snapshot']={'version':1,'agent_sha256':seed['agent_sha256'],'memory_mib':512,'vcpus':2,'max_entries':4 if copy_profile else 2,'max_bytes':(2 if copy_profile else 1)<<30}
            for name,target_name in (('admin','admin'),('snapshot_builder','snapshot-builder')):
                shutil.copyfile(sources[name],staging/'assets'/target_name);(staging/'assets'/target_name).chmod(0o555)
            private_json(staging/'config/snapshot-fixture.json',{'source_revision':args.source_revision,'agent_sha256':seed['agent_sha256'],'admin_sha256':digest(sources['admin']),'builder_sha256':digest(sources['snapshot_builder'])})
        if args.node_budget:
            backend.update(version=3,cgroup_root='/sys/fs/cgroup/xandbox/instances',node=node_budget_policy(),io={'version':1,'filesystem_device':'253:0','device':'253:0','bytes_per_second':16<<20,'operations_per_second':1024})
        private_json(staging/'config/backend.json',backend)
        disk=root/'disk.raw'
        with disk.open('xb') as f: os.posix_fallocate(f.fileno(),0,disk_bytes); os.fsync(f.fileno())
        format_options = quota_format_options(args.quota_probe or (driver_profile and not args.quota_unenforced))
        subprocess.run(['mkfs.ext4','-q','-F','-m','0','-E','root_owner=0:0',*format_options,*(['-U',str(filesystem_uuid)] if driver_profile else []),'-d',str(staging),str(disk)],check=True,timeout=120)
        with disk.open('rb') as f: os.fsync(f.fileno())
        # Only QEMU's private inputs become accessible to its reserved UID.
        for path in root.iterdir(): os.chown(path,uid,uid); path.chmod(0o600 if path==disk else 0o400)
        os.chown(root,uid,uid)
        parent_group.mkdir(mode=0o700); (parent_group/'cgroup.subtree_control').write_text('+memory +pids +cpu')
        cfg = control/'launch.json'
        launch_policy={'version':1,'root':str(root),'cgroup':str(group),'uid':uid,'kvm_group':os.stat('/dev/kvm').st_gid,
            'warden':str(warden),'warden_sha256':digest(warden),'fixture_sha256':digest(fixture),'qemu_sha256':policy['qemu_sha256'],
            'kernel_sha256':policy['l1_kernel_sha256'],'initrd_sha256':result['l1_initrd_sha256']}
        if resources['profile']: launch_policy['profile']=resources['profile']
        boot_number=0
        def boot():
            nonlocal process,lifetime,channel,launcher_log,boot_number,group
            # A new host incarnation gets a new execution generation/lease
            # binding. Reuse ONLY the private disk, never a killed domain.
            if boot_number: group=parent_group/secrets.token_hex(32)
            group.mkdir(mode=0o700);owned_groups.append(group)
            replace_private_json(logs/'resource-receipt.json',{'version':1,'root':str(root),'control':str(control),
                'cgroup_parent':str(parent_group),'cgroup':str(group),'all_cgroups':[str(p) for p in owned_groups]})
            for name,value in {'memory.max':str(resources['cgroup_memory_max']),'memory.swap.max':'0','memory.oom.group':'1','pids.max':'128','cpu.max':'400000 100000'}.items():
                (group/name).write_text(value); assert (group/name).read_text().strip()==value
            launch_policy['cgroup']=str(group);replace_private_json(cfg,launch_policy)
            boot_number+=1
            for name in ('control.sock','qmp.sock','console.log'):
                p=root/name
                if p.exists(): p.unlink()
            read,lifetime=os.pipe(); launcher_log=(logs/f'launcher-{boot_number}.log').open('xb',buffering=0)
            process=subprocess.Popen([str(fixture),'-mode','launch','-config',str(cfg)],stdin=read,stdout=launcher_log,stderr=launcher_log,
                                     env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin'})
            os.close(read)
            def ready():
                assert process.poll() is None,'owned QEMU launcher exited; inspect private log'
                console=root/'console.log'
                if console.exists(): assert console.stat().st_size<=2<<20,'unexpected console flood'
                return console.exists() and b'XANDBOX_NESTED_HOST_READY' in console.read_bytes()
            wait(ready,'L1 fixture boot',seconds=90)
            qmp_probe(root/'qmp.sock',resources['memory_mib'] if resources['profile'] else None)
            channel=JSONSocket(root/'control.sock',770 if args.quota_switch else 210 if (snapshot_profile or args.quota_negatives or args.quota_syscalls) else 90,quota_switch=args.quota_switch)
            channel.send({'version':1,'operation':'probe'}); reply=channel.read()
            assert reply['ok'] and reply['result']['nested_kvm_api']==12
            assert disk.stat().st_size==disk_bytes
            result['l1_boots_completed']+=1
        cut_receipt=None
        def request(operation,phase=None,receipt=None):
            nonlocal cut_receipt
            value={'version':1,'operation':operation}
            if phase:value['phase']=phase
            if receipt is not None:
                assert operation in ('quota-copy-cut-recover','quota-owner-cut-recover') and phase is None
                value=owner_cut_recovery_packet(receipt) if operation=='quota-owner-cut-recover' else copy_cut_recovery_packet(receipt)
            channel.send(value); out=channel.read()
            if operation=='quota-owner-cut-checkpoint':
                summary,cut_receipt=detach_owner_cut_checkpoint(out,logs/'private-owner-cut-receipt.json')
                return summary
            if operation=='quota-copy-cut-checkpoint':
                summary,cut_receipt=detach_copy_cut_checkpoint(out,logs/'private-copy-cut-receipt.json')
                return summary
            if not out['ok'] and driver_profile and operation=='recover' and 'quota_diagnostic' in out:
                result['quota_coldboot_failure_diagnostic']=out['quota_diagnostic']
            if args.quota_switch and not out['ok'] and 'result' in out:result['switch_partial_result']=out['result']
            assert out['ok'],'L1 fixed operation failed; inspect private console';return out['result']
        def power_cut():
            nonlocal process,lifetime,channel,launcher_log
            qmp_probe(root/'qmp.sock'); began=time.perf_counter(); (group/'cgroup.kill').write_text('1')
            wait(lambda:cgroup_empty(group),'exact owned L1 execution domain stops',seconds=15)
            elapsed=round((time.perf_counter()-began)*1000,3)
            process.wait(timeout=15); process=None
            shutil.copyfile(root/'console.log',logs/f'l1-console-{boot_number}.log')
            os.close(lifetime);lifetime=None;channel.close();channel=None;launcher_log.close();launcher_log=None
            private_json(logs/f'private-cgroup-{boot_number}.json',private_group_counters(group))
            group.rmdir()
            assert Path('/proc/sys/kernel/random/boot_id').read_bytes()==l0_boot
            return elapsed
        boot()
        if args.quota_unenforced:
            result['unenforced_startup']=request('quota-unenforced')
            validate_unenforced_setup(result['unenforced_startup'])
            result['cases'].append({'phase':'unenforced-ext4-startup','passed':True})
        if args.quota_switch:
            result['snapshot_setup']=request('quota-switch-setup')
            validate_quota_switch_setup(result['snapshot_setup'])
        elif args.quota_partial_copy:
            result['partial_copy_setup']=request('quota-copy-setup')
            validate_quota_copy_setup(result['partial_copy_setup'])
            result['cases'].append({'phase':'fixed-partial-workspace-write-eio-with-keeper','passed':True,'setup':result['partial_copy_setup']})
        elif snapshot_profile and not private_cut_profile: result['snapshot_setup']=request('quota-snapshot-setup')
        if args.quota_negatives:
            result['negative_setup']=request('quota-negative-setup')
            validate_negative_setup(result['negative_setup'])
        if args.quota_syscalls:
            result['syscall_setup']=request('quota-syscall-setup')
            validate_quota_syscall_setup(result['syscall_setup'],require_repeated=True)
        for phase in phases:
            if args.quota_switch:
                result['switch_load']=request('quota-switch-run')
                validate_quota_switch_run(result['switch_load'])
            checkpoint=request('node-budget-checkpoint') if args.node_budget else request('quota-owner-cut-checkpoint') if args.quota_owner_cut else request('quota-copy-cut-checkpoint') if args.quota_partial_copy_cut else request('quota-switch-checkpoint') if args.quota_switch else request(listener_operation+'-checkpoint') if listener_profile else request(commit_operation+'-checkpoint') if commit_profile else request('quota-barrier-checkpoint') if args.quota_barrier_hang else request('quota-clear-checkpoint') if args.quota_clear_crash else request('quota-probe') if args.quota_probe else request('io-fault' if state_io_profile else 'quota-checkpoint' if driver_profile else 'checkpoint',phase)
            if args.node_budget: validate_node_budget_checkpoint(checkpoint)
            elif args.quota_owner_cut: validate_quota_owner_cut_checkpoint(checkpoint)
            elif args.quota_partial_copy_cut: validate_quota_copy_cut_checkpoint(checkpoint)
            elif args.quota_switch: validate_quota_switch_checkpoint(checkpoint)
            elif listener_profile: validate_quota_listener_checkpoint(checkpoint,listener_phase)
            elif commit_profile: validate_quota_commit_checkpoint(checkpoint,commit_phase)
            elif args.quota_barrier_hang: validate_quota_barrier_checkpoint(checkpoint)
            else: assert checkpoint['real_nested_kvm'] and checkpoint['checkpoint_receipt_fsynced']
            if args.quota_clear_crash: validate_quota_clear_checkpoint(checkpoint)
            if args.quota_state_io:
                for key in ('ordinary_driver_quota_enabled','durable_project_ownership_checked','mutable_project_inheritance_checked','linked_namespace_accounted_before_cut','quota_filter_inherited_with_default_vmm_seccomp','quota_mapped_mount_and_policy_checked_before_fault'): assert checkpoint[key] is True
                assert checkpoint['private_project_space_bytes']>=128<<20 and 0<checkpoint['private_project_inodes']<=128
                assert checkpoint['quota_and_ownership_released_only_after_io_resumed' if phase.startswith('hang-') else 'quota_owner_retained_until_cold_recovery'] is True
            progress={'phase':phase,'checkpoint':checkpoint};result['checkpoint_progress'].append(progress)
            cut_began=time.monotonic()
            stopped=power_cut();progress['power_cut_to_l0_cgroup_empty_ms']=stopped
            if private_cut_profile:
                elapsed=(time.monotonic()-cut_began)*1000
                assert elapsed<15000, 'cut must arrive before fixed60s notification hold deadline'
                progress['checkpoint_reply_to_outer_stop_observed_ms']=round(elapsed,3)
            boot(); recovered=request('node-budget-recover') if args.node_budget else request('quota-owner-cut-recover',receipt=cut_receipt) if args.quota_owner_cut else request('quota-copy-cut-recover',receipt=cut_receipt) if args.quota_partial_copy_cut else request('quota-switch-recover' if args.quota_switch else listener_operation+'-recover' if listener_profile else commit_operation+'-recover' if commit_profile else 'quota-barrier-recover' if args.quota_barrier_hang else 'quota-clear-recover' if args.quota_clear_crash else 'recover')
            if args.node_budget: validate_node_budget_recovery(recovered)
            elif args.quota_owner_cut: validate_quota_owner_cut_recovery(recovered)
            elif args.quota_partial_copy_cut: validate_quota_copy_cut_recovery(recovered)
            elif args.quota_switch: validate_quota_switch_recovery(recovered)
            elif listener_profile: validate_quota_listener_recovery(recovered,listener_phase)
            elif commit_profile: validate_quota_commit_recovery(recovered,commit_phase)
            elif args.quota_barrier_hang: validate_quota_barrier_recovery(recovered)
            else:
                assert recovered['l1_boot_changed'] and recovered['old_durable_destroyed'] and recovered['old_resources_absent'] and recovered['old_key_refused_410']
                assert recovered['fresh_real_kvm_exec_destroy'] and recovered['fresh_guest_boot_changed']
            if driver_profile and not (args.quota_clear_crash or args.quota_barrier_hang or commit_profile or listener_profile or args.quota_switch or private_cut_profile or args.node_budget): assert recovered['quota_limits_and_ownership_survived_cold_boot'] and recovered['quota_accounting_matches_recovered_namespace'] and recovered['all_private_project_ids_cleared']
            if args.quota_clear_crash: validate_quota_clear_recovery(recovered)
            if args.quota_probe: assert recovered['quota_persisted_after_power_cut'] and recovered['all_fixture_project_records_cleared']
            guard = (checkpoint['host_stop_1500ms_guard_passed'] and checkpoint['new_exec_500ms_guard_passed']) if state_io_profile else True
            result['cases'].append({'phase':phase,'passed':guard,'checkpoint':checkpoint,'recovery':recovered,'power_cut_to_l0_cgroup_empty_ms':stopped})
        assert len(owned_groups)==len(phases)+1 and len(set(owned_groups))==len(phases)+1
        result['distinct_l0_execution_generations']=len(owned_groups)
        result['l0_boot_unchanged']=True; result['qmp_enabled_kvm_verified_each_boot']=True
        result['passed']=all(case['passed'] for case in result['cases'])
    finally:
        if group.exists():
            private_json(logs/'final-private-cgroup.json',private_group_counters(group))
            (group/'cgroup.kill').write_text('1');wait(lambda:cgroup_empty(group),'owned nested cleanup',seconds=15)
        if process is not None: process.wait(timeout=15)
        if lifetime is not None: os.close(lifetime)
        if channel is not None: channel.close()
        if launcher_log is not None: launcher_log.close()
        if (root/'console.log').exists():
            with (root/'console.log').open('rb') as source:
                source.seek(max(0,(root/'console.log').stat().st_size-(2<<20)))
                (logs/'final-private-console.log').write_bytes(source.read(2<<20))
        for owned in owned_groups:
            if owned.exists(): owned.rmdir()
        if parent_group.exists(): parent_group.rmdir()
        if root.exists(): shutil.rmtree(root)
        if control.exists(): shutil.rmtree(control)
        result['cleanup_confirmed']=not any(p.exists() for p in (root,control,parent_group))
        private_json(report,result)
    assert result['passed'] and result['cleanup_confirmed']
    print(json.dumps({'passed':True,'cases':len(result['cases']),'cleanup_confirmed':True}))


if __name__=='__main__':main()
