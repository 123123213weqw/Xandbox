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

from build_nested_host import build_initrd, digest, validate_manifest, static_elf
from kvm_resources import cgroup_empty
from node_load_contract import (NODE_LOAD_MAX_FRAME, node_load_profile, nested_node_load_resources, node_load_policy, validate_node_load_result, NODE_LOAD_RECOVERY_FLAGS)
from kvm_driver_smoke import wait
from kvm_snapshot_smoke import private_json, sync_dir

DISK_BYTES = 2 << 30
QUOTA_SWITCH_MAX_FRAME = 2 << 20


def quota_format_options(enabled):
    # e2fsprogs 1.46.5 uses the extended quotatype option, NOT a -Q flag.
    return ['-O','project,quota','-E','quotatype=prjquota','-I','256','-b','4096'] if enabled else []



class JSONSocket:
    def __init__(self, path, timeout=90, quota_switch=False, node_load=False):
        assert type(quota_switch) is bool and type(node_load) is bool and not (quota_switch and node_load)
        self.max_frame=NODE_LOAD_MAX_FRAME if node_load else QUOTA_SWITCH_MAX_FRAME if quota_switch else 65536
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
            assert all(r[k] is True for k in ('actual_prepare_edquot_closed_counter_checked','create_refused500','durable_destroyed_and_exact_resources_absent','old_create_key_refused410','same_binding_restart_destroyed_key410_checked','released_capacity_reused_second_edquot_cleaned','ordinary_closed_edquot_producer_counter_exact1'))
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
        flags=('checkpoint_receipt_fsynced_before_set','durable_attempted_owner_before_set','installed_limits_checked_before_fault','ordinary_qsync_returned_before_syncfs','notification_continued_no_errno_or_success_emulation','selected_syncfs_kernel_exit_observed','ordinary_prepare_eio_closed_counter_independent_of_state_io','private_metric_connection_open_before_fault_no_reconnect','create_refused500','no_false_ready_stop_destroy_confirmation','exact_owner_receipt_persisted_before_eio_for_cold_recheck','admission_new_create503','no_observer_quota_or_srv_reads_after_eio','own_mapper_error_retained_until_power_cut_no_rw_remount','no_l2_vm_born_at_checkpoint')
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


def nested_group_limits(resources):
    if resources['profile']=='systemd-ingress-v1':
        if resources!=nested_ingress_resources():raise ValueError('fixed ingress resource envelope required')
        return {'memory.max':str(18<<30),'memory.swap.max':'0','memory.oom.group':'1','pids.max':'512','cpu.max':'1200000 100000'}
    large=resources['profile'] in ('node-budget-v1','node-snapshot-v1','node-load-v1')
    return {'memory.max':str(resources['cgroup_memory_max']),'memory.swap.max':'0','memory.oom.group':'1','pids.max':'256' if large else '128','cpu.max':'800000 100000' if large else '400000 100000'}


def nested_ingress_resources():
    return {'profile':'systemd-ingress-v1','memory_mib':16384,'disk_bytes':24<<30,'cgroup_memory_max':18<<30}


def nested_node_resources(snapshot=False):
    return {'profile':'node-snapshot-v1' if snapshot else 'node-budget-v1','memory_mib':8192,'disk_bytes':12<<30,'cgroup_memory_max':10<<30}


def validate_node_budget_checkpoint(value):
    for k in NODE_BUDGET_CHECKPOINT_FLAGS: assert value[k] is True
    for k,want in {'guest_memory_touched_bytes_each':8<<20,'node_memory_max_bytes':7<<30,'controller_memory_max_bytes':1<<30,'node_cpu_quota_us':800000,'node_pids_max':384,'prepare_workers':1,'node_io_bytes_per_second':256<<20,'node_io_operations_per_second':8192}.items(): assert type(value[k]) is int and value[k]==want


def validate_node_budget_recovery(value):
    for k in NODE_BUDGET_RECOVERY_FLAGS: assert value[k] is True


NODE_OOM_CHECKPOINT_FLAGS = (
    'real_nested_kvm','checkpoint_receipt_fsynced','four_busy_guest_resident_anon_deltas_checked',
    'fifth_create503_before_pressure','helper_born_in_exact_vm_group_privileges_dropped_and_parent_verified',
    'actual_target_kernel_oom_group_kill_and_sigkill_reap_before_guard','target_domain_empty_independently_observed','target_job_failed_without_natural_timeout',
    'ancestor_control_and_neighbor_oom_counters_unchanged','three_neighbors_still_running_and_new_exec_succeeds_after_oom',
    'ordinary_stop_before_original_job_timeout','all_four_destroyed_resources_absent_projects_zero_keys410',
    'fresh_capacity_clean_workspace_new_boot_and_synced_cold_checkpoint','host_cgroup_test_pressure_not_guest_origin','global_l1_oom_kills_equal_node_hierarchical_count')
NODE_OOM_COUNTERS = ('target_observed_oom_events','target_observed_oom_kills','target_observed_oom_group_kills','node_hierarchical_oom_kills','l1_global_oom_kills')
NODE_OOM_TIMES = ('oom_release_to_target_empty_observed_ms','neighbor_stop_to_empty_observed_ms','neighbor_stop_to_all_private_reclaimed_observed_ms')


def node_oom_profile(budget, enabled, *others):
    if type(budget) is not bool or type(enabled) is not bool:
        raise ValueError('explicit boolean node OOM selection required')
    if enabled and (not budget or any(others)):
        raise ValueError('fixed node OOM requires exclusive --node-budget without other modifiers')


def validate_node_oom_checkpoint(v):
    # Exact fields: reject raw process/resource identity or an unvalidated success
    # extension rather than silently exporting it as public evidence.
    fixed={'fixed_helper_allocation_request_bytes':1<<30,'guest_workload_bytes_each':96<<20,'fixed_helper_guard_ms':20000}
    keys=set(NODE_OOM_CHECKPOINT_FLAGS+NODE_OOM_COUNTERS+NODE_OOM_TIMES)|set(fixed)|{'guest_host_anon_delta_bytes_each','production_slo_claim','whole_node_saturation_claim'}
    assert type(v) is dict and set(v)==keys
    for k in NODE_OOM_CHECKPOINT_FLAGS: assert v[k] is True
    for k in ('production_slo_claim','whole_node_saturation_claim'): assert v[k] is False
    for k,want in fixed.items(): assert type(v[k]) is int and v[k]==want
    for k in NODE_OOM_COUNTERS: assert type(v[k]) is int and 1<=v[k]<=1<<20
    assert v['target_observed_oom_kills']<=v['node_hierarchical_oom_kills']<=128
    assert v['l1_global_oom_kills']==v['node_hierarchical_oom_kills']
    assert v['target_observed_oom_group_kills']<=128
    deltas=v['guest_host_anon_delta_bytes_each']
    assert type(deltas) is list and len(deltas)==4
    assert all(type(n) is int and 64<<20<=n<=768<<20 for n in deltas)
    for k in NODE_OOM_TIMES: assert type(v[k]) in (int,float) and math.isfinite(v[k]) and 0<=v[k]<200000
    assert v['oom_release_to_target_empty_observed_ms']<20000
    assert v['neighbor_stop_to_empty_observed_ms']<=v['neighbor_stop_to_all_private_reclaimed_observed_ms']


def node_budget_policy():
    return {'version':1,'cgroup_root':'/sys/fs/cgroup/xandbox','max_instances':4,'max_records':1024,'max_sessions':32,'prepare_workers':1,'memory_max':7<<30,'controller_memory_max':1<<30,'host_memory_reserve':512<<20,'pids_max':384,'controller_pids_max':128,'cpu_quota':800000,'io_bytes_per_second':256<<20,'io_operations_per_second':8192,'disk_bytes':10<<30,'disk_inodes':100000,'external_disk_bytes':2<<30,'external_inodes':2048,'min_free_bytes':256<<20,'min_free_inodes':2048}


def node_snapshot_format_options(enabled):
    return ['-N','131072'] if enabled else []

def validate_node_snapshot_setup(v):
    for k in ('genuine_l1_unassigned_template_built','l1_host_abi_checked','builder_two_independent_clones_checked','builder_runtime_reclaimed','ordinary_catalog_published_and_activated','publisher_inside_node_control','offline_builder_outside_node_envelope_not_a_node_pressure_claim'):assert v[k] is True
    assert type(v['snapshot_memory_bytes']) is int and v['snapshot_memory_bytes']==512<<20

NODE_SNAPSHOT_CHECKPOINT_FLAGS=('real_nested_kvm','checkpoint_receipt_fsynced','schema3_snapshot_exact_node_policy','publisher_and_daemon_inside_control','two_actual_snapshot_clones_private_quota_shared_inode_pins_checked','inode_pressure_refuses_prepare_publish_but_stop_cleanup_continues','inode_filler_removed_and_headroom_restored','byte_pressure_refuses_prepare_publish_existing_exec_continues','publisher_refusal_specific_and_catalog_unchanged','healthy_synced_low_free_checkpoint_not_inflight_fault')
NODE_SNAPSHOT_RECOVERY_FLAGS=('l1_boot_changed','exact_policy_owner_namespace_quota_shared_backing_before_daemon','low_free_guard_survived_cold_and_ordinary_start_reclaims','old_keys410_all_four_projects_zero_before_reuse','only_exact_owned_filler_removed_headroom_restored','same_unassigned_declaration_publish_succeeds_after_restore','fresh_two_actual_guests_clean_workspace_new_boots','retire_pins_gc_survivor_exec_and_final_gc_checked','all_four_projects_zero_controller_reaped_entire_node_subtree_removed','no_assigned_guest_or_owner_restoration')
# Fixed new ordinary target after native ELF/disassembly calibration. Historical
# reports must retain their original frozen verifier, not inherit this pin.
PREPARE_TRACE_ELF_SHA256='5bfb2394f95a1b1c2f887b6e301357b92140586bde07448e3e09f2aa0ee3c11c'
PREPARE_CALIBRATION_FLAGS=('first_selected_token_observed_before_second_dispatch','calibration_only','second_actual_gate_entry_inside_first_held_interval','all_eight_cpu_loss_counters_zero','live_daemon_incarnation_inode_control_and_event_tgid_checked','entry_probe_only_no_uretprobe_or_user_memory_read')
def validate_prepare_calibration(v):
    assert type(v) is dict
    for k in PREPARE_CALIBRATION_FLAGS:assert v[k] is True
    assert v['exact_ordinary_elf_sha256']==PREPARE_TRACE_ELF_SHA256
    for k,want in {'instruction_entry_probes':9,'event_count':12,'completed_preparations':2}.items():assert type(v[k]) is int and v[k]==want
    for k in ('queued_request_cancellation_and_cleanup_isolation_claim','exact_channel_linearization_or_latency_slo_claim'):assert v[k] is False
    states={};held=0;entered_inside=False
    rows=v['normalized_transitions'];assert type(rows) is list and len(rows)==12
    for row in rows:
        assert type(row) is dict and set(row)=={'point','goroutine_index'}
        g=row['goroutine_index'];assert type(g) is int and g in (1,2)
        point=row['point'];before=states.get(g,0)
        want={'enter':0,'selected':1,'ok':2,'node_ok':3,'release':4,'released':5}[point];assert before==want
        if point=='enter':entered_inside=entered_inside or held==1
        if point=='selected':assert held==0;held+=1
        if point=='release':assert held==1;held-=1
        states[g]=before+1
    assert states=={1:6,2:6} and held==0 and entered_inside

def validate_node_snapshot_checkpoint(v):
    validate_prepare_calibration(v['prepare_entry_calibration'])
    for k in NODE_SNAPSHOT_CHECKPOINT_FLAGS:assert v[k] is True
    assert type(v['guest_memory_touched_bytes_each']) is int and v['guest_memory_touched_bytes_each']==8<<20
    for k in ('inode_filler_files','byte_filler_allocated_bytes','free_byte_guard','free_inode_guard','observed_free_bytes','inode_pressure_free_before_delete','inode_pressure_free_after_delete'):assert type(v[k]) is int and v[k]>0
    assert v['inode_filler_files']<=150000 and v['byte_filler_allocated_bytes']<=10<<30
    assert v['observed_free_bytes']<v['free_byte_guard'] and v['prepare_permit_hardware_trace_claim'] is False
    assert v['free_byte_guard']==3362619392 and v['free_inode_guard']==5776
    assert 1024<=v['inode_pressure_free_before_delete']<v['free_inode_guard'] and 1024<=v['inode_pressure_free_after_delete']<v['free_inode_guard']
def validate_node_snapshot_recovery(v):
    for k in NODE_SNAPSHOT_RECOVERY_FLAGS:assert v[k] is True

NODE_PREPARE_CANCEL_FLAGS=('real_nested_kvm','schema3_exact_prepare_workers_one','keeper_holder_and_two_queued_frontend_allocated_four_fifth503','two_queued_actual_gate_entries_no_backend_owner_jail_group','original_queued_http_cancelled_without_token','cancelled_key410_durable_destroyed_pools_baseline_no_backend_resources','keeper_stop_cleanup_durable_destroyed_project_zero_while_write_still_held','continue_is_not_write_completion','survivor_original_requests_ready_real_guests_independent_boots_clean_workspace','all_four_projects_zero_pins_zero_pools_idle','observed_daemon_reaped_and_ordinary_daemon_restarted')
def node_prepare_cancel_profile(snapshot,enabled):
    if enabled and not snapshot:raise ValueError('node prepare cancellation requires the exclusive schema3 node-snapshot profile')
def validate_node_prepare_cancel(v):
    for k in NODE_PREPARE_CANCEL_FLAGS:assert v[k] is True
    for k,w in {'held_workspace_prefix_bytes':16<<20,'hold_deadline_ms':20000,'prepare_timeout_ms_unchanged':30000,'http_budget_ms_unchanged':40000,'held_continue_response_count':1}.items():assert type(v[k]) is int and v[k]==w
    assert type(v['other_continue_replies_during_keeper_cleanup']) is int and 0<v['other_continue_replies_during_keeper_cleanup']<=32768
    for k in ('keeper_delete_to_execution_domain_empty_observed_ms','keeper_delete_to_full_reclaim_observed_ms','held_write_to_continue_reply_observed_ms','holder_request_to_ready_observed_ms','survivor_request_to_ready_observed_ms'):assert type(v[k]) in (int,float) and math.isfinite(v[k]) and 0<=v[k]<40000
    assert v['keeper_delete_to_execution_domain_empty_observed_ms']<=v['keeper_delete_to_full_reclaim_observed_ms']<v['held_write_to_continue_reply_observed_ms']<20000
    for k in ('filesystem_D_or_physical_media_fault_claim','exact_copy_stage_timing_scheduler_fairness_or_slo_claim'):assert v[k] is False
    t=v['trace'];assert t['exact_ordinary_elf_sha256']==PREPARE_TRACE_ELF_SHA256
    for k,w in {'instruction_entry_probes':9,'event_count':15,'completed_preparations':2,'cancelled_waiters_without_token':1}.items():assert type(t[k]) is int and t[k]==w
    for k in ('all_eight_cpu_loss_counters_zero','all_nine_probe_hits_equal_trace','live_incarnation_inode_control_event_tgid_checked'):assert t[k] is True
    assert t['exact_channel_linearization_or_slo_claim'] is False
    rows=t['normalized_transitions'];assert type(rows) is list and len(rows)==15
    states={1:0,2:0,3:0};held=0
    for row in rows:
        point=row['point'];g=row['goroutine_index'];assert type(g) is int and g in states
        assert set(row)==({'point','goroutine_index','selected_case'} if point=='selected' else {'point','goroutine_index'})
        seq=('enter','selected','cancel') if g==2 else ('enter','selected','ok','node_ok','release','released')
        assert states[g]<len(seq) and point==seq[states[g]]
        if point=='enter' and g!=1:assert held==1
        if point=='selected':
            assert type(row['selected_case']) is int
            if g==2:assert row['selected_case']==1 and held==1
            else:
                assert row['selected_case']==0 and held==0
                if g==3:assert states[2]==3
                held+=1
        if point=='release':assert held==1 and states[2]==3 and states[3]>=1;held-=1
        states[g]+=1
    assert states=={1:6,2:3,3:6} and held==0

NODE_OPERATOR_CHECKPOINT_FLAGS=('real_nested_kvm','schema3_exact_node_policy','same_uid_operator_roundtrip_and_foreign_uid_kernel_refused_after_actual_connect','foreign_probe_before_any_guest_dac_restored_child_reaped','raw_and_session_independent_kvm_uid_boot_workspace_checked','new_raw_session_switch503_no_ledger_or_session_history','exact_accepted_replays_continue_while_drained','accepted_busy_raw_progress_and_existing_session_exec_continue','stop_and_private_reclaim_continue_while_drained','stale_resume_conflict_and_rejected_keys_reusable_after_resume','five_real_generations_one_live_before_acknowledged_drained_cut','receipt_fsynced_before_final_ack_no_observer_sync_after')
NODE_OPERATOR_RECOVERY_FLAGS=('l1_boot_changed_same_disk_ack_drained_state_checked_before_daemon','exact_node_policy_live_owner_quota_namespace_before_recovery','ordinary_recovery_keeps_admission_closed_and_destroys_all_old_generations','old_raw_session_keys410_old_session_route_closed','cold_new_create503_last_command_replay_stale_resume_conflict','explicit_resume_fresh_real_guest_uid_boot_clean_workspace','all_four_projects_zero_pools_idle_controller_reaped_node_subtree_removed','no_assigned_guest_restore_or_metadata_repair')
def node_operator_profile(budget,enabled):
    if enabled and not budget:raise ValueError('node operator modifier requires the exclusive no-snapshot --node-budget profile')
def validate_node_operator_checkpoint(v):
    assert type(v) is dict and set(v)==set(NODE_OPERATOR_CHECKPOINT_FLAGS)|{'stop_execution_domain_observed_ms','private_reclaim_observed_ms','operator_filesystem_fault_or_physical_media_failure_claim','production_slo_claim'}
    for k in NODE_OPERATOR_CHECKPOINT_FLAGS:assert v[k] is True
    for k in ('operator_filesystem_fault_or_physical_media_failure_claim','production_slo_claim'):assert v[k] is False
    for k in ('stop_execution_domain_observed_ms','private_reclaim_observed_ms'):assert type(v[k]) in (int,float) and math.isfinite(v[k]) and 0<=v[k]<200000
    assert v['stop_execution_domain_observed_ms']<=v['private_reclaim_observed_ms']
def validate_node_operator_recovery(v):
    assert type(v) is dict and set(v)==set(NODE_OPERATOR_RECOVERY_FLAGS)
    for k in NODE_OPERATOR_RECOVERY_FLAGS:assert v[k] is True

NODE_SESSION_TICKET_FLAGS=('real_nested_kvm','exact_ordinary_elf_incarnation_tgid_control_and_session_fsync_inode_checked','complete_initial_creating_zero_target_payload_before_core','one_pending_ticket_existing_two_no_new_core_backend_or_quota','durable_drain_ack_while_initial_session_sync_held','new_raw_session_switch503_no_new_record_or_history','old_raw_progress_and_existing_session_exec_continue','old_raw_stop_private_destroy_quota0_while_ticket_held','original_accepted_request_kept_alive_not_cancelled','single_continue_not_synthetic_success_or_sync_completion','accepted_ticket_creates_real_session_after_gate_closed','one_shot_ticket_pending0_replay_no_new_core','three_distinct_real_guest_boots_clean_workspaces','all_four_projects_zero_pools_idle_daemon_reaped_before_cold','acknowledged_state_saved_without_fixture_metadata_rewrite')
NODE_SESSION_TICKET_RECOVERY_FLAGS=('l1_boot_changed_ack_drained_state_checked_before_daemon','ordinary_uninstrumented_restart_stays_drained_pending0','three_old_raw_session_keys410_no_route_or_ticket_resurrection','exact_ack_retry_then_explicit_resume_revision3','fresh_real_guest_uid_boot_clean_workspace_rejected_key_reusable','all_four_projects_zero_pools_idle_daemon_reaped_node_subtree_removed','control_metadata_not_repaired_rewritten_or_restored_by_fixture')
def node_session_ticket_profile(budget,operator,store,enabled):
    if enabled and (not budget or operator or store is not None):raise ValueError('session ticket requires exclusive no-snapshot node-budget, not another operator modifier')
def validate_node_session_ticket_checkpoint(v):
    exact={'initial_file_sync_entries':1,'target_continue_replies':1,'target_errno_replies':0,'pending_before_continue':1,'existing_active_before_continue':2,'core_records_before_continue':2,'pending_after_continue':0,'core_records_after_continue':3,'acknowledged_drain_revision':2,'hold_deadline_ms':20000,'original_http_budget_ms':40000,'prepare_timeout_ms_unchanged':30000}
    times=('execution_domain_stop_observed_ms','private_destroy_quota_zero_observed_ms','original_session_request_to_ready_observed_ms')
    extra=set(exact)|set(times)|{'other_fsync_continue_replies_while_held','filesystem_d_or_physical_media_claim','production_slo_claim'}
    assert type(v) is dict and set(v)==set(NODE_SESSION_TICKET_FLAGS)|extra
    for k in NODE_SESSION_TICKET_FLAGS:assert v[k] is True
    for k,w in exact.items():assert type(v[k]) is int and v[k]==w
    assert type(v['other_fsync_continue_replies_while_held']) is int and 0<v['other_fsync_continue_replies_while_held']<=8192
    for k in times:assert type(v[k]) in (int,float) and math.isfinite(v[k]) and 0<=v[k]<40000
    assert v[times[0]]<=v[times[1]]<20000
    assert v['filesystem_d_or_physical_media_claim'] is False and v['production_slo_claim'] is False
def validate_node_session_ticket_recovery(v):
    assert type(v) is dict and set(v)==set(NODE_SESSION_TICKET_RECOVERY_FLAGS)
    for k in NODE_SESSION_TICKET_RECOVERY_FLAGS:assert v[k] is True

NODE_OPERATOR_STORE_FLAGS=('real_nested_kvm','exact_ordinary_elf_incarnation_tgid_control_and_fsync_fd_inode_checked','actual_temp_payload_and_pre_or_post_rename_directory_sequence_checked','held_notification_is_not_filesystem_d_or_media_failure','caller_cancelled_after_acceptance_target_remained_valid','status_pending_and_busy_mutation_prompt_while_store_blocked','new_raw_session_switch503_no_record_or_history','accepted_raw_progress_and_existing_session_exec_continue','raw_stop_private_destroy_quota0_and_pools_baseline_while_target_held','other_fsyncs_continued_not_synthetic_success','single_target_errno_eio_and_memory_fence_until_restart','cached_committed_before_but_actual_disk_truth_checked','existing_session_exec_and_reclaim_continue_after_error_latch','all_four_projects_zero_controller_reaped_before_cold','receipt_fsynced_without_editing_control_metadata')
NODE_OPERATOR_STORE_RECOVERY_FLAGS=('l1_boot_changed_original_disk_truth_checked_before_daemon','ordinary_uninstrumented_restart_matches_pre_or_post_commit_state','old_raw_session_keys410_and_prior_quota_namespace_zero','fresh_real_guest_uid_boot_clean_workspace_rejected_key_reusable','all_four_projects_zero_pools_idle_daemon_reaped_node_subtree_removed','control_metadata_not_repaired_rewritten_or_restored_by_fixture')
def node_operator_store_profile(budget,operator,mode):
    if mode is not None and (mode not in ('pre-file','post-root') or not budget or operator):raise ValueError('fixed operator store modifier requires exclusive --node-budget and no healthy operator modifier')
def validate_node_operator_store_checkpoint(v,mode):
    assert mode in ('pre-file','post-root') and type(v) is dict
    extra={'mode','file_sync_entries','admission_dir_sync_entries','root_dir_sync_entries','target_errno_eio_replies','other_fsync_continue_replies_while_held','execution_domain_stop_observed_ms','private_destroy_quota_zero_observed_ms','expected_cold_mode','filesystem_d_or_physical_eio_claim','production_slo_claim'}
    assert set(v)==set(NODE_OPERATOR_STORE_FLAGS)|extra and v['mode']==mode
    for k in NODE_OPERATOR_STORE_FLAGS:assert v[k] is True
    for k,w in {'file_sync_entries':1,'admission_dir_sync_entries':int(mode=='post-root'),'root_dir_sync_entries':int(mode=='post-root'),'target_errno_eio_replies':1}.items():assert type(v[k]) is int and v[k]==w
    assert type(v['other_fsync_continue_replies_while_held']) is int and 0<v['other_fsync_continue_replies_while_held']<=8192
    assert v['expected_cold_mode']==('open' if mode=='pre-file' else 'drained')
    assert v['filesystem_d_or_physical_eio_claim'] is False and v['production_slo_claim'] is False
    for k in ('execution_domain_stop_observed_ms','private_destroy_quota_zero_observed_ms'):assert type(v[k]) in (int,float) and math.isfinite(v[k]) and 0<=v[k]<20000
    assert v['execution_domain_stop_observed_ms']<=v['private_destroy_quota_zero_observed_ms']
def validate_node_operator_store_recovery(v,mode):
    extra={'mode','expected_recovered_mode','precommit_failed_unacknowledged_drain_may_reopen_old_open_not_fabricated_persistence','postcommit_drained_exact_retry_and_explicit_resume_checked'}
    assert mode in ('pre-file','post-root') and type(v) is dict and set(v)==set(NODE_OPERATOR_STORE_RECOVERY_FLAGS)|extra and v['mode']==mode
    for k in NODE_OPERATOR_STORE_RECOVERY_FLAGS:assert v[k] is True
    assert v['expected_recovered_mode']==('open' if mode=='pre-file' else 'drained')
    assert v['precommit_failed_unacknowledged_drain_may_reopen_old_open_not_fabricated_persistence'] is (mode=='pre-file')
    assert v['postcommit_drained_exact_retry_and_explicit_resume_checked'] is (mode=='post-root')

NODE_OPERATOR_SHUTDOWN_FLAGS=('real_nested_kvm','exact_ordinary_elf_incarnation_tgid_control_checked','actual_pre_rename_temp_payload_pending_no_ack','actual_sigterm_while_fsync_id_valid','both_guests_execution_empty_and_durable_private_gc_before_store_resolution','actual_control_close_deadline_error_and_exit_group1_after_run_defers','two_notifications_valid_while_same_ordinary_contender_lock_refused','contender_reaped_no_metadata_namespace_or_listener_change','only_exit_group_continue_no_file_reply_or_synthetic_success','actual_exit1_reaped_then_both_ids_enoent_with_listener_open','failed_unacknowledged_pre_file_drain_actual_old_open1','all_four_projects_zero_before_private_receipt_and_cold')
NODE_OPERATOR_SHUTDOWN_RECOVERY_FLAGS=('l1_boot_changed_old_open1_original_disk_before_daemon','ordinary_unfiltered_restart_ready_open_pending0','old_raw_session_keys410_no_route_resurrection','fresh_real_guest_boot_uid_clean_workspace_rejected_key_reusable','all_four_projects_zero_pools_idle_daemon_reaped_node_subtree_removed','no_control_metadata_repair_or_failed_intent_fabrication')
NODE_OPERATOR_SHUTDOWN_TIMINGS=('sigterm_to_execution_domain_empty_observed_ms','sigterm_to_private_destroy_quota_zero_observed_ms','sigterm_to_exit_group_entry_observed_ms','sigterm_to_contender_reaped_observed_ms')
def node_operator_shutdown_profile(budget,operator,store,ticket,enabled):
    if enabled and (not budget or operator or store is not None or ticket):raise ValueError('shutdown requires exclusive --node-budget without other modifiers')
def validate_node_operator_shutdown_checkpoint(v):
    exact={'file_sync_entries':1,'file_sync_continue_or_errno_replies':0,'exit_group_continue_replies':1,'ordinary_process_exit_code':1,'hold_deadline_ms':20000,'control_close_timeout_ms_unchanged':5000}
    counts=('other_fsync_continue_replies_while_held','other_exit_group_continue_replies')
    false=('filesystem_d_or_physical_media_claim','production_slo_claim')
    assert type(v) is dict and set(v)==set(NODE_OPERATOR_SHUTDOWN_FLAGS)|set(exact)|set(counts)|set(NODE_OPERATOR_SHUTDOWN_TIMINGS)|set(false)
    for k in NODE_OPERATOR_SHUTDOWN_FLAGS:assert v[k] is True
    for k,n in exact.items():assert type(v[k]) is int and v[k]==n
    for k in counts:assert type(v[k]) is int and (1 if k=='other_fsync_continue_replies_while_held' else 0)<=v[k]<=8192
    for k in false:assert v[k] is False
    for k in NODE_OPERATOR_SHUTDOWN_TIMINGS:assert type(v[k]) in (int,float) and math.isfinite(v[k]) and 0<=v[k]<20000
    vals=[v[k] for k in NODE_OPERATOR_SHUTDOWN_TIMINGS]
    assert vals==sorted(vals) and vals[2]>=5000

def validate_node_operator_shutdown_recovery(v):
    assert type(v) is dict and set(v)==set(NODE_OPERATOR_SHUTDOWN_RECOVERY_FLAGS)
    for k in NODE_OPERATOR_SHUTDOWN_RECOVERY_FLAGS:assert v[k] is True

TLS_GATEWAY_CHECKPOINT_FLAGS=('real_nested_kvm_through_verified_tls13','root_broker_no_tcp_listener_child_uid_caps_nnp_chroot_cwd_fd_hygiene_rlimits_and_control_checked','two_tenants_independent_real_guest_uid_boot_workspace_cross404','private_backend_tokens401_at_external_frontend','operator_metrics_routes_ambiguous_headers_and_tls12_wrong_sni_rejected','durable_policy_revision2_key_and_leaf_rotation_without_controller_or_guest_restart','old_external_key401_on_existing_tls_connection_new_key_and_leaf2_verified','invalid_reload_closes_ingress_root_child_reaped_backend_guest_continue','actual_old_policy_revision1_startup_refused_no_listener','same_current_policy_gateway_restart_without_controller_restart','session_switch_busy_old_job_new_real_guest_old_revision409','old_execution_stop_private_quota0_and_durable_destroy_independent_observations','all_three_generations_destroyed_all_four_projects_zero_pools_idle','gateway_and_ordinary_controller_reaped_before_private_receipt_and_cold')
TLS_GATEWAY_RECOVERY_FLAGS=('l1_boot_changed_original_policy_config_auth_and_destroyed_records_before_daemon','ordinary_no_test_notification_restart_open_pending0','durable_gateway_revision2_reused_without_journal_rewrite_or_key_rollback','rotated_verified_tls_leaf2_and_current_key_work_old_key401_after_cold','old_raw_session_keys410_and_old_closed_route410_no_guest_revival','fresh_independent_real_kvm_guest_uid_workspace_through_tls_and_full_gc','all_four_projects_zero_pools_idle_all_processes_reaped_node_subtree_removed')
TLS_GATEWAY_TIMINGS=('switch_to_binding_observed_ms','switch_to_first_validated_new_guest_observed_ms','switch_to_old_execution_empty_observed_ms','switch_to_old_private_destroy_quota_zero_observed_ms')
def node_tls_gateway_profile(budget,operator,store,ticket,shutdown,enabled,gateway):
    if enabled and (not budget or operator or store is not None or ticket or shutdown or not gateway):raise ValueError('TLS gateway requires exclusive --node-budget and explicit --gateway artifact')
    if not enabled and gateway is not None:raise ValueError('--gateway is only permitted for the fixed TLS profile')
def validate_tls_gateway_checkpoint(v):
    exact={'fixture_http_pacing_ms':50,'verified_real_guest_generations_before_cold':3,'policy_revision':2}
    false=('production_slo_or_full_tls_qualification_claim','physical_policy_media_fault_or_complete_dos_claim')
    assert type(v) is dict and set(v)==set(TLS_GATEWAY_CHECKPOINT_FLAGS)|set(exact)|set(false)|set(TLS_GATEWAY_TIMINGS)
    for k in TLS_GATEWAY_CHECKPOINT_FLAGS:assert v[k] is True
    for k,n in exact.items():assert type(v[k]) is int and v[k]==n
    for k in false:assert v[k] is False
    for k in TLS_GATEWAY_TIMINGS:assert type(v[k]) in (int,float) and math.isfinite(v[k]) and 0<=v[k]<40000
    assert v[TLS_GATEWAY_TIMINGS[0]]<=v[TLS_GATEWAY_TIMINGS[1]] and v[TLS_GATEWAY_TIMINGS[2]]<=v[TLS_GATEWAY_TIMINGS[3]]
def validate_tls_gateway_recovery(v):
    assert type(v) is dict and set(v)==set(TLS_GATEWAY_RECOVERY_FLAGS)
    for k in TLS_GATEWAY_RECOVERY_FLAGS:assert v[k] is True

TLS_POLICY_CHECKPOINT_FLAGS=('actual_held_temp_or_rename_inventory_checked_after_root_kill_and_before_cold','real_tls13_two_tenant_kvm_uid_boot_workspace_and_cross404','exact_gateway_elf_tgid_incarnation_nodecontrol_and_child_privileges_checked','operator_config2_input_synced_no_policy_authority_fixture_patch','fixed_reload_target_held_no_reply_and_old_key_leaf1_new_key401_before_watchdog','child_heartbeat_watchdog_closes_tls_while_root_notification_valid','ordinary_controller_same_incarnation_busy_guest_progress_and_session_continue','root_actually_sigkill_reaped_target_enoent_on_still_open_listener','independent_execution_stop_private_destroy_quota0_and_all_reaped_before_cold','cold_receipt_fsynced_after_real_ordinary_cleanup_no_claim_unsynced_media_cut')
TLS_POLICY_RECOVERY_FLAGS=('ordinary_gateway_policy_inventory_named_only_before_new_tls_guest','original_disk_actual_policy_config_identity_lock_and_destroyed_guests_before_daemon_checked','ordinary_no_test_layer_cold_open_pending0_and_no_guest_revival','current_revision2_verified_tls_leaf2_new_key200_old_key401','old_raw_session_keys410_closed_route410_and_fresh_independent_kvm_full_gc','no_policy_ledger_owner_control_authority_repair_by_fixture','all_four_projects_zero_pools_idle_processes_reaped_node_subtree_removed')
TLS_POLICY_TIMINGS=('held_to_child_gone_observed_ms','delete_to_execution_empty_observed_ms','delete_to_durable_private_quota0_observed_ms')
def node_tls_policy_profile(mode,gateway_enabled):
    if mode is not None and (mode not in ('pre-file','post-commit') or gateway_enabled):raise ValueError('fixed TLS policy phase must not combine with healthy TLS profile')
def validate_tls_policy_checkpoint(v,mode):
    assert mode in ('pre-file','post-commit')
    post=mode=='post-commit'
    exact={'policy_orphans_before_cold':0 if post else 1,'file_fsync_entries':1,'directory_fsync_entries':int(post),'policy_memfd_entries':int(post),'target_continue_or_errno_replies':0,'policy_revision_before_cold':2 if post else 1,'hold_bound_ms':20000}
    counts=('other_continue_submissions','other_continue_while_held')
    false=('filesystem_d_or_physical_media_fault_claim','production_slo_or_all_policy_windows_claim')
    assert type(v) is dict and set(v)==set(TLS_POLICY_CHECKPOINT_FLAGS)|set(exact)|set(counts)|set(false)|set(TLS_POLICY_TIMINGS)
    for k in TLS_POLICY_CHECKPOINT_FLAGS:assert v[k] is True
    for k,n in exact.items():assert type(v[k]) is int and v[k]==n
    for k in counts:assert type(v[k]) is int and 0<=v[k]<=8192
    assert v['other_continue_submissions']>0
    for k in false:assert v[k] is False
    for k in TLS_POLICY_TIMINGS:assert type(v[k]) in (int,float) and math.isfinite(v[k]) and 0<=v[k]<20000
    assert v[TLS_POLICY_TIMINGS[0]]<8000 and v[TLS_POLICY_TIMINGS[1]]<=v[TLS_POLICY_TIMINGS[2]]
def validate_tls_policy_recovery(v,mode):
    assert mode in ('pre-file','post-commit')
    exact={'foreign_symlink_and_skipped_revision_refused_without_orphan_or_authority_mutation':mode=='pre-file','policy_orphans_after_ordinary_start':0,'pre_file_old_revision1_then_production_commit2':mode=='pre-file','post_commit_revision2_old_config1_refused_and_exact_replay':mode=='post-commit','policy_revision_before_start':1 if mode=='pre-file' else 2}
    assert type(v) is dict and set(v)==set(TLS_POLICY_RECOVERY_FLAGS)|set(exact)
    for k in TLS_POLICY_RECOVERY_FLAGS:assert v[k] is True
    for k,n in exact.items():assert type(v[k]) is type(n) and v[k]==n

DIAGNOSTIC_CHECKPOINT_FLAGS=('real_nested_kvm','fixed_closed_ring_phase_and_original_inode_checked','actual_ring_fsync_held_without_target_reply','real_failed_prepare_producers_with_only_owned_input_mode_fault','queue64_full_drops_explicit_no_producer_storage_wait','accepted_raw_job_progress_and_session_route_preserved','both_guests_stopped_durable_gc_and_quota0_while_ring_fsync_held','actual_sigterm_close_budget_then_exit_group1','same_ordinary_contender_original_lock_refused_no_authority_or_ring_change','actual_exit1_reaped_then_ids_enoent_listener_open','only_exit_group_continued_no_ring_reply','inputs_restored_bytes_unchanged_no_authority_repair','no_inherited_output_fallback')
DIAGNOSTIC_RECOVERY_FLAGS=('l1_boot_changed_original_disk_before_daemon_checked','cold_valid_prefix_not_a_durability_ack','ordinary_unfiltered_writer_continues_ring_no_reset_or_repair','old_raw_session_and_all_failed_keys410_no_route_resurrection','fresh_real_guest_uid_boot_clean_workspace_and_full_gc','all_projects_zero_pools_idle_daemon_reaped_node_subtree_removed','input_bytes_modes_and_authority_not_repaired')
DIAGNOSTIC_TIMINGS=('delete_to_execution_empty_observed_ms','delete_to_private_quota0_observed_ms','signal_to_exit_group_entry_observed_ms')
def node_diagnostics_profile(node_budget, mode, *others):
    if mode is not None and (not node_budget or mode not in ('record-data','header-publish') or any(others)):
        raise ValueError('fixed diagnostics phase requires exclusive no-snapshot node-budget')
def validate_diagnostic_checkpoint(v,mode):
    assert mode in ('record-data','header-publish')
    exact={'producer_failures':80,'queued':64,'dropped':15,'observed_sequence_before_cold':5 if mode=='header-publish' else 4,'ring_fsync_entries':2 if mode=='header-publish' else 1,'data_fsync_continue_submissions':int(mode=='header-publish'),'target_reply_submissions':0,'exit_group_continue_submissions':1,'hold_bound_ms':20000}
    counts=('other_continue_submissions','other_continue_while_held')
    false=('filesystem_d_or_physical_media_fault_claim','durable_audit_or_production_slo_claim')
    assert type(v) is dict and set(v)==set(DIAGNOSTIC_CHECKPOINT_FLAGS)|set(exact)|set(counts)|set(false)|set(DIAGNOSTIC_TIMINGS)|{'mode'}
    assert v['mode']==mode
    for k in DIAGNOSTIC_CHECKPOINT_FLAGS:assert v[k] is True
    for k,n in exact.items():assert type(v[k]) is int and v[k]==n
    for k in counts:assert type(v[k]) is int and 0<v[k]<=16384
    for k in false:assert v[k] is False
    for k in DIAGNOSTIC_TIMINGS:assert type(v[k]) in (int,float) and math.isfinite(v[k]) and 0<=v[k]<20000
    assert v[DIAGNOSTIC_TIMINGS[0]]<=v[DIAGNOSTIC_TIMINGS[1]] and v[DIAGNOSTIC_TIMINGS[2]]>=250
def validate_diagnostic_recovery(v,mode):
    assert mode in ('record-data','header-publish')
    assert type(v) is dict and set(v)==set(DIAGNOSTIC_RECOVERY_FLAGS)|{'mode','observed_sequence_before_start','retained_destroyed_records'}
    assert v['mode']==mode
    for k in DIAGNOSTIC_RECOVERY_FLAGS:assert v[k] is True
    assert type(v['retained_destroyed_records']) is int and v['retained_destroyed_records']==83
    assert type(v['observed_sequence_before_start']) is int and v['observed_sequence_before_start'] in ((4,5) if mode=='header-publish' else (4,))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('fixture', 'daemon', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd', 'workspace', 'alpine',
                 'source-revision', 'report', 'log-dir'):
        parser.add_argument('--' + name, required=True)
    for name in ('admin','snapshot-builder','snapshot-seed-manifest'): parser.add_argument('--'+name)
    parser.add_argument('--node-oom',action='store_true',help='TEST ONLY fixed unprivileged host-cgroup memory pressure in one owned L1 VM group, real kernel OOM/neighbor Stop/GC/cold; exclusive --node-budget, not guest-origin or whole-node saturation')
    parser.add_argument('--node-diagnostics',choices=('record-data','header-publish'),help='TEST ONLY exact ordinary ring fsync hold, bounded queue pressure, independent Stop/GC, actual exit lock and cold recovery; exclusive node-budget')
    parser.add_argument('--node-tls-policy',choices=('pre-file','post-commit'),help='TEST ONLY exact gateway reload FSYNC or post-durable pre-snapshot memfd hold; exclusive node-budget with gateway')
    parser.add_argument('--node-tls-gateway',action='store_true',help='TEST ONLY root connector/unprivileged chroot TLS gateway +credentials and real guest/cold recovery; exclusive --node-budget')
    parser.add_argument('--gateway',help='explicit static Linux gateway binary only with --node-tls-gateway')
    parser.add_argument('--node-operator-shutdown',action='store_true',help='TEST ONLY actual unresolved control FSYNC through ordinary SIGTERM/run-return/EXIT_GROUP lock contention; exclusive --node-budget')
    parser.add_argument('--node-session-ticket',action='store_true',help='TEST ONLY initial session journal fsync before Core held across actual ACK drain; requires exclusive --node-budget')
    parser.add_argument('--node-operator-store',choices=('pre-file','post-root'),help='TEST ONLY fixed actual ordinary control FileStore fsync EIO windows; requires --node-budget, not physical storage fault')
    parser.add_argument('--node-operator',action='store_true',help='TEST ONLY modifier of --node-budget: same-UID drain/resume, actual foreign-UID peer rejection and acknowledged drain same-disk cold recovery; not storage fault or full qualification')
    parser.add_argument('--node-prepare-cancel',action='store_true',help='TEST ONLY modifier of --node-snapshot: actual original queued request cancellation and independent keeper cleanup while one fixed partial workspace WRITE notification is held; no filesystemD or SLO')
    profiles = parser.add_mutually_exclusive_group()
    profiles.add_argument("--node-load",action="store_true",help="TEST ONLY fixed40min open arrivals/2tenant canaries/100serial quota tail/cold; NEW one-hour8GiB profile with10krecords/512sessions/control3840MiB; no duration/rate selectors")
    profiles.add_argument("--node-snapshot",action="store_true",help="TEST ONLY: explicit8GiB schema3 snapshots, inode/byte admission pressure and low-free same-disk cold recovery; no full OOM or prepare-permit trace claim")
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
    node_load_profile(args.node_load,args.node_oom,args.node_operator,args.node_operator_store,args.node_session_ticket,args.node_operator_shutdown,args.node_diagnostics,args.node_tls_policy,args.node_tls_gateway,args.node_prepare_cancel,args.gateway)
    node_oom_profile(args.node_budget,args.node_oom,args.node_operator,args.node_operator_store,args.node_session_ticket,args.node_operator_shutdown,args.node_diagnostics,args.node_tls_policy,args.node_tls_gateway,args.node_snapshot,args.node_prepare_cancel,args.gateway)
    node_prepare_cancel_profile(args.node_snapshot,args.node_prepare_cancel)
    node_operator_profile(args.node_budget,args.node_operator)
    node_operator_store_profile(args.node_budget,args.node_operator,args.node_operator_store)
    node_session_ticket_profile(args.node_budget,args.node_operator,args.node_operator_store,args.node_session_ticket)
    node_operator_shutdown_profile(args.node_budget,args.node_operator,args.node_operator_store,args.node_session_ticket,args.node_operator_shutdown)
    node_diagnostics_profile(args.node_budget,args.node_diagnostics,args.node_operator,args.node_operator_store,args.node_session_ticket,args.node_operator_shutdown,args.node_tls_policy,args.node_tls_gateway,args.node_snapshot,args.node_prepare_cancel)
    node_tls_policy_profile(args.node_tls_policy,args.node_tls_gateway)
    gateway_profile=args.node_tls_gateway or args.node_tls_policy is not None
    node_tls_gateway_profile(args.node_budget,args.node_operator,args.node_operator_store,args.node_session_ticket,args.node_operator_shutdown,gateway_profile,args.gateway)
    selected=[v for flag,v in COMMIT_PROFILES.items() if getattr(args,flag)]
    commit_phase,commit_operation=selected[0] if selected else (None,None)
    commit_profile=bool(selected)
    losses=[v for flag,v in LISTENER_PROFILES.items() if getattr(args,flag)]
    listener_phase,listener_operation=losses[0] if losses else (None,None)
    listener_profile=bool(losses)
    private_cut_profile=args.quota_partial_copy_cut or args.quota_owner_cut
    copy_profile=args.quota_partial_copy or private_cut_profile
    node_profile=args.node_budget or args.node_snapshot or args.node_load
    resources=nested_node_load_resources() if args.node_load else nested_node_resources(args.node_snapshot) if node_profile else nested_copy_resources() if copy_profile else nested_resources(args.quota_switch)
    disk_bytes=resources["disk_bytes"]
    snapshot_profile = args.node_snapshot or args.quota_snapshot or args.quota_clear_crash or args.quota_switch or copy_profile
    state_io_profile = args.state_io or args.quota_state_io
    driver_profile = node_profile or args.quota_driver or snapshot_profile or args.quota_negatives or args.quota_syscalls or args.quota_unenforced or args.quota_state_io or args.quota_barrier_hang or commit_profile or listener_profile
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
    assert os.statvfs('/srv').f_bavail * os.statvfs('/srv').f_frsize > (24 if node_profile else 12 if (args.quota_switch or copy_profile) else 8) << 30
    if node_profile or args.quota_switch or copy_profile:
        available=[int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')]
        assert len(available)==1 and available[0]>=(32 if node_profile else 8)<<30, 'explicit profile requires its fixed L0 memory headroom'
    suffix = secrets.token_hex(3)
    root = Path('/srv/nh-' + suffix); control = Path('/var/lib/xandbox-nested-proof-' + suffix)
    parent_group = Path('/sys/fs/cgroup/xandbox-nested-proof-' + suffix); group = parent_group / secrets.token_hex(32)
    assert not any(p.exists() for p in (root, control, parent_group))
    sources = {n: Path(getattr(args,n)).resolve() for n in ('fixture','daemon','warden','firecracker','jailer','kernel','initrd','workspace','alpine')}
    if gateway_profile:
        sources['gateway']=Path(args.gateway).resolve()
        assert sources['gateway'].is_file() and not sources['gateway'].is_symlink() and sources['gateway'].stat().st_size<32<<20
        static_elf(sources['gateway'].read_bytes())
    if snapshot_profile:
        sources.update({n:Path(getattr(args,n)).resolve() for n in ('admin','snapshot_builder')})
        seed=json.loads(Path(args.snapshot_seed_manifest).read_text())
        assert seed['assignment']=='UNASSIGNED' and re.fullmatch('[0-9a-f]{64}',seed['agent_sha256'])
        for n in ('firecracker','jailer','kernel','initrd','workspace'): assert seed[n+'_sha256']==digest(sources[n])
    phases = ('node-open-arrival-healthy-checkpoint',) if args.node_load else ('node-oom-real-group-kill-checkpoint',) if args.node_oom else (args.node_diagnostics,) if args.node_diagnostics else (args.node_tls_policy,) if args.node_tls_policy else ('privilege-separated-tls-tenant-gateway',) if args.node_tls_gateway else ('unfinished-control-shutdown-state-lock-until-exit',) if args.node_operator_shutdown else ('accepted-session-precore-ticket-across-drain',) if args.node_session_ticket else (args.node_operator_store,) if args.node_operator_store else ('operator-acknowledged-drained-checkpoint',) if args.node_operator else ('node-snapshot-space-pressure-checkpoint',) if args.node_snapshot else ('node-envelope-healthy-checkpoint',) if args.node_budget else ('owner-unlink-directory-fsync-pending',) if args.quota_owner_cut else ('partial-copy-inflight-cut',) if args.quota_partial_copy_cut else () if args.quota_partial_copy else ('quota-enabled-two-tenant-switching',) if args.quota_switch else (listener_phase,) if listener_profile else (commit_phase,) if commit_profile else ('reserve-quota-syncfs-held',) if args.quota_barrier_hang else ('quota-cleared-owner-pinned',) if args.quota_clear_crash else () if args.quota_unenforced else ('quota-prerequisites',) if args.quota_probe else ('eio-busy','eio-idle','hang-busy','hang-idle') if state_io_profile else ('running','stopped','destroyed')
    result = {'test':'owned_l1_fixed40min_open_arrival_two_tenant_canaries_quiescent_quota_tail_and_cold' if args.node_load else 'owned_l1_actual_vm_cgroup_oom_neighbor_stop_reclaim_and_cold' if args.node_oom else 'owned_l1_bounded_diagnostic_fsync_pressure_shutdown_lock_and_cold' if args.node_diagnostics else 'owned_l1_gateway_reload_commit_hold_watchdog_and_namespace_cold' if args.node_tls_policy else 'owned_l1_privilege_separated_tls_tenant_gateway' if args.node_tls_gateway else 'owned_l1_unresolved_control_shutdown_real_exit_and_state_lock' if args.node_operator_shutdown else 'owned_l1_accepted_session_precore_ticket_across_ack_drain' if args.node_session_ticket else 'owned_l1_actual_operator_filestore_single_fsync_errno_and_namespace_cold_truth' if args.node_operator_store else 'owned_l1_durable_node_operator_and_foreign_uid_peer_with_ack_drained_cold_recovery' if args.node_operator else 'owned_l1_schema3_snapshot_space_admission_pressure_and_low_free_cold_recovery' if args.node_snapshot else 'owned_l1_schema3_node_envelope_admission_and_healthy_cold_recovery' if args.node_budget else 'owned_l1_owner_unlink_directory_fsync_pending_cut_with_keeper' if args.quota_owner_cut else 'owned_l1_unsynced_partial_workspace_copy_cut_with_keeper' if args.quota_partial_copy_cut else 'owned_l1_partial_workspace_write_errno_with_live_keeper' if args.quota_partial_copy else 'owned_l1_quota_two_tenant_busy_switching' if args.quota_switch else 'owned_l1_last_quota_listener_loss' if listener_profile else 'owned_l1_fixed_real_quota_commit_fault' if commit_profile else 'owned_l1_actual_quota_syncfs_hold_prefork_crash' if args.quota_barrier_hang else 'owned_l1_fixed_quota_syscall_errno_real_l2_kvm' if args.quota_syscalls else 'owned_l1_quota_cleared_owner_pinned_power_cut_real_l2_kvm' if args.quota_clear_crash else 'owned_l1_quota_whole_state_io_failure_real_l2_kvm' if args.quota_state_io else 'owned_l1_ordinary_driver_unenforced_ext4_startup_rejection' if args.quota_unenforced else 'owned_l1_ordinary_driver_quota_negative_real_l2_kvm' if args.quota_negatives else 'owned_l1_snapshot_driver_quota_real_l2_kvm' if args.quota_snapshot else 'owned_l1_ordinary_driver_quota_real_l2_kvm' if args.quota_driver else 'owned_l1_project_quota_prerequisites_real_l2_kvm' if args.quota_probe else 'owned_l1_whole_state_io_failure_real_l2_kvm' if args.state_io else 'owned_l1_host_power_cut_real_l2_kvm',
        'production_ready':False,'passed':False,'state_io_profile':state_io_profile,'quota_state_io_profile':args.quota_state_io,'quota_prerequisite_profile':args.quota_probe,
        'production_driver_quota':driver_profile,'quota_snapshot_profile':snapshot_profile,'quota_clear_crash_profile':args.quota_clear_crash,'quota_negative_profile':args.quota_negatives,'quota_unenforced_profile':args.quota_unenforced,
        'quota_syscall_errno_profile':args.quota_syscalls,'quota_barrier_hang_profile':args.quota_barrier_hang,
        'quota_commit_fault_phase':commit_phase,'quota_listener_loss_phase':listener_phase,'quota_switch_profile':args.quota_switch,'quota_partial_copy_profile':args.quota_partial_copy,'quota_partial_copy_cut_profile':args.quota_partial_copy_cut,'quota_owner_cut_profile':args.quota_owner_cut,'node_budget_profile':args.node_budget,'node_load_profile':args.node_load,'node_oom_profile':args.node_oom,'node_snapshot_profile':args.node_snapshot,'node_prepare_cancel_profile':args.node_prepare_cancel,'node_operator_profile':args.node_operator,'node_operator_store_phase':args.node_operator_store,'node_session_ticket_profile':args.node_session_ticket,'node_operator_shutdown_profile':args.node_operator_shutdown,'tls_gateway_profile':args.node_tls_gateway,'tls_policy_phase':args.node_tls_policy,'diagnostic_hold_phase':args.node_diagnostics,
        'source_revision':args.source_revision,'validated_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'harness_sha256':digest(__file__),'builder_sha256':digest(Path(__file__).with_name('build_nested_host.py')),
        'l0_kernel':os.uname().release,'l1_kernel':policy['l1_kernel_release'],'qemu_package_version':policy['qemu_package_version'],
        'qemu_sha256':policy['qemu_sha256'],'l1_kernel_sha256':policy['l1_kernel_sha256'],
        'modules_sha256':policy['modules_sha256'],'artifacts_sha256':{n:digest(p) for n,p in sources.items()},
        'l1_memory_mib':resources['memory_mib'],'l0_cgroup_memory_max':resources['cgroup_memory_max'],'l1_vcpus':8 if node_profile else 4,'l1_disk_bytes':disk_bytes,'launch_profile':resources['profile'],
        'l1_business_network_interfaces':0,'l2_guest_memory_mib':512,'l2_vcpus':2,'l2_workspace_bytes':128<<20,
        'outer_disk_format':'raw','outer_disk_cache':'none','outer_disk_aio':'native','cases':[],
        'l1_boots_completed':0,'checkpoint_progress':[],
        'limitations':['Forced loss of our isolated L1 service-host VM, not physical L0 power/media failure.',
            'No TCG fallback, outer QEMU migration/snapshot save/restore, or shared L0 host reboot; this does not prohibit real L2 Firecracker snapshot operations.',
            'Fixed trusted test control operations, not tenant commands executed on a host.',
            'Finite checkpoint cases, not every in-flight fsync/prepare window, production SLO or independent operator acceptance.']}
    if args.node_load:
        result['limitations'] += ['NEW node-load-v1:8GiB/12GiB/CPU8/pids256/outer10GiB/noNIC/ONE-HOUR outer maximum; old profiles remain15min. Immutable Node7GiB/control3840MiB/N4/records10000/tenantrecords5000/sessions512/tenantsessions256/prepare1. Existing taskTTL300,execution60s,history64 unchanged.', 'Four fixed10min open offered phases:0.1/0.5/2/8 raw lifecycles/s,6360 total; due times independent of completion. Four fixed workers and queue16 per tenant. Generator queue/full/lateness drops counted separately, not service rejections or zero-latency successes. Scheduled-to-reply includes queue delay; API timings separate.', 'Two scheduled session canaries each120 at20s spacing; rotate8attempts or200s age, preserving64history/300TTL. Busy-old kernel stop before original60s/newguest/boot/committed replay/stale rejection. Backpressure responses are not completed switches.', 'No operator/root-observer Q_SYNC or syncfs during offered window; ordinary production fsync/quota-clear barriers and guest sync remain unchanged. Active reused projects prevent race-free per-generation project-zero attribution: report namespace/durable Destroyed latency only there. Separate100-cycle SERIAL quiescent tail observes exact full project0 timing. Final all4quota0 and cold replay mandatory, not inferred from outer disk deletion.', 'Equal workload/alternating equal offers; predeclared coarse each-tenant one-fifth successful-completion share per10min phase, not universal scheduling fairness/SLO. All errors/drop denominators and slow samples retained.', 'Kernel charges/RSS/FD/quota/free-space/pools sampled10s with observation cost; misses peaks, not unique RAM billing. Permanent tombstones planned/bounded by10k, not archival. TEST observer PID1 outside NodeRoot is overhead inside bounded L1.', 'Healthy synced distinct checkpoint after workload/quiescence; accepted private capabilities replay410 before fresh cold guest. No assigned restore/metadata repair/in-flight fault/physical media/full fault matrix/independent operator production claim.']
    if args.node_snapshot:
        result['limitations'] += ['Explicit8GiB RAM/12GiB disk/10GiB outerCG/CPU8/pids256/noNIC/hard900 profile, mkfs requests131072 inodes with fixed131072..135168 ext4 rounding bound. Old profiles unchanged; not speedup evidence.', 'Schema3 ordinary snapshots/private quota/shared backing with daemon AND all admin processes inside control. The trusted offline L1 snapshot builder is separate setup outside NodeRoot, not measured ordinary preparation or an all-node physical-memory pressure proof.', 'Only own L1 ext4 is filled with bounded exclusive root-owned files: byte fallocate actually reserves blocks, not guest data or shared L0 disk filling. Inode and byte guards are separate, retaining cleanup runway. This is admission-reserve pressure, not ENOSPC/media fault/node-wide project quota.', 'Healthy synced LOW-free original-disk cold checkpoint: ordinary startup/reclaim must work before removing only the exact owned filler. No assigned guest restore, policy retarget or quota pre-clear.', 'Two live guests touch8MiB each, not full512MiB saturation, OOM, unique-RAM billing, open-loop/fairness/long-duration/operator/SLO. Hardware prepare-permit trace remains explicitly unclaimed.']
    if args.node_budget and not (args.node_oom or args.node_operator or args.node_operator_store or args.node_session_ticket or args.node_operator_shutdown or args.node_diagnostics or gateway_profile):
        result['limitations'] += ['NEW explicit8GiB L1 RAM/12GiB raw disk/10GiB outerCG/CPU8/pids256/noNIC/900; QMP memory verified. Old2GiB and3GiB profiles unchanged; larger resources are not performance improvement evidence.', 'Schema3 node aggregate planning and kernel parent/control ceilings with exact frontend limits, quota/IO and bounded preparation. Disk/inodes use conservative full-allocation plus full-free admission reserve, NOT a node-wide project quota or unique RAM billing. Operator assets/exports/logs require external bounds; pressure checks do not guarantee media availability.', 'Each of four guests touches8MiB memory, not full512MiB. Parent memory.max tightened only4KiB with explicit safe headroom; rejection proves immutable readback enforcement, not OOM/saturation or the full set of node resource-pressure faults.', 'Healthy synced checkpoint/cold recovery only, not an in-flight metadata commit. Preparation concurrency is unit/race bounded and wired to real staging; this case does not claim a hardware trace of concurrent copy permits, unique-page attribution, fairness or production SLO.', 'New production ELF requires full DEFAULT/quota-enabled240/dual-cold/failure requalification separately; legacy frozen522 reports cannot certify this ELF. FullM1-M4/production/operator acceptance remains incomplete.']
    if args.node_oom:
        result['limitations'] += ['Exact existing node-budget-v1 envelope:8GiB L1 RAM/12GiB disk/10GiB outerCG/CPU8/pids256/noNIC/hard900. Node7GiB/control1GiB/perVM768MiB/swap0/oom.group1 unchanged. No shared L0 pressure or budget rewrite.', 'Four ordinary real guests each retain a fixed96MiB logical awk workload; actual host memory.stat anon delta must be at least64MiB per group. Not unique-page attribution or complete512MiB guest saturation.', 'Trusted TEST helper born directly into one exact existing VM host cgroup. Fixed marker/held directory inode/cgroup2/owner checks, all-thread UID/GID400000-range/groups0/caps0 including bounding/NNP/oom_score_adj0 verified before fixed1GiB anonymous mapping request and4096-byte page touching. Allocation request is not a claim that1GiB became resident.', 'Actual target memory.events max/oom/oom_kill/oom_group_kill increments plus SIGKILL/reap before original20s guard and actual empty execution domain required. Manual kill, ENOMEM, timeout or missing counters FAIL. Host-group pressure is NOT guest-origin OOM, global host RAM saturation or physical fault.', 'Three busy neighbors must retain RUNNING status and accept new ordinary guest exec after target OOM. Ordinary Stop independently observes their domains empty before each original60s execution timeout; durable Destroyed/owner/jail/cgroup absence/project quota0/key410/fresh-slot boot and clean workspace are separate checks. No SLO/benchmark claim.', 'Healthy synced new guest checkpoint only AFTER the OOM and full private reclaim. Original-disk cold recovery with a distinct fixed receipt phase, no assigned-guest resurrection or metadata restoration. Not an in-flight OOM power cut, full memory/fault matrix, sustained/open-arrival load, fairness, upgrade or production certification.']
    if args.node_diagnostics:
        result['limitations'] += ['TEST ONLY inherited FSYNC plus EXIT_GROUP observer on exact source-bound ordinary daemon TGID/start/inode/control. No production hooks, arbitrary selectors, shared L0 changes or replies to held ring FSYNC; notification is not filesystem D or media failure.', 'Original node-budget resources,20s hold/250ms logger wait/30s Prepare/40s HTTP unchanged.80 real ordinary Prepare500 failures use only owned L1 kernel/initrd/workspace INPUT mode0444->0666, with bytes/inodes unchanged and separate live private copies; securePath fails before any source copy. Restore only these input modes, never ledger/owner/control/identity/log headers.', 'One in-flight fixed record plus queue64,15 explicit drops; successful enqueue is not persistence. Raw job progress and session route remain available, ordinary Stop and full private GC/quota0 complete before diagnostic resolution. After SIGTERM observe actual EXIT_GROUP1 following bounded logger wait; same ordinary contender still fails original state lock. Continue ONLY exit-group, actual reap then both IDs ENOENT with listener still open.', 'Record-data phase never publishes header5, so cold valid prefix4. Header-publish phase reaches actual second FSYNC after checked data Sync but header sync is unACKed: cold may validly retain4 or5. Other cleanup/quota/receipt may sync filesystem; not an unsynced media crash or durable audit guarantee.', 'Same-disk ordinary unfiltered cold writer validates retained prefix/no reset or repair, all old keys410/closed session, new third real guest and full GC. Only two explicit logging windows; full changed-ELF DEFAULT/IO/quota240/TLS/trace/physical faults/open-loop/resource saturation/audit/production acceptance remain incomplete.']
    if args.node_tls_policy:
        result['limitations'] += ['Existing ordinary4ee and gateway241ca ELF; TEST ONLY inherited FSYNC plus MEMFD_CREATE notification layer/NNP on exact gateway TGID/incarnation/NodeControl, fixed20s hold. No production hooks, arbitrary syscall/path or shared L0 change.', 'Pre-file holds exact revision2 temporary record before fsync/rename, legitimate journal1. Post-commit continues file fsync and directory fsync, then holds fixed policy memfd_create entry after checked Commit returned nil; exact renamed inode/record2 and identity/lock verified. CONTINUE submissions are not completion counters; following checked source entry proves the selected ordering.', 'No reply to target. Existing oldkey/leaf1 and newkey401 checked before root heartbeat watchdog closes ingress; actual child gone while notification still valid and root alive. Ordinary busy guest/session continue. Root then actually SIGKILL/reaped, target ID ENOENT while listener remains open, not EBADF.', 'Both old guests fully stopped/durable private GC/quota0 before receipt and same-disk cold; cleanup/receipt may sync filesystem. NOT an in-flight unsynced media cut, filesystem D or physical media failure. Fixture only provisions operator auth/config/certificate INPUT and never patches policy/ledger/owner/control authority.', 'Pre-file cold legitimately starts journal1 and current operator input2; production commits2 before new ingress. Post-commit cold journal2 must reject actual oldconfig1 before listen, then exact current2 replay without journal rewrite. New verified leaf2/newkey200/old401, oldkeys410 and fresh third real guest/fullGC. No full policy fault matrix, PKI, DoS, operator/systemd or production SLO claim.']
    if args.node_tls_gateway:
        result['limitations'] += ['New production gateway, ordinary daemon/five assets remain prior4ee; root fixed connector has no TCP listener or network HTTP/TLS parsing. All new processes are born inside fixed NodeControl. Only own L1 loopback is brought up, no business NIC or sharedL0 network change.', 'Unprivileged dedicatedUID/GID60001/caps0/NNP/executable-only chroot/nofile192/nproc64 and sole child TCP listener verified from actual kernel proc. This is fixed host process least privilege, not another KVM tenant execution backend or resistance to a compromised gateway.', 'External digest/expiry maps to a distinct private controller token, exact backend owner/quota validated. Actual revision2 durable file/directory sync before atomic key+leaf publication, old key denied on existing TLS, invalid reload closes ingress while ordinary guests continue, oldrevision startup rejects, original-disk cold preserves currentpolicy. Not all policy IO/physical-media failure windows, issuer/distribution/PKI automation, long-duration/DoS or production SLO.', 'Fixture TLS client deliberately paces20req/s to stay below fixed gateway rate budgets; timings include this sampling and independent readback, no speedup or internal-stage inference. Real busy session switch measured once; closed-loop N1 is not fairness or percentile.', 'All three old guest generations fully destroyed/quota0 and ingress/controller reaped BEFORE private receipt and same-disk cold; fresh fourth guest via verified TLS then fullGC. No policyjournal/control/ledger/owner repair by fixture; operator only provisions auth/certificate/config input before load.']
    if args.node_operator_shutdown:
        result['limitations'] += ['Extra TEST ONLY FSYNC and EXIT_GROUP notification layer on exact ordinary4ee; original node-budget-v1 resources and20s hold/5s control Close unchanged.', 'Hold actual .state-N Sync before rename, send real SIGTERM, independently observe two real guests execution stopped/private quota0/durable Destroyed. Capture actual EXIT_GROUP1 after checked control Close deadline error and run defers; both IDs valid while a second same ordinary unfiltered daemon fails the kernel controller.lock. This exit barrier is TEST only, not a production indefinite pause.', 'Only EXIT_GROUP gets one CONTINUE; held FSYNC never receives reply. Reap actual exit1, check both IDs ENOENT with listener still open, not EBADF. Other FSYNC/exit CONTINUE counts are successful reply submissions, not syscall completions.', 'Unacknowledged pre-file drain legitimately retains old OPEN1; no fabricated durable fence or metadata repair. Two owned L1 boots on original disk with ordinary unfiltered recovery and fresh guest/full GC; not physical media failure, all shutdown/store windows or production SLO.']
    if args.node_operator_store:
        result['limitations'] += ['Exact existing node-budget-v1 resources and ordinary4ee ELF. Extra TEST ONLY inherited FSYNC user-notification layer, no production hooks or generic tenant targets.', 'Only one exact .state-file pre-rename or root-directory post-admission-directory FSYNC receives synthetic EIO, never synthetic success. Other notifications CONTINUE while held; CONTINUE is authorization, not an observed completion count. Notification waiting is NOT filesystem D or physical media failure.', 'Caller cancels AFTER accepted operation reaches actual FileStore FSYNC. In-process gate remains closed/pending, status/BUSY and accepted guest tasks/Stop/private GC continue, then EIO latches fence until exclusive process restart.', 'Pre-file failure can legitimately reload old OPEN; post-root phase proves next directory entry and exact renamed inode after checked prior Sync returns, then reloads DRAINED. Neither is a promise that all failed/unacknowledged drain intents survive restart.', 'Guests fully reclaimed and observed daemon cleanly reaped before receipt/cold cut; not an in-flight power cut, unfinished shutdown writer state-lock test, every commit syscall, physical media or production SLO. Full new runtime matrices remain required.']
    if args.node_operator:
        result['limitations'] += ['Existing exact node-budget-v1 resources/NodePolicy unchanged:8GiB/12GiB/CPU8, no snapshot or full resource saturation/fairness claim.', 'Before ANY guest, only isolated L1 own path DAC is deliberately widened then restored; fixed UID400003 child must actually connect, see the ordinary daemon root peer, then receive EOF/reset before any HTTP bytes. A filesystem DAC failure does not pass. Connect-time same-UID authority does not protect against malicious host owner/FD delegation.', 'Five real cold generations with raw/session/new-switch, one live at acknowledged drained cut; sixth fresh guest after cold. This case does not test a session ticket accepted but blocked before Core reservation, nor an operator filesystem commit/error window or physical media fault.', 'Private receipt fsynced BEFORE final drain ACK; no observer quota-sync/syncfs/receipt write after ACK. Same original disk cold checks committed admission before daemon; no state restoration or assigned guest revival.', 'N1 stop/private reclaim observations are separate from final pool credit, NOT physical erase or SLO. New default/IO/quota240/dual-live/failure/node/prepare matrices remain separate required qualification.']
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
        build_initrd(alpine=sources['alpine'],fixture=fixture,manifest=policy,output=root/'initrd.cpio.gz',state_io=args.state_io,quota_probe=args.quota_probe,quota_driver=(args.quota_driver or args.quota_negatives or args.quota_syscalls or listener_profile),quota_snapshot=(snapshot_profile and not (args.quota_switch or args.node_snapshot)),quota_switch=args.quota_switch,node_budget=args.node_budget,node_snapshot=args.node_snapshot,node_load=args.node_load,quota_unenforced=args.quota_unenforced,quota_state_io=(args.quota_state_io or args.quota_barrier_hang or commit_profile))
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
        if gateway_profile:
            shutil.copyfile(sources['gateway'],staging/'assets/xandbox-gateway');(staging/'assets/xandbox-gateway').chmod(0o555)
        if snapshot_profile:
            backend['version']=2
            backend['snapshot']={'version':1,'agent_sha256':seed['agent_sha256'],'memory_mib':512,'vcpus':2,'max_entries':4 if (copy_profile or args.node_snapshot) else 2,'max_bytes':(2 if (copy_profile or args.node_snapshot) else 1)<<30}
            for name,target_name in (('admin','admin'),('snapshot_builder','snapshot-builder')):
                shutil.copyfile(sources[name],staging/'assets'/target_name);(staging/'assets'/target_name).chmod(0o555)
            private_json(staging/'config/snapshot-fixture.json',{'source_revision':args.source_revision,'agent_sha256':seed['agent_sha256'],'admin_sha256':digest(sources['admin']),'builder_sha256':digest(sources['snapshot_builder'])})
        if node_profile:
            backend.update(version=3,cgroup_root='/sys/fs/cgroup/xandbox/instances',node=node_load_policy(node_budget_policy()) if args.node_load else node_budget_policy(),io={'version':1,'filesystem_device':'253:0','device':'253:0','bytes_per_second':16<<20,'operations_per_second':1024})
        private_json(staging/'config/backend.json',backend)
        disk=root/'disk.raw'
        with disk.open('xb') as f: os.posix_fallocate(f.fileno(),0,disk_bytes); os.fsync(f.fileno())
        format_options = quota_format_options(args.quota_probe or (driver_profile and not args.quota_unenforced))
        subprocess.run(['mkfs.ext4','-q','-F','-m','0','-E','root_owner=0:0',*format_options,*node_snapshot_format_options(args.node_snapshot),*(['-U',str(filesystem_uuid)] if driver_profile else []),'-d',str(staging),str(disk)],check=True,timeout=120)
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
            for name,value in nested_group_limits(resources).items():
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
            channel=JSONSocket(root/'control.sock',3350 if args.node_load else 770 if args.quota_switch else 210 if (snapshot_profile or args.quota_negatives or args.quota_syscalls or args.node_operator or args.node_operator_store or args.node_session_ticket or args.node_operator_shutdown or gateway_profile) else 90,quota_switch=args.quota_switch,node_load=args.node_load)
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
            if args.node_load and not out['ok'] and 'result' in out:
                private_json(logs/'node-load-partial-private.json',out)
                result['node_load_private_partial_reply_preserved']=True
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
        elif snapshot_profile and not private_cut_profile:
            result['snapshot_setup']=request('quota-snapshot-setup')
            if args.node_snapshot:validate_node_snapshot_setup(result['snapshot_setup'])
        if args.node_prepare_cancel:
            result['prepare_cancellation']=request('node-prepare-cancel')
            validate_node_prepare_cancel(result['prepare_cancellation'])
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
            checkpoint=request('node-load-run') if args.node_load else request('node-oom-checkpoint') if args.node_oom else request('node-diagnostics-checkpoint',phase) if args.node_diagnostics else request('node-tls-policy-checkpoint',phase) if args.node_tls_policy else request('node-tls-gateway-checkpoint') if args.node_tls_gateway else request('node-operator-shutdown-checkpoint') if args.node_operator_shutdown else request('node-session-ticket-checkpoint') if args.node_session_ticket else request('node-operator-store-checkpoint',phase) if args.node_operator_store else request('node-operator-checkpoint') if args.node_operator else request('node-snapshot-checkpoint') if args.node_snapshot else request('node-budget-checkpoint') if args.node_budget else request('quota-owner-cut-checkpoint') if args.quota_owner_cut else request('quota-copy-cut-checkpoint') if args.quota_partial_copy_cut else request('quota-switch-checkpoint') if args.quota_switch else request(listener_operation+'-checkpoint') if listener_profile else request(commit_operation+'-checkpoint') if commit_profile else request('quota-barrier-checkpoint') if args.quota_barrier_hang else request('quota-clear-checkpoint') if args.quota_clear_crash else request('quota-probe') if args.quota_probe else request('io-fault' if state_io_profile else 'quota-checkpoint' if driver_profile else 'checkpoint',phase)
            if args.node_load: validate_node_load_result(checkpoint)
            elif args.node_oom: validate_node_oom_checkpoint(checkpoint)
            elif args.node_diagnostics: validate_diagnostic_checkpoint(checkpoint,phase)
            elif args.node_tls_policy: validate_tls_policy_checkpoint(checkpoint,phase)
            elif args.node_tls_gateway: validate_tls_gateway_checkpoint(checkpoint)
            elif args.node_operator_shutdown: validate_node_operator_shutdown_checkpoint(checkpoint)
            elif args.node_session_ticket: validate_node_session_ticket_checkpoint(checkpoint)
            elif args.node_operator_store: validate_node_operator_store_checkpoint(checkpoint,phase)
            elif args.node_operator: validate_node_operator_checkpoint(checkpoint)
            elif args.node_snapshot: validate_node_snapshot_checkpoint(checkpoint)
            elif args.node_budget: validate_node_budget_checkpoint(checkpoint)
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
            boot(); recovered=request('node-load-recover') if args.node_load else request('node-oom-recover') if args.node_oom else request('node-diagnostics-recover',phase) if args.node_diagnostics else request('node-tls-policy-recover',phase) if args.node_tls_policy else request('node-tls-gateway-recover') if args.node_tls_gateway else request('node-operator-shutdown-recover') if args.node_operator_shutdown else request('node-session-ticket-recover') if args.node_session_ticket else request('node-operator-store-recover',phase) if args.node_operator_store else request('node-operator-recover') if args.node_operator else request('node-snapshot-recover') if args.node_snapshot else request('node-budget-recover') if args.node_budget else request('quota-owner-cut-recover',receipt=cut_receipt) if args.quota_owner_cut else request('quota-copy-cut-recover',receipt=cut_receipt) if args.quota_partial_copy_cut else request('quota-switch-recover' if args.quota_switch else listener_operation+'-recover' if listener_profile else commit_operation+'-recover' if commit_profile else 'quota-barrier-recover' if args.quota_barrier_hang else 'quota-clear-recover' if args.quota_clear_crash else 'recover')
            if args.node_diagnostics: validate_diagnostic_recovery(recovered,phase)
            elif args.node_tls_policy: validate_tls_policy_recovery(recovered,phase)
            elif args.node_tls_gateway: validate_tls_gateway_recovery(recovered)
            elif args.node_operator_shutdown: validate_node_operator_shutdown_recovery(recovered)
            elif args.node_session_ticket: validate_node_session_ticket_recovery(recovered)
            elif args.node_operator_store: validate_node_operator_store_recovery(recovered,phase)
            elif args.node_operator: validate_node_operator_recovery(recovered)
            elif args.node_snapshot: validate_node_snapshot_recovery(recovered)
            elif args.node_load:
                validate_node_budget_recovery(recovered)
                for key in NODE_LOAD_RECOVERY_FLAGS: assert recovered[key] is True
            elif args.node_budget: validate_node_budget_recovery(recovered)
            elif args.quota_owner_cut: validate_quota_owner_cut_recovery(recovered)
            elif args.quota_partial_copy_cut: validate_quota_copy_cut_recovery(recovered)
            elif args.quota_switch: validate_quota_switch_recovery(recovered)
            elif listener_profile: validate_quota_listener_recovery(recovered,listener_phase)
            elif commit_profile: validate_quota_commit_recovery(recovered,commit_phase)
            elif args.quota_barrier_hang: validate_quota_barrier_recovery(recovered)
            else:
                assert recovered['l1_boot_changed'] and recovered['old_durable_destroyed'] and recovered['old_resources_absent'] and recovered['old_key_refused_410']
                assert recovered['fresh_real_kvm_exec_destroy'] and recovered['fresh_guest_boot_changed']
            if driver_profile and not (args.quota_clear_crash or args.quota_barrier_hang or commit_profile or listener_profile or args.quota_switch or private_cut_profile or node_profile): assert recovered['quota_limits_and_ownership_survived_cold_boot'] and recovered['quota_accounting_matches_recovered_namespace'] and recovered['all_private_project_ids_cleared']
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
