#!/usr/bin/env python3
"""TEST ONLY: power-cut OWN L1 service host with real L2 KVM. Never reboot L0."""
import argparse
import datetime
import json
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


def quota_format_options(enabled):
    # e2fsprogs 1.46.5 uses the extended quotatype option, NOT a -Q flag.
    return ['-O','project,quota','-E','quotatype=prjquota','-I','256','-b','4096'] if enabled else []



class JSONSocket:
    def __init__(self, path, timeout=90):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.sock.settimeout(timeout)
        self.sock.connect(str(path)); self.file = self.sock.makefile('rb')
    def read(self):
        line = self.file.readline(65537)
        assert line and len(line) <= 65536, 'bounded private control frame required'
        return json.loads(line)
    def send(self, value): self.sock.sendall(json.dumps(value).encode() + b'\n')
    def close(self): self.file.close(); self.sock.close()


def qmp_probe(path):
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


def validate_quota_syscall_setup(value):
    for key in ('test_only_syscall_errno_injection','ordinary_daemon_elf_unchanged','not_physical_media_fault','all_fixed_projects_cleared'): assert value[key] is True
    cases=value['all_fixed_syscall_cases']
    assert [r['case'] for r in cases]==['reserve-set-eio','reserve-read-erofs','reserve-sync-eio','clear-set-eio','clear-sync-erofs','clear-read-eio']
    for r in cases:
        for key in ('test_only_seccomp_errno','fixed_child_thread_and_anchor_verified','durable_attempted_owner_before_injection','kernel_limits_and_zero_usage_checked_at_boundary','no_execution_namespace_at_injected_boundary','real_kernel_continue_not_emulated_success','durable_destroyed_resources_absent_key410','capacity_reused_fresh_real_kvm_guest_uid_exec_destroy','all_thread_caps_nnp_observer_and_ordinary_vmm_filters_checked','all_fixed_projects_cleared','owned_cgroup_root_removed'): assert r[key] is True
        assert type(r['injected_calls']) is int and r['injected_calls']>=1
        assert type(r['continued_kernel_calls']) is int and r['continued_kernel_calls']>=1
        if r['case'].startswith('reserve-'): assert r['prepare_refused500'] is True and r['injected_calls']==1
        else:
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
        flags=('checkpoint_receipt_fsynced_before_set','durable_attempted_owner_before_set','installed_limits_checked_before_fault','ordinary_qsync_returned_before_syncfs','notification_continued_no_errno_or_success_emulation','selected_syncfs_kernel_exit_observed','ordinary_prepare_eio_diagnostic_in_tmpfs','create_refused500','no_false_ready_stop_destroy_confirmation','exact_owner_retained_after_linear_restore','pre_fork_namespace_absent_after_eio','admission_new_create503','no_quota_query_after_eio','own_mapper_linear_restored_no_rw_remount','no_l2_vm_born_at_checkpoint')
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('fixture', 'daemon', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd', 'workspace', 'alpine',
                 'source-revision', 'report', 'log-dir'):
        parser.add_argument('--' + name, required=True)
    for name in ('admin','snapshot-builder','snapshot-seed-manifest'): parser.add_argument('--'+name)
    profiles = parser.add_mutually_exclusive_group()
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
    snapshot_profile = args.quota_snapshot or args.quota_clear_crash
    state_io_profile = args.state_io or args.quota_state_io
    driver_profile = args.quota_driver or snapshot_profile or args.quota_negatives or args.quota_syscalls or args.quota_unenforced or args.quota_state_io or args.quota_barrier_hang or commit_profile
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
    assert os.statvfs('/srv').f_bavail * os.statvfs('/srv').f_frsize > 8 << 30
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
    phases = (commit_phase,) if commit_profile else ('reserve-quota-syncfs-held',) if args.quota_barrier_hang else ('quota-cleared-owner-pinned',) if args.quota_clear_crash else () if args.quota_unenforced else ('quota-prerequisites',) if args.quota_probe else ('eio-busy','eio-idle','hang-busy','hang-idle') if state_io_profile else ('running','stopped','destroyed')
    result = {'test':'owned_l1_fixed_real_quota_commit_fault' if commit_profile else 'owned_l1_actual_quota_syncfs_hold_prefork_crash' if args.quota_barrier_hang else 'owned_l1_fixed_quota_syscall_errno_real_l2_kvm' if args.quota_syscalls else 'owned_l1_quota_cleared_owner_pinned_power_cut_real_l2_kvm' if args.quota_clear_crash else 'owned_l1_quota_whole_state_io_failure_real_l2_kvm' if args.quota_state_io else 'owned_l1_ordinary_driver_unenforced_ext4_startup_rejection' if args.quota_unenforced else 'owned_l1_ordinary_driver_quota_negative_real_l2_kvm' if args.quota_negatives else 'owned_l1_snapshot_driver_quota_real_l2_kvm' if args.quota_snapshot else 'owned_l1_ordinary_driver_quota_real_l2_kvm' if args.quota_driver else 'owned_l1_project_quota_prerequisites_real_l2_kvm' if args.quota_probe else 'owned_l1_whole_state_io_failure_real_l2_kvm' if args.state_io else 'owned_l1_host_power_cut_real_l2_kvm',
        'production_ready':False,'passed':False,'state_io_profile':state_io_profile,'quota_state_io_profile':args.quota_state_io,'quota_prerequisite_profile':args.quota_probe,
        'production_driver_quota':driver_profile,'quota_snapshot_profile':snapshot_profile,'quota_clear_crash_profile':args.quota_clear_crash,'quota_negative_profile':args.quota_negatives,'quota_unenforced_profile':args.quota_unenforced,
        'quota_syscall_errno_profile':args.quota_syscalls,'quota_barrier_hang_profile':args.quota_barrier_hang,
        'quota_commit_fault_phase':commit_phase,
        'source_revision':args.source_revision,'validated_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'harness_sha256':digest(__file__),'builder_sha256':digest(Path(__file__).with_name('build_nested_host.py')),
        'l0_kernel':os.uname().release,'l1_kernel':policy['l1_kernel_release'],'qemu_package_version':policy['qemu_package_version'],
        'qemu_sha256':policy['qemu_sha256'],'l1_kernel_sha256':policy['l1_kernel_sha256'],
        'modules_sha256':policy['modules_sha256'],'artifacts_sha256':{n:digest(p) for n,p in sources.items()},
        'l1_memory_mib':2048,'l0_cgroup_memory_max':3<<30,'l1_vcpus':4,'l1_disk_bytes':DISK_BYTES,
        'l1_business_network_interfaces':0,'l2_guest_memory_mib':512,'l2_vcpus':2,'l2_workspace_bytes':128<<20,
        'outer_disk_format':'raw','outer_disk_cache':'none','outer_disk_aio':'native','cases':[],
        'l1_boots_completed':0,'checkpoint_progress':[],
        'limitations':['Forced loss of our isolated L1 service-host VM, not physical L0 power/media failure.',
            'No TCG fallback, outer QEMU migration/snapshot save/restore, or shared L0 host reboot; this does not prohibit real L2 Firecracker snapshot operations.',
            'Fixed trusted test control operations, not tenant commands executed on a host.',
            'Finite checkpoint cases, not every in-flight fsync/prepare window, production SLO or independent operator acceptance.']}
    if args.quota_probe or driver_profile:
        result['quota_modules_sha256'] = policy['quota_modules_sha256']
    if args.quota_clear_crash:
        result['limitations'].append('Healthy catalog lock is deliberately held by L1 PID1 after ordinary quota clear, until outer L1 power cut. This tests that precise clear-before-owner-delete window, not arbitrary quota syscall errors or latency under a held catalog lock.')
    if args.quota_barrier_hang:
        result['limitations'].append('Additional TEST ONLY seccomp/NNP launch observer locates quota syncfs, then CONTINUE enters actual suspended-mapper filesystem IO. No old L2 VM is born at this pre-fork checkpoint. Fixed 4MiB project-zero dirty data ensures filesystem-wide writeback; not per-project IO or physical media failure. Receipt is synced BEFORE SET, with no observer sync after SET; unreturned commit is not assumed durable.')
    if commit_profile:
        result['limitations'].append('Additional TEST ONLY seccomp/NNP observer locates a fixed ordinary commit. CONTINUE enters the real kernel. One owned L1 mapper only: no physical L0 media failure or bounded filesystem IO guarantee. Fixed 4MiB project-zero dirty data is filesystem-wide. Reserve EIO uses an exact owned-thread, first-syncfs-return eBPF observer only inside L1; no tracee payloads or persistent hook. Release holds allow DELETE acceptance but never confirm DESTROYED/capacity before commit. Receipts sync before SET or DELETE; no observer sync after the selected mutation.')
    if args.quota_syscalls:
        result['limitations'].append('ELF-unchanged ordinary child has an additional inherited TEST ONLY seccomp notification/NNP launch layer. Six fixed errno cases, not physical media EIO/EROFS, held Q_SYNC, in-flight crash or snapshot pin acceptance. Other calls execute the real kernel via CONTINUE; no synthetic successful quota response.')
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
        build_initrd(alpine=sources['alpine'],fixture=fixture,manifest=policy,output=root/'initrd.cpio.gz',state_io=args.state_io,quota_probe=args.quota_probe,quota_driver=(args.quota_driver or args.quota_negatives or args.quota_syscalls),quota_snapshot=snapshot_profile,quota_unenforced=args.quota_unenforced,quota_state_io=(args.quota_state_io or args.quota_barrier_hang or commit_profile))
        result['l1_initrd_sha256']=digest(root/'initrd.cpio.gz')
        staging = control/'disk-root'; (staging/'assets').mkdir(mode=0o755,parents=True); (staging/'config').mkdir(mode=0o700)
        backend = {'version':1,'runtime_root':'/srv/r','cgroup_root':'/sys/fs/cgroup/xandbox','uid_start':400000,'uid_count':4,'reserved_uid_range':True}
        filesystem_uuid = uuid.uuid4()
        if driver_profile:
            backend['quota'] = {'version':1,'filesystem_uuid':filesystem_uuid.hex,'project_start':1300000,'max_bytes':192<<20,'max_inodes':128}
        for name in ('daemon','warden','firecracker','jailer','kernel','initrd','workspace'):
            target=staging/'assets'/('sandboxd' if name=='daemon' else name)
            shutil.copyfile(sources[name],target); target.chmod(0o555 if name in ('daemon','warden','firecracker','jailer') else 0o444)
            if name!='daemon': backend[name]={'path':'/srv/assets/'+name,'sha256':digest(target)}
        if snapshot_profile:
            backend['version']=2
            backend['snapshot']={'version':1,'agent_sha256':seed['agent_sha256'],'memory_mib':512,'vcpus':2,'max_entries':2,'max_bytes':1<<30}
            for name,target_name in (('admin','admin'),('snapshot_builder','snapshot-builder')):
                shutil.copyfile(sources[name],staging/'assets'/target_name);(staging/'assets'/target_name).chmod(0o555)
            private_json(staging/'config/snapshot-fixture.json',{'source_revision':args.source_revision,'agent_sha256':seed['agent_sha256'],'admin_sha256':digest(sources['admin']),'builder_sha256':digest(sources['snapshot_builder'])})
        private_json(staging/'config/backend.json',backend)
        disk=root/'disk.raw'
        with disk.open('xb') as f: os.posix_fallocate(f.fileno(),0,DISK_BYTES); os.fsync(f.fileno())
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
        boot_number=0
        def boot():
            nonlocal process,lifetime,channel,launcher_log,boot_number,group
            # A new host incarnation gets a new execution generation/lease
            # binding. Reuse ONLY the private disk, never a killed domain.
            if boot_number: group=parent_group/secrets.token_hex(32)
            group.mkdir(mode=0o700);owned_groups.append(group)
            replace_private_json(logs/'resource-receipt.json',{'version':1,'root':str(root),'control':str(control),
                'cgroup_parent':str(parent_group),'cgroup':str(group),'all_cgroups':[str(p) for p in owned_groups]})
            for name,value in {'memory.max':str(3<<30),'memory.swap.max':'0','memory.oom.group':'1','pids.max':'128','cpu.max':'400000 100000'}.items():
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
            qmp_probe(root/'qmp.sock')
            channel=JSONSocket(root/'control.sock',210 if (snapshot_profile or args.quota_negatives or args.quota_syscalls) else 90)
            channel.send({'version':1,'operation':'probe'}); reply=channel.read()
            assert reply['ok'] and reply['result']['nested_kvm_api']==12
            assert disk.stat().st_size==DISK_BYTES
            result['l1_boots_completed']+=1
        def request(operation,phase=None):
            value={'version':1,'operation':operation}
            if phase:value['phase']=phase
            channel.send(value); out=channel.read()
            if not out['ok'] and driver_profile and operation=='recover' and 'quota_diagnostic' in out:
                result['quota_coldboot_failure_diagnostic']=out['quota_diagnostic']
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
        if snapshot_profile: result['snapshot_setup']=request('quota-snapshot-setup')
        if args.quota_negatives:
            result['negative_setup']=request('quota-negative-setup')
            validate_negative_setup(result['negative_setup'])
        if args.quota_syscalls:
            result['syscall_setup']=request('quota-syscall-setup')
            validate_quota_syscall_setup(result['syscall_setup'])
        for phase in phases:
            checkpoint=request(commit_operation+'-checkpoint') if commit_profile else request('quota-barrier-checkpoint') if args.quota_barrier_hang else request('quota-clear-checkpoint') if args.quota_clear_crash else request('quota-probe') if args.quota_probe else request('io-fault' if state_io_profile else 'quota-checkpoint' if driver_profile else 'checkpoint',phase)
            if commit_profile: validate_quota_commit_checkpoint(checkpoint,commit_phase)
            elif args.quota_barrier_hang: validate_quota_barrier_checkpoint(checkpoint)
            else: assert checkpoint['real_nested_kvm'] and checkpoint['checkpoint_receipt_fsynced']
            if args.quota_clear_crash: validate_quota_clear_checkpoint(checkpoint)
            if args.quota_state_io:
                for key in ('ordinary_driver_quota_enabled','durable_project_ownership_checked','mutable_project_inheritance_checked','linked_namespace_accounted_before_cut','quota_filter_inherited_with_default_vmm_seccomp','quota_mapped_mount_and_policy_checked_before_fault'): assert checkpoint[key] is True
                assert checkpoint['private_project_space_bytes']>=128<<20 and 0<checkpoint['private_project_inodes']<=128
                assert checkpoint['quota_and_ownership_released_only_after_io_resumed' if phase.startswith('hang-') else 'quota_owner_retained_until_cold_recovery'] is True
            progress={'phase':phase,'checkpoint':checkpoint};result['checkpoint_progress'].append(progress)
            stopped=power_cut();progress['power_cut_to_l0_cgroup_empty_ms']=stopped
            boot(); recovered=request(commit_operation+'-recover' if commit_profile else 'quota-barrier-recover' if args.quota_barrier_hang else 'quota-clear-recover' if args.quota_clear_crash else 'recover')
            if commit_profile: validate_quota_commit_recovery(recovered,commit_phase)
            elif args.quota_barrier_hang: validate_quota_barrier_recovery(recovered)
            else:
                assert recovered['l1_boot_changed'] and recovered['old_durable_destroyed'] and recovered['old_resources_absent'] and recovered['old_key_refused_410']
                assert recovered['fresh_real_kvm_exec_destroy'] and recovered['fresh_guest_boot_changed']
            if driver_profile and not (args.quota_clear_crash or args.quota_barrier_hang or commit_profile): assert recovered['quota_limits_and_ownership_survived_cold_boot'] and recovered['quota_accounting_matches_recovered_namespace'] and recovered['all_private_project_ids_cleared']
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
