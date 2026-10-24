#!/usr/bin/env python3
"""TEST ONLY real systemd delegation/stop/cold primitive inside an owned KVM L1.

Reuses the existing hash-pinned, UID/netns/cgroup/lease-bounded QEMU launcher.
Explicit opt-in ordinary UDS deployment profile is separate from the legacy
primitive; neither is a full production deployment or SLO certification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
import time

from build_systemd_host import build, ROOT_BYTES
from build_nested_host import digest, validate_manifest
from kvm_nested_host import JSONSocket, qmp_probe, nested_group_limits, nested_resources, nested_node_resources, replace_private_json, private_group_counters, nested_ingress_resources
from kvm_driver_smoke import wait, same_owned_directory
from kvm_resources import cgroup_empty
from kvm_snapshot_smoke import private_json

PROBE_FLAGS=('pid1_systemd','manager_main_pid_verified','all_four_controllers','node_empty_internal_domains',
             'exact_node_control_instances_inventory','main_in_nested_node_control','exact_resource_readbacks',
             'cap_sys_resource_absent_all_sets','no_new_privileges','nested_kvm_create_vm_fd_closed','owned_child_progress')
RELOAD_FLAGS=('real_exec_reload_helper_in_unit_dot_control_outside_node','strict_node_inventory_unchanged','main_and_child_still_running')
STOP_FLAGS=('both_old_process_identities_absent','unit_cgroup_removed_without_fixture_cleanup','new_main_incarnation_verified',
            'fresh_child_progress_and_node_checks','not_production_stop_or_gc_slo','clean_unit_started_without_reset_failed_assumption')
CHECKPOINT_FLAGS=('checkpoint_fsynced','previous_checkpoint_present','boot_changed_vs_previous',
                  'machine_id_preserved_vs_previous','not_sandbox_lifecycle_recovery')


def validate_reply(operation,value,second_boot=False):
    assert type(value) is dict
    if operation=='probe':
        assert set(value)==set(PROBE_FLAGS)|{'runtime_major','nested_kvm_api'}
        assert all(value[k] is True for k in PROBE_FLAGS)
        assert type(value['runtime_major']) is int and value['runtime_major']==255
        assert type(value['nested_kvm_api']) is int and value['nested_kvm_api']==12
    elif operation=='reload':
        assert set(value)==set(RELOAD_FLAGS) and all(value[k] is True for k in RELOAD_FLAGS)
    elif operation=='stop-restart':
        assert set(value)==set(STOP_FLAGS)|{'stop_return_ms'} and all(value[k] is True for k in STOP_FLAGS)
        assert type(value['stop_return_ms']) in (int,float) and 0<value['stop_return_ms']<=20000
    elif operation=='checkpoint':
        assert set(value)==set(CHECKPOINT_FLAGS) and value['checkpoint_fsynced'] is True and value['not_sandbox_lifecycle_recovery'] is True
        assert all(value[k] is second_boot for k in ('previous_checkpoint_present','boot_changed_vs_previous','machine_id_preserved_vs_previous'))
    else:raise ValueError('fixed systemd primitive operation required')


DEPLOYMENT_PROBE_FLAGS=('ordinary_firecracker_health','manager_main_is_pinned_daemon','main_in_nested_control','immutable_backend_auth_snapshots','no_mock_or_host_fallback')
DEPLOYMENT_CHECKPOINT_FLAGS=('four_simultaneous_real_kvm_guests','guest_uid_boots_and_exact_vmm_elf_caps_filters_checked','live_kernel_project_limits_checked','two_tenant_auth_and_node_tenant_refusals','busy_stop_separate_from_durable_gc_and_capacity','exact_private_resources_and_quota_released_before_reuse','fresh_real_guest_after_slot_reuse','main_sigkill_manager_killed_unit_and_removed_runtime_inputs','same_policy_daemon_recovered_all_four_old_guests','old_create_keys_refused410','fresh_live_guest_checkpoint_fsynced','not_tls_or_full_production_deployment')
DEPLOYMENT_RECOVERY_FLAGS=('l1_boot_changed_same_machine_disk','original_policy_auth_snapshots_preserved','old_live_guest_durably_destroyed_exact_resources_quota_absent','old_key_refused410','fresh_real_guest_boot_and_pristine_workspace','fresh_destroyed_all_four_projects_zero','no_private_generation_cgroups_or_jails','not_tls_or_full_production_deployment')
def validate_deployment_reply(operation,value):
    assert type(value) is dict
    flags={'deployment-probe':DEPLOYMENT_PROBE_FLAGS,'deployment-checkpoint':DEPLOYMENT_CHECKPOINT_FLAGS,'deployment-recover':DEPLOYMENT_RECOVERY_FLAGS}[operation]
    extra={'instance_capacity'} if operation=='deployment-probe' else set()
    assert set(value)==set(flags)|extra and all(value[k] is True for k in flags)
    if extra:assert type(value['instance_capacity']) is int and value['instance_capacity']==4


INGRESS_PROBE_FLAGS=('ordinary_tls_firecracker_health','manager_main_is_pinned_gateway','root_and_child_in_separate_exact_ingress_domain','root_three_caps_child_unprivileged_nnp_root_cwd_fds','actual_parent_budgets_and_no_root_tcp_listener','no_mock_or_host_fallback')
INGRESS_CHECKPOINT_FLAGS=('three_real_preflight_refusals_no_child_or_tcp','four_simultaneous_real_guests_via_tls','two_tenant_auth_quota_and_node_refusals','guest_uid_boot_vmm_caps_filters_and_quota_checked','busy_stop_distinct_from_durable_gc_capacity','reused_slot_fresh_guest_and_workspace','ingress_stop_restart_did_not_stop_busy_guest','live_key_leaf_rotation_two_no_daemon_or_guest_restart','old_token_rejected_on_existing_tls_connection','daemon_sigkill_binds_to_closed_ingress_and_manager_removed_groups','same_policy_daemon_and_gateway_recovered_old_guests_revision_two','old_create_keys_refused410','fresh_live_guest_checkpoint_fsynced','explicit_start_after_backend_ready_not_automatic_install')
INGRESS_RECOVERY_FLAGS=('original_disk_new_l1_boot_same_machine','gateway_revision_two_leaf_and_new_credentials_survived','old_token_refused401','old_guest_durably_destroyed_and_exact_quota_resources_absent','old_create_key_refused410','new_real_guest_boot_pristine_workspace_and_destroyed','all_four_projects_zero_and_private_generations_absent','manager_clean_stop_removed_both_units_and_inputs','not_installer_catalog_backup_or_production_slo')
def validate_ingress_reply(operation,value):
    flags={'ingress-probe':INGRESS_PROBE_FLAGS,'ingress-checkpoint':INGRESS_CHECKPOINT_FLAGS,'ingress-recover':INGRESS_RECOVERY_FLAGS}[operation]
    assert type(value) is dict and set(value)==set(flags) and all(value[k] is True for k in flags)


READINESS_PROBE_FLAGS=('ordinary_tls_firecracker_health','same_actual_ingress_identity_budgets_caps_and_no_root_tcp','single_main_start_or_original_disk_boot_without_operator_ingress_start','exact_enabled_daemon_boot_and_ingress_wants_links','no_mock_or_host_task_fallback','actual_admission_matches_checkpoint_before_operator_resume')
READINESS_CHECKPOINT_FLAGS=tuple(k for k in INGRESS_CHECKPOINT_FLAGS if k!='explicit_start_after_backend_ready_not_automatic_install')+('bad_ready_pin_refused_before_ingress_and_manager_cleaned','stopped_real_main_readiness_deadline_refused_and_manager_cleaned','actual_one_cap_ready_helper_in_manager_control_not_node','ingress_stayed_closed_while_post_gate_held','single_main_restart_auto_started_ready_ordered_ingress','enablement_and_ready_inputs_checkpoint_fsynced')
READINESS_RECOVERY_FLAGS=INGRESS_RECOVERY_FLAGS+('original_enablement_and_readiness_inputs_persisted','cold_boot_both_services_without_operator_start')
from systemd_drain_probe import CHECKPOINT_FLAGS as DRAIN_CHECKPOINT_FLAGS, RECOVERY_FLAGS as DRAIN_RECOVERY_FLAGS
READINESS_CHECKPOINT_FLAGS+=DRAIN_CHECKPOINT_FLAGS
READINESS_RECOVERY_FLAGS+=DRAIN_RECOVERY_FLAGS
def validate_readiness_reply(operation,value):
    flags={'readiness-probe':READINESS_PROBE_FLAGS,'readiness-checkpoint':READINESS_CHECKPOINT_FLAGS,'readiness-recover':READINESS_RECOVERY_FLAGS}[operation]
    assert type(value) is dict and set(value)==set(flags) and all(type(v) is bool and v is True for v in value.values()),'closed true readiness result flags required'


from systemd_release_guest import PROBE_FLAGS as RELEASE_PROBE_FLAGS, CHECKPOINT_FLAGS as RELEASE_CHECKPOINT_FLAGS, RECOVERY_FLAGS as RELEASE_RECOVERY_FLAGS

def validate_release_reply(operation,value):
    base_flags={'release-probe':READINESS_PROBE_FLAGS,'release-checkpoint':READINESS_CHECKPOINT_FLAGS,'release-recover':READINESS_RECOVERY_FLAGS}[operation]
    extra={'release-probe':RELEASE_PROBE_FLAGS,'release-checkpoint':RELEASE_CHECKPOINT_FLAGS,'release-recover':RELEASE_RECOVERY_FLAGS}[operation]
    assert type(value) is dict and set(value)==set(base_flags)|set(extra) and all(type(v) is bool and v is True for v in value.values()),'complete typed publication/readiness/drain result required'


def validate_install_reply(operation,value):
    from systemd_install_guest import PROBE_FLAGS,CHECKPOINT_FLAGS,RECOVERY_FLAGS
    import math
    flags={'install-probe':PROBE_FLAGS,'install-checkpoint':CHECKPOINT_FLAGS,'install-recover':RECOVERY_FLAGS}[operation]
    extra={'stop_observed_ms','durable_reclaim_observed_ms'} if operation=='install-checkpoint' else set()
    assert type(value) is dict and set(value)==set(flags)|extra
    assert all(type(value[k]) is bool and value[k] is True for k in flags)
    if extra:
        assert all(type(value[k]) in (int,float) and math.isfinite(value[k]) and 0<value[k]<=45000 for k in extra)
        assert value['durable_reclaim_observed_ms']>=value['stop_observed_ms']


def validate_managed_reply(operation,value):
    from systemd_managed_guest import PROBE_FLAGS,CHECKPOINT_FLAGS,RECOVERY_FLAGS
    import math
    flags={'managed-probe':PROBE_FLAGS,'managed-checkpoint':CHECKPOINT_FLAGS,'managed-recover':RECOVERY_FLAGS}[operation]
    extra={'stop_observed_ms','durable_reclaim_observed_ms'} if operation=='managed-checkpoint' else set()
    assert type(value) is dict and set(value)==set(flags)|extra
    assert all(type(value[k]) is bool and value[k] is True for k in flags)
    if extra:
        assert all(type(value[k]) in (int,float) and math.isfinite(value[k]) and 0<value[k]<=45000 for k in extra)
        assert value['durable_reclaim_observed_ms']>=value['stop_observed_ms']


def harness_files(deployed,ingress,readiness,release=False,install=False,managed=False):
    if managed:
        if not deployed or ingress or readiness or release or install:raise ValueError('fresh managed profile is exclusive')
        return ('build_systemd_host.py','systemd_delegate_probe.py','systemd_host_assets.json','kvm_systemd_host.py','nested_host_assets.json','build_systemd_install.py','build_systemd_deployment.py','build_systemd_managed.py','systemd_managed_guest.py','managed_fixture_trace.py','systemd_install_guest.py','install_fixture_trace.py','systemd_deployment_guest.py','systemd_ingress_guest.py','systemd_drain_probe.py')
    if install:
        if not deployed or ingress or readiness or release:raise ValueError('fresh installer profile is exclusive, not old deployment composition')
        return ('build_systemd_host.py','systemd_delegate_probe.py','systemd_host_assets.json','kvm_systemd_host.py','nested_host_assets.json','build_systemd_install.py','build_systemd_deployment.py','systemd_install_guest.py','install_fixture_trace.py','systemd_deployment_guest.py','systemd_ingress_guest.py','systemd_drain_probe.py')
    if release and (not deployed or not readiness):raise ValueError('publication profile requires complete readiness composition')
    names=('build_systemd_host.py','systemd_delegate_probe.py','systemd_host_assets.json','kvm_systemd_host.py','nested_host_assets.json')
    if deployed:names+=('build_systemd_deployment.py','systemd_deployment_guest.py')
    if ingress or readiness:names+=('build_systemd_ingress.py','systemd_ingress_guest.py','ingress_guard_probe.py')
    if readiness:names+=('build_systemd_readiness.py','systemd_readiness_guest.py','readiness_fixture_gate.py','systemd_drain_probe.py')
    if release:names+=('build_systemd_release.py','systemd_release_guest.py')
    return names


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('ubuntu','alpine','fixture','warden','source-revision','report','log-dir'):parser.add_argument('--'+name,required=True)
    profiles=parser.add_mutually_exclusive_group()
    profiles.add_argument("--managed-assets",help="TEST ONLY fresh managed-v2 root install/committed-policy recovery/TLS-KVM/drain/cold; not supersession or production acceptance")
    profiles.add_argument("--install-assets",help="TEST ONLY fresh ordinary initial installer with pending commit gate, TLS/KVM/drain/cold; not production acceptance")
    profiles.add_argument("--release-assets",help="TEST ONLY ordinary root publisher plus full16GiB readiness/drain/TLS/KVM/cold composition, not an installer")
    profiles.add_argument("--readiness-assets",help="TEST ONLY explicit16GiB automatic readiness/enablement composition; not a release installer")
    profiles.add_argument("--ingress-assets",help="TEST ONLY explicit16GiB/CPU12/24GiB ordinary daemon + separate bounded ingress profile")
    profiles.add_argument("--deployment-assets",help="TEST ONLY explicit frozen asset manifest; selects 8GiB/12GiB/CPU8 profile, not the legacy primitive")
    args=parser.parse_args();os.umask(0o077)
    deployment=None;ingress=None;readiness=None;release=None;install=None;managed=None
    if args.deployment_assets:
        from build_systemd_deployment import load_assets
        deployment=load_assets(args.deployment_assets)
    if args.ingress_assets:
        from build_systemd_ingress import load_assets
        ingress=load_assets(args.ingress_assets)
    if args.readiness_assets:
        from build_systemd_readiness import load_assets
        readiness=load_assets(args.readiness_assets)
    if args.release_assets:
        from build_systemd_release import load_assets
        release=load_assets(args.release_assets);readiness=release
    if args.install_assets:
        from build_systemd_install import load_assets
        install=load_assets(args.install_assets)
    if args.managed_assets:
        from build_systemd_managed import load_assets
        managed=load_assets(args.managed_assets)
    deployed=deployment is not None or ingress is not None or readiness is not None or install is not None or managed is not None
    assert os.geteuid()==0 and os.uname().sysname=='Linux' and os.uname().machine=='x86_64'
    assert len(bytes.fromhex(args.source_revision))==20
    report=Path(args.report).resolve();logs=Path(args.log_dir).resolve()
    assert not report.exists() and not logs.exists();logs.mkdir(mode=0o700,parents=True)
    policy=json.loads(Path(__file__).with_name('nested_host_assets.json').read_text());validate_manifest(policy)
    kernel=Path('/boot/vmlinuz-'+policy['l1_kernel_release'])
    assert digest(kernel)==policy['l1_kernel_sha256'] and digest('/usr/bin/qemu-system-x86_64')==policy['qemu_sha256']
    assert Path('/sys/module/kvm_intel/parameters/nested').read_text().strip() in ('Y','1')
    assert os.statvfs('/srv').f_bavail*os.statvfs('/srv').f_frsize>(48 if ingress is not None or readiness is not None or install is not None or managed is not None else (24 if deployed else 8))<<30
    available=[int(l.split()[1])*1024 for l in Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:')]
    assert len(available)==1 and available[0]>=(64 if ingress is not None or readiness is not None or install is not None or managed is not None else (32 if deployed else 8))<<30
    suffix=secrets.token_hex(3);root=Path('/srv/nh-'+suffix);control=Path('/var/lib/xandbox-nested-proof-'+suffix)
    parent=Path('/sys/fs/cgroup/xandbox-nested-proof-'+suffix);group=parent/secrets.token_hex(32)
    resources=nested_ingress_resources() if ingress is not None or readiness is not None or install is not None or managed is not None else (nested_node_resources(False) if deployed else nested_resources(False));owned={};groups=[];process=None;lifetime=None;channel=None;launcher_log=None
    l0_boot=Path('/proc/sys/kernel/random/boot_id').read_bytes()
    def create(path):path.mkdir(mode=0o700);owned[path]=path.stat()
    def ours(path):return same_owned_directory(path,owned.get(path))
    def receipt():
        replace_private_json(logs/'resource-receipt.json',{'version':1,'root':str(root),'control':str(control),'cgroup_parent':str(parent),'all_cgroups':[str(g) for g in groups]})
    result={'test':'owned_l1_systemd_managed_v2_committed_recovery_tls_kvm_drain_cold' if managed is not None else 'owned_l1_systemd_initial_install_pending_gate_tls_kvm_drain_cold' if install is not None else 'owned_l1_systemd_release_publication_readiness_ingress_tls_kvm_cold' if release is not None else 'owned_l1_systemd_automatic_readiness_ingress_tls_kvm_cold' if readiness is not None else 'owned_l1_systemd_separate_ingress_tls_kvm_cold' if ingress is not None or readiness is not None else ('owned_l1_systemd_go_launch_ordinary_kvm_cold' if deployed else 'owned_l1_systemd_delegation_reload_stop_and_cold_primitive'),'source_revision':args.source_revision,
            'production_ready':False,'sandboxd_deployment_accepted':False,'l2_task_execution_accepted':False,
            'qemu_sha256':policy['qemu_sha256'],'kernel_sha256':policy['l1_kernel_sha256'],
            'resources':resources,'l1_boots':0,'cases':[],'passed':False,'cleanup_confirmed':False,
            'harness_files_sha256':{name:digest(Path(__file__).with_name(name)) for name in harness_files(deployed,ingress is not None,readiness is not None,release is not None,install is not None,managed is not None)},
            'limitations':['Real systemd primitive only, not ordinary sandboxd/guest lifecycle deployment or operator release acceptance.',
                           'Healthy fsynced original-disk checkpoint, not in-flight persistence/physical power loss or a stop/reclaim SLO.',
                           'No shared L0 service/module/mount/quota/sysctl/network changes. Raw console and resource identities remain private.']}
    try:
        create(root);create(control);receipt()
        if deployed:
            result['deployment_assets_sha256']={k:v['sha256'] for k,v in (managed if managed is not None else (install if install is not None else (readiness if readiness is not None else (ingress if ingress is not None else deployment)))).items()}
            result['limitations'][0]='Experimental separate ingress TLS/KVM/cold profile only, explicit operator start after UDS readiness; no automatic combined install, catalog, upgrade, backup, human operator or SLO acceptance.' if ingress is not None else 'Experimental ordinary UDS Go-launcher/unit KVM and cold recovery only; no TLS, catalog, installer, upgrade or independent human operator acceptance.'
        if readiness is not None:result['limitations'][0]='Experimental automatic systemd readiness/enablement composition only, not transactional production installation, catalog, upgrade, backup, human operator or SLO acceptance.'
        if release is not None:result['limitations'][0]='Ordinary root immutable artifact publication with live guest/service continuity and healthy original-disk recovery only; no installation, activation, upgrade, catalog, backup, production CLI syscall crash windows or SLO acceptance.'
        if install is not None:result['limitations'][0]='Experimental fresh ordinary initial installer, pending commit gate and healthy TLS/KVM/drain/original-disk cold only; no reconfiguration, upgrade, catalog, backup, filesystem/media fault, human operator or production SLO acceptance.'
        if managed is not None:
            result['limitations'][0]='Fresh managed-v2 initial root CLI and committed-expired-policy recovery with pre-stopped populated/empty-ingress proof/TLS-KVM/drain/cold only; active-unit production-stop branch, uncommitted supersession, physical media faults, full runtime matrix and production SLO acceptance remain open.'
            result['uncommitted_supersession_hardware_accepted']=False
        uid=850000+secrets.randbelow(30000)
        try:pwd.getpwuid(uid)
        except KeyError:pass
        else:raise AssertionError('reserved fixture UID assigned')
        for argument,name in (('fixture','fixture'),('warden','warden')):
            shutil.copyfile(Path(getattr(args,argument)).resolve(),control/name);(control/name).chmod(0o555)
        shutil.copyfile(kernel,root/'kernel');(root/'kernel').chmod(0o444)
        result['build']=build(ubuntu=Path(args.ubuntu).resolve(),alpine=Path(args.alpine).resolve(),
                              probe=Path(__file__).with_name('systemd_delegate_probe.py'),output_disk=root/'disk.raw',output_initrd=root/'initrd.cpio.gz',deployment_assets=deployment,ingress_assets=ingress,readiness_assets=None if release is not None else readiness,release_assets=release,install_assets=install,managed_assets=managed)
        result['fixture_sha256']=digest(control/'fixture');result['warden_sha256']=digest(control/'warden')
        for path in root.iterdir():os.chown(path,uid,uid);path.chmod(0o600 if path.name=='disk.raw' else 0o400)
        os.chown(root,uid,uid)
        create(parent);(parent/'cgroup.subtree_control').write_text('+memory +pids +cpu')
        cfg=control/'launch.json'
        def boot():
            nonlocal process,lifetime,channel,launcher_log,group
            if result['l1_boots']:group=parent/secrets.token_hex(32)
            create(group);groups.append(group);receipt()
            for name,value in nested_group_limits(resources).items():(group/name).write_text(value);assert (group/name).read_text().strip()==value
            launch={'version':1,'root':str(root),'cgroup':str(group),'uid':uid,'kvm_group':os.stat('/dev/kvm').st_gid,
                    'warden':str(control/'warden'),'warden_sha256':result['warden_sha256'],'fixture_sha256':result['fixture_sha256'],
                    'qemu_sha256':policy['qemu_sha256'],'kernel_sha256':policy['l1_kernel_sha256'],'initrd_sha256':result['build']['initrd_sha256']}
            if deployed:launch['profile']='systemd-ingress-v1' if ingress is not None or readiness is not None or install is not None or managed is not None else 'node-budget-v1'
            replace_private_json(cfg,launch)
            for name in ('control.sock','qmp.sock','console.log'):
                if (root/name).exists():(root/name).unlink()
            read,lifetime=os.pipe();launcher_log=(logs/f'launcher-{len(groups)}.log').open('xb',buffering=0)
            process=subprocess.Popen([str(control/'fixture'),'-mode','launch','-config',str(cfg)],stdin=read,stdout=launcher_log,stderr=launcher_log,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin'})
            os.close(read)
            def ready():
                assert process.poll() is None,'bounded QEMU launcher exited; inspect private log'
                p=root/'console.log'
                if p.exists():
                    assert p.stat().st_size<=2<<20,'console bound exceeded'
                    assert b'XANDBOX_SYSTEMD_HOST_FAILED' not in p.read_bytes(),'owned systemd operation failed; inspect private console'
                return p.exists() and b'XANDBOX_SYSTEMD_HOST_READY' in p.read_bytes()
            wait(ready,'owned systemd L1 readiness',seconds=120)
            qmp_probe(root/'qmp.sock',resources['memory_mib']);channel=JSONSocket(root/'control.sock',210 if deployed else 30)
            result['l1_boots']+=1
        def request(operation):
            channel.send({'version':1,'operation':operation});reply=channel.read()
            assert reply['ok'] is True,'fixed L1 systemd operation failed; inspect private console'
            if managed is not None:validate_managed_reply(operation,reply['result'])
            elif install is not None:validate_install_reply(operation,reply['result'])
            elif release is not None:validate_release_reply(operation,reply['result'])
            elif readiness is not None:validate_readiness_reply(operation,reply['result'])
            elif ingress is not None:validate_ingress_reply(operation,reply['result'])
            elif deployed:validate_deployment_reply(operation,reply['result'])
            else:validate_reply(operation,reply['result'],result['l1_boots']==2)
            return reply['result']
        def cut():
            nonlocal process,lifetime,channel,launcher_log
            assert ours(group)
            (group/'cgroup.kill').write_text('1');wait(lambda:cgroup_empty(group),'owned L1 execution stops',seconds=15)
            process.wait(timeout=15);process=None;os.close(lifetime);lifetime=None;channel.close();channel=None
            launcher_log.close();launcher_log=None
            shutil.copyfile(root/'console.log',logs/f'console-{result["l1_boots"]}.log')
            private_json(logs/f'private-cgroup-{result["l1_boots"]}.json',private_group_counters(group))
            group.rmdir()
        boot()
        result['cases'].append({'boot':1})
        for operation in (('managed-probe','managed-checkpoint') if managed is not None else ('install-probe','install-checkpoint') if install is not None else ('release-probe','release-checkpoint') if release is not None else ('readiness-probe','readiness-checkpoint') if readiness is not None else (('ingress-probe','ingress-checkpoint') if ingress is not None or readiness is not None else (('deployment-probe','deployment-checkpoint') if deployed else ('probe','reload','stop-restart','checkpoint')))):
            result['cases'][-1][operation]=request(operation)
        cut();boot()
        result['cases'].append({'boot':2})
        for operation in (('managed-probe','managed-recover') if managed is not None else ('install-probe','install-recover') if install is not None else ('release-probe','release-recover') if release is not None else ('readiness-probe','readiness-recover') if readiness is not None else (('ingress-probe','ingress-recover') if ingress is not None or readiness is not None else (('deployment-probe','deployment-recover') if deployed else ('probe','reload','checkpoint')))):
            result['cases'][-1][operation]=request(operation)
        result['limited_ordinary_uds_launch_passed']=deployment is not None
        result['l2_task_execution_accepted']=deployed
        result['limited_separate_ingress_tls_passed']=ingress is not None
        if readiness is not None:result['limited_readiness_ingress_passed']=True
        if release is not None:result['limited_artifact_publication_passed']=True
        if install is not None:result['limited_initial_installer_passed']=True
        if managed is not None:result['limited_managed_v2_committed_recovery_passed']=True
        result['passed']=True
    finally:
        if ours(group):
            (group/'cgroup.kill').write_text('1');wait(lambda:cgroup_empty(group),'owned systemd cleanup',seconds=15)
        if process is not None:process.wait(timeout=15)
        if lifetime is not None:os.close(lifetime)
        if channel is not None:channel.close()
        if launcher_log is not None:launcher_log.close()
        if ours(root) and (root/'console.log').exists():shutil.copyfile(root/'console.log',logs/'final-private-console.log')
        for owned_group in groups:
            if ours(owned_group):owned_group.rmdir()
        if ours(parent):parent.rmdir()
        for path in (root,control):
            if ours(path):shutil.rmtree(path)
        result['cleanup_confirmed']=not any(os.path.lexists(p) for p in (root,control,parent))
        result['l0_boot_unchanged']=Path('/proc/sys/kernel/random/boot_id').read_bytes()==l0_boot
        private_json(report,result)
    assert result['passed'] and result['cleanup_confirmed'] and result['l0_boot_unchanged']
    print(json.dumps({'passed':True,'l1_boots':2,'cleanup_confirmed':True,'sandboxd_deployment_accepted':False}))


if __name__=='__main__':main()
