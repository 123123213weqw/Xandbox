#!/usr/bin/env python3
"""TEST ONLY real systemd delegation/stop/cold primitive inside an owned KVM L1.

Reuses the existing hash-pinned, UID/netns/cgroup/lease-bounded QEMU launcher.
No sandboxd deployment, L2 workload, physical media fault or production SLO claim.
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
from kvm_nested_host import JSONSocket, qmp_probe, nested_group_limits, nested_resources, replace_private_json, private_group_counters
from kvm_driver_smoke import wait, same_owned_directory
from kvm_resources import cgroup_empty
from kvm_snapshot_smoke import private_json

PROBE_FLAGS=('pid1_systemd','manager_main_pid_verified','all_four_controllers','node_empty_internal_domains',
             'exact_node_control_instances_inventory','main_in_nested_node_control','exact_resource_readbacks',
             'cap_sys_resource_absent_all_sets','no_new_privileges','nested_kvm_create_vm_fd_closed','owned_child_progress')
RELOAD_FLAGS=('real_exec_reload_helper_in_unit_dot_control_outside_node','strict_node_inventory_unchanged','main_and_child_still_running')
STOP_FLAGS=('both_old_process_identities_absent','unit_cgroup_removed_without_fixture_cleanup','new_main_incarnation_verified',
            'fresh_child_progress_and_node_checks','not_production_stop_or_gc_slo')
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


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('ubuntu','alpine','fixture','warden','source-revision','report','log-dir'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args();os.umask(0o077)
    assert os.geteuid()==0 and os.uname().sysname=='Linux' and os.uname().machine=='x86_64'
    assert len(bytes.fromhex(args.source_revision))==20
    report=Path(args.report).resolve();logs=Path(args.log_dir).resolve()
    assert not report.exists() and not logs.exists();logs.mkdir(mode=0o700,parents=True)
    policy=json.loads(Path(__file__).with_name('nested_host_assets.json').read_text());validate_manifest(policy)
    kernel=Path('/boot/vmlinuz-'+policy['l1_kernel_release'])
    assert digest(kernel)==policy['l1_kernel_sha256'] and digest('/usr/bin/qemu-system-x86_64')==policy['qemu_sha256']
    assert Path('/sys/module/kvm_intel/parameters/nested').read_text().strip() in ('Y','1')
    assert os.statvfs('/srv').f_bavail*os.statvfs('/srv').f_frsize>8<<30
    available=[int(l.split()[1])*1024 for l in Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:')]
    assert len(available)==1 and available[0]>=8<<30
    suffix=secrets.token_hex(3);root=Path('/srv/nh-'+suffix);control=Path('/var/lib/xandbox-nested-proof-'+suffix)
    parent=Path('/sys/fs/cgroup/xandbox-nested-proof-'+suffix);group=parent/secrets.token_hex(32)
    resources=nested_resources(False);owned={};groups=[];process=None;lifetime=None;channel=None;launcher_log=None
    l0_boot=Path('/proc/sys/kernel/random/boot_id').read_bytes()
    def create(path):path.mkdir(mode=0o700);owned[path]=path.stat()
    def ours(path):return same_owned_directory(path,owned.get(path))
    def receipt():
        replace_private_json(logs/'resource-receipt.json',{'version':1,'root':str(root),'control':str(control),'cgroup_parent':str(parent),'all_cgroups':[str(g) for g in groups]})
    result={'test':'owned_l1_systemd_delegation_reload_stop_and_cold_primitive','source_revision':args.source_revision,
            'production_ready':False,'sandboxd_deployment_accepted':False,'l2_task_execution_accepted':False,
            'qemu_sha256':policy['qemu_sha256'],'kernel_sha256':policy['l1_kernel_sha256'],
            'resources':resources,'l1_boots':0,'cases':[],'passed':False,'cleanup_confirmed':False,
            'harness_files_sha256':{name:digest(Path(__file__).with_name(name)) for name in
                ('build_systemd_host.py','systemd_delegate_probe.py','systemd_host_assets.json','kvm_systemd_host.py','nested_host_assets.json')},
            'limitations':['Real systemd primitive only, not ordinary sandboxd/guest lifecycle deployment or operator release acceptance.',
                           'Healthy fsynced original-disk checkpoint, not in-flight persistence/physical power loss or a stop/reclaim SLO.',
                           'No shared L0 service/module/mount/quota/sysctl/network changes. Raw console and resource identities remain private.']}
    try:
        create(root);create(control);receipt()
        uid=850000+secrets.randbelow(30000)
        try:pwd.getpwuid(uid)
        except KeyError:pass
        else:raise AssertionError('reserved fixture UID assigned')
        for argument,name in (('fixture','fixture'),('warden','warden')):
            shutil.copyfile(Path(getattr(args,argument)).resolve(),control/name);(control/name).chmod(0o555)
        shutil.copyfile(kernel,root/'kernel');(root/'kernel').chmod(0o444)
        result['build']=build(ubuntu=Path(args.ubuntu).resolve(),alpine=Path(args.alpine).resolve(),
                              probe=Path(__file__).with_name('systemd_delegate_probe.py'),output_disk=root/'disk.raw',output_initrd=root/'initrd.cpio.gz')
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
            qmp_probe(root/'qmp.sock',2048);channel=JSONSocket(root/'control.sock',30)
            result['l1_boots']+=1
        def request(operation):
            channel.send({'version':1,'operation':operation});reply=channel.read()
            assert reply['ok'] is True,'fixed L1 systemd operation failed; inspect private console'
            validate_reply(operation,reply['result'],result['l1_boots']==2)
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
        for operation in ('probe','reload','stop-restart','checkpoint'):
            result['cases'][-1][operation]=request(operation)
        cut();boot()
        result['cases'].append({'boot':2})
        for operation in ('probe','reload','checkpoint'):
            result['cases'][-1][operation]=request(operation)
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
