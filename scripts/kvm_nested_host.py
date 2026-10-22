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

from build_nested_host import build_initrd, digest, validate_manifest
from kvm_resources import cgroup_empty
from kvm_driver_smoke import wait
from kvm_snapshot_smoke import private_json

DISK_BYTES = 2 << 30


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('fixture', 'daemon', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd', 'workspace', 'alpine',
                 'source-revision', 'report', 'log-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(); os.umask(0o077)
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
    result = {'test':'owned_l1_host_power_cut_real_l2_kvm','production_ready':False,'passed':False,
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
            'No TCG fallback, migration, snapshot save/restore or shared host reboot.',
            'Fixed trusted test control operations, not tenant commands executed on a host.',
            'Finite checkpoint cases, not every in-flight fsync/prepare window, production SLO or independent operator acceptance.']}
    process = None; lifetime = None; channel = None; launcher_log = None
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
        build_initrd(alpine=sources['alpine'],fixture=fixture,manifest=policy,output=root/'initrd.cpio.gz')
        result['l1_initrd_sha256']=digest(root/'initrd.cpio.gz')
        staging = control/'disk-root'; (staging/'assets').mkdir(mode=0o755,parents=True); (staging/'config').mkdir(mode=0o700)
        backend = {'version':1,'runtime_root':'/srv/r','cgroup_root':'/sys/fs/cgroup/xandbox','uid_start':400000,'uid_count':4,'reserved_uid_range':True}
        for name in ('daemon','warden','firecracker','jailer','kernel','initrd','workspace'):
            target=staging/'assets'/('sandboxd' if name=='daemon' else name)
            shutil.copyfile(sources[name],target); target.chmod(0o555 if name in ('daemon','warden','firecracker','jailer') else 0o444)
            if name!='daemon': backend[name]={'path':'/srv/assets/'+name,'sha256':digest(target)}
        private_json(staging/'config/backend.json',backend)
        disk=root/'disk.raw'
        with disk.open('xb') as f: os.posix_fallocate(f.fileno(),0,DISK_BYTES); os.fsync(f.fileno())
        subprocess.run(['mkfs.ext4','-q','-F','-m','0','-E','root_owner=0:0','-d',str(staging),str(disk)],check=True,timeout=120)
        with disk.open('rb') as f: os.fsync(f.fileno())
        # Only QEMU's private inputs become accessible to its reserved UID.
        for path in root.iterdir(): os.chown(path,uid,uid); path.chmod(0o600 if path==disk else 0o400)
        os.chown(root,uid,uid)
        parent_group.mkdir(mode=0o700); (parent_group/'cgroup.subtree_control').write_text('+memory +pids +cpu'); group.mkdir(mode=0o700)
        for name,value in {'memory.max':str(3<<30),'memory.swap.max':'0','memory.oom.group':'1','pids.max':'128','cpu.max':'400000 100000'}.items():
            (group/name).write_text(value); assert (group/name).read_text().strip()==value
        cfg = control/'launch.json'
        private_json(cfg,{'version':1,'root':str(root),'cgroup':str(group),'uid':uid,'kvm_group':os.stat('/dev/kvm').st_gid,
            'warden':str(warden),'warden_sha256':digest(warden),'fixture_sha256':digest(fixture),'qemu_sha256':policy['qemu_sha256'],
            'kernel_sha256':policy['l1_kernel_sha256'],'initrd_sha256':result['l1_initrd_sha256']})
        boot_number=0
        def boot():
            nonlocal process,lifetime,channel,launcher_log,boot_number
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
            channel=JSONSocket(root/'control.sock')
            channel.send({'version':1,'operation':'probe'}); reply=channel.read()
            assert reply['ok'] and reply['result']['nested_kvm_api']==12
            assert disk.stat().st_size==DISK_BYTES
            result['l1_boots_completed']+=1
        def request(operation,phase=None):
            value={'version':1,'operation':operation}
            if phase:value['phase']=phase
            channel.send(value); out=channel.read(); assert out['ok'],'L1 fixed operation failed; inspect private console';return out['result']
        def power_cut():
            nonlocal process,lifetime,channel,launcher_log
            qmp_probe(root/'qmp.sock'); began=time.perf_counter(); (group/'cgroup.kill').write_text('1')
            wait(lambda:cgroup_empty(group),'exact owned L1 execution domain stops',seconds=15)
            elapsed=round((time.perf_counter()-began)*1000,3)
            process.wait(timeout=15); process=None
            shutil.copyfile(root/'console.log',logs/f'l1-console-{boot_number}.log')
            os.close(lifetime);lifetime=None;channel.close();channel=None;launcher_log.close();launcher_log=None
            assert Path('/proc/sys/kernel/random/boot_id').read_bytes()==l0_boot
            return elapsed
        boot()
        for phase in ('running','stopped','destroyed'):
            checkpoint=request('checkpoint',phase); assert checkpoint['real_nested_kvm'] and checkpoint['checkpoint_receipt_fsynced']
            progress={'phase':phase,'checkpoint':checkpoint};result['checkpoint_progress'].append(progress)
            stopped=power_cut();progress['power_cut_to_l0_cgroup_empty_ms']=stopped
            boot(); recovered=request('recover')
            assert recovered['l1_boot_changed'] and recovered['old_durable_destroyed'] and recovered['old_resources_absent'] and recovered['old_key_refused_410']
            assert recovered['fresh_real_kvm_exec_destroy'] and recovered['fresh_guest_boot_changed']
            result['cases'].append({'phase':phase,'passed':True,'checkpoint':checkpoint,'recovery':recovered,'power_cut_to_l0_cgroup_empty_ms':stopped})
        result['l0_boot_unchanged']=True; result['qmp_enabled_kvm_verified_each_boot']=True;result['passed']=True
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
        if group.exists(): group.rmdir()
        if parent_group.exists(): parent_group.rmdir()
        if root.exists(): shutil.rmtree(root)
        if control.exists(): shutil.rmtree(control)
        result['cleanup_confirmed']=not any(p.exists() for p in (root,control,parent_group))
        private_json(report,result)
    assert result['passed'] and result['cleanup_confirmed']
    print(json.dumps({'passed':True,'cases':len(result['cases']),'cleanup_confirmed':True}))


if __name__=='__main__':main()
