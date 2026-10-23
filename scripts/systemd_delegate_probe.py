#!/usr/bin/env python3
"""TEST ONLY. Executes only inside the marked owned Ubuntu L1, never on L0.

Separate operator and delegated services exercise real manager behavior. This
is NOT the production launcher, sandboxd deployment, an L2 task or a deadline SLO.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import termios
import time

MARKER='Xandbox owned systemd delegation fixture v1\n'
UNIT='xandbox-delegate-probe.service'
UNIT_ROOT=Path('/sys/fs/cgroup/system.slice')/UNIT
NODE=UNIT_ROOT/'node'
RUN=Path('/run/xandbox-systemd-proof')
CHECKPOINT=Path('/var/lib/xandbox-delegate-probe/checkpoint.json')
CONTROLLERS={'cpu','io','memory','pids'}


def guard():
    if os.geteuid()!=0 or Path('/etc/xandbox-systemd-fixture').read_text()!=MARKER or Path('/proc/1/comm').read_text().strip()!='systemd':
        raise RuntimeError('owned systemd L1 marker required')


def read(path): return Path(path).read_text().strip()


def save(path,value):
    raw=json.dumps(value,sort_keys=True).encode()+b'\n'
    fd=os.open(str(path)+'.new',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
    os.replace(str(path)+'.new',path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)


def run(*args):
    r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    if r.returncode:raise RuntimeError('fixed systemd operation failed')
    return r.stdout.decode().strip()


def wait(check,seconds=15):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if check():return
        time.sleep(0.05)
    raise RuntimeError('fixed owned L1 condition timed out')


def identity(pid):
    try:return Path('/proc',str(pid),'stat').read_text().rsplit(') ',1)[1].split()[19]
    except FileNotFoundError:return None


def enable(path):
    if read(path/'cgroup.procs'):raise RuntimeError('no internal processes required')
    if not CONTROLLERS <= set(read(path/'cgroup.controllers').split()):raise RuntimeError('all controllers required')
    missing=CONTROLLERS-set(read(path/'cgroup.subtree_control').split())
    if missing:(path/'cgroup.subtree_control').write_text(' '.join('+'+n for n in sorted(missing)))
    if not CONTROLLERS <= set(read(path/'cgroup.subtree_control').split()):raise RuntimeError('controller readback failed')


def limits(path,values):
    for name,value in values.items():
        (path/name).write_text(value)
        if read(path/name)!=value:raise RuntimeError('exact resource readback required')


def writer():
    guard();signal.signal(signal.SIGTERM,signal.SIG_IGN)
    count=0
    while True:
        count+=1
        (RUN/'heartbeat.next').write_text(str(count))
        os.replace(RUN/'heartbeat.next',RUN/'heartbeat')
        time.sleep(0.05)


def main_service():
    guard();os.umask(0o077);RUN.mkdir(mode=0o700,exist_ok=True)
    if read('/proc/self/cgroup')!='0::/system.slice/'+UNIT+'/bootstrap':raise RuntimeError('exact delegated bootstrap required')
    for name,value in {'memory.max':'1073741824','memory.swap.max':'0','pids.max':'128','cpu.max':'400000 100000'}.items():
        if read(UNIT_ROOT/name)!=value:raise RuntimeError('manager envelope mismatch')
    enable(UNIT_ROOT)
    NODE.mkdir(mode=0o700);(NODE/'control').mkdir(mode=0o700);(NODE/'instances').mkdir(mode=0o700)
    device=str(os.major(os.stat('/').st_dev))+':'+str(os.minor(os.stat('/').st_dev))
    node_limits={'memory.max':'536870912','memory.swap.max':'0','pids.max':'64','cpu.max':'200000 100000',
                 'io.max':device+' rbps=67108864 wbps=67108864 riops=1024 wiops=1024'}
    limits(NODE,node_limits)
    enable(NODE);enable(NODE/'instances')
    control_limits={'memory.max':'134217728','memory.swap.max':'0','memory.oom.group':'1','pids.max':'16'}
    limits(NODE/'control',control_limits)
    (NODE/'control/cgroup.procs').write_text(str(os.getpid()))
    fd=os.open('/dev/kvm',os.O_RDWR|os.O_CLOEXEC)
    try:
        if fcntl.ioctl(fd,0xAE00,0)!=12:raise RuntimeError('nested KVM API required')
        vm=fcntl.ioctl(fd,0xAE01,0);os.close(vm)
    finally:os.close(fd)
    child=subprocess.Popen(['/usr/bin/python3',__file__,'writer'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    wait(lambda:(RUN/'heartbeat').is_file())
    save(RUN/'ready.json',{'main_pid':os.getpid(),'main_start':identity(os.getpid()),'writer_pid':child.pid,'writer_start':identity(child.pid),
                         'boot_id':read('/proc/sys/kernel/random/boot_id'),'node_limits':node_limits,'control_limits':control_limits,
                         'nested_kvm_api':12,'nested_kvm_create_vm_fd_closed':True})
    while True:time.sleep(1)


def reload_service():
    guard()
    placement=read('/proc/self/cgroup')
    if placement!='0::/system.slice/'+UNIT+'/.control':raise RuntimeError('reload helper not in actual manager control subgroup')
    save(RUN/'reload.json',{'boot_id':read('/proc/sys/kernel/random/boot_id'),'placement':placement,'pid':os.getpid()})


def probe():
    info=json.loads((RUN/'ready.json').read_bytes())
    pid=int(run('systemctl','show','--property=MainPID','--value',UNIT))
    if pid!=info['main_pid'] or identity(pid)!=info['main_start']:raise RuntimeError('main PID identity mismatch')
    if info['boot_id']!=read('/proc/sys/kernel/random/boot_id'):raise RuntimeError('stale boot receipt')
    run('systemctl','is-active','--quiet',UNIT)
    if read(Path('/proc',str(pid),'cgroup'))!='0::/system.slice/'+UNIT+'/node/control':raise RuntimeError('node control placement mismatch')
    if read(UNIT_ROOT/'cgroup.procs') or read(NODE/'cgroup.procs') or read(NODE/'instances/cgroup.procs'):raise RuntimeError('internal process contamination')
    if {p.name for p in NODE.iterdir() if p.is_dir()}!={'control','instances'}:raise RuntimeError('unknown node subtree')
    for parent in (UNIT_ROOT,NODE,NODE/'instances'):
        if not CONTROLLERS <= set(read(parent/'cgroup.subtree_control').split()):raise RuntimeError('delegation changed')
    for parent,values in ((NODE,info['node_limits']),(NODE/'control',info['control_limits'])):
        for name,value in values.items():
            if read(parent/name)!=value:raise RuntimeError('resource readback drift')
    status=dict(line.split(':',1) for line in Path('/proc',str(pid),'status').read_text().splitlines() if ':' in line)
    if any(int(status[k].strip(),16)&(1<<24) for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')) or status['NoNewPrivs'].strip()!='1':raise RuntimeError('quota bypass capability or NNP mismatch')
    before=int(read(RUN/'heartbeat'));time.sleep(0.15)
    if int(read(RUN/'heartbeat'))<=before or identity(info['writer_pid'])!=info['writer_start']:raise RuntimeError('owned child not progressing')
    return {'pid1_systemd':True,'runtime_major':int(run('systemctl','--version').splitlines()[0].split()[1]),
            'manager_main_pid_verified':True,'all_four_controllers':True,'node_empty_internal_domains':True,
            'exact_node_control_instances_inventory':True,'main_in_nested_node_control':True,'exact_resource_readbacks':True,
            'cap_sys_resource_absent_all_sets':True,'no_new_privileges':True,'nested_kvm_api':info['nested_kvm_api'],
            'nested_kvm_create_vm_fd_closed':info['nested_kvm_create_vm_fd_closed'],'owned_child_progress':True}


def reload_probe():
    before=probe()
    if (RUN/'reload.json').exists():(RUN/'reload.json').unlink()
    run('systemctl','reload',UNIT)
    value=json.loads((RUN/'reload.json').read_bytes())
    if value['boot_id']!=read('/proc/sys/kernel/random/boot_id') or value['placement']!='0::/system.slice/'+UNIT+'/.control':raise RuntimeError('reload identity mismatch')
    if value['pid']==json.loads((RUN/'ready.json').read_bytes())['main_pid']:raise RuntimeError('reload was main')
    after=probe()
    if before!=after:raise RuntimeError('reload changed node invariants')
    return {'real_exec_reload_helper_in_unit_dot_control_outside_node':True,'strict_node_inventory_unchanged':True,'main_and_child_still_running':True}


def stop_restart():
    probe();old=json.loads((RUN/'ready.json').read_bytes())
    began=time.monotonic();run('systemctl','stop',UNIT);elapsed=round((time.monotonic()-began)*1000,3)
    wait(lambda:identity(old['main_pid'])!=old['main_start'] and identity(old['writer_pid'])!=old['writer_start'])
    wait(lambda:not UNIT_ROOT.exists())
    (RUN/'ready.json').unlink();(RUN/'heartbeat').unlink()
    run('systemctl','reset-failed',UNIT);run('systemctl','start',UNIT)
    wait(lambda:(RUN/'ready.json').is_file());probe();new=json.loads((RUN/'ready.json').read_bytes())
    if (new['main_pid'],new['main_start'])==(old['main_pid'],old['main_start']):raise RuntimeError('main incarnation reused')
    return {'stop_return_ms':elapsed,'both_old_process_identities_absent':True,'unit_cgroup_removed_without_fixture_cleanup':True,
            'new_main_incarnation_verified':True,'fresh_child_progress_and_node_checks':True,'not_production_stop_or_gc_slo':True}


def checkpoint():
    probe();boot=read('/proc/sys/kernel/random/boot_id');machine=read('/etc/machine-id')
    if not re.fullmatch('[a-f0-9]{32}',machine):raise RuntimeError('real machine ID required')
    old=json.loads(CHECKPOINT.read_bytes()) if CHECKPOINT.exists() else None
    if old and (old['boot_id']==boot or old['machine_id']!=machine):raise RuntimeError('cold boot not changed or original disk identity lost')
    save(CHECKPOINT,{'boot_id':boot,'machine_id':machine})
    with Path('/etc/machine-id').open('rb') as f:os.fsync(f.fileno())
    return {'checkpoint_fsynced':True,'previous_checkpoint_present':old is not None,'boot_changed_vs_previous':bool(old),
            'machine_id_preserved_vs_previous':bool(old),'not_sandbox_lifecycle_recovery':True}


def operator():
    guard();os.umask(0o077);RUN.mkdir(mode=0o700,exist_ok=True)
    run('systemctl','start',UNIT);wait(lambda:(RUN/'ready.json').is_file());probe()
    fd=os.open('/dev/ttyS1',os.O_RDWR|os.O_NOCTTY);attr=termios.tcgetattr(fd)
    attr[0]=0;attr[1]=0;attr[3]=0;attr[6][termios.VMIN]=1;attr[6][termios.VTIME]=0
    termios.tcsetattr(fd,termios.TCSANOW,attr)
    with open('/dev/console','w') as console:console.write('XANDBOX_SYSTEMD_HOST_READY\n');console.flush()
    stream=os.fdopen(fd,'r+b',buffering=0)
    actions={'probe':probe,'reload':reload_probe,'stop-restart':stop_restart,'checkpoint':checkpoint}
    while True:
        line=stream.readline(1025)
        if not line or len(line)>1024:raise RuntimeError('bounded fixed operator request required')
        try:
            value=json.loads(line)
            if set(value)!={'version','operation'} or value['version']!=1 or value['operation'] not in actions:raise RuntimeError('unknown fixed request')
            result=actions[value['operation']]()
            stream.write(json.dumps({'ok':True,'result':result},sort_keys=True).encode()+b'\n')
        except Exception:
            stream.write(b'{"ok":false,"error":"owned systemd fixture operation failed"}\n')
            raise


if __name__=='__main__':
    modes={'main':main_service,'writer':writer,'reload':reload_service,'operator':operator}
    if len(sys.argv)!=2 or sys.argv[1] not in modes:raise SystemExit('fixed owned L1 mode required')
    modes[sys.argv[1]]()
