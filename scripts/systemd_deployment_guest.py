#!/usr/bin/env python3
"""TEST ONLY owned-L1 operator for the real Go launcher and ordinary KVM daemon.

All task argv goes through the ordinary guest API. No host shell or fallback.
Raw credentials, refs, boot IDs, manifests and process identities stay in L1.
"""
import ctypes
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import termios
import time
import traceback

from systemd_delegate_probe import guard, run, wait, save, read, identity

UNIT='xandbox.service'
UNIT_ROOT=Path('/sys/fs/cgroup/system.slice')/UNIT
STATE=Path('/srv/xb/s');RUNTIME=Path('/srv/xb/r');CONFIG=Path('/etc/xandbox')
CHECKPOINT=CONFIG/'deployment-checkpoint.json'
TOKENS=None


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda:stream.read(1<<20),b''):h.update(data)
    return h.hexdigest()


def setup():
    guard()
    if read('/etc/xandbox-systemd-deployment-fixture')!='Xandbox owned Go launch deployment fixture v1':raise RuntimeError('dedicated deployment fixture required')
    assets=json.loads((CONFIG/'assets.json').read_bytes())
    if set(assets)!={'launcher','daemon','warden','firecracker','jailer','kernel','initrd','workspace','node'}:raise RuntimeError('fixed asset inventory required')
    for value in assets.values():
        if sha(value['path'])!=value['sha256']:raise RuntimeError('frozen asset mismatch')
    if not (CONFIG/'launch.json').exists():
        uuid=run('/usr/sbin/blkid','-s','UUID','-o','value','/dev/vda').replace('-','')
        if not re.fullmatch('[0-9a-f]{32}',uuid):raise RuntimeError('canonical root UUID required')
        device=str(os.major(os.stat('/').st_dev))+':'+str(os.minor(os.stat('/').st_dev))
        node={'version':1,'cgroup_root':str(UNIT_ROOT/'node'),'max_instances':4,'max_records':1024,'max_sessions':32,'prepare_workers':1,
              'memory_max':7<<30,'controller_memory_max':1<<30,'host_memory_reserve':512<<20,'pids_max':384,'controller_pids_max':128,'cpu_quota':800000,
              'io_bytes_per_second':256<<20,'io_operations_per_second':8192,'disk_bytes':10<<30,'disk_inodes':100000,
              'external_disk_bytes':2<<30,'external_inodes':32768,'min_free_bytes':256<<20,'min_free_inodes':2048}
        backend={'version':3,'runtime_root':str(RUNTIME),'cgroup_root':str(UNIT_ROOT/'node/instances'),'uid_start':400000,'uid_count':4,'reserved_uid_range':True,
                 'quota':{'version':1,'filesystem_uuid':uuid,'project_start':1300000,'max_bytes':192<<20,'max_inodes':128},
                 'io':{'version':1,'filesystem_device':device,'device':device,'bytes_per_second':16<<20,'operations_per_second':1024},'node':node}
        for name in ('warden','firecracker','jailer','kernel','initrd','workspace'):backend[name]=assets[name]
        tokens={t:secrets.token_hex(32) for t in ('alpha','beta')}
        save(CONFIG/'client-fixture.json',tokens)
        save(CONFIG/'auth.json',{'version':1,'keys':[{'tenant_id':t,'max_instances':3,'token_sha256':hashlib.sha256(tokens[t].encode()).hexdigest()} for t in ('alpha','beta')]})
        save(CONFIG/'backend.json',backend)
        manifest={'version':1,'unit_root':str(UNIT_ROOT),'input_dir':'/run/xandbox-inputs','state_dir':str(STATE),'daemon':assets['daemon'],
                  'backend':{'path':str(CONFIG/'backend.json'),'sha256':sha(CONFIG/'backend.json')},
                  'auth':{'path':str(CONFIG/'auth.json'),'sha256':sha(CONFIG/'auth.json')},
                  'frontend':{'max_instances':4,'max_records':1024,'max_tenant_records':512,'max_sessions':32,'max_tenant_sessions':16,'session_history':64,'stop_workers':4,'cleanup_workers':2,'work_queue_size':32,'metrics':True},
                  'parent':{'memory_max':15<<29,'pids_max':512,'cpu_quota':800000,'io_bytes_per_second':512<<20,'io_operations_per_second':16384}}
        save(CONFIG/'launch.json',manifest)
    global TOKENS
    TOKENS=json.loads((CONFIG/'client-fixture.json').read_bytes())


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(40);self.sock.connect(str(STATE/'api.sock'))


def call(method,path,body=None,tenant='alpha',key=None,expected=200):
    conn=UnixHTTP('localhost',timeout=40)
    headers={'Content-Type':'application/json'}
    if tenant is not None:headers['Authorization']='Bearer '+TOKENS[tenant]
    if key is not None:headers['Idempotency-Key']=key
    try:
        conn.request(method,path,None if body is None else json.dumps(body),headers);response=conn.getresponse();raw=response.read(65537)
        if response.status!=expected or len(raw)>65536:raise RuntimeError('fixed guest API status/frame mismatch')
        return json.loads(raw)
    finally:conn.close()


def ready():
    def check():
        try:
            v=call('GET','/healthz',tenant=None)
            if v['backend']!='firecracker' or v['isolation'] is not True:raise RuntimeError('real backend required')
            return True
        except (OSError,http.client.HTTPException):return False
    wait(check,60)


def refpath(row):
    if not all(re.fullmatch('[0-9a-f]{32}',row[k]) for k in ('id','generation')):raise RuntimeError('canonical private ref required')
    return '/v1/sandboxes/'+row['id']


def key(row):refpath(row);return row['id']+row['generation']


def job(row,argv,tenant,timeout=5000):
    return call('POST',refpath(row)+'/exec',{'generation':row['generation'],'argv':argv,'timeout_ms':timeout},tenant=tenant,expected=202)


def execute(row,argv,tenant):
    accepted=job(row,argv,tenant);result={}
    def done():
        nonlocal result
        result=call('GET',refpath(row)+'/executions/'+accepted['id'],tenant=tenant)
        return result['status']!='RUNNING'
    wait(done,15)
    if result['status']!='EXITED' or result['output']['exit_code']!=0:raise RuntimeError('real guest command failed')
    return result['output']['stdout']


class Quota(ctypes.Structure):
    _fields_=[(n,ctypes.c_uint64) for n in ('bhard','bsoft','space','ihard','isoft','inodes','btime','itime')]+[('valid',ctypes.c_uint32),('pad',ctypes.c_uint32)]


def quota(project):
    if not 1300000<=project<1300004:raise RuntimeError('fixed private project only')
    fd=os.open(RUNTIME,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);record=Quota();libc=ctypes.CDLL(None,use_errno=True)
    try:
        result=libc.syscall(ctypes.c_long(443),ctypes.c_int(fd),ctypes.c_uint(0x80000702),ctypes.c_uint(project),ctypes.byref(record))
        if result!=0:raise RuntimeError('actual quota read failed')
    finally:os.close(fd)
    return record


def owner(row):
    value=json.loads((STATE/'firecracker'/(key(row)+'.json')).read_bytes())
    if value['ref']!={'id':row['id'],'generation':row['generation']} or value['quota_attempted'] is not True or not 400000<=value['uid']<400004:
        raise RuntimeError('durable ordinary owner mismatch')
    return value


def verify_vm(row,tenant):
    assets=json.loads((CONFIG/'assets.json').read_bytes());owned=owner(row)
    if execute(row,['id','-u'],tenant).strip()!='65534':raise RuntimeError('guest UID boundary failed')
    boot=execute(row,['cat','/proc/sys/kernel/random/boot_id'],tenant).strip()
    if not re.fullmatch('[a-f0-9-]{36}',boot):raise RuntimeError('real guest boot ID required')
    group=UNIT_ROOT/'node/instances'/key(row);found=False
    for raw in read(group/'cgroup.procs').split():
        pid=int(raw);start=identity(pid)
        try:actual=sha(Path('/proc',str(pid),'exe'))
        except FileNotFoundError:continue
        if actual!=assets['firecracker']['sha256']:continue
        status=dict(line.split(':',1) for line in Path('/proc',str(pid),'status').read_text().splitlines() if ':' in line)
        if set(status['Uid'].split())!={str(owned['uid'])} or status['NoNewPrivs'].strip()!='1' or status['Seccomp'].strip()!='2' or int(status['Seccomp_filters'])<2:
            raise RuntimeError('ordinary VMM identity/filter boundary failed')
        if any(int(status[k],16)!=0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')) or identity(pid)!=start:raise RuntimeError('ordinary VMM cap/start identity mismatch')
        found=True
    if not found:raise RuntimeError('real exact Firecracker ELF not observed in owned group')
    q=quota(owned['project_id'])
    if q.bhard!=192<<10 or q.ihard!=128 or not 0<q.space<=192<<20 or not 0<q.inodes<=128:raise RuntimeError('real kernel project limits required')
    return boot


def reclaimed(row,tenant,project):
    wait(lambda:call('GET',refpath(row),tenant=tenant)['state']=='DESTROYED',45)
    if (UNIT_ROOT/'node/instances'/key(row)).exists() or (RUNTIME/'j/firecracker'/key(row)).exists() or (STATE/'firecracker'/(key(row)+'.json')).exists():
        raise RuntimeError('ordinary private resources remain')
    q=quota(project)
    if any(getattr(q,n)!=0 for n in ('bhard','bsoft','space','ihard','isoft','inodes','btime','itime')):raise RuntimeError('quota not actually released')


def main_identity():
    pid=int(run('systemctl','show','--property=MainPID','--value',UNIT));assets=json.loads((CONFIG/'assets.json').read_bytes())
    if sha(Path('/proc',str(pid),'exe'))!=assets['daemon']['sha256']:raise RuntimeError('manager main is not ordinary pinned daemon')
    if read(Path('/proc',str(pid),'cgroup'))!='0::/system.slice/xandbox.service/node/control':raise RuntimeError('same-PID daemon not in control')
    for name in ('backend','auth'):
        if (Path('/run/xandbox-inputs')/(name+'.json')).read_bytes()!=(CONFIG/(name+'.json')).read_bytes():raise RuntimeError('immutable input snapshot mismatch')
    return pid,identity(pid)


def deployment_probe():
    ready();main_identity()
    return {'ordinary_firecracker_health':True,'manager_main_is_pinned_daemon':True,'main_in_nested_control':True,'immutable_backend_auth_snapshots':True,'no_mock_or_host_fallback':True,'instance_capacity':4}


def create(tenant,key_value):return call('POST','/v1/sandboxes',{'ttl_ms':300000},tenant=tenant,key=key_value,expected=201)


def progressing_writer(row,tenant):
    accepted=job(row,['sh','-c','i=0; while :; do i=$((i+1)); printf "%s\\n" "$i" > /workspace/heartbeat.next; mv /workspace/heartbeat.next /workspace/heartbeat; sleep 0.05; done'],tenant,45000)
    def counter():
        text=execute(row,['sh','-c','test ! -f /workspace/heartbeat || cat /workspace/heartbeat'],tenant).strip()
        return int(text) if text.isdecimal() else 0
    wait(lambda:counter()>0,10);before=counter();time.sleep(0.2)
    if counter()<=before or call('GET',refpath(row)+'/executions/'+accepted['id'],tenant=tenant)['status']!='RUNNING':raise RuntimeError('real old writer must progress before stop')
    return accepted


def first_checkpoint():
    if CHECKPOINT.exists():raise RuntimeError('first checkpoint cannot replay')
    deployment_probe();rows=[];boots=[]
    for n,tenant in enumerate(('alpha','alpha','alpha','beta')):
        request_key='systemd-first-'+str(n);row=create(tenant,request_key);boots.append(verify_vm(row,tenant));rows.append({'row':row,'tenant':tenant,'key':request_key,'owner':owner(row)})
    if len(set(boots))!=4:raise RuntimeError('four distinct guest boots required')
    call('GET',refpath(rows[0]['row']),tenant='beta',expected=404)
    call('POST','/v1/sandboxes',{},tenant=None,key='no-auth',expected=401)
    call('POST','/v1/sandboxes',{},tenant='alpha',key='alpha-fourth',expected=429)
    call('POST','/v1/sandboxes',{},tenant='beta',key='node-fifth',expected=503)
    victim=rows[0];busy=progressing_writer(victim['row'],'alpha')
    if call('GET',refpath(victim['row'])+'/executions/'+busy['id'])['status']!='RUNNING':raise RuntimeError('busy old guest required')
    stopped=call('POST',refpath(victim['row'])+'/stop',{'generation':victim['row']['generation']})
    if stopped['state']!='STOPPED':raise RuntimeError('physical stop acknowledgment required')
    g=UNIT_ROOT/'node/instances'/key(victim['row'])
    if g.exists() and 'populated 0' not in read(g/'cgroup.events'):raise RuntimeError('execution group still populated')
    call('POST','/v1/sandboxes',{},tenant='beta',key='stopped-still-full',expected=503)
    call('DELETE',refpath(victim['row']),{'generation':victim['row']['generation']},expected=202)
    reclaimed(victim['row'],'alpha',victim['owner']['project_id'])
    replacement=create('alpha','systemd-reused');replacement_boot=verify_vm(replacement,'alpha')
    if replacement_boot in boots or execute(replacement,['test','!','-e','/workspace/heartbeat'],'alpha')!='':raise RuntimeError('reused slot not pristine')
    rows[0]={'row':replacement,'tenant':'alpha','key':'systemd-reused','owner':owner(replacement)}
    old_pid,old_start=main_identity()
    run('systemctl','kill','--kill-whom=main','--signal=SIGKILL',UNIT)
    wait(lambda:identity(old_pid)!=old_start and not UNIT_ROOT.exists() and not Path('/run/xandbox-inputs').exists(),20)
    run('systemctl','start',UNIT);ready();new_pid,new_start=main_identity()
    if (old_pid,old_start)==(new_pid,new_start):raise RuntimeError('new daemon incarnation required')
    for item in rows:
        reclaimed(item['row'],item['tenant'],item['owner']['project_id'])
        call('POST','/v1/sandboxes',{'ttl_ms':300000},tenant=item['tenant'],key=item['key'],expected=410)
    fresh=create('alpha','systemd-before-cold');boot=verify_vm(fresh,'alpha')
    execute(fresh,['sh','-c','printf cold-proof > /workspace/cold-marker; sync'],'alpha')
    running=progressing_writer(fresh,'alpha')
    if call('GET',refpath(fresh)+'/executions/'+running['id'])['status']!='RUNNING':raise RuntimeError('live pre-cold execution required')
    save(CHECKPOINT,{'boot_id':read('/proc/sys/kernel/random/boot_id'),'machine_id':read('/etc/machine-id'),'row':fresh,'tenant':'alpha','key':'systemd-before-cold','owner':owner(fresh),'guest_boot':boot})
    return {'four_simultaneous_real_kvm_guests':True,'guest_uid_boots_and_exact_vmm_elf_caps_filters_checked':True,'live_kernel_project_limits_checked':True,
            'two_tenant_auth_and_node_tenant_refusals':True,'busy_stop_separate_from_durable_gc_and_capacity':True,'exact_private_resources_and_quota_released_before_reuse':True,
            'fresh_real_guest_after_slot_reuse':True,'main_sigkill_manager_killed_unit_and_removed_runtime_inputs':True,'same_policy_daemon_recovered_all_four_old_guests':True,
            'old_create_keys_refused410':True,'fresh_live_guest_checkpoint_fsynced':True,'not_tls_or_full_production_deployment':True}


def recover():
    old=json.loads(CHECKPOINT.read_bytes())
    if old['boot_id']==read('/proc/sys/kernel/random/boot_id') or old['machine_id']!=read('/etc/machine-id'):raise RuntimeError('original disk cold boot required')
    deployment_probe();reclaimed(old['row'],'alpha',old['owner']['project_id'])
    call('POST','/v1/sandboxes',{'ttl_ms':300000},key=old['key'],expected=410)
    fresh=create('alpha','systemd-after-cold');boot=verify_vm(fresh,'alpha')
    if boot==old['guest_boot']:raise RuntimeError('old assigned guest resurrected')
    execute(fresh,['test','!','-e','/workspace/cold-marker'],'alpha');owned=owner(fresh)
    call('DELETE',refpath(fresh),{'generation':fresh['generation']},expected=202);reclaimed(fresh,'alpha',owned['project_id'])
    if any(p.is_dir() for p in (UNIT_ROOT/'node/instances').iterdir()) or list((RUNTIME/'j/firecracker').glob('*')):raise RuntimeError('private generation remains')
    for project in range(1300000,1300004):
        q=quota(project)
        if any(getattr(q,n)!=0 for n in ('bhard','bsoft','space','ihard','isoft','inodes','btime','itime')):raise RuntimeError('final private project remains')
    return {'l1_boot_changed_same_machine_disk':True,'original_policy_auth_snapshots_preserved':True,'old_live_guest_durably_destroyed_exact_resources_quota_absent':True,
            'old_key_refused410':True,'fresh_real_guest_boot_and_pristine_workspace':True,'fresh_destroyed_all_four_projects_zero':True,'no_private_generation_cgroups_or_jails':True,
            'not_tls_or_full_production_deployment':True}


def failure_console():
    with open('/dev/console','w') as console:
        console.write('XANDBOX_SYSTEMD_HOST_FAILED deployment\n');traceback.print_exc(file=console);console.flush()
        subprocess.run(['journalctl','--no-pager','-n','60','-u',UNIT,'-u','xandbox-deployment-operator.service'],stdout=console,stderr=console,timeout=10)


def operator():
    setup();run('systemctl','start',UNIT);ready();deployment_probe()
    fd=os.open('/dev/ttyS1',os.O_RDWR|os.O_NOCTTY);attr=termios.tcgetattr(fd);attr[0]=attr[1]=attr[3]=0;attr[6][termios.VMIN]=1;attr[6][termios.VTIME]=0;termios.tcsetattr(fd,termios.TCSANOW,attr)
    with open('/dev/console','w') as console:console.write('XANDBOX_SYSTEMD_HOST_READY\n');console.flush()
    stream=os.fdopen(fd,'r+b',buffering=0);actions={'deployment-probe':deployment_probe,'deployment-checkpoint':first_checkpoint,'deployment-recover':recover}
    while True:
        line=stream.readline(1025)
        if not line or len(line)>1024:raise RuntimeError('bounded fixed request required')
        try:
            value=json.loads(line)
            if set(value)!={'version','operation'} or value['version']!=1 or value['operation'] not in actions:raise RuntimeError('fixed operation required')
            result=actions[value['operation']]();stream.write(json.dumps({'ok':True,'result':result},sort_keys=True).encode()+b'\n')
        except Exception:
            failure_console();stream.write(b'{"ok":false,"error":"owned deployment fixture failed"}\n');raise


if __name__=='__main__':
    guard()
    if read('/etc/xandbox-systemd-deployment-fixture')!='Xandbox owned Go launch deployment fixture v1':raise SystemExit('dedicated guest marker required')
    try:operator()
    except Exception:failure_console();raise
