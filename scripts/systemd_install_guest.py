"""TEST ONLY real initial installer, pending commit gate, TLS/KVM/drain/cold L1.

Private operator state stays separate from the closed production install root.
No production hook or host task route. Original source inputs are removed only
after commit and by exact declared names; committed files are never rewritten.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import termios
import time
import traceback
import systemd_ingress_guest as ingress
import systemd_drain_probe as drain
from systemd_delegate_probe import guard as base_guard,read,run,save,wait,identity
from install_fixture_trace import interrupt_before_commit

base=ingress.base
CONFIG=Path('/etc/xandbox-install-fixture')
ROOT=Path('/etc/xandbox-install')
CLI='/usr/libexec/xandbox-install'
BOOTSTRAP='/usr/libexec/xandbox-install-bootstrap'
CHECKPOINT=CONFIG/'checkpoint.json'
ERROR=b'xandbox-install: installation unconfirmed; preserve the exact request and inspect before reconcile\n'
ROLES=('daemon','firecracker','gateway','ingress','initrd','jailer','kernel','launcher','node','ready','template','warden','workspace')
PROBE_FLAGS=('ordinary_install_committed_and_two_services_enabled','fixed_installer_and_same_pid_daemon_ingress_pinned','real_authenticated_tls_health_and_exact_admission','source_inputs_and_bootstrap_not_required_after_commit','not_upgrade_rotation_backup_or_production_slo')
CHECKPOINT_FLAGS=('actual_installer_killed_before_commit_scratch_creation','uncommitted_start_refused_before_daemon_and_binding','actual_pregate_all_threads_caps_zero_nnp_one_exact_control','actual_nonroot_cli_body_and_bad_source_revision_refusals','same_request_recovered_without_reset_or_repair','four_simultaneous_real_tls_kvm_guests','tenant_node_capacity_and_auth_refusals','busy_stop_distinct_from_durable_reclaim_capacity','ordinary_reconcile_kept_existing_service_identities','source_absent_exact_reconcile_and_conflict_refused','fresh_guest_pristine_after_reuse','original_installed_files_checkpoint_fsynced')+drain.CHECKPOINT_FLAGS
RECOVERY_FLAGS=('original_disk_boot_changed_machine_preserved','installed_commit_and_source_absence_preserved','automatic_two_service_cold_start_without_operator_activation','old_key_refused_and_assigned_guest_not_revived','all_four_project_limits_and_generation_resources_released','manager_clean_stop_removed_domains_and_runtime_inputs')+drain.RECOVERY_FLAGS

def guard():
    base_guard()
    if read('/etc/xandbox-systemd-install-fixture')!='Xandbox owned initial installer fixture v1':raise RuntimeError('owned installer marker required')

def installed(role):
    return {'launcher':'/usr/libexec/xandbox-launch','ready':'/usr/libexec/xandbox-ready','ingress':'/usr/libexec/xandbox-ingress-launch','daemon':'/srv/xi/a/sandboxd','gateway':'/srv/xi/a/xandbox-gateway','template':'/srv/xi/a/xandbox-template'}.get(role,'/srv/xi/a/'+role)

def bind_observers():
    guard();base.STATE=Path('/srv/xi/s');base.RUNTIME=Path('/srv/xi/r');base.CONFIG=CONFIG
    base.TOKENS=json.loads((CONFIG/'client.json').read_bytes())['backend']
    ingress.CONFIG=CONFIG;ingress.MANIFEST=ROOT/'ingress.json';ingress.CLIENT=CONFIG/'client.json';ingress.CHECKPOINT=CONFIG/'guest-checkpoint.json';ingress.CHILD_ROOT='/srv/xi/g/root'
    base.call=ingress.tls_call
    drain.CHECKPOINT=CONFIG/'drain-checkpoint.json';drain.guard=guard;drain.control=control

def result(r,want=0):
    if r.returncode!=want or len(r.stdout)>8192 or len(r.stderr)>4096:raise RuntimeError('fixed installer outcome required')
    if want==1:
        if r.stdout or r.stderr!=ERROR:raise RuntimeError('actual closed installer refusal required, not exec failure')
        return None
    if r.stderr:raise RuntimeError('installer unexpected stderr')
    v=json.loads(r.stdout)
    if type(v) is not dict or set(v)!={'version','revision','files_committed','manager_reconciled','production_ready'} or type(v['version']) is not int or v['version']!=1 or type(v['revision']) is not int or v['revision']!=1 or v['files_committed'] is not True or v['manager_reconciled'] is not True or v['production_ready'] is not False:raise RuntimeError('closed committed/reconciled installer receipt required')
    return v

def arguments(operation,request=None,plan=None,bootstrap=False):
    if operation not in ('apply','reconcile','status','verify'):raise RuntimeError('fixed installer operation')
    args=[BOOTSTRAP if bootstrap else CLI,operation]
    if operation in ('apply','reconcile'):
        if type(request) is not str or not re.fullmatch('[0-9a-f]{32}',request):raise RuntimeError('private exact installer request required')
        if operation=='apply':
            if not isinstance(plan,Path) or plan.parent!=CONFIG or not re.fullmatch('[a-z-]+\.json',plan.name):raise RuntimeError('private fixed fixture plan required')
            args+=['-plan',str(plan),'-expected-revision','0']
        args+=['-request-id',request]
    elif request is not None or plan is not None:raise RuntimeError('read-only shape')
    return args

def call(operation,request=None,plan=None,want=0,bootstrap=False,nonroot=False):
    guard();args=arguments(operation,request,plan,bootstrap)
    expected=json.loads((CONFIG/'programs.json').read_bytes())['install']['sha256']
    if base.sha(args[0])!=expected:raise RuntimeError('actual installer ELF pin mismatch')
    def lower():
        import ctypes
        os.setgroups([]);os.setgid(65534);os.setuid(65534)
        if ctypes.CDLL(None).prctl(38,1,0,0,0)!=0:os._exit(92)
    if nonroot:
        for p in ('/usr','/usr/libexec',args[0]):
            st=os.stat(p)
            if st.st_uid!=0 or not st.st_mode&1:raise RuntimeError('nonroot must reach actual CLI body')
    r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},preexec_fn=lower if nonroot else None)
    if operation=='verify' and want==0:
        if r.returncode or r.stdout or r.stderr:raise RuntimeError('silent verify expected')
        return None
    return result(r,want)

def control(operation,before=None,request=None,want=0):
    guard()
    if operation not in ('status','drain','resume') or type(want) is not int or want not in (0,1):raise RuntimeError('fixed operator command')
    node=json.loads((CONFIG/'assets.json').read_bytes())['node']
    if node['path']!=installed('node') or base.sha(node['path'])!=node['sha256']:raise RuntimeError('pinned actual node operator required')
    args=[node['path'],'-state-dir',str(base.STATE)]
    if operation!='status':
        if type(before) is not dict or type(before.get('revision')) is not int or not 1<=before['revision']<(1<<64) or not re.fullmatch('[0-9a-f]{32}',before.get('epoch','')) or type(request) is not str or not re.fullmatch('[0-9a-f]{32}',request):raise RuntimeError('exact node CAS required')
        args+=['-epoch',before['epoch'],'-revision',str(before['revision']),'-request-id',request]
    elif before is not None or request is not None:raise RuntimeError('read-only node shape')
    r=subprocess.run(args+[operation],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    if r.returncode!=want or len(r.stdout)>8192 or len(r.stderr)>4096:raise RuntimeError('node operator outcome')
    if want:
        if r.stdout or r.stderr.splitlines()[-1:]!=[b'operator HTTP409: CONFLICT']:raise RuntimeError('actual node CAS conflict required')
        return None
    return drain.parse_reply(json.loads(r.stdout))

def pregate_pending():
    if not (ROOT/'intent.json').is_file() or (ROOT/'commit.json').exists() or (ROOT/'.commit.next').exists():raise RuntimeError('actual precommit persistence window required')
    unit=Path('/etc/systemd/system/xandbox.service').read_text()
    if unit.count('ExecStartPre='+CLI+' verify\n')!=1:raise RuntimeError('only guarded candidate main required')
    run('systemctl','daemon-reload')
    lock=os.open(ROOT/'.lock',os.O_RDONLY|os.O_NOFOLLOW);fcntl.flock(lock,fcntl.LOCK_EX)
    command=None
    try:
        command=subprocess.Popen(['systemctl','start',base.UNIT],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        group=base.UNIT_ROOT/'.control';observed={}
        def waiting():
            try:
                ids=read(group/'cgroup.procs').split()
                if len(ids)!=1:return False
                pid=int(ids[0]);start=identity(pid)
                if base.sha(Path('/proc',str(pid),'exe'))!=base.sha(CLI):raise RuntimeError('pre-gate must be exact production installer ELF')
                files=[]
                for f in Path('/proc',str(pid),'fd').iterdir():
                    try:files.append(os.readlink(f))
                    except FileNotFoundError:pass
                if str(ROOT/'.lock') not in files:return False
                checked=0
                for thread in Path('/proc',str(pid),'task').iterdir():
                    try:s=dict(l.split(':',1) for l in (thread/'status').read_text().splitlines() if ':' in l)
                    except FileNotFoundError:continue
                    if s['NoNewPrivs'].strip()!='1' or s['Uid'].split()!=['0']*4 or any(int(s[k],16) for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')):raise RuntimeError('all actual pre-gate threads must be NNP1/caps0')
                    checked+=1
                if not checked or identity(pid)!=start:raise RuntimeError('pre-gate incarnation changed')
                observed.update(pid=pid,start=start);return True
            except FileNotFoundError:return False
        wait(waiting,8);time.sleep(.1)
        if not waiting() or run('systemctl','show','--property=MainPID','--value',base.UNIT)!='0':raise RuntimeError('gate escaped lock or daemon started pending commit')
    finally:
        fcntl.flock(lock,fcntl.LOCK_UN);os.close(lock)
        if command is not None:
            try:status=command.wait(timeout=10)
            except subprocess.TimeoutExpired:command.kill();command.wait();raise
    if status!=1 or (ROOT/'commit.json').exists() or (base.STATE/'backend.json').exists() or list(base.STATE.iterdir()):raise RuntimeError('uncommitted start did not fail before ordinary binding')
    wait(lambda:not base.UNIT_ROOT.exists() and not Path('/run/xandbox-inputs').exists(),10)
    save(CONFIG/'pending-gate-observation.json',{'exact_caps_zero_nnp_control':True,'actual_commit_absent_start_failed':True,'no_ordinary_state_written':True})

def copy_snapshot(name):
    if name not in ('backend.json','auth.json','launch.json'):raise RuntimeError('fixed private observer snapshot')
    # These observer copies must preserve the exact production bytes. Decoding
    # and reserializing Go JSON would falsely reject a valid runtime snapshot.
    raw=(ROOT/name).read_bytes()
    fd=os.open(CONFIG/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    fd=os.open(CONFIG,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def setup():
    guard()
    if CHECKPOINT.exists():bind_observers();return
    base.STATE=Path('/srv/xi/s');base.RUNTIME=Path('/srv/xi/r')
    programs=json.loads((CONFIG/'programs.json').read_bytes());source=json.loads((CONFIG/'source-assets.json').read_bytes())
    if set(source)!=set(ROLES):raise RuntimeError('fixed real thirteen publisher roles')
    for a in (*source.values(),*programs.values()):
        if base.sha(a['path'])!=a['sha256']:raise RuntimeError('frozen original asset mismatch')
    manifest={'version':1,'source_revision':json.loads((CONFIG/'production-source.json').read_bytes())['source_revision'],'toolchain':'go1.27.3','goarch':'amd64','files':[{'role':r,'source':source[r]['path'],'sha256':source[r]['sha256'],'bytes':Path(source[r]['path']).stat().st_size} for r in ROLES]}
    save(CONFIG/'publish.json',manifest)
    p=subprocess.run([programs['release']['path'],'publish','-manifest',str(CONFIG/'publish.json'),'-expected-revision','0','-request-id',secrets.token_hex(16)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    if p.returncode or p.stderr:raise RuntimeError('ordinary root publisher failed')
    receipt=json.loads(p.stdout)
    if receipt!={'version':1,'revision':1,'retained':1,'publication_durable':True,'services_changed':False,'production_ready':False}:raise RuntimeError('actual closed publisher commit required')
    run(programs['setup']['path'],'setup')
    uuid=run('/usr/sbin/blkid','-s','UUID','-o','value','/dev/vda').replace('-','')
    if not re.fullmatch('[0-9a-f]{32}',uuid):raise RuntimeError('real root block UUID required')
    device=str(os.major(os.stat('/').st_dev))+':'+str(os.minor(os.stat('/').st_dev))
    node={'version':1,'cgroup_root':str(base.UNIT_ROOT/'node'),'max_instances':4,'max_records':1024,'max_sessions':32,'prepare_workers':1,'memory_max':7<<30,'controller_memory_max':1<<30,'host_memory_reserve':512<<20,'pids_max':384,'controller_pids_max':128,'cpu_quota':800000,'io_bytes_per_second':256<<20,'io_operations_per_second':8192,'disk_bytes':10<<30,'disk_inodes':100000,'external_disk_bytes':2<<30,'external_inodes':32768,'min_free_bytes':256<<20,'min_free_inodes':2048}
    backend={'version':3,'runtime_root':'/srv/xi/r','cgroup_root':str(base.UNIT_ROOT/'node/instances'),'uid_start':400000,'uid_count':4,'reserved_uid_range':True,'quota':{'version':1,'filesystem_uuid':uuid,'project_start':1300000,'max_bytes':192<<20,'max_inodes':128},'io':{'version':1,'filesystem_device':device,'device':device,'bytes_per_second':16<<20,'operations_per_second':1024},'node':node}
    assets={r:{'path':installed(r),'sha256':source[r]['sha256']} for r in ROLES}
    for r in ('firecracker','jailer','warden','kernel','initrd','workspace'):backend[r]=assets[r]
    save(CONFIG/'input/backend.json',backend)
    plan={'version':1,'release_revision':1,'release':json.loads(Path('/srv/xandbox-releases/ref.json').read_bytes())['release'],'self':programs['install'],'device_path':'/dev/vda','frontend':{'max_instances':4,'max_records':1024,'max_tenant_records':512,'max_sessions':32,'max_tenant_sessions':16,'session_history':64,'stop_workers':4,'cleanup_workers':2,'work_queue_size':32,'metrics':True}}
    for field,name in (('backend','backend.json'),('auth','auth.json'),('gateway','gateway.json'),('certificate','tls.pem'),('private_key','tls.key')):
        p=CONFIG/'input'/name;plan[field]={'path':str(p),'sha256':base.sha(p)}
    for name,values in {'parent':(15<<29,512,800000,512<<20,16384),'ingress':(512<<20,64,200000,64<<20,2048),'reserve':(2<<30,64,200000,128<<20,4096),'capacity':(12<<30,1024,1200000,1<<30,32768)}.items():
        plan[name]=dict(zip(('memory_max','pids_max','cpu_quota','io_bytes_per_second','io_operations_per_second'),values))
    request=secrets.token_hex(16);save(CONFIG/'request.json',{'request':request});save(CONFIG/'plan.json',plan)
    call('status',want=1,bootstrap=True,nonroot=True)
    for kind in ('bad-source','stale-release'):
        bad=json.loads(json.dumps(plan))
        if kind=='bad-source':bad['auth']['sha256']='f'*64
        else:bad['release_revision']=2
        path=CONFIG/(kind+'.json');save(path,bad);call('apply',request,path,want=1,bootstrap=True)
        if (ROOT/'intent.json').exists() or Path('/etc/systemd/system/xandbox.service').exists():raise RuntimeError('invalid input materialized a candidate')
    interrupt_before_commit(arguments('apply',request,CONFIG/'plan.json',True),str(CONFIG/'trace-child-output'),programs['install']['sha256'],base.sha)
    pregate_pending()
    call('apply',request,CONFIG/'plan.json',bootstrap=True)
    for name in ('backend.json','auth.json','launch.json'):copy_snapshot(name)
    save(CONFIG/'assets.json',assets);save(CONFIG/'ingress-assets.json',{r:assets[r] for r in ('gateway','ingress')});bind_observers()
    call('verify',want=1)
    call('apply','b'*32,CONFIG/'plan.json',want=1)
    call('apply',request,CONFIG/'plan.json')
    # No committed target is modified. Only declared original sources go away.
    for a in source.values():
        p=Path(a['path'])
        if p.parent!=Path('/srv/install-bootstrap') or base.sha(p)!=a['sha256']:raise RuntimeError('source removal outside exact frozen staging')
        p.unlink()
    Path('/srv/install-bootstrap').rmdir()
    for name in ('backend.json','auth.json','gateway.json','tls.pem','tls.key'):(CONFIG/'input'/name).unlink()
    (CONFIG/'input').rmdir();Path(BOOTSTRAP).unlink()
    call('reconcile',request);call('status')

def sources_absent():
    if (CONFIG/'input').exists() or Path('/srv/install-bootstrap').exists() or Path(BOOTSTRAP).exists():raise RuntimeError('original inputs unexpectedly restored')

def probe():
    bind_observers();sources_absent();call('status');ingress.tls_ready();base.main_identity();ingress.ingress_identity();drain.probe_mode()
    return {k:True for k in PROBE_FLAGS}

def stop_destroy(row,tenant,expect_full=False):
    owner=base.owner(row);start=time.monotonic_ns();v=base.call('POST',base.refpath(row)+'/stop',{'generation':row['generation']},tenant=tenant)
    if v['state']!='STOPPED':raise RuntimeError('physical STOPPED required')
    group=base.UNIT_ROOT/'node/instances'/base.key(row)
    if group.exists() and 'populated 0' not in read(group/'cgroup.events'):raise RuntimeError('actual execution still populated')
    stopped=(time.monotonic_ns()-start)/1e6
    if expect_full:base.call('POST','/v1/sandboxes',base.create_spec(),tenant='beta',key='install-stopped-still-full',expected=503)
    base.call('DELETE',base.refpath(row),{'generation':row['generation']},tenant=tenant,expected=202);base.reclaimed(row,tenant,owner['project_id'])
    return stopped,(time.monotonic_ns()-start)/1e6

def checkpoint():
    probe();request=json.loads((CONFIG/'request.json').read_bytes())['request'];rows=[];boots=[]
    before_main=base.main_identity();before_ingress=ingress.ingress_identity();call('reconcile',request)
    if base.main_identity()!=before_main or ingress.ingress_identity()!=before_ingress:raise RuntimeError('reconcile restarted existing services')
    for i,tenant in enumerate(('alpha','alpha','alpha','beta')):
        if i==3:base.call('POST','/v1/sandboxes',{},key='install-tenant-fourth',expected=429)
        row=base.create(tenant,'install-four-'+str(i));boots.append(base.verify_vm(row,tenant));rows.append((row,tenant))
    if len(set(boots))!=4:raise RuntimeError('four independent guest boots required')
    base.call('GET',base.refpath(rows[0][0]),tenant='beta',expected=404);base.call('POST','/v1/sandboxes',{},tenant=None,key='install-no-auth',expected=401)
    base.call('POST','/v1/sandboxes',{},tenant='beta',key='install-node-fifth',expected=503)
    writer=base.progressing_writer(rows[0][0],'alpha');drain.busy(rows[0][0],writer['id'])
    ms=stop_destroy(rows[0][0],'alpha',True)
    for row,tenant in rows[1:]:stop_destroy(row,tenant)
    warm=drain.warm(lambda:call('reconcile',request))
    fresh=base.create('alpha','install-before-cold');boot=base.verify_vm(fresh,'alpha')
    if boot in boots:raise RuntimeError('slot reused old guest')
    base.execute(fresh,['test','!','-e','/workspace/heartbeat'],'alpha');base.execute(fresh,['sh','-c','printf installed-cold > /workspace/cold-marker; sync'],'alpha')
    running=base.progressing_writer(fresh,'alpha')
    save(ingress.CHECKPOINT,{'row':fresh,'guest_boot':boot,'owner':base.owner(fresh),'writer_execution_id':running['id']})
    sealed=drain.seal_cold();sources_absent();call('status')
    pins={p.name:base.sha(p) for p in ROOT.iterdir() if p.name!='.lock'}
    save(CHECKPOINT,{'boot_id':read('/proc/sys/kernel/random/boot_id'),'machine_id':read('/etc/machine-id'),'files':pins,'row':fresh,'request':request})
    return {**{k:True for k in CHECKPOINT_FLAGS if k not in drain.CHECKPOINT_FLAGS},**warm,**sealed,'stop_observed_ms':ms[0],'durable_reclaim_observed_ms':ms[1]}

def recover():
    old=json.loads(CHECKPOINT.read_bytes());probe()
    if old['boot_id']==read('/proc/sys/kernel/random/boot_id') or old['machine_id']!=read('/etc/machine-id'):raise RuntimeError('actual original disk cold boot required')
    if {p.name:base.sha(p) for p in ROOT.iterdir() if p.name!='.lock'}!=old['files']:raise RuntimeError('installed commit/files changed across cold')
    restored=drain.restore_and_resume();base.call('POST','/v1/sandboxes',base.create_spec(),key='install-before-cold',expected=410)
    for project in range(1300000,1300004):
        q=base.quota(project)
        if any(getattr(q,n) for n in ('bhard','bsoft','space','ihard','isoft','inodes','btime','itime')):raise RuntimeError('kernel project not released')
    if any(p.is_dir() for p in (base.UNIT_ROOT/'node/instances').iterdir()) or list((base.RUNTIME/'j/firecracker').iterdir()):raise RuntimeError('private generation remains')
    call('reconcile',old['request']);sources_absent();call('status');run('systemctl','stop',base.UNIT)
    wait(lambda:not base.UNIT_ROOT.exists() and not ingress.GROUP.exists() and not Path('/run/xandbox-inputs').exists() and not ingress.tcp()[1],25)
    return {**{k:True for k in RECOVERY_FLAGS if k not in drain.RECOVERY_FLAGS},**restored}

def failure():
    with open('/dev/console','w') as c:
        c.write('XANDBOX_SYSTEMD_HOST_FAILED installer\n');traceback.print_exc(file=c);c.flush()
        subprocess.run(['journalctl','--no-pager','-n','65','-u',base.UNIT,'-u',ingress.UNIT,'-u','xandbox-systemd-operator.service'],stdout=c,stderr=c,timeout=10)

def entry():
    guard();os.umask(0o077)
    try:
        setup();probe()
        fd=os.open('/dev/ttyS1',os.O_RDWR|os.O_NOCTTY);a=termios.tcgetattr(fd);a[0]=a[1]=a[3]=0;a[6][termios.VMIN]=1;a[6][termios.VTIME]=0;termios.tcsetattr(fd,termios.TCSANOW,a)
        stream=os.fdopen(fd,'r+b',buffering=0)
        with open('/dev/console','w') as c:c.write('XANDBOX_SYSTEMD_HOST_READY\n');c.flush()
        actions={'install-probe':probe,'install-checkpoint':checkpoint,'install-recover':recover}
        while True:
            raw=stream.readline(1025)
            if not raw or len(raw)>1024:raise RuntimeError('bounded fixed installer operation required')
            value=json.loads(raw)
            if type(value) is not dict or set(value)!={'version','operation'} or type(value['version']) is not int or value['version']!=1 or value['operation'] not in actions:raise RuntimeError('fixed installer operation required')
            try:stream.write(json.dumps({'ok':True,'result':actions[value['operation']]()},sort_keys=True).encode()+b'\n')
            except Exception:
                failure();stream.write(b'{"ok":false,"error":"owned installer operation failed"}\n');raise
    except Exception:
        failure();raise

if __name__=='__main__':entry()
