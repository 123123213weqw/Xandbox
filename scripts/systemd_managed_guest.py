"""TEST ONLY fresh managed-v2 root CLI / committed recovery / TLS-KVM L1.

No ordinary service is preinstalled. Guest task argv always crosses the real
controller API. Private keys/refs/process identities stay in the owned L1.
Uncommitted supersession hardware acceptance is a separate, still-open gate.
"""
import json
import os
from pathlib import Path
import re
import secrets
import signal
import ssl
import subprocess
import termios
import time
import traceback
import systemd_install_guest as install
import systemd_ingress_guest as ingress
import systemd_drain_probe as drain
from systemd_delegate_probe import guard as base_guard,read,run,save,wait,identity
from managed_fixture_trace import interrupt

base=ingress.base
CONFIG=Path('/etc/xandbox-managed-fixture');ROOT=Path('/etc/xandbox-install')
CLI='/usr/libexec/xandbox-install';BOOTSTRAP='/usr/libexec/xandbox-install-bootstrap'
CHECKPOINT=CONFIG/'checkpoint.json';PHASE='entry'
PROBE_FLAGS=('managed_v2_exact_root_cli_and_24_target_commit','automatic_tls_child_caps_placement_budgets_and_epoch','initial_capless_pending_gate_observation_preserved','immutable_backend_auth_base_self_and_release','not_full_production_or_supersession_hardware_acceptance')
CHECKPOINT_FLAGS=('four_simultaneous_real_tls_kvm_guests_and_owner_refusals','own_actual_cli_killed_after_policy2_file_before_operator_activation','expired_committed2_recovered_by_actual_root_cli3','real_populated_ingress_subtree_refused_before_state_advance','same_request_real_empty_retry_and_exact_epoch3_child_ack','same_main_four_vmm_incarnations_boots_and_busy_writer_continue','entire_drain_commit_unchanged_across_maintenance','new_tls_leaf_and_external_keys_old_key_rejected_on_same_new_transport','source_absent_reconcile_and_bad_cas_no_service_restart','physical_stop_distinct_from_durable_reclaim_and_capacity','ordinary_original_disk_checkpoint_fsynced')+drain.CHECKPOINT_FLAGS
RECOVERY_FLAGS=('original_disk_new_boot_same_machine','installed_epoch3_and_source_absence_preserved','automatic_cold_tls_epoch3_no_operator_activation','old_guest_recovered_no_implicit_resume_and_old_key_refused','all_four_kernel_projects_and_private_generations_released','manager_clean_stop_removed_both_units_and_inputs')+drain.RECOVERY_FLAGS


def guard():
    base_guard()
    if read('/etc/xandbox-systemd-managed-fixture')!='Xandbox owned managed policy fixture v1':raise RuntimeError('owned managed fixture required')


def bind_observers():
    guard();install.CONFIG=CONFIG;install.guard=guard
    base.STATE=Path('/srv/xi/s');base.RUNTIME=Path('/srv/xi/r');base.CONFIG=CONFIG
    epoch=json.loads((CONFIG/'active-client.json').read_bytes())['epoch'] if (CONFIG/'active-client.json').exists() else 1
    if type(epoch) is not int or epoch not in (1,3):raise RuntimeError('fixed active test client required')
    envelope=json.loads((ROOT/'gateway-policy.json').read_bytes())
    base.TOKENS={k['tenant_id']:k['backend_token'] for k in envelope['snapshot']['keys']}
    ingress.CONFIG=CONFIG;ingress.CLIENT=CONFIG/('client-'+str(epoch)+'.json');ingress.MANIFEST=ROOT/'ingress.json';ingress.CHILD_ROOT='/srv/xi/g/root';ingress.CHECKPOINT=CONFIG/'guest-checkpoint.json'
    base.call=ingress.tls_call;drain.guard=guard;drain.control=install.control;drain.CHECKPOINT=CONFIG/'drain-checkpoint.json'


def arguments(operation,request=None,plan=None,expected=None,supersedes=None):
    if operation in ('status','verify'):
        if any(v is not None for v in (request,plan,expected,supersedes)):raise RuntimeError('read-only fixed CLI shape')
        return [CLI,operation]
    if operation=='reconcile':
        if plan is not None or expected is not None or supersedes is not None or not isinstance(request,str) or not re.fullmatch('[0-9a-f]{32}',request):raise RuntimeError('fixed exact reconcile')
        return [CLI,operation,'-request-id',request]
    if operation not in ('reconfigure','recover-policy') or not isinstance(plan,Path) or plan.parent!=CONFIG or plan.name not in ('rotation-2.json','rotation-3.json') or type(expected) is not int or expected not in (1,2) or not isinstance(request,str) or not re.fullmatch('[0-9a-f]{32}',request):raise RuntimeError('fixed managed policy operation')
    args=[CLI,operation,'-plan',str(plan),'-expected-revision',str(expected),'-request-id',request]
    if operation=='recover-policy':
        if expected!=2 or not isinstance(supersedes,str) or not re.fullmatch('[0-9a-f]{32}',supersedes) or supersedes==request:raise RuntimeError('explicit committed recovery CAS required')
        args+=['-supersedes-request-id',supersedes]
    elif supersedes is not None:raise RuntimeError('ordinary rotation has no supersession override')
    return args


def receipt(r,revision,want=0):
    if type(revision) is not int or not 1<=revision<=3:raise RuntimeError('fixed managed receipt revision required')
    if type(want) is not int or want not in (0,1) or r.returncode!=want or len(r.stdout)>8192 or len(r.stderr)>4096:raise RuntimeError('closed managed CLI outcome required')
    if want:
        if r.stdout or r.stderr!=install.ERROR:raise RuntimeError('actual CLI refusal, not exec failure, required')
        return None
    if r.stderr:raise RuntimeError('unexpected managed CLI stderr')
    v=json.loads(r.stdout)
    if type(v) is not dict or set(v)!={'version','revision','files_committed','manager_reconciled','production_ready'} or type(v['version']) is not int or v['version']!=1 or type(v['revision']) is not int or v['revision']!=revision or v['files_committed'] is not True or v['manager_reconciled'] is not True or v['production_ready'] is not False:raise RuntimeError('exact managed commit and actual ACK receipt required')
    return v


def call(operation,revision,request=None,plan=None,expected=None,supersedes=None,want=0):
    guard();args=arguments(operation,request,plan,expected,supersedes)
    if base.sha(CLI)!=json.loads((CONFIG/'programs.json').read_bytes())['install']['sha256']:raise RuntimeError('self-pinned actual managed CLI required')
    r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    if operation=='verify' and want==0:
        if r.returncode or r.stdout or r.stderr:raise RuntimeError('silent real startup gate required')
        return None
    return receipt(r,revision,want)


def policy_state(revision):
    v=json.loads(Path('/srv/xi/p/policy.json').read_bytes())
    if type(v) is not dict or set(v)!={'version','revision','snapshot_sha256'} or type(v['version']) is not int or v['version']!=1 or type(v['revision']) is not int or v['revision']!=revision or not re.fullmatch('[0-9a-f]{64}',v['snapshot_sha256']):raise RuntimeError('actual durable gateway epoch required')
    return v


def sources_absent():
    if (CONFIG/'input').exists() or Path('/srv/install-bootstrap').exists() or Path(BOOTSTRAP).exists():raise RuntimeError('initial source inputs unexpectedly restored')


def setup():
    global PHASE
    guard()
    if CHECKPOINT.exists():bind_observers();return
    install.CONFIG=CONFIG;install.guard=guard
    base.STATE=Path('/srv/xi/s');base.RUNTIME=Path('/srv/xi/r');base.CONFIG=CONFIG
    PHASE='managed-source-pins'
    programs=json.loads((CONFIG/'programs.json').read_bytes());source=json.loads((CONFIG/'source-assets.json').read_bytes())
    if set(source)!=set(install.ROLES) or set(programs)!={'install','release','setup'}:raise RuntimeError('closed managed image source inventory')
    for a in (*source.values(),*programs.values()):
        if base.sha(a['path'])!=a['sha256']:raise RuntimeError('current qualified program/data pin drift')
    manifest={'version':1,'source_revision':json.loads((CONFIG/'production-source.json').read_bytes())['source_revision'],'toolchain':'go1.27.3','goarch':'amd64','files':[{'role':r,'source':source[r]['path'],'sha256':source[r]['sha256'],'bytes':Path(source[r]['path']).stat().st_size} for r in install.ROLES]}
    save(CONFIG/'publish.json',manifest);PHASE='managed-publication'
    p=subprocess.run([programs['release']['path'],'publish','-manifest',str(CONFIG/'publish.json'),'-expected-revision','0','-request-id',secrets.token_hex(16)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    if p.returncode or p.stderr or json.loads(p.stdout)!={'version':1,'revision':1,'retained':1,'publication_durable':True,'services_changed':False,'production_ready':False}:raise RuntimeError('actual managed asset publication required')
    PHASE='managed-pki';run(programs['setup']['path'],'setup')
    uuid=run('/usr/sbin/blkid','-s','UUID','-o','value','/dev/vda').replace('-','')
    if not re.fullmatch('[0-9a-f]{32}',uuid):raise RuntimeError('actual root block UUID required')
    device=str(os.major(os.stat('/').st_dev))+':'+str(os.minor(os.stat('/').st_dev))
    node={'version':1,'cgroup_root':str(base.UNIT_ROOT/'node'),'max_instances':4,'max_records':1024,'max_sessions':32,'prepare_workers':1,'memory_max':7<<30,'controller_memory_max':1<<30,'host_memory_reserve':512<<20,'pids_max':384,'controller_pids_max':128,'cpu_quota':800000,'io_bytes_per_second':256<<20,'io_operations_per_second':8192,'disk_bytes':10<<30,'disk_inodes':100000,'external_disk_bytes':2<<30,'external_inodes':32768,'min_free_bytes':256<<20,'min_free_inodes':2048}
    backend={'version':3,'runtime_root':'/srv/xi/r','cgroup_root':str(base.UNIT_ROOT/'node/instances'),'uid_start':400000,'uid_count':4,'reserved_uid_range':True,'quota':{'version':1,'filesystem_uuid':uuid,'project_start':1300000,'max_bytes':192<<20,'max_inodes':128},'io':{'version':1,'filesystem_device':device,'device':device,'bytes_per_second':16<<20,'operations_per_second':1024},'node':node}
    assets={r:{'path':install.installed(r),'sha256':source[r]['sha256']} for r in install.ROLES}
    for r in ('firecracker','jailer','warden','kernel','initrd','workspace'):backend[r]=assets[r]
    save(CONFIG/'input/backend.json',backend)
    plan={'version':2,'release_revision':1,'release':json.loads(Path('/srv/xandbox-releases/ref.json').read_bytes())['release'],'self':programs['install'],'device_path':'/dev/vda','frontend':{'max_instances':4,'max_records':1024,'max_tenant_records':512,'max_sessions':32,'max_tenant_sessions':16,'session_history':64,'stop_workers':4,'cleanup_workers':2,'work_queue_size':32,'metrics':True}}
    for field,name in (('backend','backend.json'),('auth','auth.json'),('gateway','gateway.json'),('policy','policy-initial.json')):
        p=CONFIG/'input'/name;plan[field]={'path':str(p),'sha256':base.sha(p)}
    for name,values in {'parent':(15<<29,512,800000,512<<20,16384),'ingress':(512<<20,64,200000,64<<20,2048),'reserve':(2<<30,64,200000,128<<20,4096),'capacity':(12<<30,1024,1200000,1<<30,32768)}.items():plan[name]=dict(zip(('memory_max','pids_max','cpu_quota','io_bytes_per_second','io_operations_per_second'),values))
    request=secrets.token_hex(16);save(CONFIG/'request.json',{'request':request});save(CONFIG/'plan.json',plan)
    install.call('status',want=1,bootstrap=True,nonroot=True)
    PHASE='managed-initial-cut'
    interrupt(install.arguments('apply',request,CONFIG/'plan.json',True),str(CONFIG/'initial-child-output'),programs['install']['sha256'],base.sha,'initial-commit')
    PHASE='managed-pregate';install.pregate_pending()
    PHASE='managed-initial-reconcile';install.call('apply',request,CONFIG/'plan.json',bootstrap=True)
    for name in ('backend.json','auth.json','launch.json'):install.copy_snapshot(name)
    save(CONFIG/'assets.json',assets);save(CONFIG/'ingress-assets.json',{r:assets[r] for r in ('gateway','ingress')});bind_observers()
    policy_state(1);call('status',1)
    PHASE='managed-source-removal'
    for a in source.values():
        p=Path(a['path'])
        if p.parent!=Path('/srv/install-bootstrap') or base.sha(p)!=a['sha256']:raise RuntimeError('fixed source removal only')
        p.unlink()
    Path('/srv/install-bootstrap').rmdir()
    for name in ('backend.json','auth.json','gateway.json','policy-initial.json'):(CONFIG/'input'/name).unlink()
    (CONFIG/'input').rmdir();Path(BOOTSTRAP).unlink();sources_absent();call('reconcile',1,request)


def probe():
    bind_observers();sources_absent();ingress.tls_ready();base.main_identity();ingress.ingress_identity();drain.probe_mode()
    revision=json.loads((ROOT/'gateway-policy.json').read_bytes())['revision'];call('status',revision);policy_state(revision)
    commit=json.loads((ROOT/'commit.json').read_bytes())
    if commit['plan']['version']!=2 or len(commit['files'])!=24 or (ROOT/'tls.pem').exists() or (ROOT/'tls.key').exists():raise RuntimeError('actual managed24-target composition required')
    observation=json.loads((CONFIG/'pending-gate-observation.json').read_bytes())
    if observation!={'exact_caps_zero_nnp_control':True,'actual_commit_absent_start_failed':True,'no_ordinary_state_written':True}:raise RuntimeError('initial real capless gate evidence required')
    return {k:True for k in PROBE_FLAGS}


def vmm_identity(row):
    assets=json.loads((CONFIG/'assets.json').read_bytes());found=[]
    for raw in read(base.UNIT_ROOT/'node/instances'/base.key(row)/'cgroup.procs').split():
        pid=int(raw);start=identity(pid)
        try:pin=base.sha(Path('/proc',str(pid),'exe'))
        except FileNotFoundError:continue
        if pin==assets['firecracker']['sha256']:
            if identity(pid)!=start:raise RuntimeError('VMM incarnation changed during observation')
            found.append((pid,start))
    if len(found)!=1:raise RuntimeError('exact current VMM incarnation required')
    return found[0]


def wait_pending_expiry():
    envelope=json.loads((ROOT/'gateway-policy.json').read_bytes());p=CONFIG/'pending-certificate.pem'
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as out:out.write(envelope['snapshot']['certificate_pem']);out.flush();os.fsync(out.fileno())
    expires=ssl.cert_time_to_seconds(ssl._ssl._test_decode_cert(str(p))['notAfter'])
    if expires-time.time()>65:raise RuntimeError('only synthetic short-lived pending leaf accepted')
    wait(lambda:time.time()>=expires,65)
    if time.time()<expires:raise RuntimeError('actual pending certificate did not expire')


def populated_negative_then_recover(request,old_request,main_before):
    # Only an owned inert test child enters this exact L1 unit cgroup. It never
    # executes task argv or migrates a production process. No L0 call can pass guard.
    guard();run('systemctl','--job-mode=ignore-dependencies','stop',ingress.UNIT)
    wait(lambda:run('systemctl','show','--property=MainPID','--value',ingress.UNIT)=='0' and run('systemctl','show','--property=ActiveState','--value',ingress.UNIT) in ('inactive','failed'),15)
    group=ingress.GROUP
    if not group.exists():group.mkdir(mode=0o755)
    r,w=os.pipe();pid=os.fork()
    if pid==0:
        os.close(w)
        try:os.read(r,1)
        finally:os._exit(0)
    os.close(r)
    try:
        (group/'cgroup.procs').write_text(str(pid))
        if 'populated 1' not in read(group/'cgroup.events') or identity(pid) is None:raise RuntimeError('actual owned populated subtree not established')
        before=Path('/srv/xi/p/policy.json').read_bytes()
        call('recover-policy',3,request,CONFIG/'rotation-3.json',2,old_request,want=1)
        if Path('/srv/xi/p/policy.json').read_bytes()!=before or policy_state(1)['revision']!=1 or base.main_identity()!=main_before or 'populated 1' not in read(group/'cgroup.events'):raise RuntimeError('nonempty refusal advanced state or changed main')
        if not (ROOT/'policy-recovery.json').is_file():raise RuntimeError('new declaration did not pass file admission before negative')
    finally:
        os.close(w)
        try:os.kill(pid,signal.SIGKILL)
        except ProcessLookupError:pass
        got,status=os.waitpid(pid,0)
        if got!=pid or not (os.WIFEXITED(status) or os.WIFSIGNALED(status)):raise RuntimeError('owned inert child not reaped')
    if group.exists():
        events=read(group/'cgroup.events').splitlines()
        if set(events)!={'populated 0','frozen 0'}:raise RuntimeError('actual empty unfrozen subtree required')
    call('recover-policy',3,request,CONFIG/'rotation-3.json',2,old_request)
    save(CONFIG/'active-client.json',{'epoch':3});bind_observers();ingress.tls_ready();policy_state(3)


def checkpoint():
    global PHASE
    probe();rows=[];boots=[];PHASE='managed-four-kvm'
    for i,tenant in enumerate(('alpha','alpha','alpha','beta')):
        if i==3:base.call('POST','/v1/sandboxes',{},key='managed-tenant-fourth',expected=429)
        row=base.create(tenant,'managed-four-'+str(i));boots.append(base.verify_vm(row,tenant));rows.append((row,tenant))
    if len(set(boots))!=4:raise RuntimeError('four independent real guest boots required')
    base.call('GET',base.refpath(rows[0][0]),tenant='beta',expected=404);base.call('POST','/v1/sandboxes',{},tenant=None,key='managed-no-auth',expected=401)
    base.call('POST','/v1/sandboxes',{},tenant='beta',key='managed-node-fifth',expected=503)
    main_before=base.main_identity();vm_before=[vmm_identity(r) for r,_ in rows];ingress_before=ingress.ingress_identity();immutable={n:base.sha(ROOT/n) for n in ('commit.json','gateway.json','auth.json','backend.json')}
    PHASE='managed-short-policy2';program=json.loads((CONFIG/'programs.json').read_bytes())['setup'];run(program['path'],'rotation2')
    old_request=secrets.token_hex(16);args=arguments('reconfigure',old_request,CONFIG/'rotation-2.json',1)
    PHASE='managed-before-policy2-activation'
    interrupt(args,str(CONFIG/'rotation-child-output'),json.loads((CONFIG/'programs.json').read_bytes())['install']['sha256'],base.sha,'policy-activation',2,old_request)
    if json.loads((ROOT/'gateway-policy.json').read_bytes())['revision']!=2 or ingress.ingress_identity()!=ingress_before:raise RuntimeError('not actual committed-but-unactivated2')
    policy_state(1)
    drained=drain.change('drain',drain.state('open')['control']['committed'])
    PHASE='managed-actual-expiry';wait_pending_expiry()
    run(program['path'],'rotation3');request=secrets.token_hex(16)
    # Admit the busy job AFTER waiting for leaf2 expiry. Its original 45-second
    # budget is unchanged; waiting a minute must not falsely count an expired job.
    writer=base.progressing_writer(rows[0][0],'alpha');drain.busy(rows[0][0],writer['id'])
    PHASE='managed-real-population-gate';populated_negative_then_recover(request,old_request,main_before)
    PHASE='managed-continuity'
    if base.main_identity()!=main_before or [vmm_identity(r) for r,_ in rows]!=vm_before:raise RuntimeError('main/VMM restarted during ingress maintenance')
    if [base.verify_vm(r,t) for r,t in rows]!=boots:raise RuntimeError('guest boot changed during maintenance')
    drain.state('drained',drained);drain.busy(rows[0][0],writer['id'])
    if {n:base.sha(ROOT/n) for n in immutable}!=immutable:raise RuntimeError('base/backend/auth changed during recovery')
    old_client=json.loads((CONFIG/'client-1.json').read_bytes());conn=ingress.TLSHTTP('xandbox.fixture',timeout=40)
    try:
        ingress.tls_call('GET','/healthz',connection=conn);transport=ingress.transport_identity(conn)
        ingress.tls_call('GET','/healthz',token=old_client['tokens']['alpha'],expected=401,connection=conn,expected_transport=transport)
        ingress.tls_call('GET','/healthz',connection=conn,expected_transport=transport)
    finally:conn.close()
    PHASE='managed-source-free-reconcile';p=CONFIG/'sources/snapshot-3.json';pin=json.loads((CONFIG/'rotation-3.json').read_bytes())['policy']
    if str(p)!=pin['path'] or base.sha(p)!=pin['sha256']:raise RuntimeError('only exact private new source can be removed')
    p.unlink();before=ingress.ingress_identity();call('reconcile',3,request)
    call('recover-policy',3,secrets.token_hex(16),CONFIG/'rotation-3.json',2,old_request,want=1)
    if ingress.ingress_identity()!=before or base.main_identity()!=main_before:raise RuntimeError('receipt retry/conflict restarted service')
    # Resume is an explicit root CAS AFTER the preserved-drain proof, never an
    # effect of maintenance. Capacity must not be confused with NODE_DRAINING.
    drain.change('resume',drain.state('drained',drained)['control']['committed']);drain.health('open')
    PHASE='managed-stop-reclaim';ms=install.stop_destroy(rows[0][0],'alpha',True)
    for r,t in rows[1:]:install.stop_destroy(r,t)
    PHASE='managed-warm-drain';warm=drain.warm(lambda:call('reconcile',3,request))
    fresh=base.create('alpha','managed-before-cold');boot=base.verify_vm(fresh,'alpha')
    if boot in boots:raise RuntimeError('reused old guest boot')
    base.execute(fresh,['test','!','-e','/workspace/heartbeat'],'alpha');running=base.progressing_writer(fresh,'alpha')
    save(ingress.CHECKPOINT,{'row':fresh,'guest_boot':boot,'owner':base.owner(fresh),'writer_execution_id':running['id']})
    sealed=drain.seal_cold();sources_absent();call('status',3)
    save(CHECKPOINT,{'boot_id':read('/proc/sys/kernel/random/boot_id'),'machine_id':read('/etc/machine-id'),'files':{p.name:base.sha(p) for p in ROOT.iterdir() if p.name!='.lock'},'request':request})
    return {**{k:True for k in CHECKPOINT_FLAGS if k not in drain.CHECKPOINT_FLAGS},**warm,**sealed,'stop_observed_ms':ms[0],'durable_reclaim_observed_ms':ms[1]}


def recover():
    old=json.loads(CHECKPOINT.read_bytes());probe()
    if old['boot_id']==read('/proc/sys/kernel/random/boot_id') or old['machine_id']!=read('/etc/machine-id'):raise RuntimeError('actual original disk cold boot required')
    if {p.name:base.sha(p) for p in ROOT.iterdir() if p.name!='.lock'}!=old['files']:raise RuntimeError('installed managed files changed across cold')
    restored=drain.restore_and_resume();base.call('POST','/v1/sandboxes',base.create_spec(),key='managed-before-cold',expected=410)
    for project in range(1300000,1300004):
        q=base.quota(project)
        if any(getattr(q,n) for n in ('bhard','bsoft','space','ihard','isoft','inodes','btime','itime')):raise RuntimeError('kernel project not released')
    if any(p.is_dir() for p in (base.UNIT_ROOT/'node/instances').iterdir()) or list((base.RUNTIME/'j/firecracker').iterdir()):raise RuntimeError('private generation remains')
    call('reconcile',3,old['request']);sources_absent();call('status',3);run('systemctl','stop',base.UNIT)
    wait(lambda:not base.UNIT_ROOT.exists() and not ingress.GROUP.exists() and not Path('/run/xandbox-inputs').exists() and not ingress.tcp()[1],25)
    return {**{k:True for k in RECOVERY_FLAGS if k not in drain.RECOVERY_FLAGS},**restored}


def failure():
    with open('/dev/console','w') as c:
        c.write('XANDBOX_MANAGED_PRIVATE_FAILURE phase='+PHASE+'\n');traceback.print_exc(file=c)
        for unit in (base.UNIT,ingress.UNIT):
            r=subprocess.run(['journalctl','--no-pager','-o','cat','-n','80','-u',unit],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=10)
            c.write(r.stdout[:32768].decode(errors='replace'))
        c.write('XANDBOX_SYSTEMD_HOST_FAILED\n');c.flush()


def entry():
    guard()
    try:
        setup();probe();fd=os.open('/dev/ttyS1',os.O_RDWR|os.O_NOCTTY);a=termios.tcgetattr(fd);a[0]=a[1]=a[3]=0;a[6][termios.VMIN]=1;a[6][termios.VTIME]=0;termios.tcsetattr(fd,termios.TCSANOW,a);stream=os.fdopen(fd,'r+b',buffering=0)
        with open('/dev/console','w') as c:c.write('XANDBOX_SYSTEMD_HOST_READY\n');c.flush()
        actions={'managed-probe':probe,'managed-checkpoint':checkpoint,'managed-recover':recover}
        while True:
            raw=stream.readline(1025)
            if not raw or len(raw)>1024:raise RuntimeError('bounded fixed managed operation')
            v=json.loads(raw)
            if type(v) is not dict or set(v)!={'version','operation'} or type(v['version']) is not int or v['version']!=1 or v['operation'] not in actions:raise RuntimeError('closed managed operation required')
            try:stream.write(json.dumps({'ok':True,'result':actions[v['operation']]()},sort_keys=True).encode()+b'\n')
            except Exception:failure();stream.write(b'{"ok":false,"error":"owned managed operation failed"}\n');raise
    except Exception:failure();raise

if __name__=='__main__':entry()
