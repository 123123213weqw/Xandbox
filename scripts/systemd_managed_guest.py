"""TEST ONLY fresh managed-v2 root CLI / committed recovery / TLS-KVM L1.

No ordinary service is preinstalled. Guest task argv always crosses the real
controller API. Private keys/refs/process identities stay in the owned L1.
Uncommitted supersession hardware acceptance is a separate, still-open gate.
"""
import json
import hashlib
import os
from pathlib import Path
import re
import secrets
import signal
import ssl
import stat
import subprocess
import termios
import time
import traceback
from datetime import datetime
import systemd_install_guest as install
import systemd_ingress_guest as ingress
import systemd_drain_probe as drain
from systemd_delegate_probe import guard as base_guard,read,run,save,wait,identity
from managed_fixture_trace import interrupt

base=ingress.base
CONFIG=Path('/etc/xandbox-managed-fixture');ROOT=Path('/etc/xandbox-install')
CLI='/usr/libexec/xandbox-install';BOOTSTRAP='/usr/libexec/xandbox-install-bootstrap'
CHECKPOINT=CONFIG/'checkpoint.json';PHASE='entry'
PROBE_FLAGS=('managed_v2_exact_root_cli_and_24_target_commit','automatic_tls_child_caps_placement_budgets_and_epoch','initial_capless_pending_gate_observation_preserved','immutable_backend_auth_base_self_and_release','not_full_production_or_full_supersession_matrix_acceptance')
COMMITTED_CHECKPOINT_FLAGS=('own_actual_cli_killed_after_policy2_file_before_operator_activation','expired_committed2_recovered_by_actual_root_cli3')
COMMON_CHECKPOINT_FLAGS=('four_simultaneous_real_tls_kvm_guests_and_owner_refusals','same_main_four_vmm_incarnations_boots_and_busy_writer_continue','entire_drain_commit_unchanged_across_maintenance','old_key_refused_on_existing_policy3_tls_transport_and_closed','fresh_policy3_tls_and_new_key_accepted_after_expected_401_close','source_absent_reconcile_and_bad_cas_no_service_restart','physical_stop_distinct_from_durable_reclaim_and_capacity','ordinary_original_disk_checkpoint_fsynced')+drain.CHECKPOINT_FLAGS
CASE_FLAGS={'supersession-repeat':('unconsumed_file_and_runtime1_old_proposal2_expired_and_source_absent','actual_supersession_a_killed_before_publication_source_and_proposal_data_lost','actual_supersession_b_settled_a_without_ack_and_consumed2_only_once','ordinary_2_to_3_hot_rotation_old_token_refused_on_original_tls2_transport'),'supersession-visible-recovery':('actual_supersession2_fsynced_before_ingress_start_no_ack','actual_replace_refused_reuse_of_published2','actual_recovery3_advanced_installed2_then_new_child_ack'),'hot-rotation':('normal_1_to_2_rotation_retained_original_tls1_transport','normal_2_to_3_rotation_retained_original_tls2_transport','both_normal_rotations_kept_ingress_and_main_incarnations'),'populated-gate':('real_populated_ingress_subtree_refused_before_state_advance','same_request_real_empty_retry_and_exact_epoch3_child_ack'),'active-stop':('actual_cli_stopped_active_ingress_old_incarnations_absent','actual_active_stop_to_fresh_epoch3_child_ack')}
CASE_FLAGS.update({'draft-discard':('actual_nonempty_partial_draft_write_cut_and_source_lost','fresh_candidate_and_wrong_hash_pending_refused_before_draft_clear','actual_present_draft_receipt_removed_true_then_absent_different_hash_false','only_fresh_replacement_consumed2_after_discard_then_normal_hot3'),'draft-discard-cut':('actual_nonempty_partial_draft_cut_and_source_absence_before_unlink_cut','actual_root_directory_fsync_after_draft_unlink_killed_before_receipt','fresh_current_absence_retry_removed_false_not_historic_discard_receipt','unconsumed2_replaced_then_normal_hot3_after_durable_discard_cut')})
CHECKPOINT_FLAGS=COMMON_CHECKPOINT_FLAGS+COMMITTED_CHECKPOINT_FLAGS+CASE_FLAGS['populated-gate']

RECOVERY_FLAGS=('original_disk_new_boot_same_machine','installed_epoch3_and_source_absence_preserved','automatic_cold_tls_epoch3_no_operator_activation','old_guest_recovered_no_implicit_resume_and_old_key_refused','all_four_kernel_projects_and_private_generations_released','manager_clean_stop_removed_both_units_and_inputs')+drain.RECOVERY_FLAGS


def guard():
    base_guard()
    if read('/etc/xandbox-systemd-managed-fixture')!='Xandbox owned managed policy fixture v1':raise RuntimeError('owned managed fixture required')


def decode_maintenance_case(value):
    if type(value) is not dict or set(value)!={'version','case'} or type(value['version']) is not int or value['version']!=1 or type(value['case']) is not str or value['case'] not in CASE_FLAGS:raise RuntimeError('closed managed case metadata required')
    return value['case']


def maintenance_case():return decode_maintenance_case(json.loads((CONFIG/'maintenance-case.json').read_bytes()))


def checkpoint_flags(case):
    if case not in CASE_FLAGS:raise RuntimeError('fixed managed case required')
    return COMMON_CHECKPOINT_FLAGS+(COMMITTED_CHECKPOINT_FLAGS if case in ('populated-gate','active-stop') else ())+CASE_FLAGS[case]


def bind_observers():
    guard();install.CONFIG=CONFIG;install.guard=guard
    base.STATE=Path('/srv/xi/s');base.RUNTIME=Path('/srv/xi/r');base.CONFIG=CONFIG
    active=json.loads((CONFIG/'active-client.json').read_bytes()) if (CONFIG/'active-client.json').exists() else {'epoch':1}
    if type(active) is not dict:raise RuntimeError('closed active client required')
    epoch=active.get('epoch');variant=active.get('variant')
    if set(active) not in ({'epoch'},{'epoch','variant'}) or type(epoch) is not int or epoch not in (1,2,3) or ('variant' in active and (epoch!=2 or variant!='replacement-2b')):raise RuntimeError('fixed active test client required')
    envelope=json.loads((ROOT/'gateway-policy.json').read_bytes())
    base.TOKENS={k['tenant_id']:k['backend_token'] for k in envelope['snapshot']['keys']}
    ingress.CONFIG=CONFIG;ingress.CLIENT=CONFIG/('client-'+(variant or str(epoch))+'.json');ingress.MANIFEST=ROOT/'ingress.json';ingress.CHILD_ROOT='/srv/xi/g/root';ingress.CHECKPOINT=CONFIG/'guest-checkpoint.json'
    base.call=ingress.tls_call;drain.guard=guard;drain.control=install.control;drain.CHECKPOINT=CONFIG/'drain-checkpoint.json'


def arguments(operation,request=None,plan=None,expected=None,supersedes=None):
    if operation in ('status','verify'):
        if any(v is not None for v in (request,plan,expected,supersedes)):raise RuntimeError('read-only fixed CLI shape')
        return [CLI,operation]
    if operation=='reconcile':
        if plan is not None or expected is not None or supersedes is not None or not isinstance(request,str) or not re.fullmatch('[0-9a-f]{32}',request):raise RuntimeError('fixed exact reconcile')
        return [CLI,operation,'-request-id',request]
    if operation not in ('reconfigure','recover-policy','replace-pending-policy') or not isinstance(plan,Path) or plan.parent!=CONFIG or plan.name not in ('rotation-2.json','rotation-3.json','rotation-replacement-2a.json','rotation-replacement-2b.json') or type(expected) is not int or expected not in (1,2) or not isinstance(request,str) or not re.fullmatch('[0-9a-f]{32}',request):raise RuntimeError('fixed managed policy operation')
    args=[CLI,operation,'-plan',str(plan),'-expected-revision',str(expected),'-request-id',request]
    if operation=='replace-pending-policy':
        if expected!=1 or plan.name not in ('rotation-replacement-2a.json','rotation-replacement-2b.json') or not isinstance(supersedes,str) or not re.fullmatch('[0-9a-f]{32}',supersedes) or supersedes==request:raise RuntimeError('explicit unconsumed replacement CAS required')
        args+=['-replaces-request-id',supersedes]
    elif operation=='recover-policy':
        if expected!=2 or not isinstance(supersedes,str) or not re.fullmatch('[0-9a-f]{32}',supersedes) or supersedes==request:raise RuntimeError('explicit committed recovery CAS required')
        args+=['-supersedes-request-id',supersedes]
    elif supersedes is not None:raise RuntimeError('ordinary rotation has no supersession override')
    if operation!='replace-pending-policy' and plan.name not in ('rotation-2.json','rotation-3.json'):raise RuntimeError('ordinary fixed rotation source required')
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
    started=time.monotonic()
    try:r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    finally:private_timing(operation,time.monotonic()-started)
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
    return {'maintenance_case':maintenance_case(),**{k:True for k in PROBE_FLAGS}}


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


def wait_pending_expiry(proposal=False):
    if type(proposal) is not bool:raise RuntimeError('fixed expiry source required')
    envelope=json.loads((ROOT/('.policy.next' if proposal else 'gateway-policy.json')).read_bytes());p=CONFIG/'pending-certificate.pem'
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


def active_stop_recover(request,old_request,old_ingress):
    # Unlike the population differential, NOTHING pre-stops the unit here.
    # Only the production fixed root CLI may perform stop/start/advance/ACK.
    guard()
    if ingress.ingress_identity()!=old_ingress:raise RuntimeError('original active ingress required')
    policy_state(1)
    call('recover-policy',3,request,CONFIG/'rotation-3.json',2,old_request)
    save(CONFIG/'active-client.json',{'epoch':3});bind_observers();ingress.tls_ready();policy_state(3)
    if ingress.ingress_identity()==old_ingress or identity(old_ingress[0])==old_ingress[1] or identity(old_ingress[2])==old_ingress[3]:raise RuntimeError('production maintenance did not replace actual old ingress incarnations')


def old_key_rejection():
    # gatewayError deliberately sends Connection: close on 401. Prove refusal
    # on the already-established policy3 transport, not post-401 keepalive.
    old_client=json.loads((CONFIG/'client-1.json').read_bytes());conn=ingress.TLSHTTP('xandbox.fixture',timeout=40)
    try:
        ingress.tls_call('GET','/healthz',connection=conn);transport=ingress.transport_identity(conn)
        ingress.tls_call('GET','/healthz',token=old_client['tokens']['alpha'],expected=401,connection=conn,expected_transport=transport)
        if conn.sock is not None:raise RuntimeError('401 transport did not close as required')
    finally:conn.close()
    # New credentials and the current leaf must work on a separate new TLS
    # connection. Never label its successful automatic reconnect as continuity.
    ingress.tls_call('GET','/healthz')


def restart_after_explicit_warm_stop(request):
    # drain.warm has explicitly stopped main, after all maintenance continuity
    # checks. Policy reconcile MUST NOT start main; only this separate owned
    # root operator action may restart it for the named warm-restart test.
    guard()
    if run('systemctl','show','--property=MainPID','--value',base.UNIT)!='0' or run('systemctl','show','--property=ActiveState','--value',base.UNIT) not in ('inactive','failed'):raise RuntimeError('explicit warm main stop required')
    run('systemctl','start',base.UNIT);ingress.tls_ready();call('reconcile',3,request)


def produce(operation):
    guard()
    if operation not in ('rotation2','rotation2long','rotation3','replacement2a','replacement2b'):raise RuntimeError('fixed owned material producer required')
    program=json.loads((CONFIG/'programs.json').read_bytes())['setup']
    if base.sha(program['path'])!=program['sha256']:raise RuntimeError('qualified current producer required')
    run(program['path'],operation)


def trace_policy(operation,request,plan,expected,mode,replaces=None):
    guard()
    started=time.monotonic()
    try:return interrupt(arguments(operation,request,CONFIG/plan,expected,replaces),str(CONFIG/(mode+'-'+request+'-output')),json.loads((CONFIG/'programs.json').read_bytes())['install']['sha256'],base.sha,mode,2,request)
    finally:private_timing(mode,time.monotonic()-started)


def private_timing(event,seconds):
    guard()
    if event not in ('status','verify','reconcile','reconfigure','recover-policy','replace-pending-policy','rotation-proposal','supersession-proposal','supersession-visible','discard-supersession-draft','supersession-draft-short','supersession-draft-discard') or type(seconds) is not float or not 0<=seconds<=120:raise RuntimeError('closed private timing required')
    with open('/dev/console','w') as c:c.write('XANDBOX_MANAGED_PRIVATE_TIMING '+json.dumps({'event':event,'seconds':round(seconds,6)},sort_keys=True)+'\n');c.flush()


def new_busy_writer(row):
    started=time.monotonic();writer=base.progressing_writer(row,'alpha');writer['fixture_started_monotonic']=started
    return writer


def late_observation(phase,row,writer):
    # Bounded private metadata only, never IDs, tokens, argv, outputs or errors.
    # Observations do not relax a predicate, change a timeout or repair state.
    guard()
    if phase not in ('after-continuity','after-sourcefree-cas','before-stop'):raise RuntimeError('fixed late observation required')
    started=writer.get('fixture_started_monotonic');remaining=datetime.fromisoformat(row['expires_at'].replace('Z','+00:00')).timestamp()-time.time()
    owner_present=(base.STATE/'firecracker'/(base.key(row)+'.json')).exists()
    value={'phase':phase,'owner_present':owner_present,'sandbox_ttl_remaining_ms':round(remaining*1000,3),'writer_age_ms':round((time.monotonic()-started)*1000,3) if type(started) is float else None}
    if not owner_present:
        try:
            current=base.call('GET',base.refpath(row),tenant='alpha')
            state=current.get('state')
            value['sandbox_state']=state if state in ('CREATING','READY','STOPPING','STOPPED','DESTROYING','DESTROYED','FAILED') else 'unknown'
        except Exception:value['sandbox_state']='unavailable'
    with open('/dev/console','w') as c:c.write('XANDBOX_MANAGED_PRIVATE_LATE '+json.dumps(value,sort_keys=True)+'\n');c.flush()


def remove_known_file(path,pin):
    # Explicit owned-fixture DATA LOSS injection, never a production cleanup API.
    # No metadata pathname, arbitrary root, symlink or unknown bytes are admitted.
    guard()
    allowed={CONFIG/'sources'/('snapshot-'+n+'.json') for n in ('2','3','replacement-2a','replacement-2b')}|{ROOT/'.policy.next'}
    if path not in allowed or type(pin) is not str or not re.fullmatch('[0-9a-f]{64}',pin):raise RuntimeError('fixed known fixture data only')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<before.st_size<=32768:raise RuntimeError('bounded owned fixture data required')
        with os.fdopen(os.dup(fd),'rb') as f:raw=f.read(32769)
        if len(raw)!=before.st_size or hashlib.sha256(raw).hexdigest()!=pin:raise RuntimeError('exact known fixture data required')
        now=path.lstat()
        if (now.st_dev,now.st_ino,now.st_size,now.st_nlink,now.st_mode)!=(before.st_dev,before.st_ino,before.st_size,1,before.st_mode):raise RuntimeError('fixture data incarnation changed')
        path.unlink()
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:os.close(fd)


def remove_source(stem):
    guard()
    if stem not in ('2','3','replacement-2a','replacement-2b'):raise RuntimeError('closed source loss required')
    pin=json.loads((CONFIG/('rotation-'+stem+'.json')).read_bytes())['policy'];path=CONFIG/'sources'/('snapshot-'+stem+'.json')
    if pin['path']!=str(path):raise RuntimeError('fixed private source binding required')
    remove_known_file(path,pin['sha256'])


def stopped_original_ingress():
    guard()
    if run('systemctl','show','--property=MainPID','--value',ingress.UNIT)!='0' or run('systemctl','show','--property=ActiveState','--value',ingress.UNIT) not in ('inactive','failed'):raise RuntimeError('actual stopped ingress required')
    if ingress.GROUP.exists() and set(read(ingress.GROUP/'cgroup.events').splitlines())!={'populated 0','frozen 0'}:raise RuntimeError('actual absent or empty unfrozen ingress required')


def lose_a_proposal(request,main_before):
    guard();stopped_original_ingress();policy_state(1)
    if base.main_identity()!=main_before or json.loads((ROOT/'gateway-policy.json').read_bytes()).get('revision')!=1:raise RuntimeError('unchanged installed/runtime1 required for owned data loss')
    record=json.loads((ROOT/'policy-supersession.json').read_bytes());intent=json.loads((ROOT/'rotation-intent.json').read_bytes())
    required={'version','expected_revision','request_id','replaces_request_id','base_commit_sha256','config_sha256','initial_policy_sha256','old_payload_sha256','previous_snapshot_sha256','new_payload_sha256','source','previous_intent'}
    if set(record)!=required or type(record['version']) is not int or record['version']!=1 or type(record['expected_revision']) is not int or record['expected_revision']!=1 or record['request_id']!=request or record['source']['path']!=str(CONFIG/'sources/snapshot-replacement-2a.json') or intent['request_id']!=request or intent['new_payload_sha256']!=record['new_payload_sha256'] or base.sha(ROOT/'gateway-policy.json')!=record['old_payload_sha256']:raise RuntimeError('exact own uncommitted A declaration required')
    remove_source('replacement-2a')
    remove_known_file(ROOT/'.policy.next',record['new_payload_sha256'])
    if (CONFIG/'sources/snapshot-replacement-2a.json').exists() or (ROOT/'.policy.next').exists():raise RuntimeError('owned A source/proposal data still present')
    call('verify',1,want=1)


def ordinary_hot_step(epoch):
    guard()
    if type(epoch) is not int or epoch not in (2,3):raise RuntimeError('fixed normal rotation required')
    old_client=ingress.client();before=ingress.ingress_identity();conn=ingress.TLSHTTP('xandbox.fixture',timeout=40)
    try:
        ingress.tls_call('GET','/healthz',connection=conn);transport=ingress.transport_identity(conn)
        produce('rotation2long' if epoch==2 else 'rotation3');request=secrets.token_hex(16)
        call('reconfigure',epoch,request,CONFIG/('rotation-'+str(epoch)+'.json'),epoch-1)
        save(CONFIG/'active-client.json',{'epoch':epoch});bind_observers();ingress.tls_ready();policy_state(epoch)
        if ingress.ingress_identity()!=before:raise RuntimeError('normal hot rotation restarted ingress')
        ingress.tls_call('GET','/healthz',token=old_client['tokens']['alpha'],expected=401,connection=conn,expected_transport=transport)
        if conn.sock is not None:raise RuntimeError('normal old-token 401 must close the held transport')
    finally:conn.close()
    ingress.tls_call('GET','/healthz')
    return request


def unconsumed_prelude(ingress_before):
    guard();produce('rotation2');old_request=secrets.token_hex(16)
    trace_policy('reconfigure',old_request,'rotation-2.json',1,'rotation-proposal')
    if json.loads((ROOT/'gateway-policy.json').read_bytes())['revision']!=1 or ingress.ingress_identity()!=ingress_before:raise RuntimeError('old proposal consumed an epoch or restarted ingress')
    policy_state(1);drained=drain.change('drain',drain.state('open')['control']['committed'])
    wait_pending_expiry(True);remove_source('2');produce('replacement2a');produce('replacement2b')
    return old_request,drained


def draft_arguments(pending,sha):
    if type(pending) is not str or not re.fullmatch('[0-9a-f]{32}',pending) or type(sha) is not str or not re.fullmatch('[0-9a-f]{64}',sha):raise RuntimeError('fixed draft hash and pending ID required')
    return [CLI,'discard-supersession-draft','-expected-revision','1','-pending-request-id',pending,'-draft-sha256',sha]


def draft_receipt(result,pending,sha,removed):
    if type(removed) is not bool or result.returncode or result.stderr or len(result.stdout)>8192:raise RuntimeError('actual distinct draft receipt required')
    value=json.loads(result.stdout)
    expected={'version':1,'revision':1,'pending_request_id':pending,'requested_draft_sha256':sha,'draft_removed':removed,'draft_absent':True,'ingress_stopped':True,'production_ready':False}
    if type(value) is not dict or set(value)!=set(expected) or any(type(value[k]) is not type(v) or value[k]!=v for k,v in expected.items()):raise RuntimeError('exact current absence receipt required, never policy commit or historic hash receipt')
    return value


def draft_call(pending,sha,removed=False,want=0):
    if type(want) is not int or want not in (0,1) or type(removed) is not bool:raise RuntimeError('closed draft outcome required')
    guard();args=draft_arguments(pending,sha)
    if base.sha(CLI)!=json.loads((CONFIG/'programs.json').read_bytes())['install']['sha256']:raise RuntimeError('fresh qualified draft installer required')
    started=time.monotonic()
    try:result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    finally:private_timing('discard-supersession-draft',time.monotonic()-started)
    if want==1:return receipt(result,1,1)
    if type(want) is not int or want!=0:raise RuntimeError('closed actual draft outcome required')
    return draft_receipt(result,pending,sha,removed)


def stopped_ingress_busy(row,execution):
    # The ingress is intentionally stopped. Observe through the AUTHENTICATED
    # fixed controller UDS, still via the real guest API/vsock, not TLS or a host
    # command fallback. Subsequent recovered-ingress/Stop probes still use TLS.
    guard();stopped_original_ingress()
    if type(execution) is not str or not re.fullmatch('[0-9a-f]{32}',execution):raise RuntimeError('same original busy execution required')
    def counter():
        accepted=ingress.UDS_CALL('POST',base.refpath(row)+'/exec',{'generation':row['generation'],'argv':['cat','/workspace/heartbeat'],'timeout_ms':5000},tenant='alpha',expected=202)
        if type(accepted.get('id')) is not str or not re.fullmatch('[0-9a-f]{32}',accepted['id']):raise RuntimeError('actual bounded guest probe required')
        result={}
        def done():
            nonlocal result
            result=ingress.UDS_CALL('GET',base.refpath(row)+'/executions/'+accepted['id'],tenant='alpha')
            return result['status']!='RUNNING'
        wait(done,15)
        if result['status']!='EXITED' or result['output']['exit_code']!=0 or type(result['output']['stdout']) is not str or not result['output']['stdout'].strip().isdecimal():raise RuntimeError('actual guest counter required while ingress stopped')
        return int(result['output']['stdout'].strip())
    before=counter();time.sleep(.2)
    if counter()<=before or ingress.UDS_CALL('GET',base.refpath(row)+'/executions/'+execution,tenant='alpha')['status']!='RUNNING':raise RuntimeError('same writer must progress during stopped ingress')
    stopped_original_ingress()


def draft_case(case,rows,main_before,ingress_before):
    guard()
    if case not in ('draft-discard','draft-discard-cut'):raise RuntimeError('closed draft case required')
    pending,drained=unconsumed_prelude(ingress_before)
    first=secrets.token_hex(16)
    proof=trace_policy('replace-pending-policy',first,'rotation-replacement-2a.json',1,'supersession-draft-short',pending)
    path=ROOT/'.policy-supersession.next'
    if type(proof) is not dict or set(proof)!={'sha256','bytes'} or type(proof['bytes']) is not int or not 64<=proof['bytes']<=160 or path.stat().st_size!=proof['bytes'] or base.sha(path)!=proof['sha256'] or (ROOT/'policy-supersession.json').exists():raise RuntimeError('actual nonempty partial own declaration required')
    remove_source('replacement-2a')
    invariant={p.name:base.sha(p) for p in ROOT.iterdir() if p.name not in ('.lock','.policy-supersession.next')}
    second=secrets.token_hex(16)
    call('replace-pending-policy',2,second,CONFIG/'rotation-replacement-2b.json',1,pending,want=1)
    wrong=('0' if proof['sha256']!='0'*64 else '1')*64
    draft_call(pending,wrong,want=1);draft_call(first,proof['sha256'],want=1)
    if base.sha(path)!=proof['sha256'] or ingress.ingress_identity()!=ingress_before:raise RuntimeError('negative draft paths mutated metadata or stopped ingress')
    policy_state(1);call('verify',1,want=1)
    # Start the original-budget writer AFTER fault creation and negative controls,
    # but BEFORE the actual ingress-only discard under test. No budget increase.
    writer=new_busy_writer(rows[0][0]);drain.busy(rows[0][0],writer['id'])
    if case=='draft-discard':
        draft_call(pending,proof['sha256'],removed=True)
        draft_call(pending,wrong,removed=False)
    else:
        output=CONFIG/'draft-discard-cut-output';started=time.monotonic()
        try:interrupt(draft_arguments(pending,proof['sha256']),str(output),json.loads((CONFIG/'programs.json').read_bytes())['install']['sha256'],base.sha,'supersession-draft-discard',1,pending)
        finally:private_timing('supersession-draft-discard',time.monotonic()-started)
        if output.read_bytes():raise RuntimeError('discard cut must be before any CLI receipt')
        draft_call(pending,proof['sha256'],removed=False)
    stopped_original_ingress();policy_state(1)
    if path.exists() or base.main_identity()!=main_before or {p.name:base.sha(p) for p in ROOT.iterdir() if p.name not in ('.lock','.policy-supersession.next')}!=invariant:raise RuntimeError('discard modified policy/intent/proposal/base or main')
    call('verify',1,want=1);stopped_ingress_busy(rows[0][0],writer['id'])
    call('replace-pending-policy',2,second,CONFIG/'rotation-replacement-2b.json',1,pending)
    save(CONFIG/'active-client.json',{'epoch':2,'variant':'replacement-2b'});bind_observers();ingress.tls_ready();policy_state(2)
    envelope=json.loads((ROOT/'gateway-policy.json').read_bytes())
    if envelope.get('request_id')!=second or envelope.get('replaced_pending_request_id')!=pending or (ROOT/'policy-supersession.json').exists() or (ROOT/'rotation-intent.json').exists():raise RuntimeError('only new replacement may consume unconsumed epoch2')
    remove_source('replacement-2b');before=ingress.ingress_identity();call('reconcile',2,second)
    if ingress.ingress_identity()!=before:raise RuntimeError('source-free replacement receipt restarted ingress')
    request=ordinary_hot_step(3)
    return request,pending,drained,writer


def new_case(case,rows,main_before,ingress_before):
    guard()
    if case in ('draft-discard','draft-discard-cut'):return draft_case(case,rows,main_before,ingress_before)
    if case=='hot-rotation':
        drained=drain.change('drain',drain.state('open')['control']['committed'])
        writer=new_busy_writer(rows[0][0]);drain.busy(rows[0][0],writer['id'])
        old_request=ordinary_hot_step(2);request=ordinary_hot_step(3)
        return request,old_request,drained,writer
    if case not in ('supersession-repeat','supersession-visible-recovery'):raise RuntimeError('fixed new managed case required')
    old_request,drained=unconsumed_prelude(ingress_before)
    writer=new_busy_writer(rows[0][0]);drain.busy(rows[0][0],writer['id'])
    if case=='supersession-repeat':
        first=secrets.token_hex(16)
        trace_policy('replace-pending-policy',first,'rotation-replacement-2a.json',1,'supersession-proposal',old_request)
        lose_a_proposal(first,main_before);policy_state(1)
        call('reconfigure',2,old_request,CONFIG/'rotation-2.json',1,want=1);policy_state(1)
        second=secrets.token_hex(16)
        call('replace-pending-policy',2,second,CONFIG/'rotation-replacement-2b.json',1,first)
        save(CONFIG/'active-client.json',{'epoch':2,'variant':'replacement-2b'});bind_observers();ingress.tls_ready();policy_state(2)
        envelope=json.loads((ROOT/'gateway-policy.json').read_bytes())
        if envelope.get('request_id')!=second or envelope.get('replaced_pending_request_id')!=first or (ROOT/'policy-supersession.json').exists() or (ROOT/'rotation-intent.json').exists():raise RuntimeError('exact B2 child ACK/receipt required, never ACK A')
        remove_source('replacement-2b');before=ingress.ingress_identity();call('reconcile',2,second)
        if ingress.ingress_identity()!=before:raise RuntimeError('exact source-free B2 retry restarted ingress')
        request=ordinary_hot_step(3)
    else:
        second=secrets.token_hex(16)
        trace_policy('replace-pending-policy',second,'rotation-replacement-2b.json',1,'supersession-visible',old_request)
        stopped_original_ingress();policy_state(1)
        if json.loads((ROOT/'gateway-policy.json').read_bytes())['revision']!=2:raise RuntimeError('actual published file2 required')
        call('replace-pending-policy',2,secrets.token_hex(16),CONFIG/'rotation-replacement-2a.json',1,second,want=1);policy_state(1)
        remove_source('replacement-2b');produce('rotation3');request=secrets.token_hex(16)
        call('recover-policy',3,request,CONFIG/'rotation-3.json',2,second)
        save(CONFIG/'active-client.json',{'epoch':3});bind_observers();ingress.tls_ready();policy_state(3)
    return request,old_request,drained,writer


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
    case=maintenance_case()
    if case in ('populated-gate','active-stop'):
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
        PHASE='managed-'+case
        if case=='populated-gate':populated_negative_then_recover(request,old_request,main_before)
        else:active_stop_recover(request,old_request,ingress_before)
    else:
        PHASE='managed-'+case;request,old_request,drained,writer=new_case(case,rows,main_before,ingress_before)
    PHASE='managed-continuity'
    if case=='hot-rotation':
        if ingress.ingress_identity()!=ingress_before:raise RuntimeError('ordinary hot rotation replaced ingress')
    elif ingress.ingress_identity()==ingress_before or identity(ingress_before[0])==ingress_before[1] or identity(ingress_before[2])==ingress_before[3]:raise RuntimeError('actual old ingress incarnations remain')
    if base.main_identity()!=main_before or [vmm_identity(r) for r,_ in rows]!=vm_before:raise RuntimeError('main/VMM restarted during ingress maintenance')
    if [base.verify_vm(r,t) for r,t in rows]!=boots:raise RuntimeError('guest boot changed during maintenance')
    drain.state('drained',drained);drain.busy(rows[0][0],writer['id'])
    if case not in ('populated-gate','active-stop'):late_observation('after-continuity',rows[0][0],writer)
    if {n:base.sha(ROOT/n) for n in immutable}!=immutable:raise RuntimeError('base/backend/auth changed during recovery')
    old_key_rejection()
    PHASE='managed-source-free-reconcile';p=CONFIG/'sources/snapshot-3.json';pin=json.loads((CONFIG/'rotation-3.json').read_bytes())['policy']
    if str(p)!=pin['path'] or base.sha(p)!=pin['sha256']:raise RuntimeError('only exact private new source can be removed')
    p.unlink();before=ingress.ingress_identity();call('reconcile',3,request)
    call('recover-policy',3,secrets.token_hex(16),CONFIG/'rotation-3.json',2,old_request,want=1)
    if case not in ('populated-gate','active-stop'):late_observation('after-sourcefree-cas',rows[0][0],writer)
    if ingress.ingress_identity()!=before or base.main_identity()!=main_before:raise RuntimeError('receipt retry/conflict restarted service')
    # Resume is an explicit root CAS AFTER the preserved-drain proof, never an
    # effect of maintenance. Capacity must not be confused with NODE_DRAINING.
    drain.change('resume',drain.state('drained',drained)['control']['committed']);drain.health('open')
    if case not in ('populated-gate','active-stop'):late_observation('before-stop',rows[0][0],writer)
    if case not in ('populated-gate','active-stop'):
        if base.main_identity()!=main_before or [vmm_identity(r) for r,_ in rows]!=vm_before:raise RuntimeError('main/four VMM incarnations changed before busy Stop')
        drain.busy(rows[0][0],writer['id'])
    PHASE='managed-stop-reclaim';ms=install.stop_destroy(rows[0][0],'alpha',True)
    for r,t in rows[1:]:install.stop_destroy(r,t)
    PHASE='managed-warm-drain';warm=drain.warm(lambda:restart_after_explicit_warm_stop(request))
    fresh=base.create('alpha','managed-before-cold');boot=base.verify_vm(fresh,'alpha')
    if boot in boots:raise RuntimeError('reused old guest boot')
    base.execute(fresh,['test','!','-e','/workspace/heartbeat'],'alpha');running=base.progressing_writer(fresh,'alpha')
    save(ingress.CHECKPOINT,{'row':fresh,'guest_boot':boot,'owner':base.owner(fresh),'writer_execution_id':running['id']})
    sealed=drain.seal_cold();sources_absent();call('status',3)
    save(CHECKPOINT,{'boot_id':read('/proc/sys/kernel/random/boot_id'),'machine_id':read('/etc/machine-id'),'files':{p.name:base.sha(p) for p in ROOT.iterdir() if p.name!='.lock'},'request':request,'maintenance_case':case})
    return {'maintenance_case':case,**{k:True for k in checkpoint_flags(case) if k not in drain.CHECKPOINT_FLAGS},**warm,**sealed,'stop_observed_ms':ms[0],'durable_reclaim_observed_ms':ms[1]}


def recover():
    old=json.loads(CHECKPOINT.read_bytes());probe()
    if old['maintenance_case']!=maintenance_case():raise RuntimeError('original case must persist across cold')
    if old['boot_id']==read('/proc/sys/kernel/random/boot_id') or old['machine_id']!=read('/etc/machine-id'):raise RuntimeError('actual original disk cold boot required')
    if {p.name:base.sha(p) for p in ROOT.iterdir() if p.name!='.lock'}!=old['files']:raise RuntimeError('installed managed files changed across cold')
    restored=drain.restore_and_resume();base.call('POST','/v1/sandboxes',base.create_spec(),key='managed-before-cold',expected=410)
    for project in range(1300000,1300004):
        q=base.quota(project)
        if any(getattr(q,n) for n in ('bhard','bsoft','space','ihard','isoft','inodes','btime','itime')):raise RuntimeError('kernel project not released')
    if any(p.is_dir() for p in (base.UNIT_ROOT/'node/instances').iterdir()) or list((base.RUNTIME/'j/firecracker').iterdir()):raise RuntimeError('private generation remains')
    call('reconcile',3,old['request']);sources_absent();call('status',3);run('systemctl','stop',base.UNIT)
    wait(lambda:not base.UNIT_ROOT.exists() and not ingress.GROUP.exists() and not Path('/run/xandbox-inputs').exists() and not ingress.tcp()[1],25)
    return {'maintenance_case':maintenance_case(),**{k:True for k in RECOVERY_FLAGS if k not in drain.RECOVERY_FLAGS},**restored}


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
