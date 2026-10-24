"""TEST ONLY durable drain checks inside the marked readiness L1.

Only the existing same-root-UID operator CLI changes admission. All guest tasks
still cross the ordinary TLS API into a real KVM; no host task execution path.
"""
import json
from pathlib import Path
import re
import secrets
import subprocess
import time
import systemd_ingress_guest as ingress
from systemd_delegate_probe import read,run,save,wait
base=ingress.base
MARKER='Xandbox owned systemd drain extension v1'
CHECKPOINT=base.CONFIG/'drain-checkpoint.json'
CHECKPOINT_FLAGS=('real_existing_session_and_writer_continue_while_drained','raw_session_switch_denied_without_metadata_growth','drain_exact_retry_and_bad_cas_and_tenant_admin_refused','drained_stop_gc_and_quota_release','warm_auto_restart_preserved_entire_drain_commit','explicit_warm_root_resume_and_denied_keys_reusable','cold_checkpoint_same_busy_execution_continues_drained','durable_drain_checkpoint_fsynced','managed_raw_exec_refused_and_versioned_session_exec_used')
RECOVERY_FLAGS=('cold_automatic_health_up_admission_remains_drained','cold_original_epoch_revision_request_preserved','old_guest_recovered_and_quota_zero_while_drained','cold_stale_cas_and_tenant_admin_refused','explicit_cold_root_resume_one_revision_exact_retry','cold_denied_raw_session_keys_reused_real_pristine_guests')


def guard():
    ingress.guard()
    if read('/etc/xandbox-systemd-drain-fixture')!=MARKER:raise RuntimeError('owned drain extension L1 marker required')


def parse_reply(value):
    if type(value) is not dict or set(value)!={'control','resource_observation'}:raise RuntimeError('fixed operator reply required')
    c=value['control']
    if type(c) is not dict or set(c)!={'version','committed','phase','desired_mode','admission_open','pending_session_reservations'} or type(c['version']) is not int or c['version']!=1 or c['phase']!='ready' or type(c['admission_open']) is not bool or type(c['pending_session_reservations']) is not int or c['pending_session_reservations']!=0:raise RuntimeError('quiescent committed control view required')
    s=c['committed']
    if type(s) is not dict or set(s)!={'version','epoch','revision','mode','last_request_id','last_expected_revision'} or type(s['version']) is not int or s['version']!=1 or type(s['epoch']) is not str or not re.fullmatch('[0-9a-f]{32}',s['epoch']) or type(s['revision']) is not int or not 1<=s['revision']<(1<<64) or s['mode'] not in ('open','drained') or c['desired_mode']!=s['mode'] or c['admission_open'] is not (s['mode']=='open'):raise RuntimeError('exact durable control state required')
    if s['revision']==(1<<64)-1 and s['mode']!='drained':raise RuntimeError('exhausted authority must stay drained')
    if type(s['last_expected_revision']) is not int or type(s['last_request_id']) is not str:raise RuntimeError('fixed last operator request required')
    if s['revision']==1:
        if s['last_expected_revision']!=0 or s['last_request_id']!='':raise RuntimeError('initial authority mismatch')
    elif s['last_expected_revision']!=s['revision']-1 or not re.fullmatch('[0-9a-f]{32}',s['last_request_id']):raise RuntimeError('last CAS identity mismatch')
    stats=value['resource_observation']
    if type(stats) is not dict or stats.get('backend')!='firecracker' or type(stats.get('records')) is not int or stats['records']<0:raise RuntimeError('actual Firecracker resource observation required')
    return value


def control(operation,before=None,request=None,want=0):
    guard()
    if operation not in ('status','drain','resume') or type(want) is not int or want not in (0,1):raise RuntimeError('fixed operator command required')
    a=json.loads((base.CONFIG/'assets.json').read_bytes())['node']
    if a['path']!='/srv/assets/node' or base.sha(a['path'])!=a['sha256']:raise RuntimeError('pinned ordinary node CLI required')
    args=[a['path'],'-state-dir',str(base.STATE)]
    if operation=='status':
        if before is not None or request is not None:raise RuntimeError('read-only status accepts no CAS')
    else:
        if type(before) is not dict or type(before.get('revision')) is not int or not 1<=before['revision']<(1<<64) or type(before.get('epoch')) is not str or not re.fullmatch('[0-9a-f]{32}',before['epoch']) or type(request) is not str or not re.fullmatch('[0-9a-f]{32}',request):raise RuntimeError('fixed private CAS required')
        args+=['-epoch',before['epoch'],'-revision',str(before['revision']),'-request-id',request]
    result=subprocess.run(args+[operation],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    if result.returncode!=want or len(result.stdout)>8192 or len(result.stderr)>4096:raise RuntimeError('fixed operator outcome mismatch')
    if want==1 and (result.stdout or not result.stderr.splitlines() or result.stderr.splitlines()[-1]!=b'operator HTTP409: CONFLICT'):raise RuntimeError('actual stale CAS conflict required, not another CLI error')
    return parse_reply(json.loads(result.stdout)) if want==0 else None


def state(mode=None,expected=None):
    value=control('status')
    s=value['control']['committed']
    if mode is not None and s['mode']!=mode:raise RuntimeError('operator mode mismatch')
    if expected is not None and s!=expected:raise RuntimeError('entire committed authority changed unexpectedly')
    return value


def change(operation,before):
    request=secrets.token_hex(16);value=control(operation,before,request)
    s=value['control']['committed'];mode='drained' if operation=='drain' else 'open'
    if s['epoch']!=before['epoch'] or s['revision']!=before['revision']+1 or s['mode']!=mode or s['last_request_id']!=request or s['last_expected_revision']!=before['revision']:raise RuntimeError('actual acknowledged CAS required')
    if control(operation,before,request)['control']['committed']!=s:raise RuntimeError('exact operator retry changed revision')
    return s


def no_stale_resume(committed):
    if committed['mode']!='drained' or committed['revision']<=1:raise RuntimeError('real committed drain required')
    stale={**committed,'revision':committed['revision']-1}
    control('resume',stale,secrets.token_hex(16),want=1)
    state('drained',committed)


def sessions_inventory():
    result={}
    for p in (base.STATE/'sessions').iterdir():
        if p.is_symlink() or not p.is_file():raise RuntimeError('regular private session inventory required')
        result[p.name]=base.sha(p)
    return result


def health(mode):
    value=ingress.tls_call('GET','/healthz')
    if value.get('backend')!='firecracker' or value.get('isolation') is not True or value.get('authentication') is not True or value.get('admission_open') is not (mode=='open'):raise RuntimeError('actual authenticated health and admission required')
    value=ingress.tls_call('GET','/readyz',expected=200 if mode=='open' else 503)
    if value!={'admission_open':mode=='open'}:raise RuntimeError('health and admission readiness must be distinct')


def denials(label,session=None):
    before=state('drained');committed=before['control']['committed'];inventory=sessions_inventory()
    health('drained')
    for tenant in ('alpha','beta'):
        for route,body,kind in (('/v1/sandboxes',base.create_spec(),'raw'),('/v1/sessions',base.create_spec(),'session')):
            value=ingress.tls_call('POST',route,body,tenant=tenant,key=label+'-'+kind+'-'+tenant,expected=503)
            if value.get('error',{}).get('code')!='NODE_DRAINING':raise RuntimeError('drain refusal must not be capacity or another 503')
    if session is not None:
        value=ingress.tls_call('POST','/v1/sessions/'+session['id']+'/switch',{'expected_revision':session['revision'],'create':base.create_spec()},key=label+'-switch',expected=503)
        if value.get('error',{}).get('code')!='NODE_DRAINING':raise RuntimeError('actual session switch drain refusal required')
    value=ingress.tls_call('POST','/v1/node/resume',{},expected=400)
    if value.get('error',{}).get('code')!='INVALID_REQUEST':raise RuntimeError('tenant credential reached operator API')
    after=state('drained',committed)
    if after['resource_observation']['records']!=before['resource_observation']['records'] or sessions_inventory()!=inventory:raise RuntimeError('refused admission consumed metadata or changed history')


def busy(row,execution,session=None):
    if type(execution) is not str or not re.fullmatch('[0-9a-f]{32}',execution):raise RuntimeError('original busy execution identity required')
    def counter():
        text=(base.execute(row,['cat','/workspace/heartbeat'],'alpha') if session is None else execute_session(session,row,['cat','/workspace/heartbeat'])).strip()
        if not text.isdecimal():raise RuntimeError('actual guest counter required')
        return int(text)
    before=counter();time.sleep(.2)
    if counter()<=before or ingress.tls_call('GET',base.refpath(row)+'/executions/'+execution)['status']!='RUNNING':raise RuntimeError('same existing writer must continue while drained')


def open_session(key):
    value=ingress.tls_call('POST','/v1/sessions',base.create_spec(),key=key,expected=201)
    if type(value.get('id')) is not str or not re.fullmatch('[0-9a-f]{32}',value['id']) or type(value.get('revision')) is not int or value['revision']!=1:raise RuntimeError('new actual session binding required')
    row=ingress.tls_call('GET','/v1/sandboxes/'+value['current']['id'])
    if {'id':row['id'],'generation':row['generation']}!=value['current']:raise RuntimeError('actual session target mismatch')
    return value,row


def session_job(session,row,argv,timeout_ms=5000,tenant='alpha'):
    value=ingress.tls_call('POST','/v1/sessions/'+session['id']+'/exec',{'revision':session['revision'],'argv':argv,'timeout_ms':timeout_ms},tenant=tenant,expected=202)
    if value.get('sandbox')!={'id':row['id'],'generation':row['generation']} or value.get('revision')!=session['revision'] or type(value.get('job')) is not dict or type(value['job'].get('id')) is not str or not re.fullmatch('[0-9a-f]{32}',value['job']['id']):raise RuntimeError('exact versioned session execution required')
    return value['job']


def execute_session(session,row,argv,tenant='alpha'):
    job=session_job(session,row,argv,tenant=tenant);result={}
    def done():
        nonlocal result
        result=ingress.tls_call('GET',base.refpath(row)+'/executions/'+job['id'],tenant=tenant);return result['status']!='RUNNING'
    wait(done,15)
    if result['status']!='EXITED' or result['output']['exit_code']!=0:raise RuntimeError('real versioned session command failed')
    return result['output']['stdout']


def verify_session_vm(session,row):
    # Rejection is required before AND after live guest proof, not a retryable
    # startup state and never permission to route around the session capability.
    def raw_refused():
        value=ingress.tls_call('POST',base.refpath(row)+'/exec',{'generation':row['generation'],'argv':['echo','forbidden-raw-managed-route'],'timeout_ms':5000},expected=409)
        if value.get('error',{}).get('code')!='NOT_READY':raise RuntimeError('plain managed execution bypass was not refused')
    raw_refused()
    boot=base.verify_vm(row,'alpha',guest_exec=lambda ref,argv,tenant:execute_session(session,ref,argv,tenant))
    raw_refused();return boot


def session_writer(session,row):
    argv=['sh','-c','i=0; while :; do i=$((i+1)); printf "%s\\n" "$i" > /workspace/heartbeat.next; mv /workspace/heartbeat.next /workspace/heartbeat; sleep 0.05; done']
    job=session_job(session,row,argv,timeout_ms=45000)
    def started():
        text=execute_session(session,row,['sh','-c','test ! -f /workspace/heartbeat || cat /workspace/heartbeat']).strip()
        return text.isdecimal() and int(text)>0
    wait(started,10);busy(row,job['id'],session)
    return job


def destroy(row,session=None):
    owner=base.owner(row)
    stopped=ingress.tls_call('POST',base.refpath(row)+'/stop',{'generation':row['generation']})
    if stopped['state']!='STOPPED':raise RuntimeError('drained physical stop required')
    group=base.UNIT_ROOT/'node/instances'/base.key(row)
    if group.exists() and 'populated 0' not in read(group/'cgroup.events'):raise RuntimeError('stopped drained execution still populated')
    ingress.tls_call('DELETE',base.refpath(row),{'generation':row['generation']},expected=202);base.reclaimed(row,'alpha',owner['project_id'])
    if session is not None:
        value=ingress.tls_call('POST','/v1/sessions/'+session['id']+'/revoke',{'expected_revision':session['revision']})
        if value.get('admission_revoked') is not True or value.get('durable') is not False:raise RuntimeError('session revoke is not a durable GC acknowledgment')


def warm(restart):
    guard();before=state('open')['control']['committed']
    session,row=open_session('drain-warm-session');old_boot=verify_session_vm(session,row)
    execute_session(session,row,['sh','-c','printf warm-drain > /workspace/drain-warm-marker; sync'])
    writer=session_writer(session,row)
    drained=change('drain',before);denials('drain-warm-initial',session);busy(row,writer['id'],session);no_stale_resume(drained)
    # Session execution is independently allowed on the existing binding.
    if execute_session(session,row,['echo','session-continues'])!='session-continues\n':raise RuntimeError('existing real session execution failed during drain')
    destroy(row,session);state('drained',drained)
    old_main=base.main_identity();old_gateway=ingress.ingress_identity();run('systemctl','stop',base.UNIT)
    wait(lambda:not base.UNIT_ROOT.exists() and not Path('/run/xandbox-inputs').exists() and not ingress.GROUP.exists() and not ingress.tcp()[1],25)
    restart()
    if base.main_identity()==old_main or ingress.ingress_identity()==old_gateway:raise RuntimeError('fresh actual service incarnations required')
    state('drained',drained);denials('drain-warm-restarted');no_stale_resume(drained)
    opened=change('resume',state('drained',drained)['control']['committed']);health('open')
    fresh=base.create('alpha','drain-warm-restarted-raw-alpha');boot=base.verify_vm(fresh,'alpha')
    if boot==old_boot:raise RuntimeError('drain restart reused old guest')
    base.execute(fresh,['test','!','-e','/workspace/drain-warm-marker'],'alpha');destroy(fresh);state('open',opened)
    return {k:True for k in (*CHECKPOINT_FLAGS[:6],CHECKPOINT_FLAGS[8])}


def seal_cold():
    guard()
    if CHECKPOINT.exists():raise RuntimeError('new durable drain checkpoint required')
    guest=json.loads(ingress.CHECKPOINT.read_bytes());drained=change('drain',state('open')['control']['committed'])
    denials('drain-cold');busy(guest['row'],guest['writer_execution_id']);state('drained',drained)
    save(CHECKPOINT,{'committed':drained})
    return {k:True for k in CHECKPOINT_FLAGS[6:8]}


def probe_mode():
    guard()
    if CHECKPOINT.exists():
        committed=json.loads(CHECKPOINT.read_bytes())['committed'];state('drained',committed);health('drained')
    else:state('open');health('open')


def restore_and_resume():
    guard();old=json.loads(CHECKPOINT.read_bytes());committed=old['committed']
    state('drained',committed);denials('drain-cold-restarted');no_stale_resume(committed)
    guest=json.loads(ingress.CHECKPOINT.read_bytes());base.reclaimed(guest['row'],'alpha',guest['owner']['project_id']);state('drained',committed)
    opened=change('resume',state('drained',committed)['control']['committed']);health('open')
    fresh=base.create('alpha','drain-cold-restarted-raw-alpha');boot=base.verify_vm(fresh,'alpha')
    if boot==guest['guest_boot']:raise RuntimeError('old assigned guest boot revived')
    base.execute(fresh,['test','!','-e','/workspace/cold-marker'],'alpha');destroy(fresh)
    session,row=open_session('drain-cold-restarted-session-alpha');boot2=verify_session_vm(session,row)
    if boot2 in (boot,guest['guest_boot']):raise RuntimeError('fresh session guest required')
    execute_session(session,row,['test','!','-e','/workspace/cold-marker']);destroy(row,session);state('open',opened)
    return {k:True for k in RECOVERY_FLAGS}
