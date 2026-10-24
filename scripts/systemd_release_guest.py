"""TEST ONLY ordinary root release CLI inside a marked, real readiness/KVM L1.

The publisher only copies data. Tenant tasks ALWAYS use the original TLS/KVM API.
No production fault hook, host task execution or synthetic tiny artifact bundle.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import termios
import time
import systemd_readiness_guest as ready
import systemd_drain_probe as drain
from systemd_delegate_probe import read,run,save,wait
base=ready.base;ingress=ready.ingress
ROOT=Path('/srv/xandbox-releases');CONFIG=Path('/etc/xandbox-release');INCOMING=Path('/srv/xandbox-release-incoming');PARKED=Path('/srv/xandbox-release-parked');CHECKPOINT=CONFIG/'checkpoint.json'
ROLES=('daemon','firecracker','gateway','ingress','initrd','jailer','kernel','launcher','node','ready','template','warden','workspace')
CLI='/usr/libexec/xandbox-release'
NATIVE_SOURCES=('9e4da26d1ec4bda9b678966e88c7adb0b3133965','0a51f39893fd8d317c4905a603294d6028f92dcf')
ERROR=b'xandbox-release: publication unconfirmed; preserve inputs and retry the identical request\n'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','GOMAXPROCS':'2'}
PROBE_FLAGS=('publisher_actual_pin_and_thirteen_real_asset_roles_checked','publication_is_not_node_install_activation_or_admission_authority')
CHECKPOINT_FLAGS=('nonroot_cli_and_symlink_hardlink_writable_sources_refused','two_real_bundles_four_process_cas_each_one_winner','ordinary_cli_exact_retry_without_asset_sources_and_rebound_refusal','unknown_and_missing_bundle_refused_without_adoption_or_deletion','two_retained_capacity_refused_without_metadata_growth','same_services_same_guest_writer_and_full_admission_commit_unchanged','all_thirteen_role_bytes_modes_and_private_reference_checked','publication_reference_and_missing_source_checkpoint_fsynced')
RECOVERY_FLAGS=('original_disk_both_retained_bundles_and_full_reference_preserved','ordinary_root_cli_exact_retry_no_sources_after_cold','publication_status_did_not_resume_drained_node','not_install_upgrade_backup_or_production_cli_syscall_crash_proof')


def guard():
    ready.guard()
    if read('/etc/xandbox-systemd-release-fixture')!='Xandbox owned ordinary release publication fixture v1':raise RuntimeError('dedicated owned publication L1 required')


def encoded(v):return (json.dumps(v,separators=(',',':'),ensure_ascii=True)+'\n').encode()


def assets():
    guard();value=json.loads((CONFIG/'assets.json').read_bytes())
    if set(value)!=set(ROLES)|{'release'} or value['release']['path']!=CLI:raise RuntimeError('fixed ordinary publisher inventory required')
    for name,a in value.items():
        if set(a)!={'path','sha256'} or not re.fullmatch('[0-9a-f]{64}',a['sha256']) or base.sha(a['path'])!=a['sha256']:raise RuntimeError('actual publication source hash mismatch')
        if not Path(a['path']).is_absolute() or Path(a['path']).is_symlink() or not stat.S_ISREG(Path(a['path']).stat().st_mode):raise RuntimeError('real regular publication source required')
    return value


def parse_result(r,want,revision=None,retained=None):
    if r.returncode!=want or len(r.stdout)>1024 or len(r.stderr)>1024:raise RuntimeError('fixed ordinary publisher outcome required')
    if want==1:
        if r.stdout or r.stderr!=ERROR:raise RuntimeError('actual closed publisher refusal required, not launch/runtime failure')
        return None
    if r.stderr:raise RuntimeError('ordinary publisher emitted unexpected stderr')
    v=json.loads(r.stdout)
    if type(v) is not dict or set(v)!={'version','revision','retained','publication_durable','services_changed','production_ready'} or type(v['version']) is not int or v['version']!=1 or type(v['revision']) is not int or type(v['retained']) is not int or type(v['publication_durable']) is not bool or v['services_changed'] is not False or v['production_ready'] is not False:raise RuntimeError('closed typed publication reply required')
    if revision is not None and v['revision']!=revision or retained is not None and v['retained']!=retained or v['publication_durable'] is not (v['revision']>0):raise RuntimeError('actual publication revision mismatch')
    return v


def arguments(manifest=None,expected=None,request=None):
    if manifest is None:
        if expected is not None or request is not None:raise RuntimeError('status has no mutation input')
        return [CLI,'status']
    if manifest.parent!=CONFIG or not re.fullmatch(r'[a-z0-9-]+\.json',manifest.name) or type(expected) is not int or not 0<=expected<2**64-1 or type(request) is not str or not re.fullmatch('[0-9a-f]{32}',request):raise RuntimeError('fixed private publication request required')
    return [CLI,'publish','-manifest',str(manifest),'-expected-revision',str(expected),'-request-id',request]


def call(manifest=None,expected=None,request=None,want=0,revision=None,retained=None,nonroot=False):
    assets()
    def drop():
        os.setgroups([]);os.setgid(65534);os.setuid(65534)
        if ctypes.CDLL(None,use_errno=True).prctl(38,1,0,0,0)!=0:raise RuntimeError('no privilege gain required')
    if nonroot:
        paths=(Path('/'),Path('/usr'),Path('/usr/libexec'),Path(CLI))
        context=[]
        for p in paths:
            s=p.lstat();context.append({'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid})
            if s.st_uid!=0 or s.st_mode&0o0022 or not s.st_mode&stat.S_IXOTH or p!=Path(CLI) and not stat.S_ISDIR(s.st_mode) or p==Path(CLI) and not stat.S_ISREG(s.st_mode):raise RuntimeError('fixed publisher executable ancestry must actually allow nonroot entry')
        save(CONFIG/'nonroot-exec-context.json',{'prefix':context,'selected_uid':65534,'selected_gid':65534,'not_cli_uid_guard_success':True})
    r=subprocess.run(arguments(manifest,expected,request),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90,env=ENV,preexec_fn=drop if nonroot else None)
    return parse_result(r,want,revision,retained)


def private_stat(p,mode,directory=False):
    s=p.lstat()
    if s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=mode or (not stat.S_ISDIR(s.st_mode) if directory else not stat.S_ISREG(s.st_mode) or s.st_nlink!=1):raise RuntimeError('actual root private publication object required')
    return s


def sync_dir(p):
    fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def rename_sync(source,target):
    source.rename(target);sync_dir(source.parent)
    if target.parent!=source.parent:sync_dir(target.parent)


def manifest(source):
    a=assets();files=[]
    for role in ROLES:
        p=INCOMING/role;files.append({'role':role,'source':str(p),'sha256':a[role]['sha256'],'bytes':Path(a[role]['path']).stat().st_size})
    return {'version':1,'source_revision':source,'toolchain':'go1.27.3','goarch':'amd64','files':files}


def description(m):return {'version':1,'source_revision':m['source_revision'],'toolchain':m['toolchain'],'goarch':m['goarch'],'files':[{k:v[k] for k in ('role','sha256','bytes')} for v in m['files']]}


def store(expected):
    private_stat(ROOT,0o700,True)
    if {p.name for p in ROOT.iterdir()}!={'.lock','objects','ref.json'}:raise RuntimeError('complete closed committed store required')
    for p in (ROOT/'.lock',ROOT/'ref.json'):private_stat(p,0o600)
    private_stat(ROOT/'objects',0o700,True)
    ref=json.loads((ROOT/'ref.json').read_bytes())
    if set(ref)!={'version','revision','release','previous','request_id','expected_revision','intent_sha256'} or type(ref['revision']) is not int or type(ref['version']) is not int or ref['version']!=1 or ref['revision']!=expected or type(ref['expected_revision']) is not int or ref['expected_revision']!=expected-1 or not re.fullmatch('[0-9a-f]{64}',ref['intent_sha256']) or expected==1 and ref['previous']!='' or not re.fullmatch('[0-9a-f]{32}',ref['request_id']):raise RuntimeError('actual complete committed publication reference required')
    ids={ref['release'],ref['previous']} if expected==2 else {ref['release']}
    if not all(type(i) is str and re.fullmatch('[0-9a-f]{64}',i) for i in ids) or len(ids)!=expected or {p.name for p in (ROOT/'objects').iterdir()}!=ids:raise RuntimeError('exact retained publication inventory required')
    bindings={};a=assets()
    for id in ids:
        directory=ROOT/'objects'/id;private_stat(directory,0o700,True)
        if {p.name for p in directory.iterdir()}!=set(ROLES)|{'manifest.json'}:raise RuntimeError('exact thirteen sealed roles required')
        p=directory/'manifest.json';private_stat(p,0o400);raw=p.read_bytes();d=json.loads(raw)
        if hashlib.sha256(raw).hexdigest()!=id or d!=description(manifest(d['source_revision'])) or raw!=encoded(d) or d['source_revision'] not in NATIVE_SOURCES:raise RuntimeError('pinned real bundle descriptor required')
        bindings[id]=d['source_revision']
        for role in ROLES:
            p=directory/role;private_stat(p,0o400 if role in ('kernel','initrd','workspace') else 0o500)
            if p.stat().st_size!=Path(a[role]['path']).stat().st_size or base.sha(p)!=a[role]['sha256']:raise RuntimeError('actual sealed artifact bytes mismatch')
    return {'reference':ref,'reference_sha256':base.sha(ROOT/'ref.json'),'bindings':bindings}


def stable_empty():
    if {p.name for p in ROOT.iterdir()}!={'.lock','objects'} or list((ROOT/'objects').iterdir()):raise RuntimeError('refused input produced authority or artifact metadata')
    call(revision=0,retained=0)


def source_negatives(m):
    p=CONFIG/'publish-first.json';save(p,m);request=secrets.token_hex(16)
    call(p,0,request,want=1,nonroot=True)
    if ROOT.exists():raise RuntimeError('nonroot publisher touched fixed root')
    original=INCOMING/'daemon';backup=INCOMING/'daemon-backup';rename_sync(original,backup);original.symlink_to(backup)
    try:call(p,0,request,want=1);stable_empty()
    finally:original.unlink();rename_sync(backup,original)
    alias=INCOMING/'daemon-alias';os.link(original,alias)
    try:call(p,0,request,want=1);stable_empty()
    finally:alias.unlink()
    before=INCOMING.stat().st_mode&0o777;INCOMING.chmod(0o777)
    try:call(p,0,request,want=1);stable_empty()
    finally:INCOMING.chmod(before)


def race(p,expected):
    requests=[secrets.token_hex(16) for _ in range(4)];processes=[]
    try:
        assets()
        for request in requests:processes.append(subprocess.Popen(arguments(p,expected,request),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV))
        winners=[]
        for request,proc in zip(requests,processes):
            out,err=proc.communicate(timeout=90);r=subprocess.CompletedProcess([],proc.returncode,out,err)
            if proc.returncode==0:parse_result(r,0,expected+1,expected+1);winners.append(request)
            else:parse_result(r,1)
        if len(winners)!=1:raise RuntimeError('four actual concurrent publisher processes require exactly one CAS winner')
        ref=store(expected+1)['reference']
        if ref['request_id']!=winners[0]:raise RuntimeError('actual CAS winner reference required')
        return winners[0]
    finally:
        for proc in processes:
            if proc.poll() is None:proc.kill()
            proc.wait(timeout=10)


def unknown_controls(p,request):
    before=store(1);unknown=ROOT/'foreign-fixture';unknown.write_bytes(b'Xandbox release unknown inventory negative\n');unknown.chmod(0o600);identity=(unknown.stat().st_dev,unknown.stat().st_ino)
    try:
        call(want=1);call(p,0,request,want=1)
        if not unknown.is_file() or (unknown.stat().st_dev,unknown.stat().st_ino)!=identity or unknown.read_bytes()!=b'Xandbox release unknown inventory negative\n':raise RuntimeError('publisher adopted or removed unknown inventory')
    finally:
        if unknown.is_file() and (unknown.stat().st_dev,unknown.stat().st_ino)==identity:unknown.unlink()
    if store(1)!=before:raise RuntimeError('unknown refusal changed publication')
    bundle=ROOT/'objects'/before['reference']['release'];quarantine=Path('/srv/xandbox-release-missing-bundle-negative')
    if quarantine.exists():raise RuntimeError('new fixture quarantine required')
    identity=(bundle.stat().st_dev,bundle.stat().st_ino);rename_sync(bundle,quarantine)
    try:
        call(want=1);call(p,0,request,want=1)
        if (quarantine.stat().st_dev,quarantine.stat().st_ino)!=identity or bundle.exists():raise RuntimeError('publisher adopted or recreated missing retained bundle')
    finally:
        if quarantine.exists() and (quarantine.stat().st_dev,quarantine.stat().st_ino)==identity:rename_sync(quarantine,bundle)
    if store(1)!=before:raise RuntimeError('missing bundle refusal changed authority')


def publication_writer(row):
    # Use the existing guest protocol's declared60s maximum for this larger
    # asset-copy exercise, without changing the legacy45s helper or any limit.
    argv=['sh','-c','i=0; while :; do i=$((i+1)); printf "%s\\n" "$i" > /workspace/heartbeat.next; mv /workspace/heartbeat.next /workspace/heartbeat; sleep 0.05; done']
    job=base.job(row,argv,'alpha',60000)
    def started():
        text=base.execute(row,['sh','-c','test ! -f /workspace/heartbeat || cat /workspace/heartbeat'],'alpha').strip()
        return text.isdecimal() and int(text)>0
    wait(started,10);drain.busy(row,job['id']);return job


def milestone(stage,row,execution,started):
    # Private, closed lifecycle evidence only; no task output, argv or identity.
    guard()
    view={'stage':stage,'elapsed_ms':int((time.monotonic()-started)*1000),'sandbox_state':'UNAVAILABLE','execution_status':'UNAVAILABLE'}
    try:
        state=ingress.tls_call('GET',base.refpath(row)).get('state')
        status=ingress.tls_call('GET',base.refpath(row)+'/executions/'+execution).get('status')
        allowed={'PREPARING','READY','RUNNING','STOPPING','STOPPED','RECLAIMING','DESTROYED','EXITED','CANCELLED','FAILED','TIMED_OUT'}
        view['sandbox_state']=state if state in allowed else 'OTHER';view['execution_status']=status if status in allowed else 'OTHER'
    except Exception:pass
    with open('/dev/console','w') as console:console.write('XANDBOX_RELEASE_PRIVATE_PHASE '+json.dumps(view,sort_keys=True)+'\n');console.flush()


def warm():
    guard();a=assets()
    if CHECKPOINT.exists() or ROOT.exists() or INCOMING.exists() or PARKED.exists():raise RuntimeError('new ordinary publication fixture required')
    INCOMING.mkdir(mode=0o700)
    for role in ROLES:
        p=INCOMING/role;shutil.copyfile(a[role]['path'],p);p.chmod(0o500 if role not in ('initrd','kernel','workspace') else 0o400)
        if base.sha(p)!=a[role]['sha256']:raise RuntimeError('actual copied publication input mismatch')
    m1=manifest(NATIVE_SOURCES[0]);m2=manifest(NATIVE_SOURCES[1]);p1=CONFIG/'publish-first.json';p2=CONFIG/'publish-second.json';save(p1,m1);save(p2,m2)
    row=base.create('alpha','release-publisher-busy');base.verify_vm(row,'alpha');started=time.monotonic();writer=publication_writer(row)
    main=base.main_identity();gateway=ingress.ingress_identity();committed=drain.state('open')['control']['committed']
    drain.busy(row,writer['id']);milestone('writer_started',row,writer['id'],started);source_negatives(m1);milestone('source_negatives_complete',row,writer['id'],started)
    r1=race(p1,0);milestone('first_cas_complete',row,writer['id'],started);before=store(1);call(p2,0,secrets.token_hex(16),want=1)
    if store(1)!=before:raise RuntimeError('stale publication CAS changed reference')
    rename_sync(INCOMING,PARKED)
    try:call(p1,0,r1,revision=1,retained=1)
    finally:rename_sync(PARKED,INCOMING)
    altered={**m1,'source_revision':NATIVE_SOURCES[1]};rebound=CONFIG/'rebound.json';save(rebound,altered);call(rebound,0,r1,want=1)
    if store(1)!=before:raise RuntimeError('rebound exact request changed authority')
    unknown_controls(p1,r1);milestone('inventory_negatives_complete',row,writer['id'],started);r2=race(p2,1);milestone('second_cas_complete',row,writer['id'],started);snapshot=store(2)
    call(p1,2,secrets.token_hex(16),want=1)
    if store(2)!=snapshot:raise RuntimeError('third retained publication grew metadata')
    rename_sync(INCOMING,PARKED);call(p2,1,r2,revision=2,retained=2)
    drain.state('open',committed);milestone('before_final_busy_check',row,writer['id'],started);drain.busy(row,writer['id'])
    if base.main_identity()!=main or ingress.ingress_identity()!=gateway:raise RuntimeError('artifact publication restarted actual services')
    drain.destroy(row);drain.state('open',committed)
    save(CONFIG/'warm.json',{'snapshot':snapshot,'second_request':r2,'first_request':r1})
    return {k:True for k in CHECKPOINT_FLAGS[:-1]}


def seal():
    guard();old=json.loads((CONFIG/'warm.json').read_bytes());snapshot=store(2)
    if snapshot!=old['snapshot'] or INCOMING.exists() or not PARKED.is_dir():raise RuntimeError('exact persisted publication with absent sources required')
    before=drain.state('drained')['control']['committed'];call(revision=2,retained=2);drain.state('drained',before)
    save(CHECKPOINT,old)
    return {CHECKPOINT_FLAGS[-1]:True}


def probe_publication():
    assets()
    if CHECKPOINT.exists():
        old=json.loads(CHECKPOINT.read_bytes())
        if store(2)!=old['snapshot']:raise RuntimeError('original publication checkpoint changed before operator mutation')
    elif ROOT.exists():raise RuntimeError('first probe must precede publication')
    return {k:True for k in PROBE_FLAGS}


def restore():
    guard();old=json.loads(CHECKPOINT.read_bytes());before=drain.state('drained')['control']['committed']
    if store(2)!=old['snapshot'] or INCOMING.exists() or not PARKED.is_dir():raise RuntimeError('original disk two-bundle publication and missing sources required')
    call(revision=2,retained=2);call(CONFIG/'publish-second.json',1,old['second_request'],revision=2,retained=2)
    if store(2)!=old['snapshot']:raise RuntimeError('cold exact retry advanced or rebound publication')
    drain.state('drained',before)
    return {k:True for k in RECOVERY_FLAGS}


def probe():
    value=ready.probe();value.update(probe_publication());return value


def checkpoint():
    published=warm();value=ready.checkpoint();value.update(published);value.update(seal());return value


def recover():
    published=restore();value=ready.recover();value.update(published);return value


def operator():
    guard();ingress.recover_services=ready.recover_services
    if ready.CHECKPOINT.exists():
        ingress.tls_ready();ingress.ingress_identity();ready.enabled()
    else:
        base.setup();run(ingress.HELPER,'setup');run(ingress.HELPER,'readiness-setup');run('systemctl','daemon-reload');ready.negatives();ready.recover_services()
    base.call=ingress.tls_call
    fd=os.open('/dev/ttyS1',os.O_RDWR|os.O_NOCTTY);attr=termios.tcgetattr(fd);attr[0]=attr[1]=attr[3]=0;attr[6][termios.VMIN]=1;attr[6][termios.VTIME]=0;termios.tcsetattr(fd,termios.TCSANOW,attr)
    with open('/dev/console','w') as console:console.write('XANDBOX_SYSTEMD_HOST_READY\n');console.flush()
    stream=os.fdopen(fd,'r+b',buffering=0);actions={'release-probe':probe,'release-checkpoint':checkpoint,'release-recover':recover}
    while True:
        line=stream.readline(1025)
        if not line or len(line)>1024:raise RuntimeError('bounded fixed publication request required')
        try:
            request=json.loads(line)
            if set(request)!={'version','operation'} or type(request['version']) is not int or request['version']!=1 or request['operation'] not in actions:raise RuntimeError('fixed publication operation required')
            stream.write(json.dumps({'ok':True,'result':actions[request['operation']]()},sort_keys=True).encode()+b'\n')
        except Exception:ready.report_failure(stream);raise


def entry():
    guard()
    try:operator()
    except Exception:ready.report_failure();raise
if __name__=='__main__':entry()
