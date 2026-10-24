#!/usr/bin/env python3
"""TEST ONLY fixed separate ingress operator, exclusively inside marked owned L1.

Real task argv is sent through TLS to ordinary guest APIs, never a host fallback.
Start after bounded backend readiness is explicit; not an automatic installer.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import termios
import time
import traceback

import systemd_deployment_guest as base
from systemd_delegate_probe import guard as base_guard, read, save, run, wait, identity

UNIT='xandbox-ingress.service'
GROUP=Path('/sys/fs/cgroup/system.slice')/UNIT
CONFIG=base.CONFIG
MANIFEST=CONFIG/'ingress-launch.json'
CLIENT=CONFIG/'ingress-client-fixture.json'
CHECKPOINT=CONFIG/'ingress-checkpoint.json'
HELPER='/usr/libexec/xandbox-deploy-fixture'
MASK=(1<<6)|(1<<7)|(1<<18)
UDS_CALL=base.call
NEGATIVES=False
GUARD_DIAGNOSTIC_ONLY=False


def guard():
    base_guard()
    if read('/etc/xandbox-systemd-ingress-fixture')!='Xandbox owned systemd ingress fixture v1':raise RuntimeError('owned ingress L1 marker required')


def client():return json.loads(CLIENT.read_bytes())


class TLSHTTP(http.client.HTTPConnection):
    def connect(self):
        cfg=client();context=ssl.create_default_context(cafile=cfg['ca_file']);context.minimum_version=ssl.TLSVersion.TLSv1_3
        raw=socket.create_connection(('127.0.0.1',18443),timeout=40)
        try:self.sock=context.wrap_socket(raw,server_hostname=cfg['server_name'])
        except BaseException:raw.close();raise
        if hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()!=cfg['leaf_sha256']:
            self.close();raise RuntimeError('actual TLS leaf differs from expected private revision')


def tls_call(method,path,body=None,tenant='alpha',key=None,expected=200,token=None,connection=None):
    conn=connection or TLSHTTP('xandbox.fixture',timeout=40)
    headers={}
    if body is not None:headers['Content-Type']='application/json'
    if tenant is not None:headers['Authorization']='Bearer '+(token if token is not None else client()['tokens'][tenant])
    if key is not None:headers['Idempotency-Key']=key
    try:
        conn.request(method,path,None if body is None else json.dumps(body),headers)
        response=conn.getresponse();raw=response.read(65537)
        if response.status!=expected:raise RuntimeError('fixed TLS API status actual='+str(response.status)+' expected='+str(expected))
        if len(raw)>65536:raise RuntimeError('bounded TLS API response required')
        return json.loads(raw)
    finally:
        if connection is None:conn.close()


def uds_ready():
    def available():
        try:
            value=UDS_CALL('GET','/healthz',tenant=None)
            return value['backend']=='firecracker' and value['isolation'] is True
        except (OSError,http.client.HTTPException):return False
    wait(available,60)


def tls_ready():
    def available():
        try:
            value=tls_call('GET','/healthz')
            return value['backend']=='firecracker' and value['isolation'] is True
        except (OSError,http.client.HTTPException,RuntimeError):return False
    wait(available,15)


def status(pid):return dict(line.split(':',1) for line in Path('/proc',str(pid),'status').read_text().splitlines() if ':' in line)


def service_pid():
    value=run('systemctl','show','--property=MainPID','--value',UNIT)
    if not value.isdecimal() or int(value)<=1:raise RuntimeError('actual ingress main PID required')
    return int(value)


def tcp():
    all_inodes=set();listeners=set()
    for file in ('/proc/net/tcp','/proc/net/tcp6'):
        for line in Path(file).read_text().splitlines()[1:]:
            fields=line.split();inode=int(fields[9]);all_inodes.add(inode)
            if fields[3]=='0A' and int(fields[1].split(':')[-1],16)==18443:listeners.add(inode)
    return all_inodes,listeners


def socket_inodes(pid):
    found=set()
    for fd in Path('/proc',str(pid),'fd').iterdir():
        try:value=os.readlink(fd)
        except FileNotFoundError:continue
        match=re.fullmatch(r'socket:\[([0-9]+)\]',value)
        if match:found.add(int(match.group(1)))
    return found


def ingress_identity():
    pid=service_pid();run('systemctl','is-active','--quiet',UNIT)
    assets=json.loads((CONFIG/'ingress-assets.json').read_bytes());policy=json.loads(MANIFEST.read_bytes())
    processes={int(n) for n in read(GROUP/'cgroup.procs').split()}
    if len(processes)!=2 or pid not in processes or any(p.is_dir() for p in GROUP.iterdir()):raise RuntimeError('exact root and child ingress inventory required')
    child=(processes-{pid}).pop()
    for process in (pid,child):
        if base.sha(Path('/proc',str(process),'exe'))!=assets['gateway']['sha256'] or read(Path('/proc',str(process),'cgroup'))!='0::/system.slice/'+UNIT:
            raise RuntimeError('pinned gateway and exact separate placement required')
    s=status(child)
    if int(s['PPid'])!=pid or s['Uid'].split()!=['65530']*4 or s['Gid'].split()!=['65530']*4 or s['Groups'].split() or s['NoNewPrivs'].strip()!='1':raise RuntimeError('actual child identity and NNP required')
    for name in ('CapInh','CapPrm','CapEff','CapAmb'):
        if int(s[name],16)!=0:raise RuntimeError('child active capabilities forbidden')
    if int(s['CapBnd'],16)!=MASK:raise RuntimeError('child bounding ceiling drift')
    if not os.path.samefile(Path('/proc',str(child),'root'),'/srv/xb/gwroot/root') or not os.path.samefile(Path('/proc',str(child),'cwd'),'/srv/xb/gwroot/root'):
        raise RuntimeError('child root/cwd outside executable-only root')
    for fd in Path('/proc',str(child),'fd').iterdir():
        try:value=os.readlink(fd)
        except FileNotFoundError:continue
        if value not in ('/dev/null','/gateway') and not re.fullmatch(r'socket:\[[0-9]+\]|anon_inode:\[(eventpoll|eventfd)\]',value):raise RuntimeError('unexpected child inherited descriptor class')
    checked=0
    for thread in Path('/proc',str(pid),'task').iterdir():
        try:raw=(thread/'status').read_text()
        except FileNotFoundError:continue
        row=dict(line.split(':',1) for line in raw.splitlines() if ':' in line)
        if row['Uid'].split()!=['0']*4 or row['Gid'].split()!=['0']*4 or row['NoNewPrivs'].strip()!='1':raise RuntimeError('root identity/NNP mismatch')
        for name in ('CapInh','CapAmb','CapPrm','CapEff','CapBnd'):
            if int(row[name],16)!=(0 if name in ('CapInh','CapAmb') else MASK):raise RuntimeError('root exact three capabilities required')
        checked+=1
    if not checked:raise RuntimeError('actual root thread observation required')
    for group,p in ((GROUP,policy['ingress']),(base.UNIT_ROOT,json.loads((CONFIG/'launch.json').read_bytes())['parent'])):
        for name,value in {'memory.max':str(p['memory_max']),'memory.swap.max':'0','pids.max':str(p['pids_max']),'cpu.max':str(p['cpu_quota'])+' 100000'}.items():
            if read(group/name)!=value:raise RuntimeError('actual parent envelope drift')
        want={policy['device'],'rbps='+str(p['io_bytes_per_second']),'wbps='+str(p['io_bytes_per_second']),'riops='+str(p['io_operations_per_second']),'wiops='+str(p['io_operations_per_second'])}
        raw=read(group/'io.max')
        if '\n' in raw or len(raw.split())!=5 or set(raw.split())!=want:raise RuntimeError('actual parent IO envelope drift')
    if read(GROUP/'memory.oom.group')!='1' or read(GROUP/'cgroup.subtree_control'):raise RuntimeError('nondelegated grouped OOM ingress required')
    all_tcp,listeners=tcp()
    if len(listeners)!=1 or socket_inodes(pid)&all_tcp or not listeners<=socket_inodes(child):raise RuntimeError('only child may own TLS TCP listener')
    return pid,identity(pid),child,identity(child)


def start_ingress():
    run('systemctl','start',UNIT);tls_ready();return ingress_identity()


def wait_ingress_gone(old):
    wait(lambda:identity(old[0])!=old[1] and identity(old[2])!=old[3] and not GROUP.exists() and not tcp()[1],20)


def negative_preflights():
    original=MANIFEST.read_bytes();unit=Path('/etc/systemd/system')/UNIT;original_unit=unit.read_bytes()
    for case in ('pin','budget','capabilities'):
        value=json.loads(original)
        if case=='pin':value['config']['sha256']='0'*64
        if case=='budget':value['ingress']['pids_max']+=1
        save(MANIFEST,value)
        if case=='capabilities':unit.write_bytes(original_unit.replace(b'CAP_SYS_CHROOT\n',b'CAP_SYS_CHROOT CAP_NET_BIND_SERVICE\n'));run('systemctl','daemon-reload')
        # Type=exec acknowledges the launcher, not its application preflight.
        subprocess.run(['systemctl','start',UNIT],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
        wait(lambda:run('systemctl','show','--property=MainPID','--value',UNIT)=='0' and run('systemctl','show','--property=ActiveState','--value',UNIT) in ('failed','inactive') and not GROUP.exists() and not tcp()[1],15)
        if run('systemctl','show','--property=ExecMainStatus','--value',UNIT)!='1' or GROUP.exists() or tcp()[1]:raise RuntimeError('preflight must fail before child/TCP and manager must remove group')
        stage={'pin':'composition','budget':'envelope','capabilities':'placement'}[case]
        journal=run('journalctl','--no-pager','-o','cat','-n','100','-u',UNIT)
        if 'preflight failed ('+stage+'); gateway not executed' not in journal:raise RuntimeError('expected exact preflight stage not observed')
        MANIFEST.write_bytes(original);unit.write_bytes(original_unit);run('systemctl','daemon-reload')
        # Reset only after an intentional, independently observed negative case;
        # no blind retry and no relaxation of the production candidate start limit.
        run('systemctl','reset-failed',UNIT)


def probe():
    tls_ready();ingress_identity();base.main_identity()
    return {k:True for k in ('ordinary_tls_firecracker_health','manager_main_is_pinned_gateway','root_and_child_in_separate_exact_ingress_domain','root_three_caps_child_unprivileged_nnp_root_cwd_fds','actual_parent_budgets_and_no_root_tcp_listener','no_mock_or_host_fallback')}


def checkpoint():
    if CHECKPOINT.exists() or not NEGATIVES:raise RuntimeError('new first ingress checkpoint required')
    probe();rows=[];boots=[]
    for n,tenant in enumerate(('alpha','alpha','alpha','beta')):
        if n==3:base.call('POST','/v1/sandboxes',{},tenant='alpha',key='ingress-alpha-fourth',expected=429)
        request_key='ingress-first-'+str(n);row=base.create(tenant,request_key);boots.append(base.verify_vm(row,tenant));rows.append({'row':row,'tenant':tenant,'key':request_key,'owner':base.owner(row)})
    if len(set(boots))!=4:raise RuntimeError('four distinct real guest boots required')
    base.call('GET',base.refpath(rows[0]['row']),tenant='beta',expected=404)
    base.call('POST','/v1/sandboxes',{},tenant=None,key='ingress-no-auth',expected=401)
    base.call('POST','/v1/sandboxes',{},tenant='beta',key='ingress-node-fifth',expected=503)
    victim=rows[0];base.progressing_writer(victim['row'],'alpha')
    stopped=base.call('POST',base.refpath(victim['row'])+'/stop',{'generation':victim['row']['generation']})
    if stopped['state']!='STOPPED':raise RuntimeError('physical stop acknowledgment required')
    group=base.UNIT_ROOT/'node/instances'/base.key(victim['row'])
    if group.exists() and 'populated 0' not in read(group/'cgroup.events'):raise RuntimeError('stopped execution still populated')
    base.call('POST','/v1/sandboxes',{},tenant='beta',key='ingress-stopped-full',expected=503)
    base.call('DELETE',base.refpath(victim['row']),{'generation':victim['row']['generation']},expected=202);base.reclaimed(victim['row'],'alpha',victim['owner']['project_id'])
    replacement=base.create('alpha','ingress-reused');boot=base.verify_vm(replacement,'alpha')
    if boot in boots or base.execute(replacement,['test','!','-e','/workspace/heartbeat'],'alpha')!='':raise RuntimeError('fresh replacement required')
    rows[0]={'row':replacement,'tenant':'alpha','key':'ingress-reused','owner':base.owner(replacement)}
    base.progressing_writer(replacement,'alpha');old_gateway=ingress_identity();old_daemon=base.main_identity()
    # The private UDS observer is operator-only and proves the task keeps running
    # while TLS is deliberately down; it is not a tenant/host execution fallback.
    def counter():
        accepted=UDS_CALL('POST',base.refpath(replacement)+'/exec',{'generation':replacement['generation'],'argv':['cat','/workspace/heartbeat'],'timeout_ms':5000},expected=202)
        result={}
        def done():
            nonlocal result
            result=UDS_CALL('GET',base.refpath(replacement)+'/executions/'+accepted['id']);return result['status']!='RUNNING'
        wait(done,10)
        if result['status']!='EXITED' or result['output']['exit_code']!=0:raise RuntimeError('independent busy guest observer failed')
        return int(result['output']['stdout'].strip())
    before=counter();run('systemctl','stop',UNIT);wait_ingress_gone(old_gateway);time.sleep(.2)
    if counter()<=before or base.main_identity()!=old_daemon:raise RuntimeError('ingress stop interrupted ordinary busy guest')
    start_ingress();old_gateway=ingress_identity()
    held=TLSHTTP('xandbox.fixture',timeout=40);old_token=client()['tokens']['alpha']
    try:
        tls_call('GET',base.refpath(replacement),connection=held)
        run(HELPER,'rotate');run('systemctl','daemon-reload');run('systemctl','kill','--kill-whom=main','--signal=SIGHUP',UNIT);tls_ready()
        tls_call('GET',base.refpath(replacement));tls_call('GET',base.refpath(replacement),token=old_token,expected=401,connection=held)
    finally:held.close()
    if ingress_identity()!=old_gateway or base.main_identity()!=old_daemon or client()['revision']!=2:raise RuntimeError('live rotation must not restart services')
    if counter()<=before or json.loads(Path('/srv/xb/policy/policy.json').read_bytes())['revision']!=2:raise RuntimeError('actual revision and continued execution required')
    run('systemctl','kill','--kill-whom=main','--signal=SIGKILL',base.UNIT)
    wait_ingress_gone(old_gateway)
    wait(lambda:identity(old_daemon[0])!=old_daemon[1] and not base.UNIT_ROOT.exists() and not Path('/run/xandbox-inputs').exists(),20)
    run('systemctl','start',base.UNIT);uds_ready();start_ingress()
    for item in rows:
        base.reclaimed(item['row'],item['tenant'],item['owner']['project_id']);base.call('POST','/v1/sandboxes',base.create_spec(),tenant=item['tenant'],key=item['key'],expected=410)
    if json.loads(Path('/srv/xb/policy/policy.json').read_bytes())['revision']!=2:raise RuntimeError('durable gateway revision lost after daemon restart')
    tls_call('GET',base.refpath(replacement),token=old_token,expected=401)
    fresh=base.create('alpha','ingress-before-cold');fresh_boot=base.verify_vm(fresh,'alpha')
    base.execute(fresh,['sh','-c','printf cold-proof > /workspace/cold-marker; sync'],'alpha');base.progressing_writer(fresh,'alpha')
    save(CHECKPOINT,{'boot_id':read('/proc/sys/kernel/random/boot_id'),'machine_id':read('/etc/machine-id'),'row':fresh,'owner':base.owner(fresh),'guest_boot':fresh_boot,'key':'ingress-before-cold','client':client(),'manifest_sha256':base.sha(MANIFEST)})
    return {k:True for k in ('three_real_preflight_refusals_no_child_or_tcp','four_simultaneous_real_guests_via_tls','two_tenant_auth_quota_and_node_refusals','guest_uid_boot_vmm_caps_filters_and_quota_checked','busy_stop_distinct_from_durable_gc_capacity','reused_slot_fresh_guest_and_workspace','ingress_stop_restart_did_not_stop_busy_guest','live_key_leaf_rotation_two_no_daemon_or_guest_restart','old_token_rejected_on_existing_tls_connection','daemon_sigkill_binds_to_closed_ingress_and_manager_removed_groups','same_policy_daemon_and_gateway_recovered_old_guests_revision_two','old_create_keys_refused410','fresh_live_guest_checkpoint_fsynced','explicit_start_after_backend_ready_not_automatic_install')}


def recover():
    old=json.loads(CHECKPOINT.read_bytes());probe()
    if old['boot_id']==read('/proc/sys/kernel/random/boot_id') or old['machine_id']!=read('/etc/machine-id') or old['client']!=client() or old['manifest_sha256']!=base.sha(MANIFEST):raise RuntimeError('original disk/private revision persistence required')
    base.reclaimed(old['row'],'alpha',old['owner']['project_id']);base.call('POST','/v1/sandboxes',base.create_spec(),key=old['key'],expected=410)
    tls_call('GET',base.refpath(old['row']),token=client()['old_tokens']['alpha'],expected=401)
    fresh=base.create('alpha','ingress-after-cold');boot=base.verify_vm(fresh,'alpha')
    if boot==old['guest_boot']:raise RuntimeError('assigned guest resurrected')
    base.execute(fresh,['test','!','-e','/workspace/cold-marker'],'alpha');owned=base.owner(fresh)
    base.call('DELETE',base.refpath(fresh),{'generation':fresh['generation']},expected=202);base.reclaimed(fresh,'alpha',owned['project_id'])
    if any(p.is_dir() for p in (base.UNIT_ROOT/'node/instances').iterdir()) or list((base.RUNTIME/'j/firecracker').glob('*')):raise RuntimeError('private generation remains')
    for project in range(1300000,1300004):
        q=base.quota(project)
        if any(getattr(q,n)!=0 for n in ('bhard','bsoft','space','ihard','isoft','inodes','btime','itime')):raise RuntimeError('private quota remains')
    gateway=ingress_identity();run('systemctl','stop',base.UNIT);wait_ingress_gone(gateway)
    wait(lambda:not base.UNIT_ROOT.exists() and not Path('/run/xandbox-inputs').exists(),20)
    return {k:True for k in ('original_disk_new_l1_boot_same_machine','gateway_revision_two_leaf_and_new_credentials_survived','old_token_refused401','old_guest_durably_destroyed_and_exact_quota_resources_absent','old_create_key_refused410','new_real_guest_boot_pristine_workspace_and_destroyed','all_four_projects_zero_and_private_generations_absent','manager_clean_stop_removed_both_units_and_inputs','not_installer_catalog_backup_or_production_slo')}


def failure_console():
    with open('/dev/console','w') as console:
        # The L0 reader terminates the owned domain on the final marker. Never
        # emit it before the bounded diagnostic, or the cause is cut mid-line.
        traceback.print_exc(file=console);console.flush()
        try:
            subprocess.run(['journalctl','--no-pager','-n','100','-u',UNIT,'-u',base.UNIT,'-u','xandbox-ingress-operator.service'],stdout=console,stderr=console,timeout=10)
        except (OSError,subprocess.TimeoutExpired):
            console.write('owned journal diagnostic unavailable\n')
        finally:
            console.write('XANDBOX_SYSTEMD_HOST_FAILED ingress\n');console.flush()


def operator():
    global NEGATIVES
    guard();base.setup();run(HELPER,'setup');run('systemctl','daemon-reload');run('systemctl','start',base.UNIT);uds_ready()
    if GUARD_DIAGNOSTIC_ONLY:
        unit=Path('/etc/systemd/system')/UNIT;raw=unit.read_bytes()
        expected=b'ExecStart=/usr/libexec/xandbox-ingress-launch -manifest /etc/xandbox/ingress-launch.json'
        if raw.count(expected)!=1:raise RuntimeError('fixed diagnostic unit entry required')
        unit.write_bytes(raw.replace(expected,b'ExecStart=/usr/bin/python3 /opt/xandbox/ingress_guard_probe.py'))
        run('systemctl','daemon-reload')
        subprocess.run(['systemctl','start',UNIT],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
        wait(lambda:run('systemctl','show','--property=MainPID','--value',UNIT)=='0' or tcp()[1],15)
        raise RuntimeError('fixed guard birth diagnostic only, never qualification')
    if not CHECKPOINT.exists():negative_preflights();NEGATIVES=True
    start_ingress();base.call=tls_call
    fd=os.open('/dev/ttyS1',os.O_RDWR|os.O_NOCTTY);attr=termios.tcgetattr(fd);attr[0]=attr[1]=attr[3]=0;attr[6][termios.VMIN]=1;attr[6][termios.VTIME]=0;termios.tcsetattr(fd,termios.TCSANOW,attr)
    with open('/dev/console','w') as console:console.write('XANDBOX_SYSTEMD_HOST_READY\n');console.flush()
    stream=os.fdopen(fd,'r+b',buffering=0);actions={'ingress-probe':probe,'ingress-checkpoint':checkpoint,'ingress-recover':recover}
    while True:
        line=stream.readline(1025)
        if not line or len(line)>1024:raise RuntimeError('bounded fixed ingress request required')
        try:
            value=json.loads(line)
            if set(value)!={'version','operation'} or type(value['version']) is not int or value['version']!=1 or value['operation'] not in actions:raise RuntimeError('fixed ingress operation required')
            result=actions[value['operation']]();stream.write(json.dumps({'ok':True,'result':result},sort_keys=True).encode()+b'\n')
        except Exception:
            failure_console();stream.write(b'{"ok":false,"error":"owned ingress fixture failed"}\n');raise


def entry():
    guard()
    try:operator()
    except Exception:failure_console();raise


if __name__=='__main__':entry()
