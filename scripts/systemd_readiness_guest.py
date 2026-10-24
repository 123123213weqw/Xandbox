"""TEST ONLY single-main start plus real boot enablement; not a release installer."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import termios
import time
import systemd_ingress_guest as ingress
from systemd_delegate_probe import read,save,run,wait,identity
base=ingress.base
READY=base.CONFIG/'readiness.json'
CHECKPOINT=base.CONFIG/'readiness-checkpoint.json'
NEGATIVE_PROVED=False
READY_MASK=1<<19

def guard():
    ingress.guard()
    if read('/etc/xandbox-systemd-readiness-fixture')!='Xandbox owned systemd readiness fixture v1':raise RuntimeError('owned readiness L1 required')

def inactive():
    return not base.UNIT_ROOT.exists() and not Path('/run/xandbox-inputs').exists() and not ingress.GROUP.exists() and not ingress.tcp()[1]

def failed_start(stage):
    wait(inactive,70)
    if run('systemctl','show','--property=ActiveState','--value',base.UNIT)!='failed':raise RuntimeError('main startup must actually fail')
    journal=run('journalctl','--no-pager','-o','cat','-n','120','-u',base.UNIT)
    if 'xandbox-ready: failed ('+stage+'); ingress remains ordered behind startup' not in journal:raise RuntimeError('actual readiness failure stage required')
    if run('systemctl','show','--property=MainPID','--value',ingress.UNIT)!='0':raise RuntimeError('ordered ingress must not launch')
    run('systemctl','reset-failed',base.UNIT,ingress.UNIT)

def helper_observation():
    group=base.UNIT_ROOT/'.control'
    values=read(group/'cgroup.procs').split()
    if len(values)!=1:raise RuntimeError('one actual readiness helper required')
    pid=int(values[0]);assets=json.loads((base.CONFIG/'readiness-assets.json').read_bytes())
    if base.sha(Path('/proc',str(pid),'exe'))!=assets['ready']['sha256']:raise RuntimeError('actual pinned readiness helper required')
    checked=0
    for thread in Path('/proc',str(pid),'task').iterdir():
        try:fields=dict(line.split(':',1) for line in (thread/'status').read_text().splitlines() if ':' in line)
        except FileNotFoundError:continue
        if fields['Uid'].split()!=['0']*4 or fields['Gid'].split()!=['0']*4 or fields['NoNewPrivs'].strip()!='1':raise RuntimeError('actual ready identity required')
        for name in ('CapInh','CapAmb','CapPrm','CapEff','CapBnd'):
            if int(fields[name],16)!=(0 if name in ('CapInh','CapAmb') else READY_MASK):raise RuntimeError('actual ready one-cap ceiling required')
        checked+=1
    if not checked:raise RuntimeError('actual ready threads required')
    return pid

def negatives():
    global NEGATIVE_PROVED
    # Existing three true ingress guard negatives remain independent from readiness.
    run('systemctl','start',base.UNIT);ingress.uds_ready();ingress.negative_preflights();run('systemctl','stop',base.UNIT);wait(inactive,25)
    run('systemctl','enable',base.UNIT,ingress.UNIT)
    original=READY.read_bytes();bad=json.loads(original);bad['node_launch']['sha256']='0'*64;save(READY,bad)
    result=subprocess.run(['systemctl','start',base.UNIT],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=70)
    if result.returncode==0:raise RuntimeError('bad ready pin accepted')
    failed_start('manifest');READY.write_bytes(original)
    unit=Path('/etc/systemd/system')/base.UNIT;good=unit.read_bytes();needle=b'ExecStartPost=/usr/libexec/xandbox-ready -manifest /etc/xandbox/readiness.json\n'
    if good.count(needle)!=1:raise RuntimeError('actual generated gate unit required')
    unit.write_bytes(good.replace(needle,b'ExecStartPost=/usr/bin/python3 /opt/xandbox/readiness_fixture_gate.py\n'+needle));run('systemctl','daemon-reload')
    run('systemctl','start','--no-block',base.UNIT)
    wait(lambda:Path('/run/xandbox-ready-gate-entered').exists(),15);ingress.uds_ready()
    if ingress.tcp()[1] or run('systemctl','show','--property=MainPID','--value',ingress.UNIT)!='0':raise RuntimeError('ingress started before post-readiness completion')
    old=base.main_identity();run('systemctl','kill','--kill-whom=main','--signal=SIGSTOP',base.UNIT)
    Path('/run/xandbox-ready-gate-release').write_text('release\n')
    def helper_started():
        try:return any(base.sha(Path('/proc',pid,'exe'))==json.loads((base.CONFIG/'readiness-assets.json').read_bytes())['ready']['sha256'] for pid in read(base.UNIT_ROOT/'.control/cgroup.procs').split())
        except FileNotFoundError:return False
    wait(helper_started,10);time.sleep(.2);helper_observation()
    if base.main_identity()!=old or ingress.tcp()[1]:raise RuntimeError('fixed stopped original main and closed ingress required')
    failed_start('waiting')
    unit.write_bytes(good)
    for p in ('/run/xandbox-ready-gate-entered','/run/xandbox-ready-gate-release'):Path(p).unlink()
    run('systemctl','daemon-reload')
    NEGATIVE_PROVED=True;ingress.NEGATIVES=True

def recover_services():
    # One main start only; the enabled Wants + After/BindsTo dependency launches
    # ingress after the real ExecStartPost gate. No private readiness poll/start.
    run('systemctl','start',base.UNIT);ingress.tls_ready();ingress.ingress_identity()

def enabled():
    for name in (base.UNIT,ingress.UNIT):
        if run('systemctl','is-enabled',name)!='enabled':raise RuntimeError('actual boot enablement required')
    for link,target in ((Path('/etc/systemd/system/multi-user.target.wants')/base.UNIT,Path('/etc/systemd/system')/base.UNIT),(Path('/etc/systemd/system')/(base.UNIT+'.wants')/ingress.UNIT,Path('/etc/systemd/system')/ingress.UNIT)):
        if not link.is_symlink() or link.resolve()!=target:raise RuntimeError('exact boot and dependency links required')

def probe():
    ingress.probe();enabled()
    return {'ordinary_tls_firecracker_health':True,'same_actual_ingress_identity_budgets_caps_and_no_root_tcp':True,'single_main_start_or_original_disk_boot_without_operator_ingress_start':True,'exact_enabled_daemon_boot_and_ingress_wants_links':True,'no_mock_or_host_task_fallback':True}

def checkpoint():
    if not NEGATIVE_PROVED:raise RuntimeError('both real startup refusal controls required')
    value=ingress.checkpoint();del value['explicit_start_after_backend_ready_not_automatic_install']
    save(CHECKPOINT,{'ready_sha256':base.sha(READY),'daemon_unit_sha256':base.sha('/etc/systemd/system/'+base.UNIT),'ready_assets_sha256':base.sha(base.CONFIG/'readiness-assets.json')})
    value.update({'bad_ready_pin_refused_before_ingress_and_manager_cleaned':True,'stopped_real_main_readiness_deadline_refused_and_manager_cleaned':True,'actual_one_cap_ready_helper_in_manager_control_not_node':True,'ingress_stayed_closed_while_post_gate_held':True,'single_main_restart_auto_started_ready_ordered_ingress':True,'enablement_and_ready_inputs_checkpoint_fsynced':True})
    return value

def recover():
    old=json.loads(CHECKPOINT.read_bytes());enabled()
    for key,p in (('ready_sha256',READY),('daemon_unit_sha256','/etc/systemd/system/'+base.UNIT),('ready_assets_sha256',base.CONFIG/'readiness-assets.json')):
        if base.sha(p)!=old[key]:raise RuntimeError('original unit/ready policy persistence required')
    value=ingress.recover();value.update({'original_enablement_and_readiness_inputs_persisted':True,'cold_boot_both_services_without_operator_start':True})
    return value

def operator():
    guard()
    ingress.recover_services=recover_services
    if CHECKPOINT.exists():
        # Only observe: systemd, not this operator, starts enabled services at boot2.
        ingress.tls_ready();ingress.ingress_identity();enabled()
    else:
        base.setup();run(ingress.HELPER,'setup');run(ingress.HELPER,'readiness-setup');run('systemctl','daemon-reload');negatives();recover_services()
    base.call=ingress.tls_call
    fd=os.open('/dev/ttyS1',os.O_RDWR|os.O_NOCTTY);attr=termios.tcgetattr(fd);attr[0]=attr[1]=attr[3]=0;attr[6][termios.VMIN]=1;attr[6][termios.VTIME]=0;termios.tcsetattr(fd,termios.TCSANOW,attr)
    with open('/dev/console','w') as console:console.write('XANDBOX_SYSTEMD_HOST_READY\n');console.flush()
    stream=os.fdopen(fd,'r+b',buffering=0);actions={'readiness-probe':probe,'readiness-checkpoint':checkpoint,'readiness-recover':recover}
    while True:
        line=stream.readline(1025)
        if not line or len(line)>1024:raise RuntimeError('bounded fixed readiness request required')
        try:
            request=json.loads(line)
            if set(request)!={'version','operation'} or type(request['version']) is not int or request['version']!=1 or request['operation'] not in actions:raise RuntimeError('fixed readiness operation required')
            stream.write(json.dumps({'ok':True,'result':actions[request['operation']]()},sort_keys=True).encode()+b'\n')
        except Exception:ingress.failure_console();raise

def entry():
    guard()
    try:operator()
    except Exception:ingress.failure_console();raise
if __name__=='__main__':entry()
