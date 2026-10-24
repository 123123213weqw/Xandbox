"""TEST ONLY own-child x86_64 installer trace on a separately marked managed L1.

Only the operator's fresh child is traced. No attach, service PID trace or
production hook. Policy activation is cut BEFORE connect, after durable file+intent.
"""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import time
from contextlib import contextmanager
from install_fixture_trace import Registers,ptrace,string_at
from systemd_delegate_probe import guard as base_guard

MARKER='Xandbox owned managed policy fixture v1\n'
ROOT=Path('/etc/xandbox-install')
OPERATOR=b'/run/xandbox-ingress-control/operator.sock'

def guard():
    base_guard()
    if Path('/etc/xandbox-systemd-managed-fixture').read_text()!=MARKER or os.uname().machine!='x86_64':raise RuntimeError('owned x86 managed L1 required')

def activation_candidate(envelope,intent,revision,request):
    # The actual production CLI validates cryptographic/source/base invariants.
    # This observation only proves the specific post-publication cut, not ACK.
    if type(envelope) is not dict or type(intent) is not dict or type(revision) is not int or revision<2 or not re.fullmatch('[0-9a-f]{32}',request):return False
    if any(type(v) is not int for v in (envelope.get('version'),envelope.get('expected_revision'),intent.get('version'),intent.get('expected_revision'))):return False
    return envelope['version']==1 and type(envelope.get('revision')) is int and envelope['revision']==revision and envelope['expected_revision']==revision-1 and envelope.get('request_id')==request and type(envelope.get('snapshot')) is dict and type(envelope['snapshot'].get('epoch')) is int and envelope['snapshot']['epoch']==revision and intent['version']==1 and intent['expected_revision']==revision-1 and intent.get('request_id')==request


def sockaddr_at(pid,address,length):
    if not 3<=length<=110:return None
    data=bytearray()
    for offset in range(0,length,8):data.extend((ptrace(2,pid,address+offset)&((1<<64)-1)).to_bytes(8,'little'))
    raw=bytes(data[:length])
    if raw[:2]!=b'\x01\x00':return None
    return raw[2:].split(b'\0',1)[0]

def proposal_candidate(payload,intent,installed,revision,request,record=None,visible=False):
    if type(visible) is not bool:return False
    if not activation_candidate(payload,intent,revision,request):return False
    if type(intent.get('new_payload_sha256')) is not str or not re.fullmatch('[0-9a-f]{64}',intent['new_payload_sha256']):return False
    if type(installed) is not dict or type(installed.get('revision')) is not int or installed['revision']!=(revision if visible else revision-1):return False
    if record is not None:
        if type(record) is not dict or type(record.get('version')) is not int or record['version']!=1 or type(record.get('expected_revision')) is not int or record['expected_revision']!=revision-1 or record.get('request_id')!=request or record.get('new_payload_sha256')!=intent.get('new_payload_sha256'):return False
    return True


def trace_shape(args,mode,revision,request):
    modes=('initial-commit','policy-activation','rotation-proposal','supersession-proposal','supersession-visible')
    if mode not in modes or type(revision) is not int or type(args) is not list or not all(type(a) is str for a in args):raise RuntimeError('fixed managed cut required')
    if mode=='initial-commit':
        if len(args)!=8 or args[:7]!=['/usr/libexec/xandbox-install-bootstrap','apply','-plan','/etc/xandbox-managed-fixture/plan.json','-expected-revision','0','-request-id'] or not re.fullmatch('[0-9a-f]{32}',args[7]) or revision!=0 or request!='':raise RuntimeError('fixed initial commit child required')
    elif mode.startswith('supersession-'):
        if len(args)!=10 or args[:2]!=['/usr/libexec/xandbox-install','replace-pending-policy'] or type(revision) is not int or revision!=2 or args[2]!='-plan' or args[3] not in ('/etc/xandbox-managed-fixture/rotation-replacement-2a.json','/etc/xandbox-managed-fixture/rotation-replacement-2b.json') or args[4:7]!=['-expected-revision','1','-request-id'] or args[7]!=request or args[8]!='-replaces-request-id' or not re.fullmatch('[0-9a-f]{32}',args[9]) or args[9]==request:raise RuntimeError('fixed own supersession child required')
    elif len(args)!=8 or args[:2]!=['/usr/libexec/xandbox-install','reconfigure'] or revision not in (2,3) or args[2]!='-plan' or args[3]!='/etc/xandbox-managed-fixture/rotation-'+str(revision)+'.json' or args[4:7]!=['-expected-revision',str(revision-1),'-request-id'] or args[7]!=request:raise RuntimeError('fixed reconfiguration child required')
    if mode!='initial-commit' and (type(request) is not str or not re.fullmatch('[0-9a-f]{32}',request)):raise RuntimeError('fixed own request required')


def published_cut(mode,revision,request):
    installed_raw=(ROOT/'gateway-policy.json').read_bytes();installed=json.loads(installed_raw)
    raw=installed_raw if mode=='supersession-visible' else (ROOT/'.policy.next').read_bytes()
    intent=json.loads((ROOT/'rotation-intent.json').read_bytes());payload=json.loads(raw)
    record=json.loads((ROOT/'policy-supersession.json').read_bytes()) if mode.startswith('supersession-') else None
    if not proposal_candidate(payload,intent,installed,revision,request,record,mode=='supersession-visible'):raise RuntimeError('actual proposal publication cut mismatch')
    if hashlib.sha256(raw).hexdigest()!=intent.get('new_payload_sha256') or (ROOT/'.rotation-intent.next').exists() or (ROOT/'.policy-supersession.next').exists():raise RuntimeError('actual proposal hash or metadata scratch mismatch')
    if record is not None and mode!='supersession-visible' and hashlib.sha256(installed_raw).hexdigest()!=record.get('old_payload_sha256'):raise RuntimeError('supersession changed installed predecessor early')
    if mode=='supersession-visible' and (ROOT/'.policy.next').exists():raise RuntimeError('visible proposal scratch remains')
    return True


@contextmanager
def bounded_trace_wait(active):
    # Own L1 operator process only. A blocking wait avoids a fixed sleep on
    # every traced syscall; the existing 60-second bound remains enforced.
    if type(active) is not bool:raise RuntimeError('closed trace wait mode required')
    if not active:
        yield
        return
    if signal.getitimer(signal.ITIMER_REAL)!=(0.,0.):raise RuntimeError('unowned trace alarm already active')
    previous=signal.getsignal(signal.SIGALRM)
    def expired(signum,frame):raise RuntimeError('managed trace deadline')
    signal.signal(signal.SIGALRM,expired)
    try:
        signal.setitimer(signal.ITIMER_REAL,60.)
        yield
    finally:
        try:signal.setitimer(signal.ITIMER_REAL,0.)
        finally:signal.signal(signal.SIGALRM,previous)


def interrupt(args,output,expected_sha,sha,mode,revision=0,request=''):
    guard();trace_shape(args,mode,revision,request)
    pid=os.fork()
    if pid==0:
        try:
            fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.dup2(fd,1);os.dup2(fd,2);os.close(fd)
            fd=os.open('/dev/null',os.O_RDONLY);os.dup2(fd,0);os.close(fd)
            ptrace(0,0);os.kill(os.getpid(),signal.SIGSTOP)
            os.execve(args[0],args,{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        finally:os._exit(91)
    threads={pid};hit=False;executed=False;options=1|8|16|(1<<20);end=time.monotonic()+60
    blocking=mode in ('rotation-proposal','supersession-proposal','supersession-visible')
    try:
        with bounded_trace_wait(blocking):
            got,status=os.waitpid(pid,0)
            if got!=pid or not os.WIFSTOPPED(status) or os.WSTOPSIG(status)!=signal.SIGSTOP:raise RuntimeError('owned managed trace handshake')
            ptrace(0x4200,pid,0,options);ptrace(24,pid)
            while threads:
                if time.monotonic()>=end:raise RuntimeError('managed trace deadline')
                tid,status=os.waitpid(-1,0x40000000|(0 if blocking else os.WNOHANG))
                if not tid:time.sleep(.0005);continue
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    threads.discard(tid)
                    if tid==pid and not hit:raise RuntimeError('actual installer main exited before managed cut')
                    continue
                if not os.WIFSTOPPED(status):raise RuntimeError('unexpected owned trace state')
                sig=os.WSTOPSIG(status);event=status>>16
                if event==3:
                    child=ctypes.c_ulonglong();ptrace(0x4201,tid,0,ctypes.addressof(child));threads.add(child.value)
                if event==4:
                    if tid!=pid or sha(Path('/proc',str(pid),'exe'))!=expected_sha:raise RuntimeError('owned managed exec pin')
                    executed=True
                if sig==(signal.SIGTRAP|0x80) and executed and not hit:
                    r=Registers();ptrace(12,tid,0,ctypes.addressof(r));entry=r.rax==((1<<64)-errno.ENOSYS)
                    if mode=='initial-commit' and entry and r.orig_rax==257 and string_at(tid,r.rsi)==b'.commit.next':
                        if os.readlink('/proc/'+str(tid)+'/fd/'+str(ctypes.c_int(r.rdi).value))!='/etc/xandbox-install':raise RuntimeError('fixed commit dirfd required')
                        hit=True
                    elif mode=='policy-activation' and entry and r.orig_rax==42 and sockaddr_at(tid,r.rsi,r.rdx)==OPERATOR:
                        intent_path=ROOT/'rotation-intent.json'
                        # The precommit status connection normally has no rotation
                        # intent yet. Absence is NOT a cut and must not kill the child.
                        if intent_path.is_file():
                            raw=(ROOT/'gateway-policy.json').read_bytes();envelope=json.loads(raw);intent=json.loads(intent_path.read_bytes())
                            if activation_candidate(envelope,intent,revision,request):
                                if hashlib.sha256(raw).hexdigest()!=intent.get('new_payload_sha256'):raise RuntimeError('actual file/intent hash mismatch')
                                if (ROOT/'.policy.next').exists() or (ROOT/'.rotation-intent.next').exists():raise RuntimeError('policy publication not complete')
                                if sha(Path('/proc',str(pid),'exe'))!=expected_sha:raise RuntimeError('installer incarnation drift')
                                hit=True
                    elif mode in ('rotation-proposal','supersession-proposal') and entry and r.orig_rax==264 and string_at(tid,r.rsi)==b'.policy.next' and string_at(tid,r.r10)==b'gateway-policy.json':
                        if any(os.readlink('/proc/'+str(tid)+'/fd/'+str(ctypes.c_int(fd).value))!=str(ROOT) for fd in (r.rdi,r.rdx)):raise RuntimeError('fixed proposal rename dirfds required')
                        hit=published_cut(mode,revision,request)
                    elif mode=='supersession-visible' and not entry and r.orig_rax==74 and r.rax==0:
                        if os.readlink('/proc/'+str(tid)+'/fd/'+str(ctypes.c_int(r.rdi).value))==str(ROOT):
                            installed=json.loads((ROOT/'gateway-policy.json').read_bytes())
                            if installed.get('revision')==revision and installed.get('request_id')==request:hit=published_cut(mode,revision,request)
                    if hit:
                        if sha(Path('/proc',str(pid),'exe'))!=expected_sha:raise RuntimeError('final own exec pin drift')
                        os.kill(pid,signal.SIGKILL);continue
                forward=0 if sig in (signal.SIGTRAP,signal.SIGSTOP,signal.SIGTRAP|0x80) else sig
                try:ptrace(24,tid,0,forward)
                except OSError as e:
                    if e.errno!=errno.ESRCH:raise
            if not hit:raise RuntimeError('fixed managed cut not reached')
    finally:
        if threads:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            deadline=time.monotonic()+5
            while threads and time.monotonic()<deadline:
                try:tid,status=os.waitpid(-1,0x40000000|os.WNOHANG)
                except ChildProcessError:break
                if tid and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):threads.discard(tid)
                elif tid:
                    try:ptrace(24,tid,0,signal.SIGKILL)
                    except OSError:pass
                else:time.sleep(.01)
            if threads:raise RuntimeError('own managed child not fully reaped')
