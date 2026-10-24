"""TEST ONLY ptrace of the operator's OWN fresh installer child, on marked L1.

No production hooks. Fixed x86_64 Linux openat entry, kill BEFORE commit scratch
creation, reap every traced thread. Never attach another service or an L0 PID.
"""
import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import time
from systemd_delegate_probe import guard

class Registers(ctypes.Structure):
    _fields_=[(n,ctypes.c_ulonglong) for n in ('r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs')]
libc=ctypes.CDLL(None,use_errno=True);libc.ptrace.restype=ctypes.c_long

def ptrace(request,pid,address=0,data=0):
    ctypes.set_errno(0)
    value=libc.ptrace(ctypes.c_ulong(request),ctypes.c_ulong(pid),ctypes.c_void_p(address),ctypes.c_void_p(data))
    e=ctypes.get_errno()
    if value==-1 and e:raise OSError(e,'owned installer trace failed')
    return value

def string_at(pid,address):
    out=bytearray()
    for offset in range(0,128,8):
        out.extend((ptrace(2,pid,address+offset)&((1<<64)-1)).to_bytes(8,'little'))
        if 0 in out:return bytes(out).split(b'\0',1)[0]
    return None

def interrupt_before_commit(args,output,expected_sha,sha):
    guard()
    if Path('/etc/xandbox-systemd-install-fixture').read_text()!='Xandbox owned initial installer fixture v1\n' or os.uname().machine!='x86_64':raise RuntimeError('owned x86 installer L1 required')
    if args[:2]!=['/usr/libexec/xandbox-install-bootstrap','apply'] or len(args)!=8:raise RuntimeError('fixed installer child required')
    # Popen(preexec SIGSTOP) would deadlock its exec-error pipe; fork explicitly.
    pid=os.fork()
    if pid==0:
        try:
            fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            os.dup2(fd,1);os.dup2(fd,2);os.close(fd)
            null=os.open('/dev/null',os.O_RDONLY);os.dup2(null,0);os.close(null)
            ptrace(0,0);os.kill(os.getpid(),signal.SIGSTOP)
            os.execve(args[0],args,{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        finally:os._exit(91)
    threads={pid};hit=False;executed=False;options=1|8|16|(1<<20);end=time.monotonic()+60;other_exits=0;last_leaf='none'
    try:
        got,status=os.waitpid(pid,0)
        if got!=pid or not os.WIFSTOPPED(status) or os.WSTOPSIG(status)!=signal.SIGSTOP:raise RuntimeError('owned trace handshake failed')
        ptrace(0x4200,pid,0,options);ptrace(24,pid)
        while threads:
            if time.monotonic()>=end:raise RuntimeError('owned trace deadline')
            tid,status=os.waitpid(-1,0x40000000|os.WNOHANG)
            if not tid:time.sleep(.0005);continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                threads.discard(tid)
                if not hit and tid==pid:
                    # Closed private diagnostic only, never replay a raw child
                    # error/config/credential. A runtime thread exit is not the
                    # installer process exit; wait for the actual main Tgid.
                    raw=Path(output).read_bytes()[:8192]
                    refusal=b'xandbox-install: installation unconfirmed; preserve the exact request and inspect before reconcile\n'
                    root=Path('/etc/xandbox-install')
                    diag={'main_exit':os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status),'exec_pin_seen':executed,'other_thread_exits':other_exits,'last_known_leaf':last_leaf,'closed_cli_refusal':raw==refusal,'output_bytes':len(raw),'intent_present':(root/'intent.json').is_file(),'commit_present':(root/'commit.json').is_file(),'state_created':Path('/srv/xi/s').is_dir()}
                    # The TEST operator's stdout is deliberately /dev/null.
                    # Send this CLOSED private diagnostic to the captured tty,
                    # not to stdout and never relay raw child output.
                    with open('/dev/console','w') as console:
                        console.write('XANDBOX_INSTALL_PRIVATE_TRACE '+json.dumps(diag,sort_keys=True)+'\n');console.flush()
                    raise RuntimeError('actual installer main exited before fixed commit boundary')
                other_exits+=1
                continue
            if not os.WIFSTOPPED(status):raise RuntimeError('unexpected trace state')
            sig=os.WSTOPSIG(status);event=status>>16
            if event==3:
                child=ctypes.c_ulonglong();ptrace(0x4201,tid,0,ctypes.addressof(child));threads.add(child.value)
            if event==4:
                if tid!=pid or sha(Path('/proc',str(pid),'exe'))!=expected_sha:raise RuntimeError('owned installer exec pin mismatch')
                executed=True
            if sig==(signal.SIGTRAP|0x80) and executed and not hit:
                r=Registers();ptrace(12,tid,0,ctypes.addressof(r))
                leaf=string_at(tid,r.rsi) if r.orig_rax==257 and r.rax==((1<<64)-errno.ENOSYS) else None
                if leaf:
                    known={b'plan.json',b'.lock',b'ref.json',b'manifest.json',b'xandbox-install-bootstrap',b'backend.json',b'auth.json',b'gateway.json',b'tls.pem',b'tls.key',b'firecracker',b'jailer',b'kernel',b'initrd',b'workspace',b'daemon',b'gateway',b'ingress',b'launcher',b'node',b'ready',b'template',b'warden',b'.intent.next',b'intent.json',b'.commit.next',b'commit.json'}
                    if leaf in known:last_leaf=leaf.decode()
                if leaf==b'.commit.next':
                    if os.readlink('/proc/'+str(tid)+'/fd/'+str(ctypes.c_int(r.rdi).value))!='/etc/xandbox-install':raise RuntimeError('commit dirfd outside fixed install root')
                    if sha(Path('/proc',str(pid),'exe'))!=expected_sha:raise RuntimeError('installer identity drift')
                    hit=True;os.kill(pid,signal.SIGKILL)
                    continue
            forward=0 if sig in (signal.SIGTRAP,signal.SIGSTOP,signal.SIGTRAP|0x80) else sig
            try:ptrace(24,tid,0,forward)
            except OSError as e:
                # exit_group can kill a known stopped thread before resume.
                # ESRCH is NOT completion or success: keep it in threads until
                # its actual terminal wait event, under the original deadline.
                if e.errno!=errno.ESRCH:raise
        if not hit:raise RuntimeError('no exact commit entry observed')
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
            if threads:raise RuntimeError('traced owned installer children not reaped')
