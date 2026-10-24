"""Pure trace/register/protocol MODELS. Never actual root/ptrace/KVM evidence."""
from contextlib import nullcontext
import copy
import ctypes
import errno
import hashlib
import inspect
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import managed_fixture_trace as trace
import systemd_managed_guest as guest
import build_systemd_managed as builder

REQUEST='a'*32;PENDING='b'*32

def declaration():
    payload=b'{"revision":1}\n';intent={'version':1,'expected_revision':1,'request_id':PENDING}
    record={'version':1,'expected_revision':1,'request_id':REQUEST,'replaces_request_id':PENDING,'base_commit_sha256':'c'*64,'config_sha256':'d'*64,'initial_policy_sha256':'e'*64,'old_payload_sha256':hashlib.sha256(payload).hexdigest(),'previous_snapshot_sha256':'f'*64,'new_payload_sha256':'1'*64,'source':{'path':'/etc/xandbox-managed-fixture/sources/snapshot-replacement-2a.json','sha256':'2'*64},'previous_intent':intent}
    return (json.dumps(record,separators=(',',':'))+'\n').encode(),payload,intent

class DraftControls(unittest.TestCase):
    def test_closed_argv_and_prefix_requires_distinct_complete_request_not_common_header(self):
        args=guest.arguments('replace-pending-policy',REQUEST,guest.CONFIG/'rotation-replacement-2a.json',1,PENDING)
        trace.trace_shape(args,'supersession-draft-short',2,REQUEST)
        discard=guest.draft_arguments(PENDING,'c'*64);trace.trace_shape(discard,'supersession-draft-discard',1,PENDING)
        for changed in (discard+['--force'],discard[:-1],discard[:3]+['01']+discard[4:],discard[:6]+['-path','/tmp/draft'],discard[:5]+[REQUEST]+discard[6:]):
            with self.assertRaises(RuntimeError):trace.trace_shape(changed,'supersession-draft-discard',1,PENDING)
        for pending,sha in ((True,'c'*64),(PENDING,'C'*64),(PENDING,'c'),('b'*31,'c'*64)):
            with self.assertRaises(RuntimeError):guest.draft_arguments(pending,sha)
        with patch.object(trace,'guard'),patch.object(trace.os,'fork') as fork:
            with self.assertRaises(RuntimeError):trace.interrupt(discard+['extra'],None,None,None,'supersession-draft-discard',1,PENDING)
            fork.assert_not_called()
        raw,payload,intent=declaration();prefix=trace.short_draft_prefix(raw,REQUEST,PENDING,payload,intent)
        self.assertTrue(64<=len(prefix)<=160);self.assertIn(REQUEST.encode(),prefix);self.assertNotIn(PENDING.encode(),prefix)
        with self.assertRaises(json.JSONDecodeError):json.loads(prefix)
        other=json.loads(raw);other['request_id']='f'*32;other=(json.dumps(other,separators=(',',':'))+'\n').encode()
        self.assertNotEqual(prefix,trace.short_draft_prefix(other,'f'*32,PENDING,payload,intent))

    def test_prefix_rejects_authority_mismatch_noncanonical_complete_or_oversize_input(self):
        raw,payload,intent=declaration()
        for field,value in (('version',True),('expected_revision',2),('request_id','f'*32),('replaces_request_id',REQUEST),('old_payload_sha256','f'*64),('previous_intent',{}),('extra',1)):
            record=json.loads(raw);record[field]=value
            with self.assertRaises(RuntimeError):trace.short_draft_prefix((json.dumps(record,separators=(',',':'))+'\n').encode(),REQUEST,PENDING,payload,intent)
        for bad in (b'',raw[:80],raw+b' ',raw*100,raw.decode()):
            with self.assertRaises((RuntimeError,ValueError)):trace.short_draft_prefix(bad,REQUEST,PENDING,payload,intent)
        with self.assertRaises(RuntimeError):trace.short_draft_prefix(raw,REQUEST,PENDING,b'{"revision":2}',intent)
        for bad in (0,True,-1,32769):
            with patch.object(trace,'ptrace') as peek:
                with self.assertRaises(RuntimeError):trace.bytes_at(1,0,bad)
                peek.assert_not_called()
        padded=raw+bytes(8)
        with patch.object(trace,'ptrace',side_effect=lambda op,pid,address: int.from_bytes(padded[address:address+8],'little')):
            self.assertEqual(trace.bytes_at(1,0,len(raw)),raw)

    def test_distinct_current_absence_receipt_rejects_policy_or_historic_receipt(self):
        for removed in (True,False):
            value={'version':1,'revision':1,'pending_request_id':PENDING,'requested_draft_sha256':'c'*64,'draft_removed':removed,'draft_absent':True,'ingress_stopped':True,'production_ready':False}
            result=lambda v:subprocess.CompletedProcess([],0,json.dumps(v).encode(),b'')
            self.assertEqual(guest.draft_receipt(result(value),PENDING,'c'*64,removed),value)
            for key,bad in (('version',True),('revision',2),('pending_request_id',REQUEST),('requested_draft_sha256','d'*64),('draft_removed',not removed),('draft_absent',False),('ingress_stopped',False),('production_ready',True),('files_committed',True)):
                with self.assertRaises(RuntimeError):guest.draft_receipt(result({**value,key:bad}),PENDING,'c'*64,removed)
        with patch.object(guest,'guard') as guard,patch.object(guest.subprocess,'run') as run:
            for kwargs in ({'want':True},{'want':2},{'removed':1}):
                with self.assertRaises(RuntimeError):guest.draft_call(PENDING,'c'*64,**kwargs)
            guard.assert_not_called();run.assert_not_called()

    def test_fixed_private_draft_fd_mode_link_inode_size_and_nofollow_inventory(self):
        real_stat=os.stat
        for kind in ('ok','mode','link','wrong-path','wrong-inode','size','symlink','directory'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);target=root/'.policy-supersession.next';target.write_bytes(b'prefix');target.chmod(0o600)
                if kind=='mode':target.chmod(0o644)
                if kind=='link':os.link(target,root/'alias')
                if kind=='symlink':target.rename(root/'real');target.symlink_to(root/'real')
                if kind=='directory':target.unlink();target.mkdir(mode=0o700)
                def procstat(path,*a,**kw):
                    if str(path)=='/proc/321/fd/7':
                        if kind=='wrong-inode':return SimpleNamespace(st_dev=-1,st_ino=-1)
                        return real_stat(target)
                    return real_stat(path,*a,**kw)
                with patch.object(trace,'ROOT',root),patch.object(trace.os,'readlink',return_value=str(root/'different' if kind=='wrong-path' else target)),patch.object(trace.os,'stat',side_effect=procstat):
                    if kind=='ok':self.assertEqual(trace.draft_file(321,7,6)[1],b'prefix')
                    else:
                        with self.assertRaises((RuntimeError,OSError)):trace.draft_file(321,7,5 if kind=='size' else 6)
        for size in (True,-1,32769):
            with patch.object(trace.os,'readlink') as link:
                with self.assertRaises(RuntimeError):trace.draft_file(321,7,size)
                link.assert_not_called()

    def test_trace_shortens_only_one_fixed_write_and_requires_actual_successful_short_exit(self):
        for fail_result in (False,True):
            with self.subTest(fail_result=fail_result),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);raw,payload,intent=declaration();(root/'gateway-policy.json').write_bytes(payload);(root/'rotation-intent.json').write_text(json.dumps(intent))
                prefix=trace.short_draft_prefix(raw,REQUEST,PENDING,payload,intent)
                args=guest.arguments('replace-pending-policy',REQUEST,guest.CONFIG/'rotation-replacement-2a.json',1,PENDING)
                stops=[(123,(signal.SIGSTOP<<8)|127),(123,(4<<16)|(signal.SIGTRAP<<8)|127),(123,((signal.SIGTRAP|128)<<8)|127),(123,((signal.SIGTRAP|128)<<8)|127),(123,signal.SIGKILL)]
                frames=iter([dict(orig_rax=1,rax=(1<<64)-errno.ENOSYS,rdi=7,rsi=0,rdx=len(raw)),dict(orig_rax=1,rax=len(prefix)-int(fail_result),rdi=7)])
                changes=[]
                def ptrace(op,pid,address=0,data=0):
                    if op==12:
                        frame=ctypes.cast(data,ctypes.POINTER(trace.Registers)).contents
                        for key,value in next(frames).items():setattr(frame,key,value)
                    if op==13:
                        frame=ctypes.cast(data,ctypes.POINTER(trace.Registers)).contents;changes.append((pid,frame.orig_rax,frame.rdi,frame.rsi,frame.rdx))
                    return 0
                node=SimpleNamespace(st_dev=1,st_ino=2)
                with patch.object(trace,'ROOT',root),patch.object(trace,'guard'),patch.object(trace.os,'fork',return_value=123),patch.object(trace.os,'waitpid',side_effect=stops),patch.object(trace.os,'kill') as kill,patch.object(trace,'ptrace',side_effect=ptrace),patch.object(trace.os,'readlink',return_value=str(root/'.policy-supersession.next')),patch.object(trace,'bytes_at',return_value=raw),patch.object(trace,'draft_file',side_effect=[(node,b''),(node,prefix)]),patch.object(trace,'bounded_trace_wait',return_value=nullcontext()) as alarm:
                    if fail_result:
                        with self.assertRaisesRegex(RuntimeError,'short syscall result'):trace.interrupt(args,'unused','pin',lambda path:'pin','supersession-draft-short',2,REQUEST)
                    else:self.assertEqual(trace.interrupt(args,'unused','pin',lambda path:'pin','supersession-draft-short',2,REQUEST),{'sha256':hashlib.sha256(prefix).hexdigest(),'bytes':len(prefix)})
                    self.assertEqual(changes,[(123,1,7,0,len(prefix))]);kill.assert_called_once_with(123,signal.SIGKILL);alarm.assert_called_once_with(True)

    def test_discard_cut_requires_successful_fixed_unlink_then_root_fsync_not_other_directory(self):
        for good_sync in (True,False):
            with self.subTest(good_sync=good_sync),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);target=root/'.policy-supersession.next';target.write_bytes(b'known draft');sha=hashlib.sha256(target.read_bytes()).hexdigest();args=guest.draft_arguments(PENDING,sha)
                stops=[(123,(signal.SIGSTOP<<8)|127),(123,(4<<16)|(signal.SIGTRAP<<8)|127)]+[(123,((signal.SIGTRAP|128)<<8)|127)]*3+[(123,signal.SIGKILL)]
                frames=iter([dict(orig_rax=263,rax=(1<<64)-errno.ENOSYS,rdi=7,rsi=0),dict(orig_rax=263,rax=0,rdi=7),dict(orig_rax=74,rax=0,rdi=8)])
                def ptrace(op,pid,address=0,data=0):
                    if op==12:
                        frame=ctypes.cast(data,ctypes.POINTER(trace.Registers)).contents
                        values=next(frames)
                        if values['orig_rax']==263 and values['rax']==0:target.unlink() # MODEL kernel effect
                        for key,value in values.items():setattr(frame,key,value)
                    if op==13:self.fail('discard observer must not mutate syscall registers')
                    return 0
                link=lambda path:str(root) if path.endswith('/7') or good_sync else '/different/directory'
                with patch.object(trace,'ROOT',root),patch.object(trace,'guard'),patch.object(trace.os,'fork',return_value=123),patch.object(trace.os,'waitpid',side_effect=stops),patch.object(trace.os,'kill'),patch.object(trace,'ptrace',side_effect=ptrace),patch.object(trace,'string_at',return_value=b'.policy-supersession.next'),patch.object(trace.os,'readlink',side_effect=link),patch.object(trace,'bounded_trace_wait',return_value=nullcontext()):
                    if good_sync:self.assertIsNone(trace.interrupt(args,'unused',sha,lambda path:sha,'supersession-draft-discard',1,PENDING))
                    else:
                        with self.assertRaisesRegex(RuntimeError,'exited before managed cut'):trace.interrupt(args,'unused',sha,lambda path:sha,'supersession-draft-discard',1,PENDING)

    def test_two_cases_keep_busy_budget_fences_source_loss_and_complete_tail(self):
        for name in ('draft-discard','draft-discard-cut'):self.assertIn(name,builder.MAINTENANCE_CASES);self.assertIn(name,guest.CASE_FLAGS)
        source=inspect.getsource(guest.draft_case)
        self.assertLess(source.index('want=1'),source.index('writer=new_busy_writer'))
        self.assertLess(source.index('writer=new_busy_writer'),source.index('removed=True'))
        self.assertIn("remove_source('replacement-2a')",source);self.assertIn("call('verify',1,want=1)",source)
        self.assertNotIn('.unlink(',source);self.assertNotIn("'systemctl'",source)
        self.assertIn('supersession-draft-discard',source);self.assertIn('removed=False',source)
        checkpoint=inspect.getsource(guest.checkpoint)
        self.assertLess(checkpoint.index("drain.busy(rows[0][0],writer['id'])",checkpoint.index("late_observation('before-stop'")),checkpoint.index('install.stop_destroy(rows[0][0]'))

if __name__=='__main__':unittest.main()
