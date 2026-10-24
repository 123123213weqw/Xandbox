"""Pure owned managed fixture controls, NOT root/systemd/ptrace/TLS/KVM proof."""
import copy
import ctypes
import hashlib
import inspect
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import build_systemd_managed as builder
import managed_fixture_trace as trace
import systemd_managed_guest as guest
from build_systemd_host import build,configure_root
from kvm_systemd_host import harness_files,validate_managed_reply

class ManagedControls(unittest.TestCase):
    def test_exclusive_fresh_composition_and_source_boundary(self):
        self.assertEqual(len(builder.ASSETS),16);self.assertEqual(len(builder.ROLES),13)
        self.assertEqual(builder.PRODUCTION_SOURCE,'9db960370be20ad7c2570698e265c3b092eb9562')
        names=harness_files(True,False,False,managed=True)
        self.assertEqual(len(names),15);self.assertEqual(len(set(names)),15)
        for n in ('build_systemd_managed.py','systemd_managed_guest.py','managed_fixture_trace.py'):self.assertIn(n,names)
        for kwargs in ({'deployed':False},{'ingress':True},{'readiness':True},{'release':True},{'install':True}):
            base=dict(deployed=True,ingress=False,readiness=False,release=False,install=False,managed=True);base.update(kwargs)
            with self.assertRaises(ValueError):harness_files(**base)
        for other in ('install_assets','release_assets','readiness_assets','ingress_assets','deployment_assets'):
            with self.assertRaises(ValueError):build(ubuntu=None,alpine=None,probe=None,output_disk=None,output_initrd=None,managed_assets={},**{other:{}})
    def test_image_assembly_has_no_ordinary_service_or_installed_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root';root.mkdir();(root/'etc/cloud').mkdir(parents=True)
            source=Path(tmp)/'source';source.write_bytes(b'test-only bytes never executed');pin=hashlib.sha256(source.read_bytes()).hexdigest()
            configure_root(root,source);builder.configure(root,{k:{'path':str(source),'sha256':pin} for k in builder.ASSETS})
            for n in ('etc/xandbox-install','etc/xandbox-install-fixture','srv/xi','srv/xandbox-releases','etc/systemd/system/xandbox.service','etc/systemd/system/xandbox-ingress.service'):
                self.assertFalse((root/n).exists())
            self.assertEqual((root/'etc/xandbox-systemd-managed-fixture').read_text(),builder.MARKER)
            self.assertEqual((root/builder.CONFIG).stat().st_mode&0o777,0o700)
            meta=json.loads((root/builder.CONFIG/'programs.json').read_bytes())
            case_path=root/builder.CONFIG/'maintenance-case.json'
            self.assertEqual(guest.decode_maintenance_case(json.loads(case_path.read_bytes())),'populated-gate')
            self.assertEqual(case_path.stat().st_mode&0o777,0o600)
            self.assertEqual(meta['setup']['path'],'/usr/libexec/xandbox-managed-fixture')
            self.assertEqual(meta['install']['path'],guest.BOOTSTRAP)
            for name in builder.SCRIPTS:self.assertEqual((root/'opt/xandbox'/name).stat().st_mode&0o777,0o444)
            self.assertIn('systemd_managed_guest.py',(root/'etc/systemd/system/xandbox-systemd-operator.service').read_text())
            with self.assertRaises(ValueError):builder.configure(root,{k:{} for k in builder.ASSETS})
    def test_closed_flags_and_independent_positive_measurements(self):
        for case in builder.MAINTENANCE_CASES:
          for op,flags in (('managed-probe',guest.PROBE_FLAGS),('managed-checkpoint',guest.checkpoint_flags(case)),('managed-recover',guest.RECOVERY_FLAGS)):
            value={'maintenance_case':case,**{k:True for k in flags}}
            if op=='managed-checkpoint':value.update(stop_observed_ms=5.,durable_reclaim_observed_ms=20.)
            validate_managed_reply(op,value,case)
            for key in flags:
                for bad in (False,1,None):
                    with self.assertRaises(AssertionError):validate_managed_reply(op,{**value,key:bad},case)
                bad=copy.deepcopy(value);del bad[key]
                with self.assertRaises(AssertionError):validate_managed_reply(op,bad,case)
            with self.assertRaises(AssertionError):validate_managed_reply(op,{**value,'private_ref':'not-exported'},case)
            with self.assertRaises(AssertionError):validate_managed_reply(op,{k:v for k,v in value.items() if k!='maintenance_case'},case)
            for wrong in ('unknown',True,None,*[c for c in builder.MAINTENANCE_CASES if c!=case]):
                with self.assertRaises(AssertionError):validate_managed_reply(op,{**value,'maintenance_case':wrong},case)
            if op=='managed-checkpoint':
                for n in (True,0,-1,float('inf'),float('nan'),45001):
                    with self.assertRaises(AssertionError):validate_managed_reply(op,{**value,'stop_observed_ms':n},case)
                with self.assertRaises(AssertionError):validate_managed_reply(op,{**value,'durable_reclaim_observed_ms':1},case)
                other=next(c for c in builder.MAINTENANCE_CASES if c!=case)
                crossed={'maintenance_case':case,**{k:True for k in guest.checkpoint_flags(other)},'stop_observed_ms':5.,'durable_reclaim_observed_ms':20.}
                with self.assertRaises(AssertionError):validate_managed_reply(op,crossed,case)
    def test_closed_case_metadata_and_no_image_changes_for_invalid_case(self):
        for case in builder.MAINTENANCE_CASES:
            self.assertEqual(guest.decode_maintenance_case({'version':1,'case':case}),case)
            self.assertTrue(set(guest.CASE_FLAGS[case]).isdisjoint(guest.CASE_FLAGS[next(c for c in builder.MAINTENANCE_CASES if c!=case)]))
        for bad in ({},{'version':True,'case':'active-stop'},{'version':2,'case':'active-stop'},{'version':1,'case':True},{'version':1,'case':'other'},{'version':1,'case':'active-stop','extra':1},None):
            with self.assertRaises(RuntimeError):guest.decode_maintenance_case(bad)
        for bad in ('other',True,None):
            with self.assertRaises((RuntimeError,TypeError)):guest.checkpoint_flags(bad)
            with self.assertRaises(ValueError):builder.configure(None,{},maintenance_case=bad)
        with self.assertRaises(ValueError):build(ubuntu=None,alpine=None,probe=None,output_disk=None,output_initrd=None,managed_case='active-stop')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root';root.mkdir();(root/'etc/cloud').mkdir(parents=True)
            source=Path(tmp)/'source';source.write_bytes(b'pure bytes not executed');pin=hashlib.sha256(source.read_bytes()).hexdigest()
            configure_root(root,source);builder.configure(root,{k:{'path':str(source),'sha256':pin} for k in builder.ASSETS},maintenance_case='active-stop')
            self.assertEqual(guest.decode_maintenance_case(json.loads((root/builder.CONFIG/'maintenance-case.json').read_bytes())),'active-stop')
    def test_active_branch_never_prestops_and_cold_case_is_bound(self):
        s=inspect.getsource(guest.active_stop_recover)
        for forbidden in ('systemctl','os.fork','os.kill','cgroup.procs','group.mkdir'):
            self.assertNotIn(forbidden,s)
        self.assertLess(s.index('guard()'),s.index('ingress.ingress_identity()'))
        self.assertLess(s.index('policy_state(1)'),s.index("call('recover-policy'"))
        with patch.object(guest,'guard',side_effect=RuntimeError('unmarked')),patch.object(guest,'call') as call,patch.object(guest.ingress,'ingress_identity') as observation:
            with self.assertRaises(RuntimeError):guest.active_stop_recover('a'*32,'b'*32,None)
            call.assert_not_called();observation.assert_not_called()
        self.assertIn("old['maintenance_case']!=maintenance_case()",inspect.getsource(guest.recover))
        checkpoint=inspect.getsource(guest.checkpoint)
        self.assertIn("if case=='populated-gate':",checkpoint)
        self.assertIn('else:active_stop_recover(',checkpoint)
    def test_old_key_refusal_uses_original_transport_but_401_closes(self):
        original=object();calls=[]
        class Connection:
            sock=original
            def close(self):self.sock=None
        conn=Connection()
        def request(method,path,**kwargs):
            calls.append(kwargs)
            if kwargs.get('expected')==401:
                self.assertIs(kwargs['connection'],conn);self.assertIs(kwargs['expected_transport'],original)
                self.assertIs(conn.sock,original);conn.sock=None
            elif len(calls)==3:self.assertNotIn('connection',kwargs)
        with patch.object(guest.Path,'read_bytes',return_value=b'{"tokens":{"alpha":"synthetic-test-only"}}'),patch.object(guest.ingress,'TLSHTTP',return_value=conn),patch.object(guest.ingress,'transport_identity',return_value=original),patch.object(guest.ingress,'tls_call',side_effect=request):
            guest.old_key_rejection()
        self.assertEqual(len(calls),3);self.assertIsNone(conn.sock)
        conn=Connection();conn.sock=original
        with patch.object(guest.Path,'read_bytes',return_value=b'{"tokens":{"alpha":"synthetic-test-only"}}'),patch.object(guest.ingress,'TLSHTTP',return_value=conn),patch.object(guest.ingress,'transport_identity',return_value=original),patch.object(guest.ingress,'tls_call'):
            with self.assertRaisesRegex(RuntimeError,'401 transport did not close'):guest.old_key_rejection()
        self.assertIsNone(conn.sock)
    def test_real_receipt_and_exact_refusal_not_exec_failure(self):
        v={'version':1,'revision':3,'files_committed':True,'manager_reconciled':True,'production_ready':False}
        def reply(v):return subprocess.CompletedProcess([],0,json.dumps(v).encode(),b'')
        guest.receipt(reply(v),3);guest.receipt(subprocess.CompletedProcess([],1,b'',guest.install.ERROR),3,1)
        for k,bad in (('revision',True),('revision',2),('version',True),('manager_reconciled',1),('files_committed',1),('production_ready',0)):
            with self.assertRaises(RuntimeError):guest.receipt(reply({**v,k:bad}),3)
        for code,out,err in ((-9,b'',guest.install.ERROR),(1,b'',b'exec denied'),(1,b'private',guest.install.ERROR),(1,b'',guest.install.ERROR+b'extra')):
            with self.assertRaises(RuntimeError):guest.receipt(subprocess.CompletedProcess([],code,out,err),3,1)
    def test_fixed_cli_shape_no_host_tasks_or_service_selection(self):
        req='a'*32;old='b'*32;p=guest.CONFIG/'rotation-3.json'
        self.assertEqual(guest.arguments('recover-policy',req,p,2,old),[guest.CLI,'recover-policy','-plan',str(p),'-expected-revision','2','-request-id',req,'-supersedes-request-id',old])
        for op,request,plan,expected,sup in (('restart',req,p,2,old),('recover-policy',req,Path('/tmp/source.json'),2,old),('recover-policy',req,p,1,old),('recover-policy',req,p,2,req),('reconfigure',req,p,2,old),('status',req,None,None,None)):
            with self.assertRaises(RuntimeError):guest.arguments(op,request,plan,expected,sup)
    def test_unmarked_operations_cannot_fork_start_or_emit_failure(self):
        with patch.object(guest,'guard',side_effect=RuntimeError('unmarked')),patch.object(guest,'setup') as setup,patch.object(guest,'failure') as failure:
            with self.assertRaises(RuntimeError):guest.entry()
            setup.assert_not_called();failure.assert_not_called()
        with patch.object(trace,'guard',side_effect=RuntimeError('unmarked')),patch.object(trace.os,'fork') as fork:
            with self.assertRaises(RuntimeError):trace.interrupt([],None,None,None,'policy-activation')
            fork.assert_not_called()
        with patch.object(guest,'guard',side_effect=RuntimeError('unmarked')),patch.object(guest,'run') as run:
            with self.assertRaises(RuntimeError):guest.populated_negative_then_recover('a'*32,'b'*32,None)
            run.assert_not_called()
    def test_only_exact_published_policy_counts_as_activation_cut(self):
        request='a'*32
        envelope={'version':1,'revision':2,'expected_revision':1,'request_id':request,'snapshot':{'epoch':2}}
        intent={'version':1,'expected_revision':1,'request_id':request}
        self.assertTrue(trace.activation_candidate(envelope,intent,2,request))
        for e,i in (({**envelope,'revision':1},{}),({**envelope,'request_id':'b'*32},intent),(envelope,{**intent,'request_id':'b'*32}),({**envelope,'version':True},intent),(envelope,{**intent,'expected_revision':True}),({**envelope,'snapshot':{'epoch':True}},intent)):
            self.assertFalse(trace.activation_candidate(e,i,2,request))
        s=inspect.getsource(trace.interrupt)
        self.assertIn('if intent_path.is_file():',s)
        self.assertIn("hashlib.sha256(raw).hexdigest()!=intent.get('new_payload_sha256')",s)
        self.assertLess(s.index('if activation_candidate'),s.index('os.kill(pid,signal.SIGKILL)'))
    def test_trace_frame_sockaddr_bounds_and_own_child_only(self):
        self.assertEqual(ctypes.sizeof(trace.Registers),27*8)
        data=b'\x01\x00'+trace.OPERATOR+b'\0';data+=bytes((8-len(data)%8)%8)
        def peek(request,pid,address):return int.from_bytes(data[address:address+8],'little')
        with patch.object(trace,'ptrace',side_effect=peek):
            self.assertEqual(trace.sockaddr_at(1,0,len(data)),trace.OPERATOR)
            self.assertIsNone(trace.sockaddr_at(1,0,2));self.assertIsNone(trace.sockaddr_at(1,0,111))
        s=inspect.getsource(trace.interrupt)
        for text in ('os.fork()',"sha(Path('/proc',str(pid),'exe'))!=expected_sha",'threads.discard(tid)','time.monotonic()+60','os.waitpid'):
            self.assertIn(text,s)
        self.assertNotIn('PTRACE_ATTACH',s)
    def test_real_expiry_wait_precedes_original_budget_busy_writer(self):
        s=inspect.getsource(guest.checkpoint)
        self.assertLess(s.index('wait_pending_expiry()'),s.index('base.progressing_writer('))
        self.assertLess(s.index('drain.state(\'drained\',drained)'),s.index("drain.change('resume'"))
        self.assertIn("install.stop_destroy(rows[0][0],'alpha',True)",s)
        self.assertNotIn('60001',s)
    def test_population_negative_cannot_advance_before_exact_empty_retry(self):
        s=inspect.getsource(guest.populated_negative_then_recover)
        self.assertLess(s.index('want=1'),s.index('os.kill(pid,signal.SIGKILL)'))
        self.assertLess(s.index('os.waitpid(pid,0)'),s.index("save(CONFIG/'active-client.json'"))
        self.assertIn("set(events)!={'populated 0','frozen 0'}",s)
        self.assertIn("policy_state(1)",s)
        self.assertNotIn('group.rmdir',s)
    def test_cold_probe_never_activates_regenerates_or_rewrites(self):
        s=inspect.getsource(guest.probe)
        self.assertIn('sources_absent()',s);self.assertIn('drain.probe_mode()',s)
        for forbidden in ("call('reconcile'","run('systemctl'",'setup()',"save("):
            self.assertNotIn(forbidden,s)
        self.assertIn('probe()',inspect.getsource(guest.recover))
        self.assertNotIn('input/',inspect.getsource(guest.recover))
    def test_diagnostics_precede_failure_sentinel(self):
        s=inspect.getsource(guest.failure)
        self.assertLess(s.index('traceback.print_exc'),s.index('XANDBOX_SYSTEMD_HOST_FAILED'))
        self.assertLess(s.index("subprocess.run(['journalctl'"),s.index('XANDBOX_SYSTEMD_HOST_FAILED'))
        self.assertIn('c.flush()',s)

if __name__=='__main__':unittest.main()
