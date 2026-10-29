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
        self.assertEqual(builder.PRODUCTION_SOURCE,'00dc99de10b52d6988b52f12760f61e3fd43fb3d')
        names=harness_files(True,False,False,managed=True)
        self.assertEqual(len(names),16);self.assertEqual(len(set(names)),16)
        self.assertIn('systemd_fixture_provenance.py',names)
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
    def test_only_explicit_warm_operator_starts_already_stopped_main(self):
        with patch.object(guest,'guard'),patch.object(guest,'run',side_effect=['0','inactive','']) as run,patch.object(guest.ingress,'tls_ready') as ready,patch.object(guest,'call') as call:
            guest.restart_after_explicit_warm_stop('a'*32)
            self.assertEqual(run.call_args_list[-1].args,('systemctl','start',guest.base.UNIT));ready.assert_called_once_with();call.assert_called_once_with('reconcile',3,'a'*32)
        for observed in (['42'],['0','active']):
            with patch.object(guest,'guard'),patch.object(guest,'run',side_effect=observed) as run,patch.object(guest,'call') as call:
                with self.assertRaisesRegex(RuntimeError,'explicit warm main stop required'):guest.restart_after_explicit_warm_stop('a'*32)
                self.assertFalse(any(c.args==('systemctl','start',guest.base.UNIT) for c in run.call_args_list));call.assert_not_called()
        with patch.object(guest,'guard',side_effect=RuntimeError('unmarked')),patch.object(guest,'run') as run:
            with self.assertRaises(RuntimeError):guest.restart_after_explicit_warm_stop('a'*32)
            run.assert_not_called()
        s=inspect.getsource(guest.checkpoint)
        self.assertLess(s.index("PHASE='managed-continuity'"),s.index('restart_after_explicit_warm_stop(request)'))
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

    def test_supersession_trace_shapes_are_closed_before_fork(self):
        req='a'*32;old='b'*32
        args=guest.arguments('replace-pending-policy',req,guest.CONFIG/'rotation-replacement-2a.json',1,old)
        for mode in ('supersession-proposal','supersession-visible'):trace.trace_shape(args,mode,2,req)
        trace.trace_shape(guest.arguments('reconfigure',req,guest.CONFIG/'rotation-2.json',1),'rotation-proposal',2,req)
        for mode,rev,request,changed in (('other',2,req,args),('supersession-proposal',True,req,args),('supersession-proposal',3,req,args),('supersession-proposal',2,old,args),('supersession-proposal',2,req,args[:-1]+[req]),('supersession-proposal',2,req,args[:3]+['/tmp/source']+args[4:]),('supersession-proposal',2,req,args+['extra'])):
            with self.assertRaises(RuntimeError):trace.trace_shape(changed,mode,rev,request)
        with patch.object(trace,'guard'),patch.object(trace.os,'fork') as fork:
            with self.assertRaises(RuntimeError):trace.interrupt(args+['extra'],None,None,None,'supersession-proposal',2,req)
            fork.assert_not_called()
        for plan in ('rotation-2.json','rotation-replacement-2a.json'):
            with self.assertRaises(RuntimeError):guest.arguments('replace-pending-policy',req,guest.CONFIG/plan,2,old)
        with self.assertRaises(RuntimeError):guest.arguments('reconfigure',req,guest.CONFIG/'rotation-replacement-2a.json',1)

    def test_proposal_predicates_distinguish_unconsumed_and_visible_epochs(self):
        req='a'*32;pin='c'*64
        env={'version':1,'revision':2,'expected_revision':1,'request_id':req,'snapshot':{'epoch':2}}
        intent={'version':1,'expected_revision':1,'request_id':req,'new_payload_sha256':pin}
        record={'version':1,'expected_revision':1,'request_id':req,'new_payload_sha256':pin}
        self.assertTrue(trace.proposal_candidate(env,intent,{'revision':1},2,req))
        self.assertTrue(trace.proposal_candidate(env,intent,{'revision':1},2,req,record))
        self.assertTrue(trace.proposal_candidate(env,intent,env,2,req,record,True))
        for installed,metadata,visible in (({'revision':2},record,False),({'revision':1},record,True),({'revision':True},record,False),({'revision':1},{**record,'expected_revision':True},False),({'revision':1},{**record,'request_id':'b'*32},False),({'revision':1},{**record,'new_payload_sha256':'d'*64},False),({'revision':1},record,1)):
            self.assertFalse(trace.proposal_candidate(env,intent,installed,2,req,metadata,visible))
        self.assertFalse(trace.proposal_candidate(env,{**intent,'new_payload_sha256':None},{'revision':1},2,req))
        s=inspect.getsource(trace.interrupt)
        self.assertIn('r.orig_rax==264',s);self.assertIn('r.orig_rax==74 and r.rax==0',s)
        self.assertLess(s.index("mode=='supersession-visible'"),s.index('if hit:'))

    def test_actual_file_cut_view_requires_exact_hashes_and_no_metadata_scratch(self):
        req='a'*32
        with tempfile.TemporaryDirectory() as tmp,patch.object(trace,'ROOT',Path(tmp)):
            root=Path(tmp);before=json.dumps({'revision':1}).encode()
            env={'version':1,'revision':2,'expected_revision':1,'request_id':req,'snapshot':{'epoch':2}}
            raw=json.dumps(env).encode();pin=hashlib.sha256(raw).hexdigest()
            intent={'version':1,'expected_revision':1,'request_id':req,'new_payload_sha256':pin}
            record={'version':1,'expected_revision':1,'request_id':req,'new_payload_sha256':pin,'old_payload_sha256':hashlib.sha256(before).hexdigest()}
            (root/'gateway-policy.json').write_bytes(before);(root/'.policy.next').write_bytes(raw)
            (root/'rotation-intent.json').write_text(json.dumps(intent));(root/'policy-supersession.json').write_text(json.dumps(record))
            self.assertTrue(trace.published_cut('rotation-proposal',2,req));self.assertTrue(trace.published_cut('supersession-proposal',2,req))
            (root/'.rotation-intent.next').write_bytes(b'unknown')
            with self.assertRaises(RuntimeError):trace.published_cut('supersession-proposal',2,req)
            (root/'.rotation-intent.next').unlink();(root/'gateway-policy.json').write_bytes(raw);(root/'.policy.next').unlink()
            self.assertTrue(trace.published_cut('supersession-visible',2,req))
            (root/'rotation-intent.json').write_text(json.dumps({**intent,'new_payload_sha256':'d'*64}))
            with self.assertRaises(RuntimeError):trace.published_cut('supersession-visible',2,req)

    def test_fixture_data_loss_never_unlinks_unknown_metadata_or_changed_data(self):
        import os
        with tempfile.TemporaryDirectory() as tmp,patch.object(guest,'guard'),patch.object(guest,'ROOT',Path(tmp)),patch.object(guest,'CONFIG',Path(tmp)/'config'):
            root=Path(tmp);p=root/'.policy.next';raw=b'known complete synthetic proposal data';pin=hashlib.sha256(raw).hexdigest()
            for mode,content in ((0o644,raw),(0o600,b'different'),(0o600,b'x'*32769)):
                p.write_bytes(content);p.chmod(mode)
                with self.assertRaises(RuntimeError):guest.remove_known_file(p,pin)
                self.assertTrue(p.exists())
            p.write_bytes(raw);p.chmod(0o600);other=root/'linked';os.link(p,other)
            with self.assertRaises(RuntimeError):guest.remove_known_file(p,pin)
            self.assertTrue(p.exists());other.unlink()
            for name in ('policy-supersession.json','.policy-supersession.next','rotation-intent.json'):
                meta=root/name;meta.write_bytes(raw);meta.chmod(0o600)
                with self.assertRaises(RuntimeError):guest.remove_known_file(meta,pin)
                self.assertTrue(meta.exists())
            p.unlink();target=root/'unknown-target';target.write_bytes(raw);p.symlink_to(target)
            with self.assertRaises(OSError):guest.remove_known_file(p,pin)
            self.assertTrue(target.exists());p.unlink()
            p.write_bytes(raw);p.chmod(0o600);guest.remove_known_file(p,pin);self.assertFalse(p.exists())

    def test_new_case_guards_and_epoch_order_cannot_bypass_production_cli(self):
        with patch.object(guest,'guard',side_effect=RuntimeError('unmarked')),patch.object(guest,'remove_source') as source,patch.object(guest,'remove_known_file') as data,patch.object(guest,'produce') as produce:
            with self.assertRaises(RuntimeError):guest.lose_a_proposal('a'*32,None)
            with self.assertRaises(RuntimeError):guest.new_case('supersession-repeat',None,None,None)
            source.assert_not_called();data.assert_not_called();produce.assert_not_called()
        s=inspect.getsource(guest.new_case)
        self.assertLess(s.index('lose_a_proposal(first'),s.index("call('replace-pending-policy',2,second"))
        self.assertLess(s.index("call('replace-pending-policy',2,secrets"),s.index("call('recover-policy',3,request"))
        self.assertIn("'supersession-visible'",s);self.assertNotIn("'systemctl'",s)
        s=inspect.getsource(guest.unconsumed_prelude)
        self.assertLess(s.index('wait_pending_expiry(True)'),s.index("produce('replacement2a')"))
        self.assertLess(s.index("remove_source('2')"),s.index("produce('replacement2a')"))
        self.assertNotIn('clock_settime',s)

    def test_ordinary_hot_rotation_uses_held_old_transport_and_never_restarts_ingress(self):
        class Connection:
            sock=object()
            def close(self):self.sock=None
        conn=Connection();transport=object();calls=[]
        def tls(*a,**kw):
            calls.append(kw)
            if kw.get('expected')==401:
                self.assertIs(kw['connection'],conn);self.assertIs(kw['expected_transport'],transport)
                self.assertEqual(kw['token'],'synthetic-old');conn.sock=None
        with patch.object(guest,'guard'),patch.object(guest.ingress,'client',return_value={'tokens':{'alpha':'synthetic-old'}}),patch.object(guest.ingress,'ingress_identity',return_value=(1,2,3,4)),patch.object(guest.ingress,'TLSHTTP',return_value=conn),patch.object(guest.ingress,'transport_identity',return_value=transport),patch.object(guest.ingress,'tls_call',side_effect=tls),patch.object(guest,'produce') as produce,patch.object(guest,'call') as call,patch.object(guest,'save'),patch.object(guest,'bind_observers'),patch.object(guest.ingress,'tls_ready'),patch.object(guest,'policy_state'):
            request=guest.ordinary_hot_step(2)
            produce.assert_called_once_with('rotation2long')
            call.assert_called_once_with('reconfigure',2,request,guest.CONFIG/'rotation-2.json',1)
        self.assertEqual(len(calls),3);self.assertIsNone(conn.sock)

    def test_private_late_observation_exports_no_ref_token_or_arbitrary_error(self):
        from unittest.mock import mock_open
        row={'id':'a'*32,'generation':'b'*32,'expires_at':'1970-01-01T00:05:00Z'}
        writer={'id':'private-execution-ref','fixture_started_monotonic':5.0};opened=mock_open()
        with tempfile.TemporaryDirectory() as tmp,patch.object(guest,'guard'),patch.object(guest.base,'STATE',Path(tmp)),patch.object(guest.base,'call',return_value={'state':'DESTROYED','last_error':'never-export-me','token':'never-export-me'}),patch.object(guest.time,'time',return_value=0.),patch.object(guest.time,'monotonic',return_value=10.),patch('builtins.open',opened):
            guest.late_observation('before-stop',row,writer)
        text=''.join(c.args[0] for c in opened().write.call_args_list)
        self.assertIn('"owner_present": false',text);self.assertIn('"sandbox_state": "DESTROYED"',text);self.assertIn('"writer_age_ms": 5000.0',text);self.assertIn('"sandbox_ttl_remaining_ms": 300000.0',text)
        for private in (row['id'],row['generation'],writer['id'],'never-export-me'):self.assertNotIn(private,text)
        with patch.object(guest,'guard'),patch('builtins.open') as opened:
            for event,seconds in (('arbitrary-private-event',1.),('status',float('nan')),('status',float('inf')),('status',-1.),('status',True)):
                with self.assertRaises(RuntimeError):guest.private_timing(event,seconds)
            opened.assert_not_called()

    def test_new_busy_observer_records_age_without_extending_execution_budget(self):
        with patch.object(guest.time,'monotonic',return_value=10.),patch.object(guest.base,'progressing_writer',return_value={'id':'synthetic-exec'}) as start:
            writer=guest.new_busy_writer({'id':'synthetic-row'})
        start.assert_called_once_with({'id':'synthetic-row'},'alpha')
        self.assertEqual(writer,{'id':'synthetic-exec','fixture_started_monotonic':10.})
        self.assertIn('45000',inspect.getsource(guest.base.progressing_writer))

    def test_blocking_trace_wait_keeps_sixty_second_bound_and_restores_alarm(self):
        previous=object()
        with patch.object(trace.signal,'getitimer',return_value=(0.,0.)),patch.object(trace.signal,'getsignal',return_value=previous),patch.object(trace.signal,'signal') as handler,patch.object(trace.signal,'setitimer') as timer:
            with self.assertRaisesRegex(RuntimeError,'managed trace deadline'):
                with trace.bounded_trace_wait(True):
                    installed=handler.call_args.args[1];installed(None,None)
            self.assertEqual(timer.call_args_list[0].args,(trace.signal.ITIMER_REAL,60.))
            self.assertEqual(timer.call_args_list[-1].args,(trace.signal.ITIMER_REAL,0.))
            self.assertEqual(handler.call_args_list[-1].args,(trace.signal.SIGALRM,previous))
        with patch.object(trace.signal,'getitimer',return_value=(1.,0.)),patch.object(trace.signal,'signal') as handler,patch.object(trace.signal,'setitimer') as timer:
            with self.assertRaisesRegex(RuntimeError,'unowned trace alarm'):
                with trace.bounded_trace_wait(True):self.fail('foreign alarm must not be replaced')
            handler.assert_not_called();timer.assert_not_called()
        with patch.object(trace.signal,'signal') as handler,patch.object(trace.signal,'setitimer') as timer:
            with trace.bounded_trace_wait(False):pass
            handler.assert_not_called();timer.assert_not_called()

    def test_trace_alarm_restores_on_arm_failure_and_new_stop_rechecks_busy_vmm(self):
        previous=object()
        with patch.object(trace.signal,'getitimer',return_value=(0.,0.)),patch.object(trace.signal,'getsignal',return_value=previous),patch.object(trace.signal,'signal') as handler,patch.object(trace.signal,'setitimer',side_effect=[OSError('synthetic'),None]) as timer:
            with self.assertRaises(OSError):
                with trace.bounded_trace_wait(True):self.fail('timer arming failed')
            self.assertEqual(timer.call_args_list[-1].args,(trace.signal.ITIMER_REAL,0.))
            self.assertEqual(handler.call_args_list[-1].args,(trace.signal.SIGALRM,previous))
        s=inspect.getsource(trace.interrupt)
        self.assertIn('0 if blocking else os.WNOHANG',s)
        self.assertLess(s.index('with bounded_trace_wait(blocking):'),s.index('while threads:'))
        s=inspect.getsource(guest.checkpoint)
        self.assertLess(s.index("late_observation('before-stop'"),s.rindex("drain.busy(rows[0][0],writer['id'])"))
        self.assertLess(s.rindex("drain.busy(rows[0][0],writer['id'])"),s.index("ms=install.stop_destroy"))
        self.assertIn('main/four VMM incarnations changed before busy Stop',s)

if __name__=='__main__':unittest.main()
