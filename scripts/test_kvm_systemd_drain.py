"""Pure drain-extension controls, never privileged/KVM acceptance."""
import copy
import inspect
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import systemd_drain_probe as drain
import systemd_readiness_guest as ready
from kvm_systemd_host import harness_files,READINESS_CHECKPOINT_FLAGS,READINESS_RECOVERY_FLAGS,validate_readiness_reply


def reply(mode='open',revision=1):
    return {'control':{'version':1,'phase':'ready','desired_mode':mode,'admission_open':mode=='open','pending_session_reservations':0,
            'committed':{'version':1,'epoch':'a'*32,'revision':revision,'mode':mode,'last_request_id':'' if revision==1 else 'b'*32,'last_expected_revision':revision-1}},
            'resource_observation':{'backend':'firecracker','records':1}}


class DrainExtensionControls(unittest.TestCase):
    def test_operator_view_rejects_unknown_partial_and_bool_authority(self):
        for mode in ('open','drained'):self.assertEqual(drain.parse_reply(reply(mode))['control']['committed']['mode'],mode)
        changes=(lambda v:v.update(private=True),lambda v:v['control'].update(pending_request_id='a'*32),lambda v:v['control'].update(admission_open=True,desired_mode='drained'),lambda v:v['control']['committed'].update(revision=True),lambda v:v['control']['committed'].update(epoch='private'),lambda v:v['control']['committed'].update(last_request_id='b'*32),lambda v:v['resource_observation'].update(backend='mock'),lambda v:v['control'].update(pending_session_reservations=1))
        for change in changes:
            v=reply('drained');change(v)
            with self.assertRaises(RuntimeError):drain.parse_reply(v)
    def test_unmarked_operator_call_never_spawns_or_reads_asset(self):
        with patch.object(drain,'guard',side_effect=RuntimeError('unmarked')),patch.object(drain.subprocess,'run') as run:
            with self.assertRaises(RuntimeError):drain.control('status')
            run.assert_not_called()
    def test_only_fixed_pinned_cli_and_read_only_status(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);(p/'assets.json').write_text(json.dumps({'node':{'path':'/srv/assets/node','sha256':'f'*64}}))
            with patch.object(drain,'guard'),patch.object(drain.base,'CONFIG',p),patch.object(drain.base,'sha',return_value='f'*64),patch.object(drain.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(reply()).encode(),stderr=b'')) as run:
                drain.control('status');args=run.call_args.args[0]
                self.assertEqual(args,['/srv/assets/node','-state-dir',str(drain.base.STATE),'status'])
                self.assertNotIn('-epoch',args);self.assertNotIn('-request-id',args)
                for op in ('exec','/bin/sh','status --resume'):
                    with self.assertRaises(RuntimeError):drain.control(op)
                with self.assertRaises(RuntimeError):drain.control('status',before=reply()['control']['committed'])
                with self.assertRaises(RuntimeError):drain.control('resume',before={'revision':True,'epoch':'a'*32},request='b'*32)
                with self.assertRaises(RuntimeError):drain.control('status',want=True)
    def test_exact_retry_reuses_cas_and_does_not_advance_twice(self):
        before=reply()['control']['committed'];after=reply('drained',2);after['control']['committed']['last_request_id']='c'*32
        with patch.object(drain.secrets,'token_hex',return_value='c'*32),patch.object(drain,'control',return_value=after) as call:
            result=drain.change('drain',before)
            self.assertEqual(result['revision'],2);self.assertEqual(call.call_args_list[0],call.call_args_list[1])
    def test_entire_durable_commit_not_just_mode_is_compared(self):
        expected=reply('drained',2)['control']['committed'];v=reply('drained',2);v['control']['committed']['last_request_id']='c'*32
        with patch.object(drain,'control',return_value=v):
            with self.assertRaises(RuntimeError):drain.state('drained',expected)
    def test_stale_resume_uses_old_revision_and_requires_refusal(self):
        committed=reply('drained',2)['control']['committed']
        with patch.object(drain,'control') as call,patch.object(drain,'state') as state:
            drain.no_stale_resume(committed)
            self.assertEqual(call.call_args.args[0],'resume');self.assertEqual(call.call_args.args[1]['revision'],1);self.assertEqual(call.call_args.kwargs,{'want':1});state.assert_called_once_with('drained',committed)
    def test_503_must_be_drain_not_node_full_or_unauthenticated(self):
        def response(method,path,*args,**kwargs):
            return {'error':{'code':'INVALID_REQUEST' if path=='/v1/node/resume' else 'NODE_DRAINING'}}
        with patch.object(drain,'state',return_value=reply('drained',2)),patch.object(drain,'health') as health,patch.object(drain,'sessions_inventory',return_value={'one':'a'*64}),patch.object(drain.ingress,'tls_call',side_effect=response) as tls:
            drain.denials('test',{'id':'c'*32,'revision':1});health.assert_called_once_with('drained');self.assertEqual(tls.call_count,6)
        with patch.object(drain,'state',return_value=reply('drained',2)),patch.object(drain,'health'),patch.object(drain,'sessions_inventory',return_value={}),patch.object(drain.ingress,'tls_call',return_value={'error':{'code':'UNAVAILABLE'}}):
            with self.assertRaises(RuntimeError):drain.denials('test')
    def test_denied_session_history_and_record_growth_fail(self):
        def response(method,path,*args,**kwargs):return {'error':{'code':'INVALID_REQUEST' if path=='/v1/node/resume' else 'NODE_DRAINING'}}
        before=reply('drained',2);after=copy.deepcopy(before);after['resource_observation']['records']=2
        for states,inventories in (([before,after],[{},{}]),([before,before],[{}, {'new':'a'*64}])):
            with patch.object(drain,'state',side_effect=states),patch.object(drain,'health'),patch.object(drain,'sessions_inventory',side_effect=inventories),patch.object(drain.ingress,'tls_call',side_effect=response):
                with self.assertRaises(RuntimeError):drain.denials('test')
    def test_same_busy_execution_required_not_only_earlier_counter(self):
        row={'id':'a'*32,'generation':'b'*32}
        with patch.object(drain.base,'execute',side_effect=['1\n','2\n']),patch.object(drain.time,'sleep'),patch.object(drain.ingress,'tls_call',return_value={'status':'RUNNING'}) as tls:
            drain.busy(row,'c'*32);self.assertTrue(tls.call_args.args[1].endswith('/executions/'+'c'*32))
        with patch.object(drain.base,'execute',side_effect=['1\n','2\n']),patch.object(drain.time,'sleep'),patch.object(drain.ingress,'tls_call',return_value={'status':'EXITED'}):
            with self.assertRaises(RuntimeError):drain.busy(row,'c'*32)
    def test_cold_probe_is_observe_only_and_gc_precedes_explicit_resume(self):
        source=inspect.getsource(drain.probe_mode)
        for forbidden in ('change(','systemctl','write_text','resume('):self.assertNotIn(forbidden,source)
        source=inspect.getsource(drain.restore_and_resume)
        self.assertLess(source.index('base.reclaimed('),source.index("change('resume'"))
        source=inspect.getsource(ready.operator);cold=source.split('if CHECKPOINT.exists():',1)[1].split('else:',1)[0]
        self.assertNotIn("run('systemctl'",cold);self.assertNotIn('setup()',cold)
    def test_drain_checks_are_mandatory_and_new_source_is_fingerprinted(self):
        self.assertEqual(len(harness_files(True,False,True)),15);self.assertIn('systemd_drain_probe.py',harness_files(True,False,True))
        self.assertIn('systemd_fixture_provenance.py',harness_files(True,False,True))
        for operation,flags,extra in (('readiness-checkpoint',READINESS_CHECKPOINT_FLAGS,drain.CHECKPOINT_FLAGS),('readiness-recover',READINESS_RECOVERY_FLAGS,drain.RECOVERY_FLAGS)):
            good={key:True for key in flags}
            for key in extra:
                for wrong in (False,1,None):
                    with self.assertRaises(AssertionError):validate_readiness_reply(operation,{**good,key:wrong})
    def test_cold_writer_identity_is_fsynced_and_new_marker_assembled(self):
        source=inspect.getsource(drain.seal_cold);self.assertIn("guest['writer_execution_id']",source);self.assertIn('save(CHECKPOINT',source)
        import systemd_ingress_guest,build_systemd_readiness
        source=inspect.getsource(systemd_ingress_guest.checkpoint);self.assertIn("'writer_execution_id':fresh_writer['id']",source)
        source=inspect.getsource(build_systemd_readiness.configure);self.assertIn('etc/xandbox-systemd-drain-fixture',source)


class ManagedSessionRouteControls(unittest.TestCase):
    def test_managed_verify_preserves_raw_refusal_and_uses_versioned_adapter(self):
        session={'id':'c'*32,'revision':1};row={'id':'a'*32,'generation':'b'*32}
        def verify(ref,tenant,guest_exec=None):
            self.assertIsNotNone(guest_exec);self.assertEqual(guest_exec(ref,['id','-u'],tenant),'65534\n');return 'real-boot-observer'
        with patch.object(drain.ingress,'tls_call',return_value={'error':{'code':'NOT_READY'}}) as raw,patch.object(drain.base,'verify_vm',side_effect=verify),patch.object(drain,'execute_session',return_value='65534\n') as execute:
            self.assertEqual(drain.verify_session_vm(session,row),'real-boot-observer');self.assertEqual(raw.call_args.kwargs['expected'],409);execute.assert_called_once_with(session,row,['id','-u'],'alpha')
        with patch.object(drain.ingress,'tls_call',return_value={'error':{'code':'STALE_GENERATION'}}):
            with self.assertRaises(RuntimeError):drain.verify_session_vm(session,row)
    def test_session_job_binds_revision_and_actual_target(self):
        session={'id':'c'*32,'revision':1};row={'id':'a'*32,'generation':'b'*32};result={'revision':1,'sandbox':row,'job':{'id':'d'*32}}
        with patch.object(drain.ingress,'tls_call',return_value=result) as tls:
            drain.session_job(session,row,['id','-u'])
            self.assertEqual(tls.call_args.args[1],'/v1/sessions/'+'c'*32+'/exec');self.assertEqual(tls.call_args.args[2]['revision'],1);self.assertNotIn('generation',tls.call_args.args[2])
        for bad in ({**result,'revision':2},{**result,'sandbox':{'id':'e'*32,'generation':'b'*32}}):
            with patch.object(drain.ingress,'tls_call',return_value=bad):
                with self.assertRaises(RuntimeError):drain.session_job(session,row,['id','-u'])
    def test_managed_busy_counter_never_uses_raw_execution(self):
        row={'id':'a'*32,'generation':'b'*32};session={'id':'c'*32,'revision':1}
        with patch.object(drain.base,'execute',side_effect=AssertionError('forbidden raw route')),patch.object(drain,'execute_session',side_effect=['1\n','2\n']) as execute,patch.object(drain.time,'sleep'),patch.object(drain.ingress,'tls_call',return_value={'status':'RUNNING'}):
            drain.busy(row,'d'*32,session);self.assertEqual(execute.call_count,2)
    def test_session_writer_keeps_exact_known_guest_loop_not_literal_backslash(self):
        session={'id':'c'*32,'revision':1};row={'id':'a'*32,'generation':'b'*32}
        original=next(v[2] for v in drain.base.progressing_writer.__code__.co_consts if type(v) is tuple and len(v)==3 and v[:2]==('sh','-c'))
        with patch.object(drain,'session_job',return_value={'id':'d'*32}) as job,patch.object(drain,'wait'),patch.object(drain,'busy'):
            drain.session_writer(session,row)
            self.assertEqual(job.call_args.args[2],['sh','-c',original]);self.assertEqual(job.call_args.kwargs['timeout_ms'],45000)
    def test_failure_frame_follows_complete_private_diagnostic_and_is_not_duplicated(self):
        events=[]
        stream=SimpleNamespace(write=lambda b:events.append(('frame',json.loads(b))))
        with patch.object(ready,'FAILURE_REPORTED',False),patch.object(ready.ingress,'failure_console',side_effect=lambda:events.append(('diagnostic',None))) as diagnostic:
            ready.report_failure(stream);ready.report_failure();diagnostic.assert_called_once()
        self.assertEqual([x[0] for x in events],['diagnostic','frame']);self.assertEqual(events[1][1],{'ok':False,'error':'owned readiness fixture failed'})
    def test_expected_stale_cli_exit_must_be_actual_conflict_not_transport_error(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);(p/'assets.json').write_text(json.dumps({'node':{'path':'/srv/assets/node','sha256':'f'*64}}))
            with patch.object(drain,'guard'),patch.object(drain.base,'CONFIG',p),patch.object(drain.base,'sha',return_value='f'*64):
                for stderr in (b'private transport failure\n',b'operator HTTP409: CONFLICT\n'):
                    with patch.object(drain.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout=b'',stderr=stderr)):
                        if stderr.startswith(b'private'):
                            with self.assertRaises(RuntimeError):drain.control('resume',reply('drained',2)['control']['committed'],'c'*32,want=1)
                        else:self.assertIsNone(drain.control('resume',reply('drained',2)['control']['committed'],'c'*32,want=1))
