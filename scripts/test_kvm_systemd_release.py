"""Pure controls for the TEST ONLY root publisher profile; not real L1 proof."""
import copy
import hashlib
import inspect
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import build_systemd_release as builder
import systemd_release_guest as guest
from build_systemd_host import build
from kvm_systemd_host import harness_files,validate_release_reply,READINESS_PROBE_FLAGS,READINESS_CHECKPOINT_FLAGS,READINESS_RECOVERY_FLAGS

class ReleaseControls(unittest.TestCase):
    def test_exact15_assets_and_original14_plus2_harness(self):
        self.assertEqual(len(builder.ASSETS),15);self.assertEqual(len(set(builder.ASSETS)),15)
        old=harness_files(True,False,True);self.assertEqual(len(old),14)
        new=harness_files(True,False,True,True);self.assertEqual(new,old+('build_systemd_release.py','systemd_release_guest.py'))
        for deployed,readiness in ((False,False),(True,False),(False,True)):
            with self.assertRaises(ValueError):harness_files(deployed,False,readiness,True)
    def test_builder_configures_one_operator_no_activation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root';root.mkdir();(root/'opt/xandbox').mkdir(parents=True);(root/'etc/systemd/system/multi-user.target.wants').mkdir(parents=True);(root/'usr').mkdir(mode=0o700)
            source=Path(tmp)/'input';source.write_bytes(b'not executed');sha=hashlib.sha256(source.read_bytes()).hexdigest()
            builder.configure(root,{k:{'path':str(source),'sha256':sha} for k in builder.ASSETS})
            self.assertEqual((root/'usr/libexec/xandbox-release').read_bytes(),b'not executed')
            self.assertEqual((root/'usr/libexec/xandbox-release').stat().st_mode&0o777,0o555)
            self.assertEqual((root/'usr').stat().st_mode&0o777,0o755)
            self.assertEqual((root/'usr/libexec').stat().st_mode&0o777,0o755)
            value=json.loads((root/'etc/xandbox-release/assets.json').read_bytes())
            self.assertEqual(set(value),set(guest.ROLES)|{'release'});self.assertNotIn('helper',value)
            self.assertEqual(value['release']['path'],guest.CLI)
            self.assertEqual((root/'etc/xandbox-systemd-release-fixture').read_text(),builder.MARKER)
            self.assertEqual([p.name for p in (root/'etc/systemd/system/multi-user.target.wants').iterdir()],['xandbox-ingress-operator.service'])
            unit=(root/'etc/systemd/system/xandbox-ingress-operator.service').read_text();self.assertIn('systemd_release_guest.py',unit);self.assertNotIn('systemd_readiness_guest.py',unit)
            self.assertFalse((root/'srv/xandbox-releases').exists())
            self.assertEqual((root/'etc/xandbox-release').stat().st_mode&0o777,0o700)
            self.assertEqual((root/'etc/xandbox').stat().st_mode&0o777,0o700)
    def test_profiles_exclusive_before_any_image_work(self):
        for other in ('readiness_assets','ingress_assets','deployment_assets'):
            with self.assertRaises(ValueError):build(ubuntu=None,alpine=None,probe=None,output_disk=None,output_initrd=None,release_assets={},**{other:{}})
    def test_asset_schema_missing_extra_and_bad_program_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'assets.json'
            for v in ({},{'release':{}},{k:{'path':'/missing-program','sha256':'0'*64} for k in builder.ASSETS},{**{k:{} for k in builder.ASSETS},'unknown':{}}):
                p.write_text(json.dumps(v))
                with self.assertRaises(ValueError):builder.load_assets(p)
    def test_full_readiness_drain_flags_are_not_optional(self):
        for op,base,extra in [('release-probe',READINESS_PROBE_FLAGS,guest.PROBE_FLAGS),('release-checkpoint',READINESS_CHECKPOINT_FLAGS,guest.CHECKPOINT_FLAGS),('release-recover',READINESS_RECOVERY_FLAGS,guest.RECOVERY_FLAGS)]:
            value={k:True for k in (*base,*extra)};validate_release_reply(op,value)
            for k in value:
                for wrong in (False,1,None):
                    with self.assertRaises(AssertionError):validate_release_reply(op,{**value,k:wrong})
                bad=copy.deepcopy(value);del bad[k]
                with self.assertRaises(AssertionError):validate_release_reply(op,bad)
            with self.assertRaises(AssertionError):validate_release_reply(op,{**value,'request_id':'not-exported'})
    def result(self,**changes):
        return {'version':1,'revision':1,'retained':1,'publication_durable':True,'services_changed':False,'production_ready':False,**changes}
    def reply(self,v):return subprocess.CompletedProcess([],0,json.dumps(v).encode(),b'')
    def test_closed_cli_bool_and_zero_revision(self):
        guest.parse_result(self.reply(self.result()),0,1,1)
        guest.parse_result(self.reply(self.result(revision=0,retained=0,publication_durable=False)),0,0,0)
        for field in self.result():
            bad=self.result();bad[field]=None
            with self.assertRaises(RuntimeError):guest.parse_result(self.reply(bad),0,1,1)
        for bad in (self.result(version=True),self.result(revision=True),self.result(retained=True),self.result(services_changed=0),self.result(production_ready=0),self.result(publication_durable=1),self.result(extra=True)):
            with self.assertRaises(RuntimeError):guest.parse_result(self.reply(bad),0,1,1)
    def test_cli_refusal_not_arbitrary_nonzero_or_raw_error(self):
        guest.parse_result(subprocess.CompletedProcess([],1,b'',guest.ERROR),1)
        for code,out,err in ((-9,b'',guest.ERROR),(2,b'',guest.ERROR),(1,b'identity',guest.ERROR),(1,b'',b'permission denied'),(1,b'',guest.ERROR+b'raw detail')):
            with self.assertRaises(RuntimeError):guest.parse_result(subprocess.CompletedProcess([],code,out,err),1)
    def test_fixed_arguments_no_shell_target_or_task(self):
        p=guest.CONFIG/'publish-first.json';self.assertEqual(guest.arguments(p,0,'a'*32),[guest.CLI,'publish','-manifest',str(p),'-expected-revision','0','-request-id','a'*32])
        self.assertEqual(guest.arguments(),[guest.CLI,'status'])
        for p,revision,req in ((Path('/tmp/private.json'),0,'a'*32),(guest.CONFIG/'bad;.json',0,'a'*32),(p,True,'a'*32),(p,0,'A'*32),(p,2**64-1,'a'*32)):
            with self.assertRaises(RuntimeError):guest.arguments(p,revision,req)
    def test_unmarked_entry_does_not_run_or_log(self):
        with patch.object(guest,'guard',side_effect=RuntimeError('unmarked')),patch.object(guest,'operator') as op,patch.object(guest.ready,'report_failure') as failure:
            with self.assertRaises(RuntimeError):guest.entry()
            op.assert_not_called();failure.assert_not_called()
    def test_warm_checks_same_busy_execution_and_actual_node_state(self):
        source=inspect.getsource(guest.warm)
        for needle in ('base.verify_vm','publication_writer(row)',"base.main_identity()",'ingress.ingress_identity()',"drain.state('open',committed)",'drain.busy(row,writer[\'id\'])','drain.destroy(row)','source_negatives(m1)','unknown_controls(p1,r1)','race(p1,0)','race(p2,1)'):
            self.assertIn(needle,source)
        self.assertNotIn('systemctl',source);self.assertNotIn('resume',source);self.assertNotIn('rmdir',source)
    def test_cold_no_start_resume_source_recreation(self):
        source=inspect.getsource(guest.restore)
        for needle in ("drain.state('drained')",'store(2)',"call(CONFIG/'publish-second.json',1,old['second_request']",'INCOMING.exists()','PARKED.is_dir()'):
            self.assertIn(needle,source)
        for bad in ('systemctl','resume','mkdir','shutil','rename_sync'):self.assertNotIn(bad,source)
        cold=inspect.getsource(guest.operator).split('if ready.CHECKPOINT.exists():',1)[1].split('else:',1)[0]
        self.assertNotIn("run('systemctl'",cold);self.assertNotIn('setup()',cold)
    def test_wrapper_preserves_complete_readiness_and_order(self):
        checkpoint=inspect.getsource(guest.checkpoint);self.assertLess(checkpoint.index('warm()'),checkpoint.index('ready.checkpoint()'));self.assertIn('seal()',checkpoint)
        recover=inspect.getsource(guest.recover);self.assertLess(recover.index('restore()'),recover.index('ready.recover()'))
    def test_four_real_processes_and_minimal_env_and_terminal_cleanup(self):
        source=inspect.getsource(guest.race)
        for text in ('range(4)','subprocess.Popen','proc.communicate(timeout=90)','len(winners)!=1','proc.kill()','proc.wait(timeout=10)'):self.assertIn(text,source)
        self.assertEqual(set(guest.ENV),{'PATH','LC_ALL','GOMAXPROCS'});self.assertEqual(guest.ENV['GOMAXPROCS'],'2')
        self.assertNotIn('shell=',source)
    def test_missing_bundle_really_outside_closed_root(self):
        source=inspect.getsource(guest.unknown_controls)
        self.assertIn("Path('/srv/xandbox-release-missing-bundle-negative')",source);self.assertNotIn("ROOT/'lost'",source)
        self.assertIn('quarantine.stat().st_ino',source);self.assertIn('bundle.exists()',source);self.assertIn('rename_sync(quarantine,bundle)',source)
    def test_source_absence_and_retention_capacity_keep_full_snapshot(self):
        source=inspect.getsource(guest.warm)
        self.assertGreaterEqual(source.count('rename_sync(INCOMING,PARKED)'),2)
        self.assertIn('call(p1,2,secrets.token_hex(16),want=1)',source)
        self.assertIn('if store(2)!=snapshot',source)
    def test_rename_sync_both_parents(self):
        with patch.object(Path,'rename') as renamed,patch.object(guest,'sync_dir') as synced:
            guest.rename_sync(Path('/owned/a/source'),Path('/owned/b/target'))
            renamed.assert_called_once_with(Path('/owned/b/target'));self.assertEqual([c.args[0] for c in synced.call_args_list],[Path('/owned/a'),Path('/owned/b')])
    def test_writer_uses_original_loop_with_existing_protocol_maximum(self):
        import ast
        old=ast.parse(inspect.getsource(guest.base.progressing_writer));new=ast.parse(inspect.getsource(guest.publication_writer))
        original=old.body[0].body[0].value.args[1];actual=new.body[0].body[0].value
        self.assertEqual(ast.literal_eval(original),ast.literal_eval(actual))
        source=inspect.getsource(guest.publication_writer);self.assertIn("base.job(row,argv,'alpha',60000)",source);self.assertIn("drain.busy(row,job['id'])",source)
    def test_nonroot_must_enter_actual_pinned_cli_not_count_exec_failure(self):
        source=inspect.getsource(guest.call)
        for text in ("Path('/usr')","Path('/usr/libexec')",'stat.S_IXOTH','s.st_uid!=0',"save(CONFIG/'nonroot-exec-context.json'",'os.setuid(65534)','os.setgid(65534)','prctl(38,1,0,0,0)'):
            self.assertIn(text,source)
        self.assertLess(source.index('stat.S_IXOTH'),source.index('r=subprocess.run'))
        self.assertNotIn('except PermissionError',source)
    def test_private_phase_diagnostic_does_not_replace_busy_or_raise_limits(self):
        source=inspect.getsource(guest.milestone)
        for text in (".get('state')",".get('status')",'elapsed_ms','XANDBOX_RELEASE_PRIVATE_PHASE'):self.assertIn(text,source)
        self.assertNotIn(".get('output')",source);self.assertNotIn('argv',source.split('def milestone',1)[1].split('view=',1)[-1])
        warm=inspect.getsource(guest.warm);self.assertIn("milestone('before_final_busy_check'",warm);self.assertGreaterEqual(warm.count("drain.busy(row,writer['id'])"),2)
    def test_no_secret_or_control_identity_flags(self):
        for flags in (guest.PROBE_FLAGS,guest.CHECKPOINT_FLAGS,guest.RECOVERY_FLAGS):
            self.assertEqual(len(flags),len(set(flags)))
            for f in flags:self.assertNotIn('request_id',f);self.assertNotIn('token',f);self.assertNotIn('epoch',f)
