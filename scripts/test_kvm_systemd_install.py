"""Pure fixture controls. These are NOT actual installer/systemd/KVM proof."""
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
import build_systemd_install as builder
import install_fixture_trace as trace
import systemd_install_guest as guest
from build_systemd_host import build,configure_root
from kvm_systemd_host import harness_files,validate_install_reply

class InstallControls(unittest.TestCase):
    def test_exact_fresh_assets_and_independent_harness(self):
        self.assertEqual(len(builder.ASSETS),16);self.assertEqual(len(set(builder.ASSETS)),16)
        names=harness_files(True,False,False,False,True)
        self.assertEqual(len(names),12)
        self.assertIn('build_systemd_deployment.py',names) # reused validator, not its configure
        self.assertNotIn('base_configure',inspect.getsource(builder.configure))
        for deployed,ingress,readiness,release in ((False,False,False,False),(True,True,False,False),(True,False,True,False),(True,False,False,True)):
            with self.assertRaises(ValueError):harness_files(deployed,ingress,readiness,release,True)
        for other in ('release_assets','readiness_assets','ingress_assets','deployment_assets'):
            with self.assertRaises(ValueError):build(ubuntu=None,alpine=None,probe=None,output_disk=None,output_initrd=None,install_assets={},**{other:{}})
    def test_assembly_only_bootstraps_no_ordinary_units_or_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root';root.mkdir();(root/'etc/cloud').mkdir(parents=True)
            source=Path(tmp)/'source';source.write_bytes(b'test data never executed');sha=hashlib.sha256(source.read_bytes()).hexdigest()
            configure_root(root,source);(root/'usr').mkdir(mode=0o700)
            builder.configure(root,{k:{'path':str(source),'sha256':sha} for k in builder.ASSETS})
            for p in ('etc/xandbox-install','srv/xi','srv/xandbox-releases','etc/systemd/system/xandbox.service','etc/systemd/system/xandbox-ingress.service'):
                self.assertFalse((root/p).exists())
            self.assertEqual((root/'etc/xandbox-systemd-install-fixture').read_text(),builder.MARKER)
            self.assertEqual((root/'usr').stat().st_mode&0o777,0o755)
            self.assertEqual((root/'usr/libexec').stat().st_mode&0o777,0o755)
            self.assertEqual((root/'usr/libexec/xandbox-install-bootstrap').stat().st_mode&0o777,0o555)
            self.assertIn('systemd_install_guest.py',(root/'etc/systemd/system/xandbox-systemd-operator.service').read_text())
            self.assertEqual(json.loads((root/builder.CONFIG/'programs.json').read_bytes())['install']['path'],guest.BOOTSTRAP)
            self.assertEqual(set(json.loads((root/builder.CONFIG/'source-assets.json').read_bytes())),set(builder.ROLES))
            for name in builder.SCRIPTS:self.assertTrue((root/'opt/xandbox'/name).is_file())
            with self.assertRaises(ValueError):builder.configure(root,{k:{} for k in builder.ASSETS})
    def test_asset_schema_rejects_missing_extra_and_forged_programs(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'assets.json'
            for value in ({},{'install':{}},{k:{'path':'/missing','sha256':'a'*64} for k in builder.ASSETS},{**{k:{} for k in builder.ASSETS},'unknown':{}}):
                p.write_text(json.dumps(value))
                with self.assertRaises(ValueError):builder.load_assets(p)
    def test_every_closed_flag_and_separate_measurement_is_mandatory(self):
        for op,flags in (('install-probe',guest.PROBE_FLAGS),('install-checkpoint',guest.CHECKPOINT_FLAGS),('install-recover',guest.RECOVERY_FLAGS)):
            v={k:True for k in flags}
            if op=='install-checkpoint':v.update(stop_observed_ms=3.0,durable_reclaim_observed_ms=20.0)
            validate_install_reply(op,v)
            for k in flags:
                for bad in (False,1,None):
                    with self.assertRaises(AssertionError):validate_install_reply(op,{**v,k:bad})
                b=copy.deepcopy(v);del b[k]
                with self.assertRaises(AssertionError):validate_install_reply(op,b)
            with self.assertRaises(AssertionError):validate_install_reply(op,{**v,'private_request':'not-exported'})
            if op=='install-checkpoint':
                for bad in (True,0,-1,float('nan'),float('inf'),45001):
                    with self.assertRaises(AssertionError):validate_install_reply(op,{**v,'stop_observed_ms':bad})
                with self.assertRaises(AssertionError):validate_install_reply(op,{**v,'durable_reclaim_observed_ms':1})
    def test_closed_installer_receipt_and_exact_refusal(self):
        value={'version':1,'revision':1,'files_committed':True,'manager_reconciled':True,'production_ready':False}
        def reply(v):return subprocess.CompletedProcess([],0,json.dumps(v).encode(),b'')
        guest.result(reply(value));guest.result(subprocess.CompletedProcess([],1,b'',guest.ERROR),1)
        for k,bad in (('version',True),('revision',True),('files_committed',1),('manager_reconciled',1),('production_ready',0)):
            with self.assertRaises(RuntimeError):guest.result(reply({**value,k:bad}))
        for code,out,err in ((-9,b'',guest.ERROR),(1,b'identity',guest.ERROR),(1,b'',b'exec denied'),(1,b'',guest.ERROR+b'raw detail')):
            with self.assertRaises(RuntimeError):guest.result(subprocess.CompletedProcess([],code,out,err),1)
    def test_fixed_arguments_no_service_or_source_override(self):
        p=guest.CONFIG/'plan.json';args=guest.arguments('apply','a'*32,p,True)
        self.assertEqual(args,[guest.BOOTSTRAP,'apply','-plan',str(p),'-expected-revision','0','-request-id','a'*32])
        for op,req,plan in (('restart',None,None),('apply','a'*32,Path('/tmp/input.json')),('apply','A'*32,p),('status','a'*32,None)):
            with self.assertRaises(RuntimeError):guest.arguments(op,req,plan)
    def test_unmarked_entry_and_trace_have_no_side_effects(self):
        with patch.object(guest,'guard',side_effect=RuntimeError('unmarked')),patch.object(guest,'setup') as setup,patch.object(guest,'failure') as failure:
            with self.assertRaises(RuntimeError):guest.entry()
            setup.assert_not_called();failure.assert_not_called()
        with patch.object(trace,'guard',side_effect=RuntimeError('unmarked')),patch.object(trace.os,'fork') as fork:
            with self.assertRaises(RuntimeError):trace.interrupt_before_commit([],None,None,None)
            fork.assert_not_called()
    def test_own_child_trace_exec_pin_and_exact_dirfd_before_kill(self):
        self.assertEqual(ctypes.sizeof(trace.Registers),27*8)
        s=inspect.getsource(trace.interrupt_before_commit)
        for t in ('os.fork()',"sha(Path('/proc',str(pid),'exe'))!=expected_sha","b'.commit.next'","!='/etc/xandbox-install'",'os.kill(pid,signal.SIGKILL)','threads.discard(tid)','time.monotonic()+60'):
            self.assertIn(t,s)
        self.assertNotIn('PTRACE_ATTACH',s)
    def test_pending_gate_checks_real_capless_threads_before_releasing_lock(self):
        s=inspect.getsource(guest.pregate_pending)
        for t in ("ROOT/'intent.json'","ROOT/'.commit.next'","'CapBnd'","'NoNewPrivs'","base.STATE.iterdir()","flock(lock,fcntl.LOCK_UN)"):
            self.assertIn(t,s)
        self.assertNotIn('reset-failed',s)
        setup=inspect.getsource(guest.setup)
        self.assertLess(setup.index('interrupt_before_commit'),setup.index('pregate_pending()'))
        self.assertLess(setup.index("call('apply',request,CONFIG/'plan.json',bootstrap=True)"),setup.index("p.unlink()"))
    def test_cold_probe_has_no_activation_or_source_regeneration(self):
        s=inspect.getsource(guest.probe)
        self.assertIn('sources_absent()',s);self.assertIn('drain.probe_mode()',s)
        self.assertLess(s.index('ingress.tls_ready()'),s.index("call('status')"))
        self.assertNotIn('reconcile',s);self.assertNotIn('setup',s);self.assertNotIn('start',s)
        s=inspect.getsource(guest.recover)
        self.assertLess(s.index('probe()'),s.index('drain.restore_and_resume()'))
        self.assertNotIn('input/',s)
    def test_observer_preserves_exact_go_json_bytes_and_never_overwrites(self):
        raw=b'{"version":1,"keys":[]}\n'
        self.assertNotEqual(json.dumps(json.loads(raw),sort_keys=True).encode()+b'\n',raw)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'installed';config=Path(tmp)/'observer';root.mkdir();config.mkdir()
            (root/'auth.json').write_bytes(raw)
            with patch.object(guest,'ROOT',root),patch.object(guest,'CONFIG',config):
                guest.copy_snapshot('auth.json')
                self.assertEqual((config/'auth.json').read_bytes(),raw)
                self.assertEqual((config/'auth.json').stat().st_mode&0o777,0o600)
                with self.assertRaises(FileExistsError):guest.copy_snapshot('auth.json')
                with self.assertRaises(RuntimeError):guest.copy_snapshot('../unknown')
    def test_capacity_is_retained_between_physical_stop_and_delete(self):
        s=inspect.getsource(guest.stop_destroy)
        self.assertLess(s.index("v['state']!='STOPPED'"),s.index("'install-stopped-still-full'"))
        self.assertLess(s.index("'install-stopped-still-full'"),s.index("'DELETE'"))
        self.assertIn('tenant=tenant',s)
    def test_boot_failure_sentinel_follows_flushed_diagnostics(self):
        s=inspect.getsource(guest.failure)
        self.assertLess(s.index('traceback.print_exc'),s.index('XANDBOX_SYSTEMD_HOST_FAILED'))
        self.assertLess(s.index("subprocess.run(['journalctl'"),s.index('XANDBOX_SYSTEMD_HOST_FAILED'))
        self.assertIn('c.flush()',s)
    def test_thread_exit_is_not_main_exit_and_diagnostic_is_closed(self):
        s=inspect.getsource(trace.interrupt_before_commit)
        self.assertIn('not hit and tid==pid',s)
        self.assertIn("'closed_cli_refusal':raw==refusal",s)
        self.assertNotIn('print(raw',s)
        self.assertIn("with open('/dev/console','w') as console",s)
        self.assertIn('json.dumps(diag,sort_keys=True)',s)
        self.assertIn('if e.errno!=errno.ESRCH:raise',s)
    def test_fresh_manager_diagnostic_never_activates_or_relays_raw_errors(self):
        s=inspect.getsource(guest.fresh_manager_observation)
        self.assertIn("'--quiet','show'",s)
        self.assertIn("'stderr_bytes':len(r.stderr)",s)
        for op in ("'start'","'enable'","'restart'",'r.stderr.decode()'):self.assertNotIn(op,s)

if __name__=='__main__':unittest.main()
