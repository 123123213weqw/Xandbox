"""Pure controls, not automatic readiness/systemd/KVM acceptance."""
import copy
import hashlib
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import build_systemd_readiness as builder
import systemd_readiness_guest as guest
import readiness_fixture_gate as gate
from build_systemd_host import build
from kvm_systemd_host import harness_files,validate_readiness_reply,READINESS_PROBE_FLAGS,READINESS_CHECKPOINT_FLAGS,READINESS_RECOVERY_FLAGS,INGRESS_CHECKPOINT_FLAGS

class ReadinessControls(unittest.TestCase):
    def test_exact_13_roles_and_only_one_owned_operator(self):
        self.assertEqual(len(builder.ASSETS),13);self.assertEqual(len(set(builder.ASSETS)),13)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'root';root.mkdir();(root/'opt/xandbox').mkdir(parents=True);(root/'etc/systemd/system/multi-user.target.wants').mkdir(parents=True)
            p=Path(temp)/'asset';p.write_bytes(b'not executed');sha=hashlib.sha256(p.read_bytes()).hexdigest()
            builder.configure(root,{k:{'path':str(p),'sha256':sha} for k in builder.ASSETS})
            self.assertEqual((root/'usr/libexec/xandbox-ready').read_bytes(),b'not executed')
            self.assertEqual((root/'usr/libexec/xandbox-ready').stat().st_mode&0o777,0o555)
            self.assertEqual((root/'etc/xandbox-systemd-readiness-fixture').read_text(),builder.MARKER)
            self.assertEqual([p.name for p in (root/'etc/systemd/system/multi-user.target.wants').iterdir()],['xandbox-ingress-operator.service'])
            unit=(root/'etc/systemd/system/xandbox-ingress-operator.service').read_text();self.assertIn('systemd_readiness_guest.py',unit);self.assertNotIn('systemd_ingress_guest.py',unit)
            self.assertEqual(json.loads((root/'etc/xandbox/readiness-assets.json').read_bytes()),{'ready':{'path':'/usr/libexec/xandbox-ready','sha256':sha}})
            self.assertFalse((root/'etc/systemd/system/multi-user.target.wants/xandbox.service').exists())
    def test_profile_selection_exclusive_before_any_build(self):
        for pair in ({'readiness_assets':{},'ingress_assets':{}},{'readiness_assets':{},'deployment_assets':{}},{'ingress_assets':{},'deployment_assets':{}}):
            with self.assertRaises(ValueError):build(ubuntu=None,alpine=None,probe=None,output_disk=None,output_initrd=None,**pair)
    def test_new_source_hash_set_is_complete_legacy_names_unchanged(self):
        self.assertEqual(len(harness_files(False,False,False)),5)
        self.assertEqual(len(harness_files(True,False,False)),7)
        self.assertEqual(len(harness_files(True,True,False)),10)
        names=harness_files(True,False,True);self.assertEqual(len(set(names)),14)
        for name in ('build_systemd_readiness.py','systemd_readiness_guest.py','readiness_fixture_gate.py'):self.assertIn(name,names)
    def test_typed_closed_results_do_not_claim_old_explicit_start(self):
        self.assertIn('explicit_start_after_backend_ready_not_automatic_install',INGRESS_CHECKPOINT_FLAGS)
        self.assertNotIn('explicit_start_after_backend_ready_not_automatic_install',READINESS_CHECKPOINT_FLAGS)
        for operation,flags in [('readiness-probe',READINESS_PROBE_FLAGS),('readiness-checkpoint',READINESS_CHECKPOINT_FLAGS),('readiness-recover',READINESS_RECOVERY_FLAGS)]:
            good={k:True for k in flags};validate_readiness_reply(operation,good)
            for k in flags:
                for wrong in (False,1,None):
                    with self.assertRaises(AssertionError):validate_readiness_reply(operation,{**good,k:wrong})
                bad=copy.deepcopy(good);del bad[k]
                with self.assertRaises(AssertionError):validate_readiness_reply(operation,bad)
            with self.assertRaises(AssertionError):validate_readiness_reply(operation,{**good,'private_pid':123})
    def test_positive_restart_has_only_one_main_start_no_uds_poll_or_ingress_start(self):
        source=inspect.getsource(guest.recover_services)
        self.assertEqual(source.count("run('systemctl','start',base.UNIT)"),1)
        self.assertNotIn('uds_ready()',source)
        self.assertNotIn("run('systemctl','start',ingress.UNIT)",source)
        source=inspect.getsource(guest.operator);cold=source.split('if CHECKPOINT.exists():',1)[1].split('else:',1)[0]
        self.assertNotIn("run('systemctl'",cold);self.assertNotIn('setup()',cold);self.assertIn('ingress.tls_ready()',cold)
    def test_gated_timeout_not_a_fake_backend_or_blind_retry(self):
        source=inspect.getsource(guest.negatives)
        for part in ('--signal=SIGSTOP','helper_observation()',"failed_start('waiting')","failed_start('manifest')","run('systemctl','enable',base.UNIT,ingress.UNIT)"):
            self.assertIn(part,source)
        self.assertNotIn('SIGCONT',source);self.assertNotIn('rmdir',source);self.assertNotIn('mock',source)
        self.assertIn('Path(p).unlink()',source)
    def test_unmarked_guest_and_pause_do_not_write(self):
        with patch.object(guest,'guard',side_effect=RuntimeError('unmarked')),patch.object(guest,'operator') as op,patch.object(guest.ingress,'failure_console') as out:
            with self.assertRaises(RuntimeError):guest.entry()
            op.assert_not_called();out.assert_not_called()
        with patch.object(gate,'guard',side_effect=RuntimeError('unmarked')),patch.object(gate.os,'open') as opened:
            with self.assertRaises(RuntimeError):gate.entry()
            opened.assert_not_called()
    def test_missing_and_extra_asset_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'assets.json'
            for v in ({},{'ready':{}},{k:{'path':'/not-executed','sha256':'0'*64} for k in builder.ASSETS}):
                p.write_text(json.dumps(v))
                with self.assertRaises(ValueError):builder.load_assets(p)
