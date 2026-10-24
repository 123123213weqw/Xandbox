"""Pure controls only; no current systemd/TLS/KVM acceptance from these tests."""
import copy
import contextlib
import io
import subprocess
import hashlib
import inspect
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from build_systemd_ingress import configure,load_assets,ASSETS,operator_unit
from kvm_nested_host import nested_ingress_resources,nested_node_resources,nested_resources,nested_group_limits
from kvm_systemd_host import validate_ingress_reply,INGRESS_PROBE_FLAGS,INGRESS_CHECKPOINT_FLAGS,INGRESS_RECOVERY_FLAGS
import systemd_ingress_guest as guest


class IngressDeploymentControls(unittest.TestCase):
    def test_profile_has_closed_new_bounds_and_legacy_unchanged(self):
        r=nested_ingress_resources()
        self.assertEqual(r,{'profile':'systemd-ingress-v1','memory_mib':16384,'disk_bytes':24<<30,'cgroup_memory_max':18<<30})
        self.assertEqual(nested_group_limits(r),{'memory.max':str(18<<30),'memory.swap.max':'0','memory.oom.group':'1','pids.max':'512','cpu.max':'1200000 100000'})
        for key in r:
            bad=copy.deepcopy(r);bad[key]=r[key]+1 if type(r[key]) is int else r[key]
            if bad!=r:
                with self.assertRaises(ValueError):nested_group_limits(bad)
        self.assertEqual(nested_node_resources(False)['memory_mib'],8192);self.assertEqual(nested_resources(False)['memory_mib'],2048)
        self.assertEqual(nested_group_limits(nested_node_resources(False))['cpu.max'],'800000 100000')

    def test_guest_assembly_copies_only_owned_tree_and_one_operator(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'root';root.mkdir();(root/'opt/xandbox').mkdir(parents=True);(root/'etc/systemd/system/multi-user.target.wants').mkdir(parents=True)
            source=Path(temp)/'asset';source.write_bytes(b'not executed');sha=hashlib.sha256(source.read_bytes()).hexdigest()
            configure(root,{name:{'path':str(source),'sha256':sha} for name in ASSETS})
            self.assertEqual((root/'usr/libexec/xandbox-deploy-fixture').read_bytes(),b'not executed')
            self.assertEqual((root/'srv/assets/xandbox-gateway').stat().st_mode&0o777,0o555)
            links=list((root/'etc/systemd/system/multi-user.target.wants').iterdir())
            self.assertEqual([p.name for p in links],['xandbox-ingress-operator.service'])
            self.assertEqual(set(json.loads((root/'etc/xandbox/ingress-assets.json').read_bytes())),{'gateway','ingress','helper'})
            self.assertIn('MemoryMax=268435456',operator_unit())

    def test_missing_or_unpinned_assets_cannot_select_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'assets.json';p.write_text('{}')
            with self.assertRaises(ValueError):load_assets(p)
            value={n:{'path':'/unexecuted','sha256':'0'*64} for n in ASSETS};p.write_text(json.dumps(value))
            with self.assertRaises(ValueError):load_assets(p)

    def test_every_result_flag_requires_actual_typed_true_without_runtime_ids(self):
        for operation,flags in [('ingress-probe',INGRESS_PROBE_FLAGS),('ingress-checkpoint',INGRESS_CHECKPOINT_FLAGS),('ingress-recover',INGRESS_RECOVERY_FLAGS)]:
            good={k:True for k in flags};validate_ingress_reply(operation,good)
            for k in flags:
                for wrong in (False,1,None):
                    with self.assertRaises(AssertionError):validate_ingress_reply(operation,{**good,k:wrong})
            with self.assertRaises(AssertionError):validate_ingress_reply(operation,{**good,'private_pid':123})

    def test_unmarked_entry_cannot_call_helper_or_failure_console(self):
        with patch.object(guest,'guard',side_effect=RuntimeError('unmarked')),patch.object(guest,'operator') as operator,patch.object(guest,'failure_console') as output:
            with self.assertRaises(RuntimeError):guest.entry()
            operator.assert_not_called();output.assert_not_called()

    def test_tls_get_is_authenticated_and_has_no_body_headers(self):
        calls=[]
        response=SimpleNamespace(status=200,read=lambda limit:b'{}')
        connection=SimpleNamespace(request=lambda *a:calls.append(a),getresponse=lambda:response)
        with patch.object(guest,'client',return_value={'tokens':{'alpha':'test-fixture-token'}}):
            guest.tls_call('GET','/healthz',connection=connection)
            guest.tls_call('POST','/v1/sandboxes',{},key='test-key',connection=connection)
        self.assertNotIn('Content-Type',calls[0][3]);self.assertIn('Authorization',calls[0][3])
        self.assertEqual(calls[1][3]['Content-Type'],'application/json');self.assertEqual(calls[1][3]['Idempotency-Key'],'test-key')
        with patch.object(guest,'tls_call',return_value={'backend':'firecracker','isolation':True}) as request,patch.object(guest,'wait',side_effect=lambda check,seconds:check()):
            guest.tls_ready()
        request.assert_called_once_with('GET','/healthz')

    def test_actual_guest_tasks_are_ordinary_api_and_no_host_command_fallback(self):
        source=inspect.getsource(guest.checkpoint)
        for text in ('base.verify_vm','base.progressing_writer','base.reclaimed','base.create','--signal=SIGHUP','--signal=SIGKILL','wait_ingress_gone'):
            self.assertIn(text,source)
        self.assertNotIn("subprocess.run(['sh'",source)
        self.assertIn("if CHECKPOINT.exists() or not NEGATIVES",source)
        self.assertIn("run(HELPER,'setup')",inspect.getsource(guest.operator))
        self.assertNotIn('reset-failed',inspect.getsource(guest.start_ingress))

    def test_failure_marker_is_last_after_complete_diagnostic(self):
        output=io.StringIO()
        with patch('builtins.open',return_value=contextlib.nullcontext(output)),patch.object(guest.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
            try:raise RuntimeError('controlled unit diagnostic')
            except RuntimeError:guest.failure_console()
        text=output.getvalue()
        self.assertLess(text.index('Traceback'),text.index('XANDBOX_SYSTEMD_HOST_FAILED ingress'))
        self.assertTrue(text.endswith('XANDBOX_SYSTEMD_HOST_FAILED ingress\n'))

    def test_failure_footer_survives_bounded_journal_error(self):
        output=io.StringIO()
        with patch('builtins.open',return_value=contextlib.nullcontext(output)),patch.object(guest.subprocess,'run',side_effect=subprocess.TimeoutExpired('unexecuted',10)):
            try:raise RuntimeError('controlled unit diagnostic')
            except RuntimeError:guest.failure_console()
        text=output.getvalue()
        self.assertIn('owned journal diagnostic unavailable',text)
        self.assertTrue(text.endswith('XANDBOX_SYSTEMD_HOST_FAILED ingress\n'))


if __name__=='__main__':unittest.main()
