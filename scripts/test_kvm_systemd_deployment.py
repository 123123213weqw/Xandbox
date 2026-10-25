import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from build_systemd_deployment import deployment_units, configure, load_assets, ASSETS
from kvm_systemd_host import (validate_deployment_reply,DEPLOYMENT_PROBE_FLAGS,DEPLOYMENT_CHECKPOINT_FLAGS,DEPLOYMENT_RECOVERY_FLAGS)
import systemd_delegate_probe


class SystemdDeploymentControls(unittest.TestCase):
    def test_unit_uses_actual_go_exec_and_manager_private_snapshots(self):
        unit,operator=deployment_units()
        for text in ('Type=exec','ExecStart=/usr/libexec/xandbox-launch','DelegateSubgroup=bootstrap','RuntimeDirectory=xandbox-inputs',
                     'RuntimeDirectoryPreserve=no','MemoryMax=8053063680','TasksMax=512','CPUQuota=800%','CapabilityBoundingSet=~CAP_SYS_RESOURCE','NoNewPrivileges=yes'):
            self.assertIn(text,unit)
        self.assertNotIn('ExecStartPre=',unit);self.assertNotIn('ExecReload=',unit);self.assertIn('MemoryMax=268435456',operator)

    def test_assembly_only_copies_into_given_guest_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'root';root.mkdir();(root/'opt/xandbox').mkdir(parents=True);(root/'etc/systemd/system/multi-user.target.wants').mkdir(parents=True)
            source=Path(temp)/'asset';source.write_bytes(b'never-executed');digest=hashlib.sha256(source.read_bytes()).hexdigest()
            assets={name:{'path':str(source),'sha256':digest} for name in ASSETS};configure(root,assets)
            self.assertEqual((root/'srv/assets/sandboxd').read_bytes(),b'never-executed')
            self.assertEqual((root/'usr/libexec/xandbox-launch').read_bytes(),b'never-executed')
            self.assertEqual((root/'srv/xb/s').stat().st_mode&0o777,0o700)
            self.assertEqual((root/'etc/systemd/system/multi-user.target.wants/xandbox-deployment-operator.service').readlink(),Path('../xandbox-deployment-operator.service'))
            self.assertEqual(set(json.loads((root/'etc/xandbox/assets.json').read_text())),set(ASSETS))

    def test_wrong_asset_schema_and_hash_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest=Path(temp)/'assets.json';manifest.write_text('{}')
            with self.assertRaises(ValueError):load_assets(manifest)
            manifest.write_text(json.dumps({n:{'path':'/nonexistent','sha256':'0'*64} for n in ASSETS}))
            with self.assertRaises(ValueError):load_assets(manifest)

    def test_closed_deployment_results_do_not_accept_legacy_or_missing_flags(self):
        for operation,flags,extra in [('deployment-probe',DEPLOYMENT_PROBE_FLAGS,{'instance_capacity':4}),('deployment-checkpoint',DEPLOYMENT_CHECKPOINT_FLAGS,{}),('deployment-recover',DEPLOYMENT_RECOVERY_FLAGS,{})]:
            good={**{k:True for k in flags},**extra};validate_deployment_reply(operation,good)
            for key in flags:
                bad=copy.deepcopy(good);bad[key]=False
                with self.assertRaises(AssertionError):validate_deployment_reply(operation,bad)
            with self.assertRaises(AssertionError):validate_deployment_reply(operation,{**good,'private_ref':'forbidden'})
        with self.assertRaises(AssertionError):validate_deployment_reply('deployment-probe',{**{k:True for k in DEPLOYMENT_PROBE_FLAGS},'instance_capacity':True})

    def test_vmm_active_empty_and_bounding_exact_parent(self):
        from systemd_deployment_guest import observe_vmm_capabilities
        fields=('CapInh','CapPrm','CapEff','CapBnd','CapAmb')
        good={name:'0000000000000000' for name in fields};good['CapBnd']='0000000000000003'
        observe_vmm_capabilities(good,good['CapBnd'])
        for name in ('CapInh','CapPrm','CapEff','CapAmb'):
            with self.assertRaisesRegex(RuntimeError,'active or inheritable'):
                observe_vmm_capabilities({**good,name:'0000000000000001'},good['CapBnd'])
        for value in ('0000000000000000','0000000000000001','0000000000000007'):
            with self.assertRaisesRegex(RuntimeError,'ceiling changed'):observe_vmm_capabilities({**good,'CapBnd':value},good['CapBnd'])
        for name in fields:
            bad=good.copy();del bad[name]
            with self.assertRaisesRegex(RuntimeError,'observation malformed'):observe_vmm_capabilities(bad,good['CapBnd'])
        with self.assertRaisesRegex(RuntimeError,'observation malformed'):observe_vmm_capabilities({**good,'CapBnd':'secret-not-relayed'},good['CapBnd'])
        with self.assertRaisesRegex(RuntimeError,'observation malformed'):observe_vmm_capabilities(good,'invalid')

    def test_resource_capability_rejected_in_every_set_and_parent(self):
        from systemd_deployment_guest import observe_vmm_capabilities
        fields=('CapInh','CapPrm','CapEff','CapBnd','CapAmb');good={name:'0000000000000000' for name in fields}
        for name in fields:
            with self.assertRaisesRegex(RuntimeError,'quota bypass'):observe_vmm_capabilities({**good,name:'0000000001000000'},good['CapBnd'])
        with self.assertRaisesRegex(RuntimeError,'quota bypass'):observe_vmm_capabilities(good,'0000000001000000')

    def test_create_explicitly_allows_fixed_busy_writer_and_replay_uses_same_spec(self):
        import inspect
        import systemd_deployment_guest as guest
        spec=guest.create_spec()
        self.assertEqual(spec,{'ttl_ms':300000,'limits':{'max_exec_ms':60000}})
        with patch('systemd_deployment_guest.call',return_value={'not_executed':True}) as request:
            self.assertEqual(guest.create('alpha','test-key'),{'not_executed':True})
        request.assert_called_once_with('POST','/v1/sandboxes',spec,tenant='alpha',key='test-key',expected=201)
        self.assertIn('tenant,45000)',inspect.getsource(guest.progressing_writer))
        self.assertIn('create_spec()',inspect.getsource(guest.first_checkpoint))
        self.assertIn('create_spec()',inspect.getsource(guest.recover))

    def test_unmarked_host_guard_cannot_fall_back_to_console(self):
        with patch('systemd_delegate_probe.guard',side_effect=RuntimeError('unmarked')),patch('systemd_delegate_probe.failure_console') as output:
            with self.assertRaises(RuntimeError):systemd_delegate_probe.entry('operator')
            output.assert_not_called()


if __name__=='__main__':unittest.main()
