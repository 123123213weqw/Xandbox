"""Pure safety/closed-result controls. Actual systemd/KVM is separate opt-in."""
import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from build_guest_image import safe_guest_filter
from build_systemd_host import validate_root_members, units, init_script, configure_root, ROOT_BYTES, MARKER
from kvm_systemd_host import validate_reply, PROBE_FLAGS, RELOAD_FLAGS, STOP_FLAGS, CHECKPOINT_FLAGS
import systemd_delegate_probe


class SystemdFixtureControls(unittest.TestCase):
    def test_bounded_archive_refuses_special_and_oversized_members(self):
        validate_root_members([tarfile.TarInfo('ordinary')])
        for kind in (tarfile.CHRTYPE,tarfile.BLKTYPE,tarfile.FIFOTYPE):
            member=tarfile.TarInfo('special');member.type=kind
            with self.assertRaises(ValueError):validate_root_members([member])
        known=tarfile.TarInfo('dev/null');known.type=tarfile.CHRTYPE;known.devmajor=1;known.devminor=3
        self.assertEqual(validate_root_members([known]),[])
        known.devminor=4
        with self.assertRaises(ValueError):validate_root_members([known])
        member=tarfile.TarInfo('oversize');member.size=(1<<30)+1
        with self.assertRaises(ValueError):validate_root_members([member])
        with self.assertRaises(ValueError):validate_root_members([tarfile.TarInfo('a')]*50001)

    @unittest.skipUnless(hasattr(tarfile,'data_filter'),'security-patched tarfile required')
    def test_rootfs_absolute_link_is_rewritten_not_host_followed(self):
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w') as archive:
            member=tarfile.TarInfo('etc/mtab');member.type=tarfile.SYMTYPE;member.linkname='/proc/mounts';archive.addfile(member)
        raw.seek(0)
        with tempfile.TemporaryDirectory() as root,tarfile.open(fileobj=raw) as archive:
            archive.extractall(root,filter=safe_guest_filter)
            self.assertEqual((Path(root)/'etc/mtab').readlink(),Path('../proc/mounts'))

    def test_switch_root_executes_systemd_only_after_guest_mounts_and_modules(self):
        script=init_script(['fixed.ko'])
        self.assertIn('mount -t ext4 -o rw,nosuid,prjquota /dev/vda /newroot',script)
        self.assertLess(script.index('insmod /lib/fixture/fixed.ko'),script.index('switch_root'))
        self.assertIn('exec switch_root -c /dev/console /newroot /sbin/init',script)
        self.assertNotIn('chroot',script)
        self.assertEqual(ROOT_BYTES,2<<30)

    def test_manager_unit_nests_node_and_does_not_relax_strict_inventory(self):
        main,operator=units()
        for text in ('Delegate=cpu io memory pids','DelegateSubgroup=bootstrap','CapabilityBoundingSet=~CAP_SYS_RESOURCE',
                     'NoNewPrivileges=yes','KillMode=mixed','TimeoutStopSec=3s','MemorySwapMax=0'):
            self.assertIn(text,main)
        self.assertIn('ExecReload=',main);self.assertNotIn('ExecStartPre=',main)
        self.assertIn('systemd_delegate_probe.py operator',operator)
        self.assertEqual(systemd_delegate_probe.NODE,systemd_delegate_probe.UNIT_ROOT/'node')

    def test_configuration_changes_only_explicit_guest_root(self):
        with tempfile.TemporaryDirectory() as private:
            root=Path(private)/'guest';root.mkdir();(root/'etc/cloud').mkdir(parents=True)
            source=Path(private)/'probe';source.write_text('nonexecuted test payload')
            configure_root(root,source)
            self.assertEqual((root/'etc/xandbox-systemd-fixture').read_text(),MARKER)
            self.assertEqual((root/'etc/systemd/system/ssh.service').readlink(),Path('../../../dev/null'))
            self.assertEqual((root/'etc/machine-id').read_text(),'')
            self.assertEqual((root/'opt/xandbox/systemd_delegate_probe.py').read_text(),'nonexecuted test payload')

    def test_probe_cannot_accidentally_run_on_unmarked_host(self):
        with patch('systemd_delegate_probe.os.geteuid',return_value=0),patch('systemd_delegate_probe.Path.read_text',return_value='not owned'):
            with self.assertRaises(RuntimeError):systemd_delegate_probe.guard()

    def test_all_probe_flags_and_typed_versions_are_required(self):
        value={**{k:True for k in PROBE_FLAGS},'runtime_major':255,'nested_kvm_api':12}
        validate_reply('probe',value)
        for key in PROBE_FLAGS:
            bad=copy.deepcopy(value);bad[key]=False
            with self.assertRaises(AssertionError):validate_reply('probe',bad)
        for key,wrong in (('runtime_major',True),('runtime_major',254),('nested_kvm_api',True),('nested_kvm_api',11)):
            bad=copy.deepcopy(value);bad[key]=wrong
            with self.assertRaises(AssertionError):validate_reply('probe',bad)
        with self.assertRaises(AssertionError):validate_reply('probe',{**value,'private_pid':123})

    def test_reload_and_stop_require_independent_checks_not_only_active_state(self):
        for operation,flags,extra in (('reload',RELOAD_FLAGS,{}),('stop-restart',STOP_FLAGS,{'stop_return_ms':3001.2})):
            value={**{k:True for k in flags},**extra};validate_reply(operation,value)
            for key in flags:
                bad=copy.deepcopy(value);bad[key]=False
                with self.assertRaises(AssertionError):validate_reply(operation,bad)
        value={**{k:True for k in STOP_FLAGS},'stop_return_ms':True}
        with self.assertRaises(AssertionError):validate_reply('stop-restart',value)

    def test_checkpoint_first_and_cold_boot_are_not_interchangeable(self):
        value={k:True for k in CHECKPOINT_FLAGS}
        validate_reply('checkpoint',value,True)
        with self.assertRaises(AssertionError):validate_reply('checkpoint',value,False)
        first={**value,'previous_checkpoint_present':False,'boot_changed_vs_previous':False,'machine_id_preserved_vs_previous':False}
        validate_reply('checkpoint',first,False)
        with self.assertRaises(AssertionError):validate_reply('checkpoint',first,True)
        with self.assertRaises(ValueError):validate_reply('arbitrary',{})


if __name__=='__main__':unittest.main()
