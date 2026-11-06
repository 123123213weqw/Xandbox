import importlib.util
import errno
import os
from pathlib import Path
import tempfile
import shutil
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('resources',Path(__file__).with_name('kvm_resources.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class ResourceObservationTests(unittest.TestCase):
    def test_removed_cgroup_fd_enodev_is_not_live_stop_proof(self):
        with tempfile.TemporaryDirectory() as root:
            group=Path(root)/'group';group.mkdir()
            for number in (errno.ENODEV,errno.ENOENT):
                with patch.object(Path,'read_text',side_effect=OSError(number,'injected')):
                    self.assertFalse(module.cgroup_empty(group))
                    self.assertTrue(module.cgroup_empty(group/'already-removed'))
            with patch.object(Path,'read_text',side_effect=PermissionError(errno.EACCES,'injected')):
                with self.assertRaises(PermissionError):module.cgroup_empty(group)
            (group/'cgroup.events').write_text('populated 0\nfrozen 0\n')
            self.assertTrue(module.cgroup_empty(group))
            (group/'cgroup.events').write_text('populated 1\nfrozen 0\n')
            self.assertFalse(module.cgroup_empty(group))
    def test_kb_counters_and_units(self):
        self.assertEqual(module.parse_kb('Rss: 12 kB\nPss: 7 kB\nVmFlags: rd wr\n'),{'Rss':12288,'Pss':7168})
        for text in ['Pss: -1 kB','Rss: 1 MB','Anonymous: not-a-number kB']:
            with self.assertRaises(ValueError):module.parse_kb(text)
    def test_exact_inode_mapping_not_filename(self):
        text=('1000-2000 rw-p 00000000 fd:02 23 /template.mem\nRss: 8 kB\nPss: 4 kB\nAnonymous: 2 kB\n'
              '2000-3000 rw-p 00000000 fd:02 24 /template.mem\nRss: 99 kB\nPss: 99 kB\n'
              '3000-4000 rw-p 00000000 fd:02 23 /private/another-hardlink\nRss: 1 kB\nPss: 1 kB\n')
        values=module.mapped_backing(text,(253,2,23))
        self.assertEqual(values['Rss'],9*1024);self.assertEqual(values['Pss'],5*1024)
        self.assertEqual(values['Anonymous'],2*1024)
    def test_start_identity_handles_space_and_parenthesis(self):
        fields=['S']+['0']*18+['1234']+['0']*5
        self.assertEqual(module.start_ticks('99 (guest (worker)) '+' '.join(fields)),'1234')
        with self.assertRaises(ValueError):module.start_ticks('invalid')
    def test_preparing_workspace_is_counted_not_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'workspace.ext4';p.write_bytes(b'x'*4096)
            info, preparing=module.workspace_observation(p)
            self.assertEqual(info.st_size,4096);self.assertEqual(preparing,1)
            with p.open('r+b') as f:f.truncate(128<<20)
            self.assertEqual(module.workspace_observation(p)[1],0)
            os.link(p,Path(root)/'unexpected-hardlink')
            with self.assertRaises(ValueError):module.workspace_observation(p)
    @unittest.skipUnless(os.uname().sysname=='Linux','mincore layout is explicitly Linux-only')
    def test_residency_bounded_and_no_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'memory';p.write_bytes(b'x'*8192)
            value=module.file_resident_bytes(p,8192)
            self.assertGreaterEqual(value,0);self.assertLessEqual(value,8192)
            (Path(root)/'link').symlink_to(p)
            with self.assertRaises(ValueError):module.file_resident_bytes(Path(root)/'link',8192)
            with self.assertRaises(ValueError):module.file_resident_bytes(p,4096)

    def sampler_fixture(self, root):
        root=Path(root);jails=root/'runtime/j/firecracker';jails.mkdir(parents=True)
        group=root/'cgroups';group.mkdir();backend=root/'backend';backend.mkdir()
        memory=root/'memory'
        with memory.open('wb') as file:file.truncate(512<<20)
        state=root/'state';state.write_bytes(b'state')
        sampler=module.ResourceSampler.__new__(module.ResourceSampler)
        sampler.process=SimpleNamespace(pid=987654321,poll=lambda:None)
        sampler.controller_identity='fixed';sampler.transient_misses=0
        sampler.cgroup=group;sampler.runtime=root/'runtime';sampler.memory=memory
        sampler.snapshot_state=state;sampler.backend=backend
        sampler._process=lambda pid:('fixed',{'Rss':1024,'Pss':512},{})
        return sampler,jails
    def test_removed_valid_jail_is_counted_as_transient_not_unknown(self):
        with tempfile.TemporaryDirectory() as root:
            sampler,parent=self.sampler_fixture(root);jail=parent/('a'*64)
            (jail/'root').mkdir(parents=True);(jail/'root/workspace.ext4').write_bytes(b'x')
            original=Path.iterdir
            def enumerate_then_remove(path):
                if path==Path('/proc/987654321/fd'):return iter(())
                entries=list(original(path))
                if path==parent:shutil.rmtree(jail)
                return iter(entries)
            with patch.object(Path,'iterdir',enumerate_then_remove),patch.object(module,'file_resident_bytes',return_value=0):
                row=sampler.sample()
            self.assertEqual(row['private_workspace_logical_bytes'],0)
            self.assertEqual(row['private_workspace_preparing_files'],0)
            self.assertEqual(row['transient_identity_misses_total'],1)
    def test_unknown_jail_name_remains_fatal_even_when_absent(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ('foreign','A'*64,'a'*63,'a'*65):
                with self.subTest(name=name),self.assertRaises(ValueError):
                    module.jail_workspace_observation(Path(root)/name)
    def test_jail_directory_fd_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);target=root/'foreign';(target/'root').mkdir(parents=True)
            (target/'root/workspace.ext4').write_bytes(b'x');jail=root/('a'*64);jail.symlink_to(target,target_is_directory=True)
            with self.assertRaises(ValueError):module.jail_workspace_observation(jail)
    def test_root_directory_fd_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);target=root/'foreign';target.mkdir();(target/'workspace.ext4').write_bytes(b'x')
            jail=root/('a'*64);jail.mkdir();(jail/'root').symlink_to(target,target_is_directory=True)
            with self.assertRaises(ValueError):module.jail_workspace_observation(jail)
    def test_descriptor_workspace_rejects_symlink_hardlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);jail=root/('a'*64);(jail/'root').mkdir(parents=True)
            file=jail/'root/workspace.ext4';target=root/'foreign';target.write_bytes(b'x')
            file.symlink_to(target)
            with self.assertRaises(ValueError):module.jail_workspace_observation(jail)
            file.unlink();os.link(target,file)
            with self.assertRaises(ValueError):module.jail_workspace_observation(jail)
            file.unlink();os.mkfifo(file)
            with self.assertRaises(ValueError):module.jail_workspace_observation(jail)
    def test_descriptor_workspace_preserves_partial_and_complete_sizes(self):
        with tempfile.TemporaryDirectory() as root:
            jail=Path(root)/('a'*64);(jail/'root').mkdir(parents=True);file=jail/'root/workspace.ext4';file.write_bytes(b'x'*4096)
            info,partial=module.jail_workspace_observation(jail)
            self.assertEqual(info.st_size,4096);self.assertEqual(partial,1)
            with file.open('r+b') as handle:handle.truncate(128<<20)
            self.assertEqual(module.jail_workspace_observation(jail)[1],0)
            with file.open('r+b') as handle:handle.truncate((128<<20)+1)
            with self.assertRaises(ValueError):module.jail_workspace_observation(jail)
    def test_jail_open_only_missing_may_be_transient(self):
        with tempfile.TemporaryDirectory() as root:
            jail=Path(root)/('a'*64)
            with self.assertRaises(FileNotFoundError):module.jail_workspace_observation(jail)
            for error in (errno.EACCES,errno.EIO,errno.ENODEV):
                with self.subTest(error=error),patch.object(module.os,'open',side_effect=OSError(error,'injected')):
                    with self.assertRaises(OSError) as caught:module.jail_workspace_observation(jail)
                    self.assertEqual(caught.exception.errno,error)
    def test_directory_anchor_cannot_be_redirected_after_open(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);jail=root/('a'*64);(jail/'root').mkdir(parents=True)
            (jail/'root/workspace.ext4').write_bytes(b'x'*4096)
            foreign=root/'foreign';(foreign/'root').mkdir(parents=True)
            (foreign/'root/workspace.ext4').write_bytes(b'y'*8192)
            moved=root/'original-owned';real_open=os.open
            def redirect_after_open(path,*args,**kwargs):
                fd=real_open(path,*args,**kwargs)
                if path==jail:
                    jail.rename(moved);jail.symlink_to(foreign,target_is_directory=True)
                return fd
            with patch.object(module.os,'open',side_effect=redirect_after_open):
                value,partial=module.jail_workspace_observation(jail)
            self.assertEqual(value.st_size,4096);self.assertEqual(partial,1)
            self.assertEqual(value.st_ino,(moved/'root/workspace.ext4').stat().st_ino)
            self.assertNotEqual(value.st_ino,(foreign/'root/workspace.ext4').stat().st_ino)
    def test_directory_fds_close_after_root_or_workspace_disappears(self):
        with tempfile.TemporaryDirectory() as root:
            jail=Path(root)/('a'*64);jail.mkdir();real_open=os.open;opened=[]
            def opened_fd(*args,**kwargs):
                fd=real_open(*args,**kwargs);opened.append(fd);return fd
            for with_root in (False,True):
                if with_root:(jail/'root').mkdir()
                opened.clear()
                with patch.object(module.os,'open',side_effect=opened_fd):
                    with self.assertRaises(FileNotFoundError):module.jail_workspace_observation(jail)
                self.assertEqual(len(opened),2 if with_root else 1)
                for fd in opened:
                    with self.assertRaises(OSError) as caught:os.fstat(fd)
                    self.assertEqual(caught.exception.errno,errno.EBADF)

if __name__=='__main__':unittest.main()
