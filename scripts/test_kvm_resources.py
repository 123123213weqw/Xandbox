import importlib.util
import errno
import os
from pathlib import Path
import tempfile
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

if __name__=='__main__':unittest.main()
