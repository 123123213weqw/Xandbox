import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('resources',Path(__file__).with_name('kvm_resources.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class ResourceObservationTests(unittest.TestCase):
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
