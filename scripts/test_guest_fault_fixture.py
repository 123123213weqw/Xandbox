import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('fault_fixture',Path(__file__).with_name('build_guest_fault_fixture.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class FaultFixtureTest(unittest.TestCase):
    def test_newc_roundtrip_retains_devices_and_permissions(self):
        items={'.':module.fixture_entry(1,stat.S_IFDIR|0o755),
               'dev/console':([2,stat.S_IFCHR|0o600,0,0,1,0,0,0,0,5,1,0,0],b''),
               'etc/inittab':module.fixture_entry(3,stat.S_IFREG|0o644,b'fixed\n')}
        decoded=module.entries(module.pack(items))
        self.assertEqual(decoded['dev/console'][0][9:11],[5,1])
        self.assertEqual(decoded['etc/inittab'][1],b'fixed\n')
        self.assertEqual(decoded['.'][0][1],stat.S_IFDIR|0o755)
    def test_archive_rejects_traversal_duplicates_and_truncation(self):
        for name in ('../escape','/absolute'):
            with self.assertRaises(ValueError):module.entries(module.pack({name:module.fixture_entry(1,stat.S_IFREG|0o600)}))
        with self.assertRaises(ValueError):module.entries(b'070701')
    def test_overlay_requires_exact_reviewed_source(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root);source=path/'internal/guest';source.mkdir(parents=True)
            (source/'initialize_linux.go').write_text('not the reviewed initializer')
            with self.assertRaises(ValueError):module.prepare_overlay(path,path/'overlay')
            self.assertFalse((path/'overlay/overlay.json').exists())

if __name__=='__main__':unittest.main()
