import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from verify_fixture_calibration import MAX_BYTES, read_regular, verify


class FixtureCalibrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.go = self.root / 'cmd/xandbox-host-fixture'
        self.go.mkdir(parents=True)
        (self.root / 'scripts').mkdir()
        self.daemon = self.root / 'daemon'
        self.gateway = self.root / 'gateway'
        # Structural ELF test data only; never claim this is a real Go build.
        elf = bytearray(64)
        elf[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', elf, 18, 62)
        struct.pack_into('<H', elf, 54, 56)
        self.daemon.write_bytes(elf + b'daemon')
        self.gateway.write_bytes(elf + b'gateway')
        self.pins()

    def pins(self):
        self.d = hashlib.sha256(self.daemon.read_bytes()).hexdigest()
        self.g = hashlib.sha256(self.gateway.read_bytes()).hexdigest()
        (self.go / 'node_prepare_trace_linux.go').write_text(
            'const prepareTraceELFSHA = "' + self.d + '"\n')
        (self.go / 'node_tls_policy_notify_linux.go').write_text(
            'const tlsPolicyGatewaySHA = "' + self.g + '"\n')
        (self.root / 'scripts/kvm_nested_host.py').write_text(
            'PREPARE_TRACE_ELF_SHA256="' + self.d + '"\n')

    def check(self):
        return verify(self.root, self.daemon, self.gateway)

    def test_exact_pair_passes_without_executing_any_input(self):
        self.assertEqual(self.check(), {'daemon': self.d, 'gateway': self.g})

    def test_old_fixed_gateway_pin_rejects_current_input(self):
        (self.go / 'node_tls_policy_notify_linux.go').write_text(
            'const tlsPolicyGatewaySHA = "' + '4' * 64 + '"\n')
        with self.assertRaises(ValueError): self.check()

    def test_swapped_and_changed_artifacts_rejected(self):
        with self.assertRaises(ValueError): verify(self.root, self.gateway, self.daemon)
        self.gateway.write_bytes(self.gateway.read_bytes() + b'changed')
        with self.assertRaises(ValueError): self.check()

    def test_go_python_daemon_must_agree(self):
        (self.root / 'scripts/kvm_nested_host.py').write_text(
            'PREPARE_TRACE_ELF_SHA256="' + '0' * 64 + '"\n')
        with self.assertRaises(ValueError): self.check()

    def test_duplicate_missing_uppercase_or_nonliteral_pin_rejected(self):
        p = self.root / 'scripts/kvm_nested_host.py'
        original = p.read_text()
        for bad in ('', original + original, 'PREPARE_TRACE_ELF_SHA256=True\n',
                    'PREPARE_TRACE_ELF_SHA256="a"*64\n', original.upper()):
            p.write_text(bad)
            with self.subTest(bad=bad), self.assertRaises(ValueError): self.check()

    def test_duplicate_go_pin_rejected(self):
        p = self.go / 'node_tls_policy_notify_linux.go'
        p.write_text(p.read_text() * 2)
        with self.assertRaises(ValueError): self.check()

    def test_matching_hash_does_not_admit_wrong_architecture(self):
        b = bytearray(self.gateway.read_bytes())
        struct.pack_into('<H', b, 18, 183)
        self.gateway.write_bytes(b)
        self.pins()
        with self.assertRaises(ValueError): self.check()

    def test_matching_hash_does_not_admit_dynamic_elf(self):
        b = bytearray(self.gateway.read_bytes()[:64]) + bytearray(56)
        struct.pack_into('<Q', b, 32, 64)
        struct.pack_into('<H', b, 56, 1)
        struct.pack_into('<I', b, 64, 3)
        self.gateway.write_bytes(b)
        self.pins()
        with self.assertRaises(ValueError): self.check()

    def test_truncated_or_non_elf_rejected_even_with_matching_hash(self):
        for b in (b'\x7fELF\x02\x01', b'#!/bin/sh\nexit 0\n'):
            self.gateway.write_bytes(b)
            self.pins()
            with self.assertRaises(ValueError): self.check()

    def test_missing_empty_directory_and_oversize_rejected(self):
        with self.assertRaises(OSError): read_regular(self.root / 'missing')
        self.gateway.write_bytes(b'')
        with self.assertRaises(ValueError): self.check()
        with self.assertRaises(ValueError): read_regular(self.root)
        with self.gateway.open('wb') as f: f.truncate(MAX_BYTES + 1)
        with self.assertRaises(ValueError): self.check()

    def test_symlink_rejected_not_followed(self):
        original = self.gateway.read_bytes()
        self.gateway.unlink()
        self.gateway.symlink_to(self.daemon)
        with self.assertRaises(OSError): self.check()
        self.gateway.unlink()
        self.gateway.write_bytes(original)
        self.check()

    def test_fifo_rejected_without_waiting_for_writer(self):
        import os
        self.gateway.unlink()
        os.mkfifo(self.gateway)
        with self.assertRaises(ValueError): self.check()


if __name__ == '__main__':
    unittest.main()
