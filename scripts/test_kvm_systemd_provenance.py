"""Synthetic reader/wiring controls, not root, systemd or KVM acceptance."""
import contextlib
import copy
import hashlib
import inspect
import io
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import build_systemd_host as host
import build_systemd_install as initial
import build_systemd_managed as managed
import build_systemd_release as release
import kvm_systemd_host as harness
import systemd_fixture_provenance as p
import systemd_release_guest as guest


def elf(suffix=b''):
    value = bytearray(64)
    value[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<H', value, 18, 62)
    struct.pack_into('<H', value, 54, 56)
    return bytes(value) + suffix


class SystemdProvenanceControls(unittest.TestCase):
    def declarations(self, profile):
        return {role: {'path': '/synthetic-not-opened/' + role,
                       'sha256': p.PINS['managed-setup' if role == 'setup' and profile == 'managed' else role]}
                for role in p.PROFILES[profile]}

    def test_one_qualified_source_and_two_byte_equal_publication_sources(self):
        self.assertEqual(p.SOURCE_REVISION, '00dc99de10b52d6988b52f12760f61e3fd43fb3d')
        self.assertEqual(initial.PRODUCTION_SOURCE, p.SOURCE_REVISION)
        self.assertEqual(managed.PRODUCTION_SOURCE, p.SOURCE_REVISION)
        self.assertEqual(guest.NATIVE_SOURCES, p.RELEASE_SOURCES)
        self.assertEqual(p.RELEASE_SOURCES, ('bf405dccbead973eacadfa89a0c6866fcc266e36', p.SOURCE_REVISION))
        self.assertEqual(len(p.PUBLICATION), 13)
        self.assertEqual(len(p.PROGRAM_FILES), 13)
        self.assertEqual(len(set(p.PROGRAM_FILES.values())), 13)

    def test_complete_profile_roles_and_every_declared_file_is_checked(self):
        expected = {'deployment': 9, 'ingress': 12, 'readiness': 13,
                    'release': 15, 'install': 16, 'managed': 16}
        for profile, count in expected.items():
            value = self.declarations(profile)
            self.assertEqual(len(value), count)
            with patch.object(p, 'read_pinned') as read:
                self.assertEqual(p.validate_assets(value, profile), p.SOURCE_REVISION)
                self.assertEqual(read.call_count, count)
                for call, role in zip(read.call_args_list, value):
                    self.assertEqual(call.args, (value[role]['path'], value[role]['sha256']))
                    self.assertIs(call.kwargs['workspace'], role == 'workspace')
                    self.assertIs(call.kwargs['program'], role in p.PROGRAM_FILES or role in ('firecracker', 'jailer'))

    def test_each_role_wrong_digest_refused_before_any_file_read(self):
        for profile in p.PROFILES:
            original = self.declarations(profile)
            for role in original:
                value = copy.deepcopy(original); value[role]['sha256'] = '0' * 64
                with patch.object(p, 'read_pinned') as read:
                    with self.assertRaises(ValueError): p.validate_assets(value, profile)
                    read.assert_not_called()

    def test_missing_extra_or_unknown_declaration_never_opens_a_file(self):
        for profile in p.PROFILES:
            original = self.declarations(profile)
            for role in original:
                value = copy.deepcopy(original); del value[role]
                with patch.object(p, 'read_pinned') as read:
                    with self.assertRaises(ValueError): p.validate_assets(value, profile)
                    read.assert_not_called()
            for bad in (None, [], {}, {**original, 'source_revision': p.SOURCE_REVISION}):
                with patch.object(p, 'read_pinned') as read:
                    with self.assertRaises(ValueError): p.validate_assets(bad, profile)
                    read.assert_not_called()

    def test_closed_role_fields_types_and_no_source_override(self):
        value = self.declarations('install')
        for bad in (None, [], {}, {'path': '/synthetic', 'sha256': True},
                    {**value['daemon'], 'source_revision': p.SOURCE_REVISION},
                    {**value['daemon'], 'path': None}):
            with patch.object(p, 'read_pinned') as read:
                with self.assertRaises(ValueError): p.validate_assets({**value, 'daemon': bad}, 'install')
                read.assert_not_called()
        for profile in ('other', True, None, [], 'Install'):
            with self.assertRaises(ValueError): p.validate_assets(value, profile)

    def test_initial_and_managed_setup_cannot_be_crossed(self):
        for profile, wrong in (('install', 'managed-setup'), ('managed', 'setup')):
            value = self.declarations(profile); value['setup']['sha256'] = p.PINS[wrong]
            with self.assertRaises(ValueError): p.validate_assets(value, profile)

    def test_reader_real_synthetic_static_elf_and_data_never_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input'; data = elf(b'synthetic never executed'); path.write_bytes(data)
            self.assertEqual(p.read_pinned(path, hashlib.sha256(data).hexdigest(), program=True), len(data))
            path.write_bytes(b'non-executable image data')
            self.assertEqual(p.read_pinned(path, hashlib.sha256(path.read_bytes()).hexdigest(), program=False), path.stat().st_size)

    def test_reader_relative_missing_directory_empty_and_wrong_hash(self):
        with self.assertRaises(ValueError): p.read_pinned('relative', '0' * 64, program=False)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for path in (root, root / 'missing'):
                with self.assertRaises((ValueError, OSError)): p.read_pinned(path, '0' * 64, program=False)
            path = root / 'file'; path.touch()
            with self.assertRaises(ValueError): p.read_pinned(path, '0' * 64, program=False)
            path.write_bytes(elf())
            with self.assertRaises(ValueError): p.read_pinned(path, '0' * 64, program=True)

    def test_reader_symlink_and_fifo_refused_without_wait(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'source'; source.write_bytes(elf())
            link = root / 'link'; link.symlink_to(source)
            with self.assertRaises(OSError): p.read_pinned(link, '0' * 64, program=True)
            fifo = root / 'fifo'; os.mkfifo(fifo)
            with self.assertRaises(ValueError): p.read_pinned(fifo, '0' * 64, program=False)

    def test_matching_hash_does_not_admit_dynamic_or_wrong_arch_elf(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input'
            arch = bytearray(elf()); struct.pack_into('<H', arch, 18, 183)
            dynamic = bytearray(elf()) + bytearray(56)
            struct.pack_into('<Q', dynamic, 32, 64); struct.pack_into('<H', dynamic, 56, 1)
            struct.pack_into('<I', dynamic, 64, 3)
            for value in (arch, dynamic, b'#!/bin/sh\nexit 0\n'):
                path.write_bytes(value)
                with self.assertRaises(ValueError): p.read_pinned(path, hashlib.sha256(value).hexdigest(), program=True)

    def test_workspace_and_other_inputs_have_distinct_fixed_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'data'
            with path.open('wb') as file: file.truncate((64 << 20) + 1)
            with self.assertRaises(ValueError): p.read_pinned(path, '0' * 64, program=False)
            with self.assertRaises(ValueError): p.read_pinned(path, '0' * 64, program=False, workspace=True)
            with path.open('wb') as file: file.truncate(128 << 20)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(p.read_pinned(path, digest, program=False, workspace=True), 128 << 20)
            with path.open('wb') as file: file.truncate((128 << 20) + 1)
            with self.assertRaises(ValueError): p.read_pinned(path, '0' * 64, program=False, workspace=True)

    def test_changed_inode_metadata_during_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input'; data = elf(); path.write_bytes(data)
            original = os.fstat
            calls = []
            def changed(fd):
                value = original(fd); calls.append(value)
                if len(calls) == 2:
                    class Changed:
                        st_dev=value.st_dev; st_ino=value.st_ino; st_size=value.st_size
                        st_mtime_ns=value.st_mtime_ns; st_ctime_ns=value.st_ctime_ns + 1
                    return Changed()
                return value
            with patch.object(p.os, 'fstat', side_effect=changed):
                with self.assertRaises(ValueError): p.read_pinned(path, hashlib.sha256(data).hexdigest(), program=True)

    def test_all_thirteen_programs_are_verified_with_synthetic_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); pins = {}
            for role, filename in p.PROGRAM_FILES.items():
                value = elf(role.encode()); (root / filename).write_bytes(value)
                pins[role] = hashlib.sha256(value).hexdigest()
            with patch.dict(p.PINS, pins):
                self.assertEqual(p.verify_programs(root), p.SOURCE_REVISION)
                (root / p.PROGRAM_FILES['managed-setup']).write_bytes(b'changed')
                with self.assertRaises(ValueError): p.verify_programs(root)

    def test_cli_rejects_without_leaking_raw_exception_or_paths(self):
        stderr = io.StringIO()
        with patch.object(sys, 'argv', ['reader', '--programs-dir', '/private-not-exported']), patch.object(p, 'verify_programs', side_effect=OSError('secret/path')), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as result: p.main()
        self.assertEqual(result.exception.code, 1)
        self.assertEqual(stderr.getvalue(), 'fixed systemd fixture provenance rejected\n')

    def test_all_image_build_profiles_gate_before_extraction_or_allocation(self):
        for profile in p.PROFILES:
            with patch.object(p, 'validate_assets', side_effect=ValueError('synthetic refusal')) as gate, patch.object(host.tempfile, 'TemporaryDirectory') as temp, patch.object(host.subprocess, 'run') as command:
                with self.assertRaises(ValueError):
                    host.build(ubuntu=None, alpine=None, probe=None, output_disk=None, output_initrd=None, **{profile + '_assets': self.declarations(profile)})
                gate.assert_called_once(); temp.assert_not_called(); command.assert_not_called()

    def test_harness_refuses_all_profiles_before_log_or_resource_creation(self):
        for profile in p.PROFILES:
            module = __import__('build_systemd_' + profile)
            args = ['harness']
            for flag in ('ubuntu', 'alpine', 'fixture', 'warden', 'source-revision', 'report', 'log-dir'):
                args += ['--' + flag, '/not-opened']
            args += ['--' + profile + '-assets', '/not-opened']
            with patch.object(sys, 'argv', args), patch.object(module, 'load_assets', return_value=self.declarations(profile)), patch.object(p, 'validate_assets', side_effect=ValueError('synthetic refusal')) as gate, patch.object(Path, 'mkdir') as mkdir:
                with self.assertRaises(ValueError): harness.main()
                self.assertEqual(gate.call_args.args[1], profile); mkdir.assert_not_called()

    def test_provenance_module_is_in_every_affected_frozen_harness_inventory(self):
        for args in ((True,False,False), (True,True,False), (True,False,True), (True,False,True,True), (True,False,False,False,True), (True,False,False,False,False,True)):
            self.assertEqual(harness.harness_files(*args).count('systemd_fixture_provenance.py'), 1)
        self.assertNotIn('systemd_fixture_provenance.py', harness.harness_files(False,False,False))
        self.assertIn('systemd_fixture_provenance.py', inspect.getsource(release.configure))


if __name__ == '__main__': unittest.main()
