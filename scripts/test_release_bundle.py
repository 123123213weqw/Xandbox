import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import verify_release_bundle as bundle


VERSION, SOURCE, TARGET = 'v0.1.0-preview.1', '1' * 40, 'linux-amd64'


def binary(target):
    if target.startswith('linux-'):
        value = bytearray(b'\x7fELF\x02\x01' + b'\x00' * 58)
        struct.pack_into('<HH', value, 16, 2, 62 if target.endswith('amd64') else 183)
    else:
        value = bytearray(b'\xcf\xfa\xed\xfe' + b'\x00' * 60)
        struct.pack_into('<I', value, 4, 0x1000007 if target.endswith('amd64') else 0x100000c)
    return bytes(value)


def content(target=TARGET):
    executable = binary(target)
    names = bundle.LINUX if target.startswith('linux-') else bundle.COMMON
    info = {'CGO_ENABLED': 0, 'TEST_ONLY_helpers_included': False,
            'build_flags': ['-trimpath', '-buildvcs=false'], 'experimental_preview': True,
            'go_toolchain': 'go1.27.3', 'guest_images_or_Firecracker_included': False,
            'new_KVM_or_performance_qualification': False, 'production_ready': False,
            'source_commit': SOURCE, 'source_tree': '2' * 40, 'target': target, 'version': VERSION,
            'programs': {n: {'bytes': len(executable), 'sha256': hashlib.sha256(executable).hexdigest()} for n in names}}
    rows = [(f'bin/{n}', executable, 0o755, tarfile.REGTYPE) for n in sorted(names)]
    rows += [(n, b'public text\n', 0o644, tarfile.REGTYPE) for n in sorted(bundle.REQUIRED_TEXT - {'BUILD_INFO.json'})]
    rows += [('docs/STATUS.md', b'experimental\n', 0o644, tarfile.REGTYPE)]
    return rows, info


def archive(rows=None, info=None, target=TARGET, *, info_raw=None, suffix=b'', pax=None):
    defaults, metadata = content(target)
    rows = defaults if rows is None else rows
    info = metadata if info is None else info
    rows = rows + [('BUILD_INFO.json', info_raw if info_raw is not None else json.dumps(info).encode(), 0o644, tarfile.REGTYPE)]
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for name, data, mode, kind in rows:
            member = tarfile.TarInfo(f'Xandbox-{VERSION}-{target}/{name}')
            member.size, member.mode, member.type = len(data), mode, kind
            if pax is not None: member.pax_headers = pax
            if kind == tarfile.SYMTYPE: member.linkname = '/private/never-read'
            tar.addfile(member, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return gzip.compress(out.getvalue() + suffix)


class BundleTests(unittest.TestCase):
    def verify(self, data, target=TARGET, **pins):
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / 'preview.tar.gz'; file.write_bytes(data)
            expected = dict(sha256=hashlib.sha256(data).hexdigest(), version=VERSION,
                            target=target, source=SOURCE)
            expected.update(pins)
            return bundle.verify(file, **expected)

    def reject(self, data, **pins):
        with self.assertRaises((ValueError, OSError, EOFError, tarfile.TarError, KeyError, TypeError)):
            self.verify(data, **pins)

    def test_all_four_architectures_read_only(self):
        for target in ('linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64'):
            with self.subTest(target=target):
                result = self.verify(archive(target=target), target)
                self.assertTrue(result['archive_verified'])
                self.assertFalse(result['installed']); self.assertFalse(result['production_ready'])
                self.assertEqual(result['programs_verified'], 15 if target.startswith('linux-') else 12)

    def test_every_external_pin_is_required(self):
        data = archive()
        for pins in ({'sha256': '0' * 64}, {'sha256': 'X' * 64}, {'source': '3' * 40},
                     {'version': 'v0.1.0-preview.2'}, {'target': 'linux-arm64'}, {'target': 'windows-amd64'}):
            with self.subTest(pins=pins): self.reject(data, **pins)

    def test_metadata_boolean_flags_not_truthy_integers(self):
        rows, base = content()
        for key in ('TEST_ONLY_helpers_included', 'guest_images_or_Firecracker_included',
                    'new_KVM_or_performance_qualification', 'production_ready'):
            for value in (True, 0, None):
                info = copy.deepcopy(base); info[key] = value
                with self.subTest(key=key, value=value): self.reject(archive(rows, info))
        info = copy.deepcopy(base); info['CGO_ENABLED'] = False
        self.reject(archive(rows, info))

    def test_metadata_hash_size_inventory_and_duplicate_keys(self):
        rows, base = content()
        for value in ({'bytes': True, 'sha256': base['programs']['sandboxd']['sha256']},
                      {'bytes': 64, 'sha256': '0' * 64}, {'bytes': 65, 'sha256': '0' * 64}):
            info = copy.deepcopy(base); info['programs']['sandboxd'] = value
            self.reject(archive(rows, info))
        info = copy.deepcopy(base); del info['programs']['sandboxd']
        self.reject(archive(rows, info))
        self.reject(archive(info_raw=b'{"version":"x","version":"y"}'))

    def test_paths_duplicates_links_devices_and_unlisted_executables(self):
        rows, _ = content()
        for name, kind in [('../escape', tarfile.REGTYPE), ('docs/../escape.txt', tarfile.REGTYPE),
                           ('/absolute', tarfile.REGTYPE), ('docs//x.md', tarfile.REGTYPE),
                           ('bin/foreign', tarfile.REGTYPE), ('.env', tarfile.REGTYPE),
                           ('docs/link.md', tarfile.SYMTYPE), ('docs/device.md', tarfile.CHRTYPE),
                           ('docs/hard.md', tarfile.LNKTYPE), ('docs/pipe.md', tarfile.FIFOTYPE)]:
            with self.subTest(name=name, kind=kind):
                self.reject(archive(rows + [(name, b'x', 0o644, kind)]))
        self.reject(archive(rows + [rows[0]]))

    def test_required_documents_and_programs_cannot_be_omitted(self):
        rows, _ = content()
        for name in ('LICENSE', 'README_PREVIEW.md', 'docs/STATUS.md', 'bin/sandboxd'):
            with self.subTest(name=name): self.reject(archive([row for row in rows if row[0] != name]))

    def test_wrong_binary_mode_and_architecture(self):
        rows, _ = content()
        bad = rows.copy(); name, data, _, kind = bad[0]; bad[0] = (name, data, 0o4755, kind)
        self.reject(archive(bad))
        bad[0] = (name, binary('linux-arm64'), 0o755, kind)
        self.reject(archive(bad))

    def test_compressed_expanded_and_member_count_caps(self):
        data = archive()
        for key, bound in [('MAX_COMPRESSED', 1), ('MAX_EXPANDED', 1000), ('MAX_MEMBERS', 1)]:
            with self.subTest(key=key), mock.patch.object(bundle, key, bound): self.reject(data)

    def test_truncation_crc_and_concatenated_or_buffered_nonzero_tail(self):
        data = archive()
        self.reject(data[:-4])
        bad = bytearray(data); bad[-8] ^= 1; self.reject(bytes(bad))
        self.reject(archive(suffix=b'foreign payload'))
        self.reject(data + gzip.compress(b'foreign second member'))
        raw = bytearray(gzip.decompress(data))
        # Nonzero bytes after the first zero block but within tarfile read-ahead.
        raw[-512] = 1
        self.reject(gzip.compress(raw))

    def test_symlink_and_fifo_sources_are_never_followed_or_blocked(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'source'; source.write_bytes(archive())
            link = Path(root) / 'link'; link.symlink_to(source)
            fifo = Path(root) / 'fifo'; os.mkfifo(fifo)
            for path in (link, fifo):
                with self.assertRaises((ValueError, OSError)):
                    bundle.verify(path, hashlib.sha256(source.read_bytes()).hexdigest(), VERSION, TARGET, SOURCE)

    def test_source_mutation_observation_refuses_success(self):
        original = bundle._verify
        # fdopen.name is an FD, so perform a harmless metadata mutation on that
        # exact already-open file, never an arbitrary external path.
        def chmod(file, *args):
            result = original(file, *args); os.fchmod(file.fileno(), 0o400); return result
        with mock.patch.object(bundle, '_verify', side_effect=chmod): self.reject(archive())

    def test_only_matching_long_name_pax_path_is_allowed(self):
        rows, _ = content()
        rows.append(('docs/' + 'long' * 30 + '.md', b'public', 0o644, tarfile.REGTYPE))
        self.assertTrue(self.verify(archive(rows))['archive_verified'])
        for pax in ({'comment': 'unexpected'}, {'size': '1'}, {'path': '../escape'}):
            with self.subTest(pax=pax): self.reject(archive(pax=pax))

    def test_cli_error_is_closed_and_does_not_echo_private_path(self):
        command = [sys.executable, str(Path(bundle.__file__)), '--archive', '/private/do-not-echo',
                   '--sha256', '0' * 64, '--version', VERSION, '--target', TARGET, '--source-commit', SOURCE]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 1); self.assertEqual(result.stdout, b'')
        self.assertNotIn(b'/private', result.stderr)


if __name__ == '__main__':
    unittest.main()
