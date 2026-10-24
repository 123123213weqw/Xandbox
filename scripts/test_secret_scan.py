"""Pure fail-closed installation/environment tests; no network or credentials."""
import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from install_secret_scanner import binary_from_archive, digest, install, InstallError, native_pin, read_archive, HTTPSOnly
from secret_scan import environment, scanner_path, scan, ScanError


class SecretGateUnitTests(unittest.TestCase):
    def archive(self, name='gitleaks', kind=tarfile.REGTYPE):
        output = io.BytesIO(); data = b'nonexecuted-test-artifact'
        with tarfile.open(fileobj=output, mode='w:gz') as t:
            member = tarfile.TarInfo(name); member.type = kind
            if kind == tarfile.REGTYPE:
                member.size = len(data); t.addfile(member, io.BytesIO(data))
            else:
                member.linkname = '/outside'; t.addfile(member)
        blob = output.getvalue()
        return blob, {'archive_sha256': digest(blob), 'binary_sha256': digest(data)}

    def test_pin_selects_only_native_supported_platform(self):
        version, pin = native_pin()
        self.assertEqual(version, '8.30.1'); self.assertEqual(len(pin['binary_sha256']), 64)
        with patch('install_secret_scanner.platform.machine', return_value='unqualified'):
            with self.assertRaises(InstallError): native_pin()

    def test_archive_hash_checked_before_parsing(self):
        with self.assertRaises(InstallError): binary_from_archive(b'invalid', {'archive_sha256': '0'*64})

    def test_only_exact_regular_member_is_read(self):
        for name, kind in (('../gitleaks', tarfile.REGTYPE), ('gitleaks', tarfile.SYMTYPE), ('gitleaks', tarfile.LNKTYPE)):
            data, pin = self.archive(name, kind)
            with self.assertRaises(InstallError): binary_from_archive(data, pin)
        data, pin = self.archive(); self.assertEqual(binary_from_archive(data, pin), b'nonexecuted-test-artifact')

    def test_binary_hash_is_independent_of_archive_hash(self):
        data, pin = self.archive(); pin['binary_sha256'] = '0'*64
        with self.assertRaises(InstallError): binary_from_archive(data, pin)

    def test_exclusive_install_never_overwrites_or_follows_links(self):
        data, pin = self.archive()
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)/'tool'; install(p, data, pin)
            with self.assertRaises(FileExistsError): install(p, data, pin)
            link = Path(root)/'link'; link.symlink_to(p)
            with self.assertRaises(FileExistsError): install(link, data, pin)
            with self.assertRaises(ScanError): scanner_path(p)
            self.assertEqual(p.read_bytes(), b'nonexecuted-test-artifact')

    def test_bounded_archive_reader_rejects_fifo_symlink_directory(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root); (p/'regular').write_bytes(b'data'); (p/'link').symlink_to(p/'regular'); os.mkfifo(p/'fifo')
            self.assertEqual(read_archive(p/'regular'), b'data')
            for name in ('link', 'fifo', '.'):
                with self.assertRaises((InstallError, OSError)): read_archive(p/name)

    def test_nonempty_error_console_cannot_return_clean_even_with_zero_status(self):
        def fake_run(command, **kwargs):
            Path(command[command.index('--report-path')+1]).write_text('[]')
            return SimpleNamespace(returncode=0, stdout=b'', stderr=b'fixed synthetic git error')
        with patch('secret_scan.scanner_path', return_value=('/unexecuted', '8.30.1', '0'*64)), patch('secret_scan.subprocess.run', side_effect=fake_run):
            with self.assertRaises(ScanError): scan(Path('/unexecuted'), 'stdin', payload=b'ordinary')

    def test_malformed_unredacted_or_status_mismatched_reports_fail_closed(self):
        for content, code in [('{}', 0), ('[null]', 1), ('[{"RuleID":"fixed", "Secret":"not-redacted"}]', 1), ('[]', 1), ('[]', 2)]:
            def fake_run(command, **kwargs):
                Path(command[command.index('--report-path')+1]).write_text(content)
                return SimpleNamespace(returncode=code, stdout=b'', stderr=b'')
            with patch('secret_scan.scanner_path', return_value=('/unexecuted', '8.30.1', '0'*64)), patch('secret_scan.subprocess.run', side_effect=fake_run):
                with self.assertRaises(ScanError): scan(Path('/unexecuted'), 'stdin', payload=b'ordinary')

    def test_redirect_cannot_downgrade_tls_or_change_trusted_host(self):
        for url in ('http://github.com/asset', 'https://untrusted.invalid/asset', 'https://github.com.untrusted.invalid/asset'):
            with self.assertRaises(InstallError): HTTPSOnly().redirect_request(None, None, 302, '', {}, url)

    def test_ambient_scanner_git_config_cannot_suppress_gate(self):
        with patch.dict(os.environ, {'GITLEAKS_CONFIG':'unsafe','GITLEAKS_CONFIG_TOML':'unsafe','GIT_CONFIG_COUNT':'1','GIT_CONFIG_VALUE_0':'unsafe','GIT_EXTERNAL_DIFF':'unsafe','GIT_DIR':'unsafe','GIT_GRAFT_FILE':'unsafe','GIT_SHALLOW_FILE':'unsafe'}, clear=False):
            env = environment()
        self.assertFalse(any(k.startswith('GITLEAKS_') for k in env)); self.assertNotIn('GIT_CONFIG_COUNT', env)
        self.assertNotIn('GIT_EXTERNAL_DIFF', env); self.assertNotIn('GIT_DIR', env)
        self.assertEqual(env['GIT_CONFIG_GLOBAL'], os.devnull); self.assertNotIn('GIT_GRAFT_FILE', env)
        self.assertEqual(env['GIT_NO_REPLACE_OBJECTS'], '1')


if __name__ == '__main__': unittest.main()
