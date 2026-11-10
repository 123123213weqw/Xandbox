"""Pure fail-closed installation/environment tests; no network or credentials."""
import hashlib
import contextlib
import json
import string
import subprocess
import sys
import types
from collections import Counter
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
import secret_scan_smoke as smoke


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


class SecretSmokeControlTests(unittest.TestCase):
    # A synthetic sentinel, NEVER a credential. Tests never echo exception data.
    marker = 'SYNTHETIC_PRIVATE_DIAGNOSTIC_SENTINEL'
    expected = (
        'provider_format', 'raw64hex_not_hash_exempt', 'inline_allow_cannot_suppress',
        'only_public_validation_alphabet', 'allowlisted_alphabet_does_not_hide_neighbor',
        'ordinary_text',
        'deleted_binary_marked_history_with_repo_env_config_and_inline_allow_still_detected',
        'repo_ignore_inventory_refused_not_silently_accepted', 'grafted_history_refused',
        'merge_only_addition_detected', 'shallow_history_refused',
        'changed_tool_refused_before_execution',
    )

    def test_provider_fixture_is_stable_unique_ascii_not_random_entropy(self):
        value = smoke._synthetic_pat()
        self.assertTrue(value.startswith('gh' + 'p_'), 'provider format')
        self.assertEqual(len(value), 40)
        self.assertTrue(len(set(value[4:])) == 36 and set(value[4:]) <= set(string.ascii_letters + string.digits), 'closed unique suffix')
        self.assertTrue(all(smoke._synthetic_pat() == value for _ in range(128)), 'fixture changed')

    def test_hex_fixtures_are_stable_balanced64_and_distinct_domains(self):
        values = [smoke._synthetic_hex64(label) for label in ('direct', 'merge')]
        for label, value in zip(('direct', 'merge'), values):
            self.assertEqual(len(value), 64)
            self.assertTrue(set(value) == set('0123456789abcdef') and set(Counter(value).values()) == {4}, 'balanced lowercase fixture')
            self.assertTrue(all(smoke._synthetic_hex64(label) == value for _ in range(64)), 'fixture changed')
        self.assertTrue(values[0] != values[1], 'direct/merge fixtures alias')

    def test_fixture_labels_are_closed_and_never_echo_bad_value(self):
        for label in (self.marker, None, 0, b'merge'):
            try:
                smoke._synthetic_hex64(label)
            except ValueError as error:
                self.assertTrue(self.marker not in str(error), 'fixture label leaked')
            else:
                self.fail('unknown fixture label accepted')

    def test_exact_original_twelve_control_roster_retained(self):
        self.assertEqual(smoke.CONTROL_NAMES, self.expected)
        self.assertEqual(len(smoke.CONTROL_NAMES), 12)

    def invoke(self, error=None, main=None, argv=None):
        out, err = io.StringIO(), io.StringIO()
        call = patch.object(smoke, 'main', side_effect=main) if main is not None else patch.object(smoke, 'scan', side_effect=error)
        with call, patch.object(sys, 'argv', argv or ['secret_scan_smoke', '--scanner', '/nonexecuted']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = smoke.entrypoint()
        self.assertTrue(self.marker not in out.getvalue() + err.getvalue(), 'diagnostic leaked input')
        return code, out.getvalue(), err.getvalue()

    def test_failure_output_never_formats_exception_args_paths_or_console(self):
        class Unprintable(Exception):
            def __str__(self): raise RuntimeError('exception text must not be rendered')
            def __repr__(self): raise RuntimeError('exception repr must not be rendered')
        for error, kind in ((ScanError(self.marker), 'scan_error'), (OSError(self.marker), 'os_error'),
                            (AssertionError(self.marker), 'assertion'), (ValueError(self.marker), 'value_error'),
                            (subprocess.TimeoutExpired(self.marker, 1, output=self.marker, stderr=self.marker), 'timeout'),
                            (Unprintable(self.marker), 'unexpected_exception')):
            code, out, err = self.invoke(error)
            self.assertEqual(code, 1); self.assertEqual(out, '')
            v = json.loads(err)
            self.assertEqual(v['exception'], kind); self.assertEqual(v['phase'], 'provider_format')
            self.assertFalse(v['clean_history_claim']); self.assertFalse(v['sensitive_data_exported'])
            self.assertTrue(v['origin_mapped']); self.assertEqual(v['function'], 'main')
            self.assertEqual(v['source_sha256'], hashlib.sha256(Path(smoke.__file__).read_bytes()).hexdigest())
            self.assertEqual(set(v), {'version', 'result', 'phase', 'exception', 'source_sha256', 'origin_mapped', 'clean_history_claim', 'sensitive_data_exported', 'function', 'line'})

    def test_unknown_phase_and_foreign_traceback_never_export_arbitrary_names(self):
        def fail(progress):
            progress['phase'] = self.marker
            raise AssertionError(self.marker)
        code, out, err = self.invoke(main=fail)
        self.assertEqual(code, 1); self.assertEqual(out, '')
        v = json.loads(err); self.assertEqual(v['phase'], 'unknown')
        self.assertEqual(v.get('function'), 'entrypoint') # Actual outer source call site, NOT foreign frame.
        self.assertNotIn('filename', v); self.assertNotIn('message', v)

    def test_hostile_phase_object_is_not_formatted_or_hashed(self):
        class Hostile:
            def __str__(self): raise AssertionError('must not format phase')
            def __hash__(self): raise AssertionError('must not hash phase')
        v = smoke._failure_metadata(AssertionError(self.marker), Hostile(), b'fixed source')
        self.assertEqual(v['phase'], 'unknown'); self.assertFalse(v['origin_mapped'])
        self.assertTrue(self.marker not in json.dumps(v), 'arbitrary phase output')

    def test_actual_internal_origin_has_bounded_source_line_and_no_bad_label(self):
        source = Path(smoke.__file__).read_bytes()
        try:
            smoke._synthetic_hex64(self.marker)
        except ValueError as error:
            v = smoke._failure_metadata(error, 'fixture_generation', source)
        self.assertTrue(v['origin_mapped']); self.assertEqual(v['function'], 'hex_fixture')
        self.assertTrue(0 < v['line'] <= len(source.splitlines()), 'unbound line')
        self.assertTrue(self.marker not in json.dumps(v), 'fixture input exported')

    def test_same_filename_foreign_code_object_cannot_spoof_an_origin(self):
        source = Path(smoke.__file__).read_bytes()
        foreign = compile("raise ValueError('synthetic-unexported')", smoke.main.__code__.co_filename, 'exec')
        try:
            exec(foreign, {})
        except ValueError as error:
            v = smoke._failure_metadata(error, 'provider_format', source)
        self.assertFalse(v['origin_mapped']); self.assertNotIn('function', v)
        self.assertNotIn('filename', v); self.assertNotIn('line', v)

    def test_structurally_equal_code_clone_is_not_module_identity(self):
        original = smoke._synthetic_hex64.__code__
        clone = original.replace()
        self.assertTrue(clone is not original and clone == original, 'clone setup')
        call = types.FunctionType(clone, smoke.__dict__)
        try:
            call(self.marker)
        except ValueError as error:
            v = smoke._failure_metadata(error, 'fixture_generation', Path(smoke.__file__).read_bytes())
        self.assertFalse(v['origin_mapped']); self.assertNotIn('function', v)
        self.assertTrue(self.marker not in json.dumps(v), 'cloned-code diagnostic leaked')

    def test_failed_second_probe_reports_its_exact_closed_phase(self):
        out, err = io.StringIO(), io.StringIO()
        first = (1, {'findings': 1}, b'[]', b'')
        with patch.object(smoke, 'scan', side_effect=[first, OSError(self.marker)]), patch.object(sys, 'argv', ['secret_scan_smoke', '--scanner', '/nonexecuted']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(smoke.entrypoint(), 1)
        v = json.loads(err.getvalue()); self.assertEqual(v['phase'], 'raw64hex_not_hash_exempt')
        self.assertTrue(self.marker not in out.getvalue() + err.getvalue(), 'probe diagnostic leaked')

    def test_source_unavailable_is_failure_without_unbound_origin_claim(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(smoke, '_source_bytes', side_effect=OSError(self.marker)), patch.object(smoke, 'main') as main, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(smoke.entrypoint(), 1)
            main.assert_not_called()
        v = json.loads(err.getvalue()); self.assertIsNone(v['source_sha256']); self.assertFalse(v['origin_mapped'])
        self.assertEqual(v['phase'], 'source_snapshot')
        self.assertTrue(self.marker not in out.getvalue() + err.getvalue(), 'source error output')
        for data in (b'', b'x' * ((64 << 10) + 1)):
            with patch.object(smoke.Path, 'open', return_value=io.BytesIO(data)):
                with self.assertRaises(ValueError): smoke._source_bytes()

    def test_invalid_arguments_do_not_echo_argv_or_paths(self):
        code, out, err = self.invoke(ScanError('unreached'), argv=['secret_scan_smoke', '--scanner', self.marker, '--unknown', self.marker])
        self.assertEqual(code, 1); self.assertEqual(out, '')
        self.assertEqual(json.loads(err)['phase'], 'arguments')

    def test_keyboard_interrupt_is_closed_metadata_and_nonzero(self):
        code, out, err = self.invoke(KeyboardInterrupt(self.marker))
        self.assertEqual(code, 130); self.assertEqual(out, '')
        self.assertEqual(json.loads(err)['exception'], 'interrupted')

    def test_optimized_python_cannot_disable_assertion_controls(self):
        for flag in ('-O', '-OO'):
            p = subprocess.run([sys.executable, flag, str(Path(smoke.__file__).resolve()), '--scanner', '/nonexecuted'], capture_output=True, timeout=10)
            self.assertEqual(p.returncode, 1); self.assertEqual(p.stdout, b'')
            v = json.loads(p.stderr); self.assertEqual(v['phase'], 'assertions_required')
            self.assertFalse(v['clean_history_claim']); self.assertTrue(v['origin_mapped'])


if __name__ == '__main__': unittest.main()
