#!/usr/bin/env python3
"""Actual pinned scanner positive/history/redaction controls; synthetic only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import string
import subprocess
import tempfile
import sys
import types

from secret_scan import environment, scan, ScanError


# Positive controls, NOT credentials or a production key generator. Stable
# SHA-ranked permutations avoid unconstrained-random low-entropy test values.
CONTROL_NAMES = (
    'provider_format', 'raw64hex_not_hash_exempt', 'inline_allow_cannot_suppress',
    'only_public_validation_alphabet', 'allowlisted_alphabet_does_not_hide_neighbor',
    'ordinary_text',
    'deleted_binary_marked_history_with_repo_env_config_and_inline_allow_still_detected',
    'repo_ignore_inventory_refused_not_silently_accepted', 'grafted_history_refused',
    'merge_only_addition_detected', 'shallow_history_refused',
    'changed_tool_refused_before_execution',
)
_PHASES = frozenset(('source_snapshot', 'arguments', 'assertions_required', 'fixture_generation') + CONTROL_NAMES)


def _permutation(pool, domain):
    return ''.join(sorted(pool, key=lambda c: hashlib.sha256((domain + ':' + c).encode('ascii')).digest()))


def _synthetic_pat():
    suffix = _permutation(string.ascii_letters + string.digits, 'xandbox-pat-control-v1')[:36]
    return 'gh' + 'p_' + suffix


def _synthetic_hex64(label):
    if type(label) is not str or label not in ('direct', 'merge'):
        raise ValueError('closed synthetic fixture label required')
    alphabet = '0123456789abcdef'
    return ''.join(_permutation(alphabet, 'xandbox-hex-control-v1-' + label + '-' + str(i)) for i in range(4))


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error includes arbitrary argv/path values.
        raise ValueError('fixed control arguments required')


def main(progress=None):
    if progress is None:
        progress = {'phase': 'arguments'}
    parser = _Parser(prog='secret_scan_smoke', description=__doc__); parser.add_argument('--scanner', type=Path, required=True)
    args = parser.parse_args(); scanner = args.scanner.resolve(); checks = []
    progress['phase'] = 'fixture_generation'
    fake_pat = _synthetic_pat()
    fake_hex = _synthetic_hex64('direct')
    probes = [('provider_format', 'token = "'+fake_pat+'"', fake_pat, True),
              ('raw64hex_not_hash_exempt', 'api_key = "'+fake_hex+'"', fake_hex, True),
              ('inline_allow_cannot_suppress', 'token = "'+fake_pat+'" # gitleaks:allow', fake_pat, True),
              ('only_public_validation_alphabet', 'key = "0123456789abcdef"', '', False),
              ('allowlisted_alphabet_does_not_hide_neighbor', 'key = "0123456789abcdef"; token = "'+fake_pat+'"', fake_pat, True),
              ('ordinary_text', 'ordinary source without credentials', '', False)]
    for name, text, value, expected in probes:
        progress['phase'] = name
        status, summary, report, console = scan(scanner, 'stdin', payload=text.encode())
        assert (status == 1) is expected and bool(summary['findings']) is expected, name
        if value: assert value.encode() not in report + console, 'synthetic value was not fully redacted'
        checks.append(name)
    progress['phase'] = CONTROL_NAMES[6]
    with tempfile.TemporaryDirectory(prefix='xandbox-secret-controls-') as root:
        root = Path(root); repo = root/'repo'; repo.mkdir(mode=0o700)
        env = environment(); env.update(GIT_AUTHOR_NAME='Synthetic fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid', GIT_COMMITTER_NAME='Synthetic fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid')
        def run(*a):
            r = subprocess.run(['git','-C',str(repo),*a],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
            assert r.returncode == 0, 'synthetic history operation failed'; return r.stdout
        run('init','-q')
        (repo/'credential.fixture').write_text('token = "'+fake_pat+'" # gitleaks:allow\n')
        (repo/'.gitattributes').write_text('*.fixture binary\n')
        run('add','.'); run('-c','commit.gpgsign=false','commit','-qm','synthetic first')
        first = run('rev-parse','HEAD').decode().strip()
        (repo/'credential.fixture').unlink()
        (repo/'.gitleaks.toml').write_text('[allowlist]\nregexes=[".*"]\n')
        run('add','-A'); run('-c','commit.gpgsign=false','commit','-qm','synthetic removal')
        os.environ['GITLEAKS_CONFIG_TOML'] = '[allowlist]\nregexes=[".*"]\n'
        status, summary, report, console = scan(scanner, 'git', repo)
        assert status == 1 and summary['reachable_commits'] == 2 and 'github-pat' in summary['rule_ids'], json.dumps(summary, sort_keys=True)
        assert fake_pat.encode() not in report + console
        checks.append('deleted_binary_marked_history_with_repo_env_config_and_inline_allow_still_detected')
        progress['phase'] = CONTROL_NAMES[7]
        (repo/'.gitleaksignore').write_text(first+':credential.fixture:github-pat:1\n')
        try: scan(scanner, 'git', repo)
        except ScanError: checks.append('repo_ignore_inventory_refused_not_silently_accepted')
        else: raise AssertionError('repository ignore suppressed detection')
        (repo/'.gitleaksignore').unlink()
        progress['phase'] = CONTROL_NAMES[8]
        graft = repo/'.git/info/grafts'; graft.write_text('')
        try: scan(scanner, 'git', repo)
        except ScanError: checks.append('grafted_history_refused')
        else: raise AssertionError('grafted history falsely certified')
        graft.unlink()
        progress['phase'] = CONTROL_NAMES[9]
        # A secret introduced only by merge resolution is not in either parent.
        run('branch', 'side'); run('checkout', '-qb', 'main-control')
        (repo/'main.txt').write_text('main\n'); run('add','.'); run('-c','commit.gpgsign=false','commit','-qm','main')
        run('checkout', '-q', 'side'); (repo/'side.txt').write_text('side\n')
        run('add','.'); run('-c','commit.gpgsign=false','commit','-qm','side')
        run('checkout', '-q', 'main-control'); run('merge', '--no-commit', '--no-ff', 'side')
        merge_secret = _synthetic_hex64('merge')
        (repo/'merge.txt').write_text('api_key = "'+merge_secret+'"\n')
        run('add','.'); run('-c','commit.gpgsign=false','commit','-qm','merge-only')
        status, summary, report, console = scan(scanner, 'git', repo)
        assert status == 1 and 'generic-api-key' in summary['rule_ids']
        assert merge_secret.encode() not in report+console
        checks.append('merge_only_addition_detected')
        progress['phase'] = CONTROL_NAMES[10]
        shallow = root/'shallow'
        r = subprocess.run(['git','clone','--quiet','--depth=1',repo.as_uri(),str(shallow)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20); assert r.returncode == 0
        try: scan(scanner, 'git', shallow)
        except ScanError: checks.append('shallow_history_refused')
        else: raise AssertionError('shallow history falsely certified')
        progress['phase'] = CONTROL_NAMES[11]
        wrong = root/'wrong-tool'; shutil.copyfile(scanner, wrong)
        with wrong.open('ab') as out: out.write(b'changed')
        wrong.chmod(0o500)
        try: scan(wrong, 'stdin', payload=b'ordinary')
        except ScanError: checks.append('changed_tool_refused_before_execution')
        else: raise AssertionError('changed scanner accepted')
    assert tuple(checks) == CONTROL_NAMES, 'complete original control roster required'
    print(json.dumps({'scanner_version':'8.30.1','checks':checks,'real_credentials_used':False,'synthetic_value_or_private_report_exported':False},sort_keys=True))


def _source_bytes():
    with Path(__file__).open('rb') as source:
        data = source.read((64 << 10) + 1)
    if not data or len(data) > 64 << 10:
        raise ValueError('control source exceeds bound')
    return data


def _failure_metadata(exc, phase, source):
    # Never format the exception, its args/locals, paths, scanner reports,
    # fixture strings or third-party console. Only closed/count metadata.
    kind = 'unexpected_exception'
    for cls, name in ((AssertionError, 'assertion'), (ScanError, 'scan_error'),
                      (OSError, 'os_error'), (ValueError, 'value_error'),
                      (subprocess.TimeoutExpired, 'timeout'),
                      (KeyboardInterrupt, 'interrupted')):
        if isinstance(exc, cls):
            kind = name
            break
    data = source if type(source) is bytes else None
    result = {'version': 1, 'result': 'failed',
              'phase': phase if type(phase) is str and phase in _PHASES else 'unknown',
              'exception': kind, 'source_sha256': hashlib.sha256(data).hexdigest() if data is not None else None,
              'origin_mapped': False, 'clean_history_claim': False,
              'sensitive_data_exported': False}
    tb = exc.__traceback__
    while tb is not None:
        role = next((role for code, role in _CONTROL_CODES if code is tb.tb_frame.f_code), None)
        if role is not None and data is not None and 0 < tb.tb_lineno <= len(data.splitlines()):
            result.update(origin_mapped=True, function=role, line=tb.tb_lineno)
        tb = tb.tb_next
    return result


def entrypoint():
    progress = {'phase': 'source_snapshot'}
    source = None
    try:
        source = _source_bytes()
        if not __debug__:
            progress['phase'] = 'assertions_required'
            raise ValueError('control assertions must be enabled')
        progress['phase'] = 'arguments'
        main(progress)
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        print(json.dumps(_failure_metadata(exc, progress.get('phase'), source), sort_keys=True), file=sys.stderr)
        return 130 if isinstance(exc, KeyboardInterrupt) else 1


# Code-object identity, not caller-supplied filenames or traceback text.
_CONTROL_CODES = [(main.__code__, 'main'), (entrypoint.__code__, 'entrypoint'),
                  (_source_bytes.__code__, 'source'), (_permutation.__code__, 'permutation'),
                  (_synthetic_pat.__code__, 'provider_fixture'),
                  (_synthetic_hex64.__code__, 'hex_fixture'), (_Parser.error.__code__, 'arguments')]
for _code in main.__code__.co_consts:
    if isinstance(_code, types.CodeType) and _code.co_name == 'run':
        _CONTROL_CODES.append((_code, 'git_command'))


if __name__ == '__main__':
    raise SystemExit(entrypoint())
