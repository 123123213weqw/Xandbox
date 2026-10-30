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

from secret_scan import environment, scan, ScanError


def synthetic_values():
    # Fixed TEST values, not credentials or a secret generator. A random hex
    # sample can fall below the pinned scanner's entropy floor. Permute the
    # alphabets to avoid its ordered-alphabet stopword. No scanner rule,
    # threshold, ignore or fail-closed production policy is changed.
    alphabet = string.ascii_letters + string.digits
    provider = 'gh' + 'p_' + ''.join(alphabet[(17 * i) % len(alphabet)] for i in range(36))
    hexadecimal = ''.join(format((7 * i) % 16, 'x') for i in range(16))
    return provider, hexadecimal * 4, (hexadecimal[3:] + hexadecimal[:3]) * 4


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--scanner', type=Path, required=True)
    args = parser.parse_args(); scanner = args.scanner.resolve(); checks = []
    fake_pat, fake_hex, merge_secret = synthetic_values()
    probes = [('provider_format', 'token = "'+fake_pat+'"', fake_pat, True),
              ('raw64hex_not_hash_exempt', 'api_key = "'+fake_hex+'"', fake_hex, True),
              ('inline_allow_cannot_suppress', 'token = "'+fake_pat+'" # gitleaks:allow', fake_pat, True),
              ('only_public_validation_alphabet', 'key = "0123456789abcdef"', '', False),
              ('allowlisted_alphabet_does_not_hide_neighbor', 'key = "0123456789abcdef"; token = "'+fake_pat+'"', fake_pat, True),
              ('ordinary_text', 'ordinary source without credentials', '', False)]
    for name, text, value, expected in probes:
        status, summary, report, console = scan(scanner, 'stdin', payload=text.encode())
        assert (status == 1) is expected and bool(summary['findings']) is expected, name
        if value: assert value.encode() not in report + console, 'synthetic value was not fully redacted'
        checks.append(name)
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
        (repo/'.gitleaksignore').write_text(first+':credential.fixture:github-pat:1\n')
        try: scan(scanner, 'git', repo)
        except ScanError: checks.append('repo_ignore_inventory_refused_not_silently_accepted')
        else: raise AssertionError('repository ignore suppressed detection')
        (repo/'.gitleaksignore').unlink()
        graft = repo/'.git/info/grafts'; graft.write_text('')
        try: scan(scanner, 'git', repo)
        except ScanError: checks.append('grafted_history_refused')
        else: raise AssertionError('grafted history falsely certified')
        graft.unlink()
        # A secret introduced only by merge resolution is not in either parent.
        run('branch', 'side'); run('checkout', '-qb', 'main-control')
        (repo/'main.txt').write_text('main\n'); run('add','.'); run('-c','commit.gpgsign=false','commit','-qm','main')
        run('checkout', '-q', 'side'); (repo/'side.txt').write_text('side\n')
        run('add','.'); run('-c','commit.gpgsign=false','commit','-qm','side')
        run('checkout', '-q', 'main-control'); run('merge', '--no-commit', '--no-ff', 'side')
        (repo/'merge.txt').write_text('api_key = "'+merge_secret+'"\n')
        run('add','.'); run('-c','commit.gpgsign=false','commit','-qm','merge-only')
        status, summary, report, console = scan(scanner, 'git', repo)
        assert status == 1 and 'generic-api-key' in summary['rule_ids']
        assert merge_secret.encode() not in report+console
        checks.append('merge_only_addition_detected')
        shallow = root/'shallow'
        r = subprocess.run(['git','clone','--quiet','--depth=1',repo.as_uri(),str(shallow)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20); assert r.returncode == 0
        try: scan(scanner, 'git', shallow)
        except ScanError: checks.append('shallow_history_refused')
        else: raise AssertionError('shallow history falsely certified')
        wrong = root/'wrong-tool'; shutil.copyfile(scanner, wrong)
        with wrong.open('ab') as out: out.write(b'changed')
        wrong.chmod(0o500)
        try: scan(wrong, 'stdin', payload=b'ordinary')
        except ScanError: checks.append('changed_tool_refused_before_execution')
        else: raise AssertionError('changed scanner accepted')
    print(json.dumps({'scanner_version':'8.30.1','checks':checks,'real_credentials_used':False,'synthetic_value_or_private_report_exported':False},sort_keys=True))


if __name__ == '__main__':
    try: main()
    except (AssertionError, ScanError, OSError, ValueError, subprocess.TimeoutExpired):
        raise SystemExit('secret scanner controls failed; no clean-history claim')
