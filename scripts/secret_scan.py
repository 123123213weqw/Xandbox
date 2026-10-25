#!/usr/bin/env python3
"""Pinned full-history secret gate. Only fixed/count metadata reaches stdout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from install_secret_scanner import native_pin, MAX_BINARY


class ScanError(Exception):
    pass


def scanner_path(path):
    version, pin = native_pin()
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise ScanError('private caller-owned tool directory required')
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_mode & 0o022 or st.st_uid not in (0, os.geteuid()) or not 0 < st.st_size <= MAX_BINARY:
        raise ScanError('untrusted scanner file')
    if hashlib.sha256(path.read_bytes()).hexdigest() != pin['binary_sha256']:
        raise ScanError('scanner binary hash mismatch')
    return str(path.resolve()), version, pin['binary_sha256']


def environment():
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(('GITLEAKS_', 'GIT_')):
            del env[key]
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
               GIT_NO_REPLACE_OBJECTS='1', GIT_PAGER='cat', GIT_TERMINAL_PROMPT='0', LC_ALL='C')
    return env


def git(repo, *args):
    result = subprocess.run(['git', '-C', str(repo), *args], env=environment(), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=60)
    if result.returncode:
        raise ScanError('git history observation failed')
    return result.stdout


def history(repo):
    # Gitleaks loads source/.gitleaksignore even with an explicit CLI ignore
    # path. Refuse it instead of incorrectly claiming the empty file wins.
    if os.path.lexists(repo / '.gitleaksignore'):
        raise ScanError('repository ignore inventory forbidden')
    graft = Path(os.fsdecode(git(repo, 'rev-parse', '--path-format=absolute', '--git-path', 'info/grafts').strip()))
    if os.path.lexists(graft):
        raise ScanError('grafted history forbidden')
    if git(repo, 'rev-parse', '--is-shallow-repository').strip() != b'false':
        raise ScanError('full non-shallow history required')
    count = int(git(repo, 'rev-list', '--count', '--all'))
    if count < 1:
        raise ScanError('nonempty reachable history required')
    # Submodule object databases are separate; do not silently certify them.
    raw = git(repo, 'log', '--all', '--full-history', '--format=', '--raw', '--no-ext-diff', '--no-textconv')
    if re.search(rb'(?m)^:[0-7]{6} 160000 |^:160000 ', raw):
        raise ScanError('submodule history requires separate qualification')
    commits = git(repo, 'rev-list', '--all').splitlines()
    if len(commits) != count or not all(re.fullmatch(rb'[0-9a-f]{40}|[0-9a-f]{64}', c) for c in commits):
        raise ScanError('invalid reachable commit inventory')
    head = git(repo, 'rev-parse', '--verify', 'HEAD').strip()
    if not re.fullmatch(rb'[0-9a-f]{40}|[0-9a-f]{64}', head):
        raise ScanError('invalid head identity')
    return {'reachable_commits': count, 'head_revision': head.decode('ascii'),
            'reachable_commit_set_sha256': hashlib.sha256(b'\n'.join(sorted(commits))+b'\n').hexdigest()}


def scan(scanner, mode, repo=None, payload=None):
    executable, version, binary_sha = scanner_path(scanner)
    inventory = history(repo) if mode == 'git' else {}
    with tempfile.TemporaryDirectory(prefix='xandbox-secret-scan-') as directory:
        private = Path(directory)
        os.chmod(private, 0o700)
        # Explicit CLI config and empty ignore inventory defeat ambient repo/env
        # settings (source ignore files are refused above). The exact public
        # alphabet exemption is rule-scoped.
        config = Path(__file__).with_name('secret_scan_config.toml').resolve()
        ignore = private / '.gitleaksignore'
        ignore.write_text('')
        report = private / 'report.json'
        command = [executable, mode, '--config', str(config), '--gitleaks-ignore-path', str(ignore),
                   '--ignore-gitleaks-allow', '--redact=100', '--no-banner', '--no-color', '--log-level=error',
                   '--max-decode-depth=5', '--max-archive-depth=2', '--max-target-megabytes=0',
                   '--timeout=240', '--report-format=json', '--report-path', str(report)]
        if mode == 'git':
            command += ['--log-opts=--all --full-history --root -m --no-renames --format=medium --no-decorate --no-color --text --no-ext-diff --no-textconv', str(repo)]
        elif mode != 'stdin':
            raise ScanError('fixed scanner mode required')
        result = subprocess.run(command, input=payload, env=environment(), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=260)
        # Never relay third-party console, finding Match/Secret, paths, author
        # identities or exception text, even if the tool exits unexpectedly.
        # The pinned tool can return 0 after a Git stderr/parser error. At
        # error log level a nonempty console is NEVER a clean scan.
        if result.stdout or result.stderr or result.returncode not in (0, 1) or not report.is_file() or report.stat().st_size > 16 << 20:
            raise ScanError('scanner execution/report unavailable')
        report_bytes = report.read_bytes()
        try:
            values = json.loads(report_bytes)
        except ValueError:
            raise ScanError('invalid scanner report') from None
        if not isinstance(values, list) or bool(values) != (result.returncode == 1):
            raise ScanError('scanner status/report mismatch')
        rules = set()
        for value in values:
            if not isinstance(value, dict):
                raise ScanError('invalid finding type')
            rule = value.get('RuleID')
            if not isinstance(rule, str) or not re.fullmatch('[a-z0-9-]{1,80}', rule) or value.get('Secret') != 'REDACTED':
                raise ScanError('unredacted/invalid scanner report')
            rules.add(rule)
        if mode == 'git' and history(repo) != inventory:
            raise ScanError('reachable history changed during scan')
        summary = {'scanner_version': version, 'scanner_binary_sha256': binary_sha,
                   'mode': 'reachable_git_history' if mode == 'git' else 'synthetic_stdin',
                   **inventory, 'findings': len(values), 'rule_ids': sorted(rules),
                   'raw_console_or_findings_exported': False, 'uncommitted_files_covered': False}
        return result.returncode, summary, report_bytes, result.stdout + result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scanner', type=Path, required=True)
    parser.add_argument('--repo', type=Path, default=Path('.'))
    args = parser.parse_args()
    status, summary, _, _ = scan(args.scanner, 'git', args.repo.resolve())
    print(json.dumps(summary, sort_keys=True))
    return status


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ScanError, OSError, ValueError, subprocess.TimeoutExpired):
        raise SystemExit('secret scan unavailable; no clean-history claim')
