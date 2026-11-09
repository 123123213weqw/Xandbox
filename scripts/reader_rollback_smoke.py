#!/usr/bin/env python3
"""Fixed old/new/old/new MOCK reader test; NOT an installation or VM rollback.

Only a fresh caller-owned /tmp directory is used. No state-directory, binary
digest, backend, command or compatibility override is accepted from the caller.
The two fixed daemon files and the released operator client must be supplied.
"""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time

from process_exit import project_view
from smoke import UnixHTTP


BASE_SOURCE = '46b625311828edfd8e3abed2d6bae56560346460'
RUNTIME_SOURCE = '1a78d4b2942f97ae945bafd6681c26470b438a8e'


@dataclass(frozen=True)
class Pin:
    size: int
    sha256: str


PINS = {
    'baseline': Pin(12600219, '5bfb2394f95a1b1c2f887b6e301357b92140586bde07448e3e09f2aa0ee3c11c'),
    'candidate': Pin(12622263, '64883c528ba1d574aaa082c24b136e4938717c13c6abc122afcbddbb3b6c2abe'),
    'node': Pin(10471303, 'ea48602300fcde5aa90171e2dea3adf0f4ec36c8afd91b68aded103e04a69071'),
}


class Refused(RuntimeError):
    def __init__(self, code, **closed):
        self.closed = {'passed': False, 'reason': code, **closed}


def require(condition, code):
    if not condition:
        raise Refused(code)


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def open_pinned(path, pin):
    """Read and execute the same retained descriptor; never reopen by path."""
    p = Path(path)
    require(p.is_absolute() and str(p.resolve(strict=True)) == str(p), 'canonical_binary_required')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and before.st_size == pin.size
                and not before.st_mode & 0o022 and before.st_mode & 0o111,
                'binary_metadata_refused')
        h = hashlib.sha256()
        offset = 0
        while offset < pin.size:
            data = os.pread(fd, min(256 << 10, pin.size - offset), offset)
            require(bool(data), 'binary_short_read')
            h.update(data)
            offset += len(data)
        require(identity(os.fstat(fd)) == identity(before) and h.hexdigest() == pin.sha256,
                'binary_identity_refused')
        return fd, identity(before)
    except BaseException:
        os.close(fd)
        raise


def private_rows(directory, maximum):
    names = list(directory.iterdir())
    require(len(names) <= maximum, 'fixture_inventory_bound')
    for f in names:
        s = f.lstat()
        require(f.suffix == '.json' and stat.S_ISREG(s.st_mode)
                and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1
                and s.st_uid == os.geteuid() and 0 < s.st_size <= 128 << 10,
                'fixture_row_inventory')
        raw = f.read_bytes()
        require(len(raw) == s.st_size and identity(f.lstat()) == identity(s), 'fixture_row_drift')
        yield f, raw


def terminal_snapshot(state):
    """Private in-memory evidence; neither contents nor hashes are exported."""
    ledger = {}
    for f, raw in private_rows(state / 'ledger', 32):
        envelope = json.loads(raw)
        require(envelope['version'] == 1 and envelope['record']['state'] == 'DESTROYED',
                'nonterminal_ledger')
        require(f.name == envelope['record']['id'] + '.json', 'ledger_identity')
        ledger[f.name] = hashlib.sha256(raw).hexdigest()
    sessions = {}
    for f, raw in private_rows(state / 'sessions', 8):
        envelope = json.loads(raw)
        require(envelope['version'] == 1, 'session_envelope')
        record = envelope['record']
        require(record['state'] == 'CLOSED' and record['revision'] == 2
                and len(record['attempts']) == 2, 'nonterminal_session')
        require(f.name == record['id'] + '.json', 'session_identity')
        # Startup deliberately advances UpdatedAt while fencing a CLOSED row.
        # Everything else, including both request hashes/refs and attempts,
        # must remain exactly intact across this fixed pair of readers.
        record.pop('updated_at')
        sessions[f.name] = record
    require(not list((state / 'instances').iterdir()), 'mock_workspace_not_reclaimed')
    control = json.loads((state / 'admission/state.json').read_bytes())
    identity_bytes = (state / 'admission.identity').read_bytes()
    return {'ledger': ledger, 'sessions': sessions, 'control': control, 'identity': identity_bytes}


def preserved(previous, current):
    require(all(current['ledger'].get(k) == v for k, v in previous['ledger'].items()),
            'ledger_rewound_or_mutated')
    require(all(current['sessions'].get(k) == v for k, v in previous['sessions'].items()),
            'session_history_rewound_or_mutated')
    require(current['identity'] == previous['identity'] and current['control'] == previous['control'],
            'node_authority_rewound_or_mutated')


@contextmanager
def disposable_root(reaped):
    # No finalizer may remove live writer state after an unsuccessful kill/wait.
    root = Path(tempfile.mkdtemp(prefix='xb-reader-', dir='/tmp'))
    before = root.lstat()
    try:
        yield root
    finally:
        if reaped():
            current = root.lstat()
            require((current.st_dev, current.st_ino, current.st_uid, current.st_mode)
                    == (before.st_dev, before.st_ino, os.geteuid(), stat.S_IFDIR | 0o700),
                    'fixture_cleanup_identity_changed')
            shutil.rmtree(root)


def exercise(images):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'linux_amd64_only')
    descriptors = {}
    process = None
    boots = 0
    # All inherited credentials/configuration are excluded from the child.
    env = {'PATH': os.environ['PATH'], 'GOMAXPROCS': '2', 'GOMEMLIMIT': '128MiB'}
    deadline = time.monotonic() + 180
    try:
        for role, pin in PINS.items():
            descriptors[role] = open_pinned(images[role], pin)
        with disposable_root(lambda: process is None or process.poll() is not None) as root:
            require(stat.S_IMODE(root.stat().st_mode) == 0o700 and root.stat().st_uid == os.geteuid(),
                    'private_fixture_required')
            state, auth = root / 'state', root / 'auth.json'
            tokens = [os.urandom(32).hex(), os.urandom(32).hex()]
            active_token = tokens[0]
            epoch = None
            revision = 1
            previous = None
            old_keys = []
            with (root / 'private.log').open('xb', buffering=0) as log:
                os.chmod(log.name, 0o600)

                def checked(role):
                    fd, expected = descriptors[role]
                    require(identity(os.fstat(fd)) == expected, 'binary_changed_before_exec')
                    return '/proc/self/fd/' + str(fd), fd

                def check_clock():
                    require(time.monotonic() < deadline, 'whole_case_deadline')

                def call(method, path, body=None, key=None, status=200, token=None):
                    check_clock()
                    conn = UnixHTTP(state / 'api.sock')
                    try:
                        headers = {'Content-Type': 'application/json',
                                   'Authorization': 'Bearer ' + (active_token if token is None else token)}
                        if key is not None:
                            headers['Idempotency-Key'] = key
                        conn.request(method, path, None if body is None else json.dumps(body), headers)
                        response = conn.getresponse()
                        raw = response.read((1 << 20) + 1)
                        require(len(raw) <= 1 << 20 and response.status == status, 'unexpected_api_status')
                        return json.loads(raw)
                    finally:
                        conn.close()

                def wait(predicate):
                    end = min(deadline, time.monotonic() + 15)
                    while time.monotonic() < end:
                        require(process is not None and process.poll() is None, 'own_daemon_exited')
                        try:
                            value = predicate()
                            if value:
                                return value
                        except (OSError, http.client.HTTPException):
                            pass
                        time.sleep(0.005)
                    raise Refused('process_predicate_deadline')

                def node(operation, expected=None, request=None, status=0):
                    check_clock()
                    binary, fd = checked('node')
                    argv = [binary, '-state-dir', str(state)]
                    if expected is not None:
                        argv += ['-epoch', epoch, '-revision', str(expected), '-request-id', request]
                    result = subprocess.run(argv + [operation], stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE, stderr=log, pass_fds=(fd,),
                                            env=env, timeout=10)
                    require(result.returncode == status and len(result.stdout) <= 32768,
                            'operator_process_failed')
                    return json.loads(result.stdout) if status == 0 else None

                def change(operation):
                    nonlocal revision
                    request = os.urandom(16).hex()
                    reply = node(operation, revision, request)['control']
                    require(reply['committed']['epoch'] == epoch
                            and reply['committed']['revision'] == revision + 1
                            and reply['admission_open'] == (operation == 'resume'), 'node_CAS_failed')
                    require(node(operation, revision, request)['control']['committed'] == reply['committed'],
                            'exact_retry_changed_commit')
                    revision += 1
                    # An unrelated stale command cannot rewind or reopen it.
                    before = (state / 'admission/state.json').read_bytes()
                    node('resume', revision - 1, os.urandom(16).hex(), status=1)
                    require((state / 'admission/state.json').read_bytes() == before, 'stale_CAS_mutated')

                def write_auth(token):
                    staged = root / 'auth.next'
                    with staged.open('xb') as output:
                        os.chmod(staged, 0o600)
                        output.write(json.dumps({'version': 1, 'keys': [{'tenant_id': 'reader-test',
                            'max_instances': 4, 'token_sha256': hashlib.sha256(token.encode()).hexdigest()}]}).encode())
                        output.flush()
                        os.fsync(output.fileno())
                    os.replace(staged, auth)
                    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)

                def stop():
                    nonlocal process
                    process.terminate()
                    status = process.wait(timeout=15)
                    if status != 0:
                        context = []
                        try:
                            context = project_view(json.dumps(node('diagnostics')).encode())
                        except Exception:
                            pass
                        raise Refused('graceful_exit_failed', exit_status=status, closed_records=context)
                    process = None
                    require(not (state / 'api.sock').exists() and not (state / 'operator.sock').exists(),
                            'listeners_remain_after_exit')

                def create_stage(label):
                    raw_key, session_key = label + '-raw', label + '-session'
                    raw = call('POST', '/v1/sandboxes', {}, raw_key, 201)
                    binding = call('POST', '/v1/sessions', {}, session_key, 201)
                    switched = call('POST', '/v1/sessions/' + binding['id'] + '/switch',
                                    {'expected_revision': 1, 'create': {}}, label + '-switch')
                    require(switched['revision'] == 2 and switched['previous'] == binding['current']
                            and switched['current'] != binding['current'], 'binding_switch_failed')
                    job = call('POST', '/v1/sessions/' + binding['id'] + '/exec',
                               {'revision': 2, 'argv': ['echo', 'reader-ok']}, status=202)
                    result = wait(lambda: (v if (v := call('GET', '/v1/sandboxes/' +
                        job['sandbox']['id'] + '/executions/' + job['job']['id']))['status'] != 'RUNNING' else None))
                    require(result['status'] == 'EXITED' and result['output']['stdout'] == 'reader-ok\n',
                            'fixed_mock_execution_failed')
                    require(call('POST', '/v1/sessions/' + binding['id'] + '/exec',
                            {'revision': 1, 'argv': ['echo']}, status=409)['error']['code'] == 'STALE_SESSION',
                            'stale_session_revision_accepted')
                    old_keys.append((raw_key, session_key))
                    return raw

                try:
                    write_auth(active_token)
                    for stage, role in enumerate(('baseline', 'candidate', 'baseline', 'candidate')):
                        check_clock()
                        if stage == 1:
                            active_token = tokens[1]
                            write_auth(active_token)  # forward rotation only, never restored
                        auth_before = auth.read_bytes()
                        binary, fd = checked(role)
                        process = subprocess.Popen([binary, '-backend', 'mock', '-state-dir', str(state),
                            '-auth-file', str(auth), '-max-instances', '4', '-max-records', '32',
                            '-max-tenant-records', '32', '-max-sessions', '8', '-max-tenant-sessions', '8'],
                            stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env, pass_fds=(fd,))
                        health = wait(lambda: call('GET', '/healthz'))
                        require(identity(os.stat('/proc/' + str(process.pid) + '/exe')) == descriptors[role][1],
                                'running_executable_identity_changed')
                        require(health['backend'] == 'mock' and health['isolation'] is False
                                and health['production_ready'] is False, 'unexpected_backend')
                        boots += 1
                        control = node('status')['control']
                        if stage == 0:
                            epoch = control['committed']['epoch']
                        require(control['committed']['epoch'] == epoch
                                and control['committed']['revision'] == revision
                                and control['admission_open'] == (stage == 0), 'authority_changed_on_restart')
                        if previous is not None:
                            preserved(previous, terminal_snapshot(state))
                            require(call('POST', '/v1/sandboxes', {}, 'drained-probe', 503)['error']['code']
                                    == 'NODE_DRAINING', 'drained_admission_reopened')
                            call('POST', '/v1/sandboxes', {}, 'retired-token', 401, token=tokens[0])
                            change('resume')
                            for raw_key, session_key in old_keys:
                                require(call('POST', '/v1/sandboxes', {}, raw_key, 410)['error']['code']
                                        == 'IDEMPOTENCY_GONE', 'raw_key_resurrected')
                                require(call('POST', '/v1/sessions', {}, session_key, 410)['error']['code']
                                        == 'SESSION_GONE', 'session_key_resurrected')
                        if stage < 3:
                            create_stage(('released', 'new', 'rolled-back')[stage])
                        change('drain')
                        stop()
                        current = terminal_snapshot(state)
                        require(len(current['ledger']) == 3 * min(stage + 1, 3)
                                and len(current['sessions']) == min(stage + 1, 3), 'identity_inventory_changed')
                        # Compare old records/history even after the older writer
                        # adds new identities; only the explicit node CAS advanced.
                        if previous is not None:
                            history = {**current, 'control': previous['control']}
                            preserved(previous, history)
                        require(current['control']['revision'] == revision
                                and current['control']['mode'] == 'drained', 'final_drain_not_durable')
                        require(auth.read_bytes() == auth_before, 'credential_file_rewound')
                        previous = current
                    require(revision == 8 and boots == 4, 'monotonic_transition_count')
                    require(not any(token.encode() in (root / 'private.log').read_bytes() for token in tokens),
                            'credential_leaked_to_private_log')
                finally:
                    if process is not None:
                        if process.poll() is None:
                            process.kill()  # only this retained, un-reaped child
                        process.wait(timeout=15)
            return {'passed': True, 'backend': 'mock', 'actual_fixed_daemon_boots': boots,
                    'retained_ledger_records': len(previous['ledger']),
                    'retained_closed_sessions': len(previous['sessions']),
                    'final_node_revision': revision, 'same_state_directory_no_restore': True,
                    'retired_token_rejected_after_backward_start': True,
                    'baseline_source': BASE_SOURCE, 'runtime_candidate_source': RUNTIME_SOURCE,
                    'installation_or_activation_allowed': False, 'KVM_or_load_qualified': False,
                    'production_ready': False}
    finally:
        for fd, _ in descriptors.values():
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in PINS:
        parser.add_argument('--' + role, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    def interrupted(_signum, _frame):
        raise Refused('interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        result = exercise(vars(args))
    except Refused as error:
        print(json.dumps(error.closed, sort_keys=True), file=sys.stderr)
        return 1
    except BaseException as error:
        # Never relay paths, JSON payloads, subprocess output or exception text.
        print(json.dumps({'passed': False, 'failure_class': type(error).__name__}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
