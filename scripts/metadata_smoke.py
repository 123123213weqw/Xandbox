#!/usr/bin/env python3
"""Private process-level metadata limits, strict schema and offline migration tests.

Default legacy fixtures are explicitly downgraded test copies. --legacy-daemon
adds a real old-binary crash/upgrade test; it must never target business state.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from smoke import UnixHTTP
from process_exit import failure_summary, KINDS, REASONS


# Fixed source-level labels, not CLI values. True retains the original kill /
# nonzero assertion; False retains terminate / zero. No budget or case changes.
STOP_PHASES = {
    'tenant_capacity_stop': False,
    'node_capacity_stop': False,
    'active_exec_kill': True,
    'post_crash_recovery_stop': False,
    'migrated_legacy_stop': False,
    'partial_migration_kill': True,
    'imported_2048_stop': False,
    'historical_daemon_kill': True,
    'historical_recovery_stop': False,
}


def _exit_status(value):
    return type(value) is int and -128 <= value <= 255


def _stop_failure(phase, category, status=None, node=None, directory=None, collect=False):
    # Only this closed payload is diagnostic. Standard Python source traceback
    # locations are not tenant paths or evidence of the daemon's failure cause.
    if type(phase) is not str or phase not in STOP_PHASES:
        phase = 'unavailable'
    if category not in ('invalid_policy', 'optimized_python', 'signal_failed',
                        'wait_timeout', 'wait_failed', 'invalid_exit_status', 'unexpected_exit_status'):
        category = 'invalid_policy'
    payload = {'schema': 'xandbox.metadata-stop-failure.v1', 'phase': phase,
               'failure': category, 'wait_limit_seconds': 15,
               'expected': ('nonzero_after_kill' if STOP_PHASES[phase] else 'zero_after_terminate')
               if phase in STOP_PHASES else 'unavailable',
               'exit_status': status if _exit_status(status) else None,
               'diagnostic_view': 'not_requested', 'closed_records': [],
               'persisted_tail_is_not_current_process_proof': True}
    if collect:
        payload['diagnostic_view'] = 'unavailable'
        try:
            summary = failure_summary(status, node, directory)
            if type(summary) is dict:
                tool_status = summary.get('view_exit_status')
                if _exit_status(tool_status):
                    payload['view_exit_status'] = tool_status
                rows = summary.get('closed_records')
                if summary.get('diagnostic_view') == 'closed' and type(tool_status) is int and tool_status == 0 and type(rows) is list and len(rows) <= 6:
                    projected = []
                    for row in rows:
                        if type(row) is not dict or type(row.get('kind')) is not str or row['kind'] not in KINDS or type(row.get('reason')) is not str or row['reason'] not in REASONS:
                            raise ValueError()
                        projected.append({'kind': row['kind'], 'reason': row['reason']})
                    payload['closed_records'] = projected
                    payload['diagnostic_view'] = 'closed'
        except Exception:
            # Never relay an OS/CLI/parser exception, report, path or console.
            pass
    raise AssertionError(json.dumps(payload, sort_keys=True)) from None


def stop_metadata_process(process, node, directory, phase, crash=False):
    if type(phase) is not str or phase not in STOP_PHASES or type(crash) is not bool or STOP_PHASES[phase] != crash:
        _stop_failure('unavailable', 'invalid_policy')
    if sys.flags.optimize:
        _stop_failure(phase, 'optimized_python')
    try:
        if crash:
            process.kill()
        else:
            process.terminate()
    except Exception:
        _stop_failure(phase, 'signal_failed')
    try:
        status = process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        # Do not spend another diagnostic wait while the owned process may be
        # live. The original main finally still kills/reaps this exact handle.
        _stop_failure(phase, 'wait_timeout')
    except Exception:
        _stop_failure(phase, 'wait_failed')
    if not _exit_status(status):
        _stop_failure(phase, 'invalid_exit_status')
    if status != 0 if crash else status == 0:
        return
    # Only a known-exited, unexpected status gets the EXISTING bounded read-only
    # diagnostic query. Never infer this process's success from an earlier tail.
    _stop_failure(phase, 'unexpected_exit_status', status, node, directory, collect=True)


def main():
    if sys.flags.optimize:
        _stop_failure('unavailable', 'optimized_python')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--daemon', required=True)
    parser.add_argument('--node', required=True, help='same-UID operator CLI for explicit legacy-fixture resume')
    parser.add_argument('--legacy-daemon')
    parser.add_argument('--report')
    parser.add_argument('--source-revision')
    args = parser.parse_args()
    daemon = str(Path(args.daemon).resolve())
    node = str(Path(args.node).resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix='xb-meta-') as temp:
        root = Path(temp)
        token = os.urandom(32).hex()
        auth = root / 'auth.json'
        auth.write_text(json.dumps({'version': 1, 'keys': [{'token_sha256': hashlib.sha256(token.encode()).hexdigest(), 'tenant_id': 'alpha', 'max_instances': 4}]}))
        auth.chmod(0o600)
        state = root / 'state'
        process = None
        with (root / 'private.log').open('ab', buffering=0) as log:
            def wait(predicate, label, seconds=15):
                end = time.monotonic() + seconds
                while time.monotonic() < end:
                    result = predicate()
                    if result:
                        return result
                    time.sleep(0.002)
                raise AssertionError('timed out: ' + label)

            def base(binary=daemon, directory=state):
                return [binary, '-backend', 'mock', '-state-dir', str(directory), '-auth-file', str(auth)]

            def call(method, path, body=None, key=None, status=200, directory=state):
                conn = UnixHTTP(directory / 'api.sock')
                try:
                    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
                    if key:
                        headers['Idempotency-Key'] = key
                    conn.request(method, path, None if body is None else json.dumps(body), headers)
                    response = conn.getresponse()
                    data = json.loads(response.read())
                    assert response.status == status, (response.status, status, data.get('error', {}).get('code'))
                    return data
                finally:
                    conn.close()

            def start(extra=(), binary=daemon, directory=state):
                proc = subprocess.Popen(base(binary, directory) + list(extra), stdout=log, stderr=log)
                try:
                    def ready():
                        assert proc.poll() is None, 'daemon exited during startup'
                        try:
                            return call('GET', '/healthz', directory=directory)
                        except (OSError, http.client.HTTPException):
                            return None
                    wait(ready, 'startup')
                    return proc
                except BaseException:
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait(timeout=10)
                    raise

            def stopped(proc, crash=False, *, phase, directory):
                stop_metadata_process(proc, node, directory, phase, crash=crash)

            def migrate(directory=state):
                return subprocess.run([daemon, '-state-dir', str(directory), '-migrate-ledger'], capture_output=True, timeout=60)

            def path(record):
                return '/v1/sandboxes/' + record['id']

            def create(key, directory=state):
                return call('POST', '/v1/sandboxes', {}, key=key, status=201, directory=directory)

            def destroyed(record, directory=state):
                wait(lambda: call('GET', path(record), directory=directory)['state'] == 'DESTROYED', 'durable reclamation')

            def atomic_fixture(file, value):
                staged = file.with_suffix('.fixture')
                with staged.open('w') as output:
                    os.chmod(staged, 0o600)
                    json.dump(value, output)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(staged, file)

            try:
                # Per-tenant metadata quota, unlike active instance quota, is
                # never returned by reclaiming an instance.
                process = start(['-max-records', '3', '-max-tenant-records', '2'])
                first, second = create('one'), create('two')
                call('DELETE', path(first), {'generation': first['generation']}, status=202)
                destroyed(first)
                denied = call('POST', '/v1/sandboxes', {}, key='three', status=429)
                assert denied['error']['code'] == 'TENANT_METADATA_QUOTA'
                assert create('two')['id'] == second['id']
                assert migrate().returncode != 0, 'offline migration bypassed live controller lock'
                checks.append('tenant metadata saturation preserves live replay, tombstone and exclusive migration lock')
                stopped(process, phase='tenant_capacity_stop', directory=state); process = None
                process = start(['-max-records', '2', '-max-tenant-records', '2'])
                destroyed(second)
                denied = call('POST', '/v1/sandboxes', {}, key='three', status=503)
                assert denied['error']['code'] == 'METADATA_CAPACITY'
                assert call('POST', '/v1/sandboxes', {}, key='one', status=410)['error']['code'] == 'IDEMPOTENCY_GONE'
                checks.append('node metadata cap survives restart and does not recycle destroyed keys')
                stopped(process, phase='node_capacity_stop', directory=state); process = None

                # Add one live record, then crash. Lower caps may stop new
                # admission but must not prevent recovery of old ownership.
                process = start(['-max-records', '3', '-max-tenant-records', '3'])
                third = create('three')
                call('POST', path(third) + '/exec', {'generation': third['generation'], 'argv': ['sleep', '4s']}, status=202)
                stopped(process, crash=True, phase='active_exec_kill', directory=state); process = None
                process = start(['-max-records', '1', '-max-tenant-records', '1'])
                destroyed(third)
                assert call('POST', '/v1/sandboxes', {}, key='three', status=410)['error']['code'] == 'IDEMPOTENCY_GONE'
                checks.append('SIGKILL restart below old record budget reclaims every old generation without resurrection')
                stopped(process, phase='post_crash_recovery_stop', directory=state); process = None

                files = list((state / 'ledger').glob('*.json'))
                for file in files:
                    value = json.loads(file.read_text())
                    assert value['version'] == 1
                    atomic_fixture(file, value['record'])
                rejected = subprocess.run(base(), stdout=log, stderr=log, timeout=10)
                assert rejected.returncode != 0
                migrated = migrate(); assert migrated.returncode == 0
                assert json.loads(migrated.stdout) == {'version': 1, 'records': 3, 'upgraded': 3}
                assert json.loads(migrate().stdout)['upgraded'] == 0
                process = start(['-max-records', '1', '-max-tenant-records', '1'])
                assert call('POST', '/v1/sandboxes', {}, key='one', status=410)['error']['code'] == 'IDEMPOTENCY_GONE'
                stopped(process, phase='migrated_legacy_stop', directory=state); process = None
                checks.append('legacy fixture requires explicit offline upgrade; rerun is idempotent and preserves key rejection')

                before = {f: f.read_bytes() for f in files}
                value = json.loads(files[0].read_text()); value['version'] = 999
                atomic_fixture(files[0], value)
                corrupt = {f: f.read_bytes() for f in files}
                assert migrate().returncode != 0
                assert subprocess.run(base(), stdout=log, stderr=log, timeout=10).returncode != 0
                assert all(f.read_bytes() == raw for f, raw in corrupt.items()), 'failed preflight mutated a prefix'
                for f, raw in before.items():
                    f.write_bytes(raw)
                checks.append('unknown schema rejects migration and service startup without modifying valid records')

                # Only disposable terminal mock fixtures, never VMM ownership.
                interrupted = root / 'interrupted'
                ledger = interrupted / 'ledger'; ledger.mkdir(parents=True, mode=0o700); interrupted.chmod(0o700)
                seed = json.loads(before[files[0]])['record']
                seed['create_key_hash'] = ''; seed['create_spec_hash'] = ''
                count = 2048
                for n in range(count):
                    row = dict(seed, id=f'{n:032x}')
                    f = ledger / (row['id'] + '.json'); f.write_text(json.dumps(row)); f.chmod(0o600)
                proc = subprocess.Popen([daemon, '-state-dir', str(interrupted), '-migrate-ledger'], stdout=log, stderr=log)
                process = proc
                def partial_upgrade():
                    assert proc.poll() is None, 'migration finished before fault injection; no interruption proof'
                    return any('version' in json.loads(f.read_text()) for f in ledger.glob('*.json'))
                wait(partial_upgrade, 'first atomic upgrade', seconds=30)
                stopped(proc, crash=True, phase='partial_migration_kill', directory=interrupted); process = None
                upgraded = sum('version' in json.loads(f.read_text()) for f in ledger.glob('*.json'))
                assert 0 < upgraded < count, 'not an actual partial migration'
                assert subprocess.run(base(directory=interrupted), stdout=log, stderr=log, timeout=10).returncode != 0
                resumed = migrate(interrupted); assert resumed.returncode == 0
                assert json.loads(resumed.stdout)['upgraded'] == count - upgraded
                assert len(list(ledger.glob('*.json'))) == count
                assert not list(ledger.glob('.record-*'))
                process = start(['-max-records', '1', '-max-tenant-records', '1'], directory=interrupted)
                # Imported legacy state has no admission identity. It must
                # start drained; explicitly authorize this disposable test
                # root before measuring its independent metadata-cap error.
                assert call('POST', '/v1/sandboxes', {}, key='new', status=503, directory=interrupted)['error']['code'] == 'NODE_DRAINING'
                query = subprocess.run([node, '-state-dir', str(interrupted), 'status'], capture_output=True, timeout=10)
                assert query.returncode == 0
                control = json.loads(query.stdout)['control']
                assert not control['admission_open'] and control['committed']['mode'] == 'drained'
                committed = control['committed']
                opened = subprocess.run([node, '-state-dir', str(interrupted), '-epoch', committed['epoch'],
                    '-revision', str(committed['revision']), '-request-id', os.urandom(16).hex(), 'resume'],
                    capture_output=True, timeout=10)
                assert opened.returncode == 0 and json.loads(opened.stdout)['control']['admission_open']
                assert call('POST', '/v1/sandboxes', {}, key='new', status=503, directory=interrupted)['error']['code'] == 'METADATA_CAPACITY'
                stopped(process, phase='imported_2048_stop', directory=interrupted); process = None
                checks.append('actual SIGKILL during 2048-record migration leaves mixed schema; resume preserves all identities and cleans orphan temps')
                checks.append('imported legacy fixture remains drained until same-UID operator CAS resume; metadata cap still enforced')

                if args.legacy_daemon:
                    old = str(Path(args.legacy_daemon).resolve())
                    historical = root / 'historical'
                    process = start(binary=old, directory=historical)
                    owned = create('historical', directory=historical)
                    raw = json.loads((historical / 'ledger' / (owned['id'] + '.json')).read_text())
                    assert 'version' not in raw and raw['state'] == 'READY'
                    stopped(process, crash=True, phase='historical_daemon_kill', directory=historical); process = None
                    assert subprocess.run(base(directory=historical), stdout=log, stderr=log, timeout=10).returncode != 0
                    assert migrate(historical).returncode == 0
                    process = start(directory=historical)
                    destroyed(owned, directory=historical)
                    assert call('POST', '/v1/sandboxes', {}, key='historical', status=410, directory=historical)['error']['code'] == 'IDEMPOTENCY_GONE'
                    stopped(process, phase='historical_recovery_stop', directory=historical); process = None
                    checks.append('actual pre-upgrade daemon SIGKILL ownership migrates and is reclaimed without key reuse')
            finally:
                if process is not None and process.poll() is None:
                    process.kill(); process.wait(timeout=15)
        assert token not in (root / 'private.log').read_text(errors='replace')
        report = {'backend': 'mock', 'production_ready': False, 'source_revision': args.source_revision,
                  'test': 'ledger_metadata_process_acceptance', 'migration_fault_records': count,
                  'actual_old_binary': bool(args.legacy_daemon), 'checks': checks,
                  'daemon_sha256': hashlib.sha256(Path(daemon).read_bytes()).hexdigest()}
        if args.legacy_daemon:
            report['legacy_daemon_sha256'] = hashlib.sha256(Path(args.legacy_daemon).read_bytes()).hexdigest()
        if args.report:
            Path(args.report).write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
