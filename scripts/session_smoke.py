#!/usr/bin/env python3
"""Process acceptance for experimental cold session switching; mock is NOT isolation."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time

from smoke import UnixHTTP


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--daemon', required=True)
    p.add_argument('--report')
    p.add_argument('--source-revision')
    args = p.parse_args()
    daemon = str(Path(args.daemon).resolve())
    checks, samples = [], {}
    with tempfile.TemporaryDirectory(prefix='xb-session-') as temp:
        root = Path(temp); state = root / 'state'; auth = root / 'auth.json'
        tokens = {tenant: os.urandom(32).hex() for tenant in ('alpha', 'beta')}
        auth.write_text(json.dumps({'version': 1, 'keys': [
            {'tenant_id': tenant, 'max_instances': 4, 'token_sha256': hashlib.sha256(token.encode()).hexdigest()}
            for tenant, token in tokens.items()]})); auth.chmod(0o600)
        base = [daemon, '-backend', 'mock', '-state-dir', str(state), '-auth-file', str(auth),
                '-max-instances', '4', '-max-sessions', '2', '-max-tenant-sessions', '1']
        process = None
        with (root / 'private.log').open('ab', buffering=0) as log:
            def call(method, path, body=None, key=None, status=200, tenant='alpha'):
                conn = UnixHTTP(state / 'api.sock')
                try:
                    headers = {'Content-Type': 'application/json'}
                    if tenant is not None:
                        headers['Authorization'] = 'Bearer ' + tokens[tenant]
                    if key:
                        headers['Idempotency-Key'] = key
                    conn.request(method, path, None if body is None else json.dumps(body), headers)
                    r = conn.getresponse(); value = json.loads(r.read())
                    assert r.status == status, (r.status, status, value.get('error', {}).get('code'))
                    return value
                finally:
                    conn.close()

            def wait(predicate, label, seconds=15):
                end = time.monotonic() + seconds
                while time.monotonic() < end:
                    value = predicate()
                    if value:
                        return value
                    time.sleep(0.005)
                raise AssertionError('timed out: ' + label)

            def start():
                proc = subprocess.Popen(base, stdout=log, stderr=log)
                try:
                    def health():
                        assert proc.poll() is None, 'daemon exited during startup'
                        try:
                            return call('GET', '/healthz', tenant=None)
                        except (OSError, http.client.HTTPException):
                            return None
                    h = wait(health, 'daemon startup'); assert h['backend'] == 'mock' and not h['isolation']
                    return proc
                except BaseException:
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait(timeout=10); raise

            def path(binding):
                return '/v1/sessions/' + binding['id']

            def execute(binding, argv, tenant='alpha'):
                accepted = call('POST', path(binding) + '/exec', {'revision': binding['revision'], 'argv': argv}, status=202, tenant=tenant)
                assert accepted['revision'] == binding['revision'] and accepted['sandbox'] == binding['current']
                def finish():
                    r = call('GET', '/v1/sandboxes/' + accepted['sandbox']['id'] + '/executions/' + accepted['job']['id'], tenant=tenant)
                    return r if r['status'] != 'RUNNING' else None
                return wait(finish, 'session execution')

            try:
                process = start()
                call('POST', '/v1/sessions', {}, key='unauthenticated', status=401, tenant=None)
                first = call('POST', '/v1/sessions', {}, key='alpha-session', status=201)
                assert call('POST', '/v1/sessions', {}, key='alpha-session', status=201)['current'] == first['current']
                assert execute(first, ['write', 'note', 'old-private'])['status'] == 'EXITED'
                for method, target, body in [
                    ('GET', path(first), None), ('POST', path(first) + '/switch', {'expected_revision': 1}),
                    ('POST', path(first) + '/exec', {'revision': 1, 'argv': ['echo']}),
                    ('POST', path(first) + '/revoke', {'expected_revision': 1})]:
                    call(method, target, body, key='cross-tenant', status=404, tenant='beta')
                call('POST', '/v1/sandboxes/' + first['current']['id'] + '/exec',
                     {'generation': first['current']['generation'], 'argv': ['echo', 'bypass']}, status=409)
                checks.append('authenticated scoped session API; plain per-VM Exec cannot bypass managed admission')
                assert call('POST', '/v1/sessions', {}, key='alpha-other', status=429)['error']['code'] == 'TENANT_SESSION_QUOTA'
                beta = call('POST', '/v1/sessions', {}, key='beta-session', status=201, tenant='beta')
                assert call('POST', '/v1/sessions', {}, key='alpha-other', status=503)['error']['code'] == 'SESSION_CAPACITY'
                checks.append('per-tenant and node session metadata budgets include retained session identities')

                call('POST', path(first) + '/exec', {'revision': 1, 'argv': ['sleep', '4s']}, status=202)
                before = time.perf_counter()
                second = call('POST', path(first) + '/switch', {'expected_revision': 1}, key='switch-one')
                bound_ms = (time.perf_counter() - before) * 1000
                assert second['revision'] == 2 and second['previous'] == first['current'] and second['current'] != first['current']
                assert execute(second, ['read', 'note'])['status'] == 'FAILED', 'dirty workspace reused'
                assert execute(second, ['echo', 'new'])['status'] == 'EXITED'
                first_command_ms = (time.perf_counter() - before) * 1000
                call('POST', path(first) + '/exec', {'revision': 1, 'argv': ['echo']}, status=409)
                replay = call('POST', path(first) + '/switch', {'expected_revision': 1}, key='switch-one')
                assert replay['current'] == second['current']
                call('POST', path(first) + '/switch', {'expected_revision': 2}, key='switch-one', status=409)
                wait(lambda: call('GET', '/v1/sandboxes/' + first['current']['id'])['state'] == 'DESTROYED', 'old durable reclaim')
                samples['mock_switch_response_ms'] = round(bound_ms, 3)
                samples['mock_request_to_new_commands_completed_ms'] = round(first_command_ms, 3)
                samples['mock_server_phase_observations'] = second['timings']
                checks.append('conditional cold switch rejects old revision; new workspace clean; old VM lifecycle separately reclaimed; idempotent switch key')

                def competing(key):
                    conn = UnixHTTP(state / 'api.sock')
                    try:
                        conn.request('POST', path(first) + '/switch', json.dumps({'expected_revision': 2}),
                                     {'Authorization': 'Bearer ' + tokens['alpha'], 'Content-Type': 'application/json', 'Idempotency-Key': key})
                        r = conn.getresponse(); return r.status, json.loads(r.read())
                    finally:
                        conn.close()
                with ThreadPoolExecutor(max_workers=2) as pool:
                    races = list(pool.map(competing, ['cas-a', 'cas-b']))
                assert sorted(code for code, _ in races) == [200, 409]
                third = next(value for code, value in races if code == 200)
                assert third['revision'] == 3
                public = call('GET', path(first))
                assert 'create_key_hash' not in public and 'spec_hash' not in json.dumps(public) and public['has_binding']
                checks.append('two concurrent expected-revision switches publish exactly one next binding; private hashes omitted')

                accepted = call('POST', path(third) + '/exec', {'revision': 3, 'argv': ['sleep', '4s']}, status=202)
                assert accepted['sandbox'] == third['current']
                process.kill(); process.wait(timeout=10); process = None
                process = start()
                for binding, tenant in [(third, 'alpha'), (beta, 'beta')]:
                    view = call('GET', path(binding), tenant=tenant)
                    assert view['phase'] == 'CLOSED' and not view['has_binding']
                    call('POST', path(binding) + '/exec', {'revision': binding['revision'], 'argv': ['echo']}, status=410, tenant=tenant)
                    wait(lambda: call('GET', '/v1/sandboxes/' + binding['current']['id'], tenant=tenant)['state'] == 'DESTROYED', 'restart reclaimed core ownership')
                call('POST', '/v1/sessions', {}, key='alpha-session', status=410)
                call('POST', path(first) + '/switch', {'expected_revision': 3}, key='after-crash', status=410)
                assert not list((state / 'instances').iterdir())
                checks.append('actual controller SIGKILL restart closes old session routes, retains keys and reclaims all underlying generations')
                process.terminate(); assert process.wait(timeout=15) == 0; process = None
            finally:
                if process is not None and process.poll() is None:
                    process.kill(); process.wait(timeout=15)
        for token in tokens.values():
            assert token not in (root / 'private.log').read_text(errors='replace')
        report = {'test': 'experimental_session_switch_process_acceptance', 'backend': 'mock', 'microvm_benchmark': False,
                  'production_ready': False, 'source_revision': args.source_revision,
                  'runtime_platform': platform.system() + '/' + platform.machine(),
                  'daemon_sha256': hashlib.sha256(Path(daemon).read_bytes()).hexdigest(),
                  'checks': checks, 'samples': samples}
        if args.report:
            Path(args.report).write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
