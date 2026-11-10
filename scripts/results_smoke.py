#!/usr/bin/env python3
"""Opt-in bounded result retention via private authenticated MOCK HTTP only."""
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
from process_exit import failure_summary


def main():
    if sys.flags.optimize:
        raise AssertionError('normal Python required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--daemon', required=True)
    parser.add_argument('--node', required=True)
    args = parser.parse_args()
    daemon, node = str(Path(args.daemon).resolve()), str(Path(args.node).resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix='xb-results-') as private:
        root = Path(private)
        state, auth = root / 'state', root / 'auth.json'
        tokens = {tenant: os.urandom(32).hex() for tenant in ('alpha', 'beta')}
        auth.write_text(json.dumps({'version': 1, 'keys': [dict(token_sha256=hashlib.sha256(token.encode()).hexdigest(), tenant_id=tenant, max_instances=2) for tenant, token in tokens.items()]}))
        auth.chmod(0o600)
        process = None
        with (root / 'private.log').open('ab', buffering=0) as log:
            def command(budget=3*16512, tenant_budget=16512, records=2):
                return [daemon, '-backend', 'mock', '-state-dir', str(state), '-auth-file', str(auth), '-max-instances', '2'] + ([] if budget is None else ['-result-bytes', str(budget), '-result-tenant-bytes', str(tenant_budget), '-result-records', str(records)])
            def call(method, path, body=None, tenant='alpha', status=200, key=None):
                conn = UnixHTTP(state / 'api.sock')
                try:
                    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + tokens[tenant]}
                    if key is not None: headers['Idempotency-Key'] = key
                    conn.request(method, path, None if body is None else json.dumps(body), headers)
                    response = conn.getresponse()
                    raw = response.read()
                    assert response.status == status, 'unexpected results fixture HTTP status'
                    return json.loads(raw)
                finally:
                    conn.close()
            def wait(predicate):
                end = time.monotonic() + 15
                while time.monotonic() < end:
                    value = predicate()
                    if value: return value
                    time.sleep(.005)
                raise AssertionError('results fixture wait expired')
            def start(**kwargs):
                proc = subprocess.Popen(command(**kwargs), stdout=log, stderr=log)
                try:
                    def ready():
                        assert proc.poll() is None, 'results fixture startup exited'
                        try: return call('GET', '/healthz')['backend'] == 'mock'
                        except (OSError, http.client.HTTPException): return False
                    wait(ready)
                    return proc
                except BaseException:
                    if proc.poll() is None: proc.kill()
                    proc.wait(timeout=15)
                    raise
            def stop(proc):
                proc.terminate()
                status = proc.wait(timeout=15)
                if status != 0:
                    raise AssertionError(json.dumps(failure_summary(status, node, state), sort_keys=True))
            def base(ref): return '/v1/sandboxes/' + ref['id']
            def request(ref): return {'generation': ref['generation'], 'argv': ['echo', 'synthetic-retained'], 'timeout_ms': 5000}
            def result(ref, job, tenant): return call('GET', base(ref) + '/executions/' + job['id'], tenant=tenant)
            def snapshot(): return {p.name: p.read_bytes() for p in (state / 'results').iterdir()}
            try:
                process = start()
                refs = {tenant: call('POST', '/v1/sandboxes', {'limits': {'max_output_bytes': 64}}, tenant=tenant, status=201, key='retained-' + tenant) for tenant in tokens}
                jobs = {}
                for tenant in tokens:
                    ref = refs[tenant]
                    job = call('POST', base(ref) + '/exec', request(ref), tenant=tenant, status=202)
                    final = wait(lambda: (current if (current := result(ref, job, tenant))['status'] != 'RUNNING' else None))
                    assert final.get('result_retained') is True and final['status'] == 'EXITED' and final['output']['stdout'] == 'synthetic-retained\n'
                    jobs[tenant] = job
                    if tenant == 'alpha':
                        denied = call('POST', base(ref) + '/exec', request(ref), tenant=tenant, status=503)
                        assert denied['error']['code'] == 'RESULT_CAPACITY'
                denied = call('POST', base(refs['beta']) + '/exec', request(refs['beta']), tenant='beta', status=503)
                assert denied['error']['code'] == 'RESULT_CAPACITY'
                checks.append('tenant and node/record reservation caps reject before new execution; separate tenant can still finish')
                call('GET', base(refs['alpha']) + '/executions/' + jobs['alpha']['id'], tenant='beta', status=404)
                checks.append('cross-tenant retained result lookup remains NOT_FOUND')
                for tenant, ref in refs.items():
                    call('DELETE', base(ref), {'generation': ref['generation']}, tenant=tenant, status=202)
                    wait(lambda: call('GET', base(ref), tenant=tenant)['state'] == 'DESTROYED')
                    assert result(ref, jobs[tenant], tenant).get('result_retained') is True
                checks.append('VM/mock instance reclamation does not discard the separate retained outcome')
                stop(process); process = None
                before = snapshot()
                refused = subprocess.run(command(budget=None), stdout=log, stderr=log, timeout=10)
                assert refused.returncode != 0 and snapshot() == before
                checks.append('disabling retention over existing result data refuses without erasing bytes')
                process = start(budget=1, tenant_budget=1, records=1)
                for tenant, ref in refs.items():
                    final = result(ref, jobs[tenant], tenant)
                    assert final.get('result_retained') is True and final['output']['stdout'] == 'synthetic-retained\n'
                call('GET', base(refs['alpha']) + '/executions/' + jobs['alpha']['id'], tenant='beta', status=404)
                stop(process); process = None
                assert snapshot() == before
                checks.append('restart with lowered admission budgets preserves both old outcomes and tenant isolation without command replay')
                scratch = state / 'results' / '.unknown-prefix.next'
                scratch.write_bytes(b'SYNTHETIC_UNKNOWN_PREFIX')
                scratch.chmod(0o600)
                corrupt = snapshot()
                refused = subprocess.run(command(), stdout=log, stderr=log, timeout=10)
                assert refused.returncode != 0 and snapshot() == corrupt
                checks.append('unknown/partial result scratch blocks startup and is preserved unchanged')
            finally:
                if process is not None and process.poll() is None:
                    process.kill(); process.wait(timeout=15)
        text = (root / 'private.log').read_text(errors='replace')
        assert all(token not in text for token in tokens.values())
    print(json.dumps({'test': 'bounded_retained_results_mock_process', 'backend': 'mock', 'production_ready': False, 'checks': checks}, indent=2))


if __name__ == '__main__':
    main()
