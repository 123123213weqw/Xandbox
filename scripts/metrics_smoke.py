#!/usr/bin/env python3
"""Private operator metrics process acceptance; mock is not isolation/performance."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from smoke import UnixHTTP


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--daemon', required=True)
    args = p.parse_args()
    daemon = str(Path(args.daemon).resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix='xb-metrics-') as tmp:
        root = Path(tmp); state = root / 'state'
        token = os.urandom(32).hex()
        auth = root / 'auth.json'
        auth.write_text(json.dumps({'version': 1, 'keys': [{'tenant_id': 'secret-tenant', 'max_instances': 2,
            'token_sha256': hashlib.sha256(token.encode()).hexdigest()}]})); auth.chmod(0o600)
        base = [daemon, '-backend', 'mock', '-state-dir', str(state), '-auth-file', str(auth)]
        process = None
        def call(method, path, body=None, status=200):
            conn = UnixHTTP(state / 'api.sock')
            try:
                conn.request(method, path, None if body is None else json.dumps(body),
                    {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Idempotency-Key': 'sensitive-key'})
                r = conn.getresponse(); data = r.read(); assert r.status == status, (r.status, status)
                return {} if r.status == 404 and not r.getheader('Content-Type', '').startswith('application/json') else json.loads(data)
            finally:
                conn.close()
        def wait(predicate):
            until = time.monotonic() + 15
            while time.monotonic() < until:
                assert process.poll() is None, 'controller exited'
                try:
                    v = predicate()
                    if v: return v
                except (OSError, http.client.HTTPException): pass
                time.sleep(0.005)
            raise AssertionError('timed out')
        def metric():
            conn = UnixHTTP(state / 'metrics.sock')
            try:
                conn.request('GET', '/metrics'); r = conn.getresponse(); text = r.read(65537).decode()
                assert r.status == 200 and len(text) <= 65536
                return text
            finally: conn.close()
        with (root / 'private.log').open('ab', buffering=0) as log:
            try:
                process = subprocess.Popen(base, stdout=log, stderr=log)
                wait(lambda: call('GET', '/healthz'))
                assert not (state / 'metrics.sock').exists()
                process.terminate(); assert process.wait(timeout=15) == 0
                checks.append('metrics socket disabled by default')
                (state / 'metrics.sock').write_text('preserve'); (state / 'metrics.sock').chmod(0o600)
                refused = subprocess.run(base + ['-metrics'], stdout=log, stderr=log, timeout=15)
                assert refused.returncode != 0 and (state / 'metrics.sock').read_text() == 'preserve'
                (state / 'metrics.sock').unlink()
                checks.append('startup refuses to replace regular metrics path')
                process = subprocess.Popen(base + ['-metrics'], stdout=log, stderr=log)
                wait(lambda: call('GET', '/healthz'))
                assert (state / 'metrics.sock').stat().st_mode & 0o777 == 0o600
                call('GET', '/metrics', status=404)
                vm = call('POST', '/v1/sandboxes', {}, status=201)
                sockets = []
                try:
                    for _ in range(24):
                        conn = socket.socket(socket.AF_UNIX); conn.settimeout(2); conn.connect(str(state / 'metrics.sock'))
                        sockets.append(conn)
                    stopped = call('POST', '/v1/sandboxes/' + vm['id'] + '/stop', {'generation': vm['generation']})
                    assert stopped['state'] == 'STOPPED'
                finally:
                    for conn in sockets: conn.close()
                call('DELETE', '/v1/sandboxes/' + vm['id'], {'generation': vm['generation']}, status=202)
                wait(lambda: call('GET', '/v1/sandboxes/' + vm['id'])['state'] == 'DESTROYED')
                text = wait(lambda: (v if 'xandbox_allocated 0\n' in (v := metric()) else None))
                for sensitive in (token, 'secret-tenant', 'sensitive-key', str(state), vm['id'], vm['generation']):
                    assert sensitive not in text
                assert 'xandbox_records 1\n' in text
                assert 'xandbox_operation_seconds_count{operation="cleanup_attempt",outcome="success"} 1' in text
                checks += ['operator UDS0600 separate from authenticated tenant API and no sensitive labels',
                           'stop/reclaim succeed under offered metrics connection saturation; tombstone remains counted']
                process.terminate(); assert process.wait(timeout=15) == 0
                assert not (state / 'metrics.sock').exists()
                process = subprocess.Popen(base + ['-metrics'], stdout=log, stderr=log)
                wait(lambda: call('GET', '/healthz'))
                text = metric()
                assert 'xandbox_records 1\n' in text
                assert 'xandbox_operation_seconds_count{operation="cleanup_attempt",outcome="success"} 0' in text
                checks.append('restart resets process counters, rebuilds retained gauges and removes socket on shutdown')
                process.terminate(); assert process.wait(timeout=15) == 0; process = None
            finally:
                if process is not None and process.poll() is None:
                    process.kill(); process.wait(timeout=5)
    print(json.dumps({'backend': 'mock', 'production_ready': False, 'checks': checks}, indent=2))

if __name__ == '__main__':
    main()
