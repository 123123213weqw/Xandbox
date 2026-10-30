#!/usr/bin/env python3
"""Real mock daemon/CLI diagnostics acceptance; not KVM or disk-fault proof."""
import argparse
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from smoke import UnixHTTP
from process_exit import require_clean_exit


def terminate_cleanly(process, node, state, cycle):
    process.terminate()
    try:
        require_clean_exit(process, node, state, previous_sequence=cycle*3)
    except AssertionError as error:
        # The shared helper only projects integer status / timeout and closed
        # diagnostic enums. Never inspect or drain the inherited full streams.
        raise AssertionError(f'diagnostics restart cycle {cycle}: {error}') from None


def main(*, daemon_popen=subprocess.Popen):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--daemon', required=True)
    p.add_argument('--node', required=True)
    args = p.parse_args()
    daemon, node = str(Path(args.daemon).resolve()), str(Path(args.node).resolve())
    checks = []
    # Keep both streams FULL and undrained throughout all daemon incarnations.
    # Any ordinary stderr/stdout fallback would block startup or shutdown.
    read_fd, write_fd = os.pipe()
    os.set_blocking(write_fd, False)
    filled = 0
    while True:
        try:
            filled += os.write(write_fd, b'x' * 1024)
        except BlockingIOError as e:
            assert e.errno in (errno.EAGAIN, errno.EWOULDBLOCK)
            break
    os.set_blocking(write_fd, True)
    proc = None
    try:
        with tempfile.TemporaryDirectory(prefix='xb-diag-') as tmp:
            root = Path(tmp); state = root / 'state'
            token = os.urandom(32).hex()
            auth = root / 'private-auth.json'
            auth.write_text(json.dumps({'version': 1, 'keys': [{'tenant_id': 'private-diagnostic-tenant',
                'max_instances': 2, 'token_sha256': hashlib.sha256(token.encode()).hexdigest()}]}))
            auth.chmod(0o600)
            base = [daemon, '-backend', 'mock', '-state-dir', str(state), '-auth-file', str(auth), '-metrics']
            def call(method, path, body=None, expected=200):
                c = UnixHTTP(state / 'api.sock')
                try:
                    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
                    if method == 'POST' and path == '/v1/sandboxes':
                        headers['Idempotency-Key'] = 'private-diagnostic-key-' + str(cycle)
                    c.request(method, path, None if body is None else json.dumps(body), headers)
                    r = c.getresponse(); raw = r.read()
                    assert r.status == expected, (r.status, expected)
                    return json.loads(raw)
                finally:
                    c.close()
            def wait(predicate):
                end = time.monotonic() + 10
                while time.monotonic() < end:
                    assert proc.poll() is None, 'ordinary controller exited'
                    try:
                        if v := predicate(): return v
                    except (OSError, http.client.HTTPException): pass
                    time.sleep(.005)
                raise AssertionError('mock process predicate timeout')
            def view():
                r = subprocess.run([node, '-state-dir', str(state), 'diagnostics'],
                                   capture_output=True, timeout=10)
                assert r.returncode == 0 and not r.stderr and len(r.stdout) <= 32768
                v = json.loads(r.stdout)
                assert v['version'] == 1 and v['retained_capacity'] == 128 and len(v['records']) <= 128
                for record in v['records']:
                    assert set(record) == {'sequence', 'event'}
                    assert set(record['event']) == {'kind', 'reason', 'time_ns', 'dropped_before'}
                    assert record['event']['dropped_before'] == 0
                for secret in (token, 'private-diagnostic-tenant', str(state), str(auth), 'secret-argv-marker'):
                    assert secret.encode() not in r.stdout
                return v
            ring_inode = lock_inode = None
            for cycle in range(45):
                proc = daemon_popen(base, stdin=subprocess.DEVNULL, stdout=write_fd, stderr=write_fd)
                wait(lambda: call('GET', '/healthz'))
                if cycle in (0, 44):
                    vm = call('POST', '/v1/sandboxes', {}, 201)
                    prefix = '/v1/sandboxes/' + vm['id']
                    job = call('POST', prefix + '/exec', {'generation': vm['generation'],
                               'argv': ['echo', 'secret-argv-marker']}, 202)
                    wait(lambda: call('GET', prefix + '/executions/' + job['id'])['status'] == 'EXITED')
                    job = call('POST', prefix + '/exec', {'generation': vm['generation'],
                               'argv': ['sleep', '2s']}, 202)
                    # Stop/GC is independent of the full inherited output pipe;
                    # neither completed secret argv/output nor live job enters it.
                    stopped = call('POST', prefix + '/stop', {'generation': vm['generation']})
                    assert stopped['state'] == 'STOPPED'
                    call('DELETE', prefix, {'generation': vm['generation']}, 202)
                    wait(lambda: call('GET', prefix)['state'] == 'DESTROYED')
                    assert job['id']
                    c = UnixHTTP(state / 'metrics.sock')
                    try:
                        c.request('GET', '/metrics'); r = c.getresponse(); text = r.read(65537).decode()
                        assert r.status == 200 and len(text) <= 65536
                        for key in ('enqueued', 'dropped', 'written', 'write_errors'):
                            assert 'xandbox_diagnostics_' + key + '_total ' in text
                        assert 'xandbox_diagnostics_queue_capacity 64\n' in text
                        for secret in (token, 'private-diagnostic-tenant', str(state), 'secret-argv-marker'):
                            assert secret not in text
                    finally: c.close()
                # Independent view works while the actual ordinary writer lives.
                observed = view()
                assert observed['observed_sequence'] >= cycle * 3
                terminate_cleanly(proc, node, state, cycle); proc = None
                observed = view()
                assert observed['observed_sequence'] == (cycle + 1) * 3
                assert observed['records'][-1]['event']['kind'] == 'collector_closed'
                assert observed['records'][-2]['event']['kind'] == 'process_stopped'
                ring = state / 'diagnostics' / 'events.ring'; lock = ring.with_name('logger.lock')
                assert ring.stat().st_size == 16768 and ring.stat().st_mode & 0o777 == 0o600
                assert lock.stat().st_size == 0 and lock.stat().st_mode & 0o777 == 0o600
                if cycle == 0: ring_inode, lock_inode = ring.stat().st_ino, lock.stat().st_ino
                assert (ring.stat().st_ino, lock.stat().st_ino) == (ring_inode, lock_inode)
            assert observed['observed_sequence'] == 135 and observed['overwritten'] == 7
            assert observed['records'][0]['sequence'] == 8 and len(observed['records']) == 128
            checks += ['45 actual ordinary mock restarts with full undrained inherited stdout/stderr',
                       'Stop/private GC and fixed-cardinality metrics remain available with full inherited pipes',
                       'same private ring/lock inodes, 16768 logical bytes, 128 retained records and explicit overwrite count',
                       'independent bounded read-only live/offline view has closed fields and no request/error/path values']
            before = hashlib.sha256(ring.read_bytes()).digest()
            probe = ring.with_name('unrecognized-probe'); probe.write_bytes(b'preserve'); probe.chmod(0o600)
            refused = subprocess.run(base, capture_output=True, timeout=10)
            assert refused.returncode == 1 and refused.stdout == b''
            assert refused.stderr == b'sandboxd: private diagnostics unavailable\n'
            assert hashlib.sha256(ring.read_bytes()).digest() == before and probe.read_bytes() == b'preserve'
            checks.append('unknown diagnostic inventory refuses startup without rewriting ring or auto-reset')
            for extra in (['-max-instances', 'secret-argv-marker'], ['-unknown-secret-argv-marker']):
                r = subprocess.run([daemon] + extra, capture_output=True, timeout=10)
                assert r.returncode == 1 and r.stdout == b''
                assert r.stderr == b'sandboxd: configuration or bootstrap failure\n'
            checks.append('flag/bootstrap failures emit only one closed class, not supplied values')
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill(); proc.wait(timeout=10)
        os.close(write_fd)
        # Nonblocking drain after all owned producers are gone; exact original
        # fill proves no daemon output was hidden inside the saturated pipe.
        os.set_blocking(read_fd, False)
        total = 0
        while True:
            try: chunk = os.read(read_fd, 65536)
            except BlockingIOError: break
            if not chunk: break
            assert chunk == b'x' * len(chunk)
            total += len(chunk)
        os.close(read_fd)
        assert total == filled
    print(json.dumps({'backend': 'mock', 'production_ready': False, 'checks': checks}, indent=2))


if __name__ == '__main__':
    main()
