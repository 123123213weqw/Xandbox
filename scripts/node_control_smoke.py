#!/usr/bin/env python3
"""Actual daemon/CLI drain and restart process checks; MOCK ONLY, not KVM evidence."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile
import time

from smoke import UnixHTTP


def digest(filename):
    with Path(filename).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else hashlib.sha256(stream.read()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--daemon', required=True)
    parser.add_argument('--node', required=True)
    parser.add_argument('--work-dir')
    parser.add_argument('--report', help='sanitized JSON; never contains runtime IDs, tokens, paths or logs')
    args = parser.parse_args()
    daemon, node = str(Path(args.daemon).resolve()), str(Path(args.node).resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix='xb-node-', dir=args.work_dir) as tmp:
        root = Path(tmp)
        state = root / 'state'
        process = None

        def api(method, path, body=None, key=None, want=200):
            connection = UnixHTTP(state / 'api.sock')
            try:
                headers = {'Content-Type': 'application/json'}
                if key:
                    headers['Idempotency-Key'] = key
                connection.request(method, path, None if body is None else json.dumps(body), headers)
                response = connection.getresponse()
                data = response.read((1 << 20) + 1)
                assert response.status == want and len(data) <= 1 << 20, 'unexpected tenant API result'
                return json.loads(data) if data else None
            finally:
                connection.close()

        def control(operation, revision=None, epoch=None, request=None, want=0):
            command = [node, '-state-dir', str(state)]
            if revision is not None:
                command += ['-epoch', epoch, '-revision', str(revision), '-request-id', request]
            result = subprocess.run(command + [operation], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
            assert result.returncode == want, 'unexpected operator CLI exit'
            return json.loads(result.stdout) if result.returncode == 0 else None

        def wait(predicate):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                assert process is not None and process.poll() is None, 'own daemon exited'
                try:
                    value = predicate()
                    if value:
                        return value
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.01)
            raise AssertionError('process acceptance deadline')

        def boot(log):
            nonlocal process
            process = subprocess.Popen([daemon, '-backend', 'mock', '-state-dir', str(state), '-insecure-mock'],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                       env={'PATH': os.environ['PATH']}, start_new_session=True)
            health = wait(lambda: api('GET', '/healthz'))
            assert health['backend'] == 'mock' and health['isolation'] is False and health['production_ready'] is False

        def stop():
            nonlocal process
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
            assert process.wait(timeout=15) == 0, 'own daemon shutdown failed'
            process = None

        def execute(path, body, output):
            accepted = api('POST', path + '/exec', body, want=202)
            job = accepted.get('job', accepted)
            job_path = ('/v1/sandboxes/' + accepted['sandbox']['id']) if 'sandbox' in accepted else path
            result = wait(lambda: (value if (value := api('GET', job_path + '/executions/' + job['id']))['status'] != 'RUNNING' else None))
            assert result['status'] == 'EXITED' and result['output']['stdout'] == output and result['output']['exit_code'] == 0

        with (root / 'private.log').open('xb', buffering=0) as log:
            os.chmod(log.name, 0o600)
            try:
                boot(log)
                status = control('status')['control']
                assert status['admission_open'] and status['committed']['revision'] == 1
                epoch = status['committed']['epoch']
                raw = api('POST', '/v1/sandboxes', {}, 'old-create', 201)
                session = api('POST', '/v1/sessions', {}, 'old-session', 201)
                before = control('status')['resource_observation']
                assert before['records'] == 2
                drained = control('drain', 1, epoch, '1' * 32)['control']
                assert not drained['admission_open'] and drained['committed']['revision'] == 2
                assert control('drain', 1, epoch, '1' * 32)['control']['committed'] == drained['committed']
                assert api('GET', '/readyz', want=503)['admission_open'] is False
                assert api('GET', '/healthz')['admission_open'] is False
                assert api('POST', '/v1/sandboxes', {}, 'denied-create', 503)['error']['code'] == 'NODE_DRAINING'
                assert api('POST', '/v1/sessions', {}, 'denied-session', 503)['error']['code'] == 'NODE_DRAINING'
                switch = {'expected_revision': session['revision'], 'create': {}}
                assert api('POST', '/v1/sessions/' + session['id'] + '/switch', switch, 'denied-switch', 503)['error']['code'] == 'NODE_DRAINING'
                assert control('status')['resource_observation']['records'] == before['records']
                sessions = list((state / 'sessions').glob('*.json'))
                assert len(sessions) == 1
                saved = json.loads(sessions[0].read_text())
                # The durable envelope shape belongs to the session store.
                saved_record = saved.get('record', saved)
                assert len(saved_record['attempts']) == 1 and saved_record['revision'] == 1
                checks.append('new raw/session/switch rejected without durable metadata or history')
                raw_path = '/v1/sandboxes/' + raw['id']
                execute(raw_path, {'generation': raw['generation'], 'argv': ['echo', 'alive']}, 'alive\n')
                execute('/v1/sessions/' + session['id'], {'revision': session['revision'], 'argv': ['echo', 'session-alive']}, 'session-alive\n')
                api('DELETE', raw_path, {'generation': raw['generation']}, want=202)
                wait(lambda: api('GET', raw_path)['state'] == 'DESTROYED')
                checks.append('existing raw/session executions succeed and raw destruction completes while drained')
                control('resume', 1, epoch, '2' * 32, want=1)
                assert control('resume', 2, epoch, '2' * 32)['control']['admission_open']
                api('GET', '/readyz')
                api('POST', '/v1/sandboxes', {}, 'denied-create', 201)
                switched = api('POST', '/v1/sessions/' + session['id'] + '/switch', switch, 'denied-switch')
                assert switched['revision'] == 2
                assert control('drain', 3, epoch, '3' * 32)['control']['committed']['revision'] == 4
                stop()
                boot(log)
                restored = control('status')['control']
                assert restored['committed']['epoch'] == epoch and restored['committed']['revision'] == 4 and not restored['admission_open']
                api('GET', '/readyz', want=503)
                api('POST', '/v1/sandboxes', {}, 'after-restart', 503)
                control('resume', 2, epoch, '2' * 32, want=1)
                assert control('resume', 4, epoch, '4' * 32)['control']['admission_open']
                api('POST', '/v1/sandboxes', {}, 'after-restart', 201)
                stop()
                ledger = [json.loads(p.read_text())['record'] for p in (state / 'ledger').glob('*.json')]
                assert len(ledger) == 5 and all(r['state'] == 'DESTROYED' for r in ledger)
                checks += ['exact retry/stale resume rejection and rejected keys reusable after resume',
                           'acknowledged drain survives clean daemon restart with same epoch/revision',
                           'two daemon boots reaped; all five MOCK generations durably destroyed']
            finally:
                if process is not None:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
    report = {'version': 1, 'passed': True, 'backend': 'mock', 'isolation': False, 'production_ready': False,
              'hardware_qualification': False, 'system': platform.system(), 'architecture': platform.machine(),
              'daemon_sha256': digest(daemon), 'node_cli_sha256': digest(node), 'harness_sha256': digest(__file__), 'checks': checks}
    if args.report:
        # Refuse to overwrite an earlier acceptance result.
        with Path(args.report).open('x') as stream:
            os.chmod(args.report, 0o600)
            json.dump(report, stream, indent=2)
            stream.write('\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
