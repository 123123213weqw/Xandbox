#!/usr/bin/env python3
"""Experimental sandboxd/Firecracker crash acceptance on an isolated root KVM node.

Uses only its own cgroup subtree and short runtime root. Never runs tenant
commands on the host. Raw controller logs stay private; the report is sanitized.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=40)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def wait(predicate, name, seconds=15):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(0.005)
    raise AssertionError('timed out: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('daemon', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd', 'report', 'log-dir'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--source-revision', default='uncommitted')
    args = parser.parse_args()
    if os.geteuid() != 0 or os.uname().sysname != 'Linux':
        parser.error('requires root on an isolated Linux/KVM test node')
    inputs = {name: Path(getattr(args, name)).resolve() for name in ('daemon', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd')}
    report = Path(args.report).resolve()
    assert not report.exists(), 'refusing to overwrite report'
    logs = Path(args.log_dir).resolve()
    logs.mkdir(mode=0o700, parents=True, exist_ok=True)
    suffix = secrets.token_hex(3)
    runtime = Path('/srv/xb' + suffix)
    noexec_runtime = Path('/run/xb' + suffix)
    cgroup = Path('/sys/fs/cgroup') / ('xandbox-driver-proof-' + suffix)
    assert not runtime.exists() and not cgroup.exists()
    result = {'validated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'test': 'experimental_sandboxd_firecracker_driver', 'production_ready': False,
              'source_revision': args.source_revision, 'host_kernel': os.uname().release,
              'architecture': os.uname().machine, 'guest_memory_mib': 512, 'vcpus': 2,
              'workspace_bytes': 128 << 20, 'guest_network_interfaces': 0,
              'metrics_note': 'Small sequential acceptance samples; warm cache and load uncontrolled; not percentiles or SLO. Stop observations include observer overhead; RSS not measured.',
              'artifacts_sha256': {k: digest(v) for k, v in inputs.items()},
              'checks': [], 'samples': {}}
    process = None
    watch_stop = threading.Event()
    watcher = None
    root = Path(tempfile.mkdtemp(prefix='xandbox-driver-proof-', dir='/var/lib'))
    try:
        assets = root / 'assets'
        assets.mkdir(mode=0o700)
        copied = {}
        for name, path in inputs.items():
            target = assets / name
            shutil.copyfile(path, target)
            target.chmod(0o555 if name in ('daemon', 'warden', 'jailer', 'firecracker') else 0o444)
            assert digest(target) == result['artifacts_sha256'][name]
            copied[name] = target
        workspace = assets / 'empty.ext4'
        with workspace.open('xb') as disk:
            disk.truncate(128 << 20)
        subprocess.run(['/usr/sbin/mkfs.ext4', '-q', '-F', str(workspace)], check=True)
        workspace.chmod(0o444)
        result['workspace_template_sha256'] = digest(workspace)
        cgroup.mkdir(mode=0o700)
        (cgroup / 'cgroup.subtree_control').write_text('+memory +pids +cpu')
        uid = 400000 + secrets.randbelow(30000)
        config = {'version': 1, 'runtime_root': str(runtime), 'cgroup_root': str(cgroup),
                  'uid_start': uid, 'uid_count': 2, 'reserved_uid_range': True}
        for name in ('warden', 'firecracker', 'jailer', 'kernel', 'initrd'):
            config[name] = {'path': str(copied[name]), 'sha256': digest(copied[name])}
        config['workspace'] = {'path': str(workspace), 'sha256': digest(workspace)}
        cfg = root / 'backend.json'
        cfg.write_text(json.dumps(config)); cfg.chmod(0o600)
        token = secrets.token_hex(32)
        auth = root / 'auth.json'
        auth.write_text(json.dumps({'version': 1, 'keys': [{'tenant_id': 'proof', 'max_instances': 1,
                                    'token_sha256': hashlib.sha256(token.encode()).hexdigest()}]}))
        auth.chmod(0o600)
        state = root / 'state'
        state.mkdir(mode=0o700)
        base = [str(copied['daemon']), '-backend', 'firecracker', '-state-dir', str(state),
                '-auth-file', str(auth), '-firecracker-config', str(cfg), '-max-instances', '2']
        sock = state / 'api.sock'
        # A private diagnostic observer captures transient lifecycle failures before
        # successful cleanup clears LastError. Never include this in public reports.
        def observe_failures():
            seen = set()
            with (logs / 'driver-failures.jsonl').open('a') as diagnostics:
                while not watch_stop.wait(0.001):
                    for item in (state / 'ledger').glob('*.json'):
                        try:
                            value = json.loads(item.read_text()).get('last_error', '')
                        except (OSError, ValueError):
                            continue
                        if value and value not in seen:
                            seen.add(value)
                            diagnostics.write(json.dumps({'error': value}) + '\n')
                            diagnostics.flush()
        watcher = threading.Thread(target=observe_failures, daemon=True)
        watcher.start()
        with (logs / 'controller.log').open('ab', buffering=0) as log:
            def call(method, path, body=None, expected=200, key=None, authenticated=True):
                headers = {'Content-Type': 'application/json'}
                if authenticated:
                    headers['Authorization'] = 'Bearer ' + token
                if key:
                    headers['Idempotency-Key'] = key
                conn = UnixHTTP(sock)
                try:
                    conn.request(method, path, None if body is None else json.dumps(body), headers)
                    response = conn.getresponse()
                    data = response.read()
                    allowed = expected if isinstance(expected, tuple) else (expected,)
                    assert response.status in allowed, (response.status, data.decode())
                    assert token.encode() not in data
                    return json.loads(data)
                finally:
                    conn.close()

            def start():
                proc = subprocess.Popen(base, stdout=log, stderr=log)
                def health():
                    if proc.poll() is not None:
                        raise AssertionError('controller exited; inspect private log')
                    try:
                        return call('GET', '/healthz', authenticated=False)
                    except (OSError, http.client.HTTPException):
                        return None
                h = wait(health, 'controller start')
                assert h['backend'] == 'firecracker' and h['isolation'] and not h['production_ready'] and 'stats' not in h
                return proc

            def create():
                before = time.perf_counter()
                record = call('POST', '/v1/sandboxes', {}, expected=201, key=secrets.token_hex(16))
                assert record['state'] == 'READY'
                result['samples'].setdefault('create_api_ready_ms', []).append(round((time.perf_counter() - before) * 1000, 3))
                return record

            def path(r):
                return '/v1/sandboxes/' + r['id']

            def group(r):
                return cgroup / (r['id'] + r['generation'])

            def stopped(g):
                return not g.exists() or 'populated 0' in (g / 'cgroup.events').read_text()

            def job(r, argv, timeout=5000):
                return call('POST', path(r) + '/exec', {'generation': r['generation'], 'argv': argv,
                                                      'timeout_ms': timeout}, expected=202)

            def finish(r, j):
                return wait(lambda: (v if (v := call('GET', path(r) + '/executions/' + j['id']))['status'] != 'RUNNING' else None), 'execution completion')

            def execute(r, argv):
                j = finish(r, job(r, argv))
                assert j['status'] == 'EXITED', j
                return j['output']

            def destroyed(r):
                record = wait(lambda: (v if (v := call('GET', path(r)))['state'] == 'DESTROYED' else None), 'durable destroy')
                assert not group(r).exists()
                assert not (runtime / 'j/firecracker' / (r['id'] + r['generation'])).exists()
                assert not list((state / 'firecracker').glob(r['id'] + '*.json'))
                return record

            def remove(r):
                from_state = call('GET', path(r))['state']
                before = time.perf_counter()
                call('DELETE', path(r), {'generation': r['generation']}, expected=202)
                accepted_ms = (time.perf_counter() - before) * 1000
                wait(lambda: stopped(group(r)), 'delete stopped execution')
                stopped_ms = (time.perf_counter() - before) * 1000
                destroyed(r)
                result['samples'].setdefault('delete_phases', []).append({
                    'from_state': from_state, 'accepted_ms': round(accepted_ms, 3),
                    'observed_stopped_ms': round(stopped_ms, 3),
                    'durable_destroyed_ms': round((time.perf_counter() - before) * 1000, 3)})

            if os.statvfs('/run').f_flag & os.ST_NOEXEC:
                bad = dict(config); bad['runtime_root'] = str(noexec_runtime)
                cfg.write_text(json.dumps(bad))
                denied = subprocess.run(base, stdout=log, stderr=log, timeout=10)
                assert denied.returncode != 0 and not list((state / 'ledger').glob('*.json'))
                assert not [p for p in cgroup.iterdir() if p.is_dir()]
                cfg.write_text(json.dumps(config))
                result['checks'].append('noexec runtime rejected before any per-generation allocation')
            process = start()
            call('POST', '/v1/sandboxes', {}, expected=401, key='denied', authenticated=False)
            first = create()
            assert execute(first, ['id', '-u'])['stdout'].strip() == '65534'
            assert execute(first, ['sh', '-c', "grep '^NoNewPrivs:' /proc/self/status"])['stdout'].strip() == 'NoNewPrivs:\t1'
            assert execute(first, ['ls', '/sys/class/net'])['stdout'].strip() == 'lo'
            assert execute(first, ['sh', '-c', 'echo private > note; cat note'])['stdout'] == 'private\n'
            call('POST', '/v1/sandboxes', {}, expected=429, key='over-quota')
            call('POST', path(first) + '/exec', {'generation': '0' * 32, 'argv': ['true'], 'timeout_ms': 1000}, expected=409)
            result['checks'] += ['authenticated real-driver create and tenant quota', 'guest UID 65534 and no_new_privs',
                                 'guest network loopback only', 'private workspace', 'stale generation rejected']
            # Assert host cgroup, actual KVM fd, default seccomp and private netns.
            pids = [int(p) for p in (group(first) / 'cgroup.procs').read_text().split()]
            assert len(pids) >= 2
            vm = None
            for pid in pids:
                try:
                    status = Path(f'/proc/{pid}/status').read_text()
                    if f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}' in status:
                        vm = pid
                        assert 'Seccomp:\t2\n' in status
                except FileNotFoundError:
                    pass
            assert vm is not None
            assert any('kvm-vm' in os.readlink(fd) for fd in Path(f'/proc/{vm}/fd').iterdir())
            assert os.readlink(f'/proc/{vm}/ns/net') != os.readlink('/proc/self/ns/net')
            links = json.loads(subprocess.check_output(['nsenter', '--target', str(vm), '--net', 'ip', '-j', 'link'], timeout=3))
            assert [link['ifname'] for link in links] == ['lo']
            assert (group(first) / 'memory.max').read_text().strip() == '805306368'
            assert (group(first) / 'pids.max').read_text().strip() == '64'
            result['checks'].append('actual KVM, jailer UID drop, default seccomp, private host netns and host cgroup limits')
            long = job(first, ['sh', '-c', 'echo started > active; sleep 30'])
            wait(lambda: execute(first, ['test', '-e', 'active'])['exit_code'] == 0, 'guest task started')
            queued_a = job(first, ['sleep', '0.2'])
            queued_b = job(first, ['true'])
            assert finish(first, queued_a)['status'] == 'EXITED'
            assert finish(first, queued_b)['status'] == 'EXITED'
            result['checks'].append('three accepted executions queue onto two guest slots without fencing healthy VM')
            pidfd = os.pidfd_open(process.pid)
            try:
                exited = select.poll(); exited.register(pidfd, select.POLLIN)
                began = time.perf_counter()
                process.kill()
                assert exited.poll(5000), 'controller did not exit'
                wait(lambda: stopped(group(first)), 'lifetime EOF killed cgroup', seconds=5)
                result['samples']['controller_sigkill_to_empty_cgroup_ms'] = round((time.perf_counter() - began) * 1000, 3)
                process.wait(timeout=5); process = None
            finally:
                os.close(pidfd)
            # A changed locator cannot mark the old generation as reclaimed.
            changed = dict(config); changed['runtime_root'] = str(runtime) + 'z'
            cfg.write_text(json.dumps(changed))
            refused = subprocess.run(base, stdout=log, stderr=log, timeout=10)
            assert refused.returncode != 0
            assert json.loads((state / 'ledger' / (first['id'] + '.json')).read_text())['state'] != 'DESTROYED'
            cfg.write_text(json.dumps(config))
            began = time.perf_counter()
            process = start(); destroyed(first)
            result['samples']['restart_to_durable_reclaim_ms'] = round((time.perf_counter() - began) * 1000, 3)
            result['checks'] += ['controller SIGKILL stops a running guest via lifetime-pipe cgroup kill',
                                 'changed backend locator rejected before ledger recovery', 'restart reclaim and UID/quota release']
            second = create()
            assert execute(second, ['test', '!', '-e', 'note'])['exit_code'] == 0
            running = job(second, ['sh', '-c', 'echo started > active; sleep 30'])
            wait(lambda: execute(second, ['test', '-e', 'active'])['exit_code'] == 0, 'stop race task started')
            began = time.perf_counter()
            stop = call('POST', path(second) + '/stop', {'generation': second['generation']})
            result['samples']['stop_api_confirmed_ms'] = round((time.perf_counter() - began) * 1000, 3)
            assert stop['state'] == 'STOPPED' and stopped(group(second))
            assert not stop['delete_requested'], 'explicit stop must not become automatic deletion'
            assert finish(second, running)['status'] == 'CANCELLED'
            call('POST', path(second) + '/exec', {'generation': second['generation'], 'argv': ['true'], 'timeout_ms': 1000}, expected=409)
            remove(second)
            result['checks'] += ['new generation has fresh disk', 'concurrent exec/stop drains without deadlock and preserves explicit stop']
            third = create()
            deadline_job = job(third, ['sleep', '30'], timeout=100)
            def deadline_done():
                value = call('GET', path(third) + '/executions/' + deadline_job['id'], expected=(200, 404))
                if 'error' in value:
                    assert call('GET', path(third))['state'] == 'DESTROYED'
                    return True  # Contract drops in-memory history at reclamation.
                if value['status'] == 'RUNNING':
                    return False
                assert value['status'] == 'TIMED_OUT', value
                return True
            wait(deadline_done, 'deadline terminal or reclaimed')
            destroyed(third)
            result['checks'].append('host hard deadline fences and reclaims entire VM')
            # Interrupt allocation after durable ownership but before API readiness.
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(create)
                owner_path = wait(lambda: next((state / 'firecracker').glob('?' * 64 + '.json'), None), 'ownership persistence')
                owner = json.loads(owner_path.read_text())['ref']
                wait(lambda: group(owner).exists(), 'owned cgroup allocation')
                process.kill(); process.wait(timeout=5); process = None
                try:
                    pending.result(timeout=5)
                    raise AssertionError('partial prepare unexpectedly completed before crash')
                except (OSError, http.client.HTTPException):
                    pass
            wait(lambda: stopped(group(owner)), 'partial prepare quiescence', seconds=5)
            process = start(); destroyed(owner)
            final = create(); remove(final)
            result['checks'].append('partial prepare SIGKILL recovery releases capacity only after cleanup')
            process.terminate(); assert process.wait(timeout=15) == 0; process = None
            assert not [p for p in cgroup.iterdir() if p.is_dir()]
            assert not list((runtime / 'j/firecracker').iterdir())
            assert [p.name for p in (state / 'firecracker').iterdir() if not p.name.startswith('.')] == ['config.json']
            result['checks'].append('no owned VMM/cgroup/jail/UID manifest residue')
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'passed': len(result['checks']), 'production_ready': False, 'samples': result['samples']}))
    finally:
        watch_stop.set()
        if watcher is not None:
            watcher.join(timeout=2)
        if process is not None and process.poll() is None:
            process.kill(); process.wait(timeout=5)
        if cgroup.exists():
            (cgroup / 'cgroup.kill').write_text('1')
            wait(lambda: stopped(cgroup), 'test cleanup', seconds=5)
            for child in cgroup.iterdir():
                if child.is_dir():
                    child.rmdir()
            cgroup.rmdir()
        for path in (runtime, noexec_runtime, Path(str(runtime) + 'z'), root):
            shutil.rmtree(path, ignore_errors=False) if path.exists() else None


if __name__ == '__main__':
    main()
