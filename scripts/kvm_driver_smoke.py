#!/usr/bin/env python3
"""Experimental sandboxd/Firecracker crash acceptance on an isolated root KVM node.

Uses only its own cgroup subtree and short runtime root. Never runs tenant
commands on the host. Raw controller logs stay private; the report is sanitized.
"""
from concurrent.futures import ThreadPoolExecutor
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
    parser.add_argument('--queue-test', help='optional Linux Go test binary for controlled fsync queue acceptance')
    parser.add_argument('--session-test', help='optional patched Linux session test binary, also enables HTTP session acceptance')
    parser.add_argument('--legacy-daemon', help='optional trusted pre-ledger-v1 binary for actual KVM crash/upgrade acceptance')
    parser.add_argument('--legacy-source-revision')
    parser.add_argument('--source-revision', default='uncommitted')
    args = parser.parse_args()
    if os.geteuid() != 0 or os.uname().sysname != 'Linux':
        parser.error('requires root on an isolated Linux/KVM test node')
    inputs = {name: Path(getattr(args, name)).resolve() for name in ('daemon', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd')}
    if args.queue_test:
        inputs['queue_test'] = Path(args.queue_test).resolve()
    if args.session_test:
        inputs['session_test'] = Path(args.session_test).resolve()
    if args.legacy_daemon:
        assert args.legacy_source_revision, 'legacy source revision is required'
        inputs['legacy_daemon'] = Path(args.legacy_daemon).resolve()
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
            target.chmod(0o555 if name in ('daemon', 'warden', 'jailer', 'firecracker', 'queue_test', 'legacy_daemon', 'session_test') else 0o444)
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
                            raw = json.loads(item.read_text())
                            value = (raw['record'] if 'version' in raw else raw).get('last_error', '')
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

            def start(command=None):
                proc = subprocess.Popen(base if command is None else command, stdout=log, stderr=log)
                def health():
                    if proc.poll() is not None:
                        raise AssertionError('controller exited; inspect private log')
                    try:
                        return call('GET', '/healthz', authenticated=False)
                    except (OSError, http.client.HTTPException):
                        return None
                try:
                    h = wait(health, 'controller start')
                    assert h['backend'] == 'firecracker' and h['isolation'] and not h['production_ready'] and 'stats' not in h
                    return proc
                except BaseException:
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait(timeout=5)
                    raise

            def create(ttl_ms=0, max_exec_ms=0, key=None):
                before = time.perf_counter()
                body = {}
                if ttl_ms: body['ttl_ms'] = ttl_ms
                if max_exec_ms: body['limits'] = {'max_exec_ms': max_exec_ms}
                record = call('POST', '/v1/sandboxes', body, expected=201, key=key or secrets.token_hex(16))
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

            # Real root process tests: reject before creating a child/lock or
            # consuming another UID's private auth policy. All paths belong to
            # this disposable root-owned fixture, never another user's tree.
            for mode in ('writable-parent', 'foreign-parent', 'foreign-auth', 'foreign-migration'):
                parent = root / mode; parent.mkdir(mode=0o700)
                target = parent / 'would-create'
                denied_base = list(base)
                denied_base[denied_base.index('-state-dir') + 1] = str(target)
                if mode == 'writable-parent':
                    parent.chmod(0o777)
                elif mode == 'foreign-parent':
                    os.chown(parent, 65534, 65534)
                elif mode == 'foreign-auth':
                    foreign_auth = parent / 'auth.json'; shutil.copyfile(auth, foreign_auth)
                    foreign_auth.chmod(0o600); os.chown(foreign_auth, 65534, 65534)
                    denied_base[denied_base.index('-auth-file') + 1] = str(foreign_auth)
                else:
                    target.mkdir(mode=0o700); (target / 'ledger').mkdir(mode=0o700)
                    os.chown(target, 65534, 65534)
                    denied_base = [str(copied['daemon']), '-state-dir', str(target), '-migrate-ledger']
                assert subprocess.run(denied_base, stdout=log, stderr=log, timeout=10).returncode != 0
                if mode == 'foreign-migration':
                    assert not (target / 'controller.lock').exists() and not list((target / 'ledger').iterdir())
                else:
                    assert not target.exists(), 'created state before path/owner rejection'
            result['checks'].append('real root rejects writable/foreign state ancestry and foreign private auth before state creation; offline migration cannot bypass ownership')

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
            assert json.loads((state / 'ledger' / (first['id'] + '.json')).read_text())['record']['state'] != 'DESTROYED'
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
                if isinstance(value.get('error'), dict):
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
            # Healthy reconciliation must renew across multiple 5s lease windows.
            healthy = create(ttl_ms=60000, max_exec_ms=60000)
            healthy_job = finish(healthy, job(healthy, ['sleep', '12'], timeout=15000))
            assert healthy_job['status'] == 'EXITED' and call('GET', path(healthy))['state'] == 'READY'
            remove(healthy)
            result['checks'].append('healthy controller reconciliation renews across multiple guardian lease windows')
            result['guardian_policy'] = {'clock': 'CLOCK_BOOTTIME', 'lease_window_ms': 5000,
                                         'renew_interval_ms': 1000, 'wire_version': 'XBL1'}
            result['guardian_samples'] = []

            def warden_identity(record):
                for raw in (group(record) / 'cgroup.procs').read_text().split():
                    pid = int(raw)
                    try:
                        status = Path(f'/proc/{pid}/status').read_text()
                        argv = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
                        if 'Uid:\t0\t0\t0\t0' in status and b'-hard-deadline-ns' in argv:
                            hard = int(argv[argv.index(b'-hard-deadline-ns') + 1])
                            return os.pidfd_open(pid), hard
                    except FileNotFoundError:
                        continue
                raise AssertionError('owned guardian process not found')

            for mode in ('controller_pause_lease', 'controller_pause_hard_ttl', 'guardian_sigkill'):
                guarded = create(ttl_ms=10000 if mode.endswith('hard_ttl') else 60000, max_exec_ms=60000)
                active = job(guarded, ['sh', '-c', 'echo started > guardian-started; sleep 55'], timeout=60000)
                wait(lambda: execute(guarded, ['test', '-e', 'guardian-started'])['exit_code'] == 0, 'guardian workload started')
                guardian_fd, hard = warden_identity(guarded)
                paused = False
                controller_fd = os.pidfd_open(process.pid)
                try:
                    if mode == 'controller_pause_hard_ttl':
                        # Use the actual root guardian's immutable BOOTTIME policy,
                        # not the wall-clock ExpiresAt display to schedule this test.
                        remaining = (hard - time.clock_gettime_ns(time.CLOCK_BOOTTIME)) / 1e9
                        assert remaining > 2, 'not enough hard TTL remaining for pause test'
                        time.sleep(remaining - 1.5)
                        assert hard - time.clock_gettime_ns(time.CLOCK_BOOTTIME) > 0
                    began = time.perf_counter()
                    if mode.startswith('controller_pause'):
                        signal.pidfd_send_signal(controller_fd, signal.SIGSTOP)
                        paused = True
                    else:
                        signal.pidfd_send_signal(guardian_fd, signal.SIGKILL)
                    wait(lambda: stopped(group(guarded)), mode + ' independently fenced VMM', seconds=8)
                    sample = {'case': mode, 'fault_to_empty_cgroup_ms': round((time.perf_counter() - began) * 1000, 3)}
                    if mode == 'controller_pause_hard_ttl':
                        now_boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
                        assert now_boot >= hard, 'VM died early instead of reaching hard TTL'
                        sample['hard_deadline_to_empty_observed_ms'] = round((now_boot - hard) / 1e6, 3)
                    if paused:
                        persisted = json.loads((state / 'ledger' / (guarded['id'] + '.json')).read_text())['record']
                        assert persisted['state'] == 'READY', 'controller performed stop instead of independent guardian'
                        assert list((state / 'firecracker').glob(guarded['id'] + '*.json')), 'ownership vanished while controller paused'
                    result['guardian_samples'].append(sample)
                finally:
                    if paused:
                        signal.pidfd_send_signal(controller_fd, signal.SIGCONT)
                    os.close(controller_fd); os.close(guardian_fd)
                destroyed(guarded)
                result['checks'].append(mode + ' host execution fenced and controller recovery reclaimed ownership')
            process.terminate(); assert process.wait(timeout=15) == 0; process = None
            assert not [p for p in cgroup.iterdir() if p.is_dir()]
            assert not list((runtime / 'j/firecracker').iterdir())
            assert [p.name for p in (state / 'firecracker').iterdir() if not p.name.startswith('.')] == ['config.json']
            result['checks'].append('no owned VMM/cgroup/jail/UID manifest residue')
            if args.legacy_daemon:
                # A separate private state directory, same now-empty fixture
                # roots. Never rewrite a live ledger or run two controllers.
                state = root / 'legacy-state'; state.mkdir(mode=0o700)
                sock = state / 'api.sock'
                base = [str(copied['daemon']), '-backend', 'firecracker', '-state-dir', str(state),
                        '-auth-file', str(auth), '-firecracker-config', str(cfg), '-max-instances', '2']
                old_base = list(base); old_base[0] = str(copied['legacy_daemon'])
                process = start(old_base)
                legacy_key = secrets.token_hex(16)
                legacy_vm = create(ttl_ms=60000, max_exec_ms=60000, key=legacy_key)
                legacy_job = job(legacy_vm, ['sh', '-c', 'echo started > upgrade-started; sleep 55'], timeout=60000)
                wait(lambda: execute(legacy_vm, ['test', '-e', 'upgrade-started'])['exit_code'] == 0, 'legacy VM running')
                ledger_path = state / 'ledger' / (legacy_vm['id'] + '.json')
                raw_legacy = json.loads(ledger_path.read_text())
                assert 'version' not in raw_legacy and raw_legacy['state'] == 'READY'
                process.kill(); process.wait(timeout=5); process = None
                wait(lambda: stopped(group(legacy_vm)), 'old controller EOF stopped old KVM', seconds=5)
                before = ledger_path.read_bytes()
                assert subprocess.run(base, stdout=log, stderr=log, timeout=10).returncode != 0
                assert ledger_path.read_bytes() == before, 'new startup rewrote legacy ownership without migration'
                migration = subprocess.run([str(copied['daemon']), '-state-dir', str(state), '-migrate-ledger'],
                                           stdout=subprocess.PIPE, stderr=log, timeout=30)
                assert migration.returncode == 0 and json.loads(migration.stdout)['upgraded'] == 1
                upgraded = json.loads(ledger_path.read_text())
                assert upgraded['version'] == 1 and upgraded['record']['id'] == legacy_vm['id']
                assert upgraded['record']['create_key_hash'] == raw_legacy['create_key_hash']
                assert upgraded['record']['state'] == 'READY', 'offline migration falsely claimed resource reclamation'
                base += ['-max-records', '1', '-max-tenant-records', '1']
                process = start(); destroyed(legacy_vm)
                assert call('POST', '/v1/sandboxes', {'ttl_ms': 60000, 'limits': {'max_exec_ms': 60000}},
                            expected=410, key=legacy_key)['error']['code'] == 'IDEMPOTENCY_GONE'
                assert call('POST', '/v1/sandboxes', {}, expected=503, key=secrets.token_hex(16))['error']['code'] == 'METADATA_CAPACITY'
                process.terminate(); assert process.wait(timeout=15) == 0; process = None
                assert not [p for p in cgroup.iterdir() if p.is_dir()]
                assert not list((runtime / 'j/firecracker').iterdir())
                assert [p.name for p in (state / 'firecracker').iterdir() if not p.name.startswith('.')] == ['config.json']
                result['legacy_migration'] = {'source_revision': args.legacy_source_revision,
                                             'new_api_admission_at_capacity': 'rejected; ownership/key retained',
                                             'old_kvm_recovered': True}
                result['checks'].append('actual old-daemon KVM SIGKILL ownership explicitly migrated then durably reclaimed at metadata capacity without key reuse')
            if args.session_test:
                state = root / 'session-api-state'; state.mkdir(mode=0o700)
                sock = state / 'api.sock'
                session_auth = root / 'session-auth.json'
                other_token = secrets.token_hex(32)
                session_auth.write_text(json.dumps({'version': 1, 'keys': [
                    {'tenant_id': 'proof', 'max_instances': 2, 'token_sha256': hashlib.sha256(token.encode()).hexdigest()},
                    {'tenant_id': 'other', 'max_instances': 2, 'token_sha256': hashlib.sha256(other_token.encode()).hexdigest()}]}))
                session_auth.chmod(0o600)
                base = [str(copied['daemon']), '-backend', 'firecracker', '-state-dir', str(state),
                        '-auth-file', str(session_auth), '-firecracker-config', str(cfg), '-max-instances', '2']
                process = start()
                session_req = {'ttl_ms': 60000, 'limits': {'max_exec_ms': 60000}}
                session_key = secrets.token_hex(16)
                initial = call('POST', '/v1/sessions', session_req, expected=201, key=session_key)
                session_path = '/v1/sessions/' + initial['id']
                def session_job(binding, argv, timeout=5000):
                    accepted = call('POST', session_path + '/exec', {'revision': binding['revision'], 'argv': argv, 'timeout_ms': timeout}, expected=202)
                    assert accepted['revision'] == binding['revision'] and accepted['sandbox'] == binding['current']
                    return accepted
                def session_exec(binding, argv):
                    accepted = session_job(binding, argv)
                    return finish(accepted['sandbox'], accepted['job'])
                assert session_exec(initial, ['sh', '-c', 'echo old > session-note'])['status'] == 'EXITED'
                call('POST', path(initial['current']) + '/exec', {'generation': initial['current']['generation'], 'argv': ['true']}, expected=409)
                for method, endpoint, body in [('GET', session_path, None), ('POST', session_path + '/switch', {'expected_revision': 1}),
                                                ('POST', session_path + '/exec', {'revision': 1, 'argv': ['true']}),
                                                ('POST', session_path + '/revoke', {'expected_revision': 1})]:
                    conn = UnixHTTP(sock)
                    try:
                        conn.request(method, endpoint, None if body is None else json.dumps(body),
                                     {'Authorization': 'Bearer ' + other_token, 'Content-Type': 'application/json', 'Idempotency-Key': secrets.token_hex(16)})
                        response = conn.getresponse(); response.read(); assert response.status == 404
                    finally:
                        conn.close()
                session_job(initial, ['sh', '-c', 'echo started > session-active; sleep 55'], timeout=60000)
                wait(lambda: session_exec(initial, ['test', '-e', 'session-active'])['output']['exit_code'] == 0, 'session guest active')
                began = time.perf_counter()
                def observe_old_stop():
                    wait(lambda: stopped(group(initial['current'])), 'old session VM host stop', seconds=15)
                    return round((time.perf_counter() - began) * 1000, 3)
                with ThreadPoolExecutor(max_workers=1) as observers:
                    stop_sample = observers.submit(observe_old_stop)
                    switch_key = secrets.token_hex(16)
                    switched = call('POST', session_path + '/switch', {'expected_revision': 1, 'create': session_req}, key=switch_key)
                    bind_ms = round((time.perf_counter() - began) * 1000, 3)
                    assert switched['revision'] == 2 and switched['previous'] == initial['current']
                    assert switched['current'] != initial['current']
                    assert session_exec(switched, ['test', '!', '-e', 'session-note'])['output']['exit_code'] == 0
                    assert session_exec(switched, ['true'])['output']['exit_code'] == 0
                    command_ms = round((time.perf_counter() - began) * 1000, 3)
                    stopped_ms = stop_sample.result(timeout=15)
                destroyed(initial['current'])
                reclaimed_ms = round((time.perf_counter() - began) * 1000, 3)
                assert call('POST', session_path + '/switch', {'expected_revision': 1, 'create': session_req}, key=switch_key)['current'] == switched['current']
                call('POST', session_path + '/exec', {'revision': 1, 'argv': ['true']}, expected=409)
                result['session_samples'] = {'cold_request_to_binding_response_ms': bind_ms,
                    'request_to_new_commands_completed_ms': command_ms, 'request_to_old_stopped_observed_ms': stopped_ms,
                    'request_to_old_durable_destroyed_observed_ms': reclaimed_ms, 'server_phase_observations': switched['timings']}
                result['checks'].append('real cold session switch: scoped capability, fresh workspace, stale-version rejection and separate old stop/reclaim observations')
                def competing_session_switch(key):
                    conn = UnixHTTP(sock)
                    try:
                        conn.request('POST', session_path + '/switch', json.dumps({'expected_revision': 2, 'create': session_req}),
                                     {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Idempotency-Key': key})
                        response = conn.getresponse(); return response.status, json.loads(response.read())
                    finally:
                        conn.close()
                with ThreadPoolExecutor(max_workers=2) as contenders:
                    outcomes = list(contenders.map(competing_session_switch, [secrets.token_hex(16), secrets.token_hex(16)]))
                assert sorted(status for status, _ in outcomes) == [200, 409]
                latest = next(value for status, value in outcomes if status == 200)
                assert latest['revision'] == 3
                public = call('GET', session_path)
                assert 'key_hash' not in json.dumps(public) and public['has_binding']
                result['checks'].append('real KVM concurrent session CAS publishes one next revision without duplicate preparation')
                session_job(latest, ['sh', '-c', 'echo started > session-crash; sleep 55'], timeout=60000)
                wait(lambda: session_exec(latest, ['test', '-e', 'session-crash'])['output']['exit_code'] == 0, 'session crash task started')
                pidfd = os.pidfd_open(process.pid)
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    process.wait(timeout=5); process = None
                finally:
                    os.close(pidfd)
                wait(lambda: stopped(group(latest['current'])), 'crashed session controller stopped VMM', seconds=5)
                process = start()
                recovered = call('GET', session_path)
                assert recovered['phase'] == 'CLOSED' and not recovered['has_binding']
                call('POST', session_path + '/exec', {'revision': 3, 'argv': ['true']}, expected=410)
                call('POST', '/v1/sessions', session_req, key=session_key, expected=410)
                destroyed(latest['current'])
                process.terminate(); assert process.wait(timeout=15) == 0; process = None
                assert not [p for p in cgroup.iterdir() if p.is_dir()]
                assert not list((runtime / 'j/firecracker').iterdir())
                result['checks'].append('actual session-controller SIGKILL restart retains binding tombstone and reclaims underlying VMM without session revival')
                session_report = report.with_name(report.stem + '-session.json')
                fixture = root / 'session-fixture.json'
                fixture.write_text(json.dumps({'state_dir': str(root / 'session-stall-state'), 'config_path': str(cfg),
                                               'report_path': str(session_report), 'source_revision': args.source_revision}))
                fixture.chmod(0o600)
                check = subprocess.run([str(copied['session_test']), '-test.run', '^TestKVMSessionCommitIOIsolation$', '-test.timeout', '120s', '-test.v'],
                    stdout=log, stderr=log, timeout=140, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                    'XANDBOX_KVM_SESSION_ACCEPTANCE': '1', 'XANDBOX_KVM_SESSION_FIXTURE': str(fixture)})
                assert check.returncode == 0, 'session commit-fsync KVM acceptance failed; inspect private log'
                session_result = json.loads(session_report.read_text())
                assert len(session_result['checks']) == 9 and session_result['source_revision'] == args.source_revision
                assert session_result['toolchain'] == 'go1.27.3' and session_result['production_ready'] is False
                result['session_acceptance_report'] = session_report.name
                result['checks'].append('separate real KVM blocked session binding fsync/Close/recovery acceptance passed')
            if args.queue_test:
                queue_report = report.with_name(report.stem + '-queue.json')
                fixture = root / 'queue-fixture.json'
                fixture.write_text(json.dumps({'state_dir': str(root / 'queue-state'), 'config_path': str(cfg),
                                               'report_path': str(queue_report), 'source_revision': args.source_revision}))
                fixture.chmod(0o600)
                check = subprocess.run([str(copied['queue_test']), '-test.run', '^TestKVMQueueIsolation$',
                                        '-test.timeout', '120s', '-test.v'], stdout=log, stderr=log, timeout=140,
                                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'XANDBOX_KVM_QUEUE_ACCEPTANCE': '1',
                                            'XANDBOX_KVM_QUEUE_FIXTURE': str(fixture)})
                assert check.returncode == 0, 'controlled-fsync KVM test failed; inspect private controller log'
                queue_result = json.loads(queue_report.read_text())
                assert queue_result['production_ready'] is False and queue_result['toolchain'] == 'go1.27.3'
                assert len(queue_result['checks']) == 9 and queue_result['source_revision'] == args.source_revision
                result['queue_acceptance_report'] = queue_report.name
                result['checks'].append('separate real KVM controlled-fsync queue/recovery acceptance passed')

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
