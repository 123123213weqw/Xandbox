#!/usr/bin/env python3
"""Finite real ext4 ENOSPC or ledger EROFS + KVM recovery, not media attestation.

Re-execs in a private mount namespace. Only the exclusive 64MiB loop image is
filled. Runtime/guest images and private diagnostics stay OUTSIDE that volume.
"""
import argparse
import datetime
import hashlib
import http.client
import itertools
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
import sys
import time
import traceback

from kvm_driver_smoke import UnixHTTP, digest, wait
from kvm_resources import cgroup_empty, REF_NAME
from kvm_snapshot_smoke import private_json
from kvm_storage import BoundedExt4, VOLUME_BYTES, require_private_namespace


def validate_host_stop_guard(value):
    if value != 0 and not 100 <= value <= 4000:
        raise ValueError('guard must be0(disabled) or100..4000ms')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('daemon', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd', 'workspace',
                 'source-revision', 'report', 'log-dir'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--parent-mntns', help=argparse.SUPPRESS)
    parser.add_argument('--fault-suite', choices=('enospc', 'ledger-readonly'), default='enospc',
                        help='ENOSPC affects all state; read-only affects only a separately mounted ledger')
    parser.add_argument('--max-host-stop-ms', type=float, default=0,
                        help='optional finite experimental observation guard, 100..4000ms; NOT a production SLO')
    args = parser.parse_args()
    try:
        validate_host_stop_guard(args.max_host_stop_ms)
    except ValueError as error:
        parser.error(str(error))
    os.umask(0o077)
    if os.geteuid() != 0 or os.uname().sysname != 'Linux' or os.uname().machine != 'x86_64':
        parser.error('requires root Linux amd64 KVM')
    assert len(bytes.fromhex(args.source_revision)) == 20
    if args.parent_mntns is None:
        child = subprocess.run(['unshare', '--mount', '--propagation', 'private', '--', sys.executable,
                                str(Path(__file__).resolve()), *sys.argv[1:], '--parent-mntns',
                                os.readlink('/proc/self/ns/mnt')])
        raise SystemExit(child.returncode)
    require_private_namespace(args.parent_mntns)
    report, logs = Path(args.report).resolve(), Path(args.log_dir).resolve()
    assert not report.exists() and not logs.exists()
    logs.mkdir(mode=0o700, parents=True)
    inputs = {n: Path(getattr(args, n)).resolve() for n in
              ('daemon', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd', 'workspace')}
    suffix = secrets.token_hex(3)
    root = Path('/srv/x' + suffix)
    cgroup = Path('/sys/fs/cgroup/xandbox-storage-proof-' + suffix)
    assert not root.exists() and not cgroup.exists()
    assert os.statvfs('/srv').f_bavail * os.statvfs('/srv').f_frsize > 512 << 20
    root.mkdir(mode=0o700)
    runtime, assets = root / 'r', root / 'a'
    assets.mkdir(mode=0o700)
    readonly = args.fault_suite == 'ledger-readonly'
    if readonly:
        state = root / 's'
        state.mkdir(mode=0o700)
        volume = BoundedExt4(state, mount_name='ledger')
    else:
        volume = BoundedExt4(root)
        state = volume.mount / 's'
    process = None
    result = {'test': 'bounded_ext4_ledger_erofs_real_kvm_recovery' if readonly else 'bounded_ext4_enospc_real_kvm_recovery',
              'fault_suite': args.fault_suite, 'fault_scope': 'ledger_only' if readonly else 'entire_state_directory',
              'passed': False, 'production_ready': False,
              'source_revision': args.source_revision, 'validated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'host_kernel': os.uname().release, 'architecture': os.uname().machine,
              'harness_sha256': digest(__file__), 'helper_sha256': {n: digest(Path(__file__).with_name(n)) for n in
                  ('kvm_storage.py', 'kvm_driver_smoke.py', 'kvm_resources.py', 'kvm_snapshot_smoke.py')},
              'artifacts_sha256': {n: digest(p) for n, p in inputs.items()},
              'fault_image_bytes': VOLUME_BYTES, 'configured_node_instance_capacity': 1, 'configured_tenant_instance_quota': 1, 'guest_memory_mib': 512, 'vcpus': 2, 'workspace_bytes': 128 << 20,
              'experimental_host_stop_guard_ms': args.max_host_stop_ms,
              'guest_network_interfaces': 0, 'modes': [], 'checks': [], 'limitations': [
                  '64MiB dedicated loop ext4 in private mount namespace; no shared host filesystem filled/remounted.',
                  'Cold schema1 runtime stays on healthy host ext4; not snapshot cross-filesystem behavior.',
                  'Returned ENOSPC or explicit ledger-only read-only remount/EROFS, not media EIO, automatic error-triggered remount, power loss, journal corruption, project quota or secure erase.',
                  'Stop observation includes existing independent guardian lease; no production latency/SLO claim.',
                  'No whole-host restart, dual-supervisor failure, long-term metadata retention or independent operator acceptance.']}
    log = (logs / 'controller.log').open('xb', buffering=0)
    try:
        # Keep an early recovery identity OUTSIDE the fault volume. It is
        # private diagnostics and must never be copied to a public report.
        private_json(logs / 'resource-receipt.json', {'version': 1, 'source_revision': args.source_revision,
            'root': str(root), 'runtime': str(runtime), 'cgroup': str(cgroup),
            'fault_image': str(volume.image), 'mountpoint': str(volume.mount),
            'parent_mount_namespace': args.parent_mntns, 'mount_namespace': os.readlink('/proc/self/ns/mnt')})
        copied = {}
        for name, source in inputs.items():
            target = assets / name
            shutil.copyfile(source, target)
            target.chmod(0o444 if name in ('kernel', 'initrd', 'workspace') else 0o555)
            assert digest(target) == result['artifacts_sha256'][name]
            copied[name] = target
        assert copied['workspace'].stat().st_size == 128 << 20
        volume.create()
        result['private_mount_and_exact_autoclear_loop_binding_verified'] = True
        if not readonly:
            state.mkdir(mode=0o700)
        cgroup.mkdir(mode=0o700)
        (cgroup / 'cgroup.subtree_control').write_text('+memory +pids +cpu')
        uid = 700000 + secrets.randbelow(30000)
        for number in range(uid, uid + 4):
            try:
                pwd.getpwuid(number)
            except KeyError:
                pass
            else:
                raise AssertionError('fixture UID assigned')
        config = {'version': 1, 'runtime_root': str(runtime), 'cgroup_root': str(cgroup),
                  'uid_start': uid, 'uid_count': 4, 'reserved_uid_range': True}
        for name in ('warden', 'firecracker', 'jailer', 'kernel', 'initrd', 'workspace'):
            config[name] = {'path': str(copied[name]), 'sha256': digest(copied[name])}
        cfg, auth = root / 'config.json', root / 'auth.json'
        private_json(cfg, config)
        token = secrets.token_hex(32)
        private_json(auth, {'version': 1, 'keys': [{'tenant_id': 'storage-fixture', 'max_instances': 1,
                     'token_sha256': hashlib.sha256(token.encode()).hexdigest()}]})
        base = [str(copied['daemon']), '-backend', 'firecracker', '-state-dir', str(state),
                '-auth-file', str(auth), '-firecracker-config', str(cfg), '-max-instances', '1', '-metrics']
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}

        def call(method, endpoint, body=None, expected=200, key=None, with_status=False):
            conn = UnixHTTP(state / 'api.sock')
            headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}
            if key: headers['Idempotency-Key'] = key
            try:
                conn.request(method, endpoint, None if body is None else json.dumps(body), headers)
                response = conn.getresponse(); raw = response.read()
                assert response.status in ((expected,) if isinstance(expected, int) else expected), (response.status, raw.decode())
                assert token.encode() not in raw and str(root).encode() not in raw
                value = json.loads(raw)
                return (response.status, value) if with_status else value
            finally:
                conn.close()

        def start():
            proc = subprocess.Popen(base, env=env, stdout=log, stderr=log)
            def healthy():
                assert proc.poll() is None, 'controller exited; inspect private log'
                try:
                    value = call('GET', '/healthz')
                    assert value['isolation'] and value['backend'] == 'firecracker' and not value['production_ready']
                    return True
                except (OSError, http.client.HTTPException):
                    return False
            try:
                wait(healthy, 'storage fixture controller', seconds=30)
            except BaseException:
                if proc.poll() is None: proc.kill()
                proc.wait(timeout=10)
                raise
            return proc

        def path(ref): return '/v1/sandboxes/' + ref['id']
        def name(ref): return ref['id'] + ref['generation']
        def group(ref): return cgroup / name(ref)
        def owner(ref): return state / 'firecracker' / (name(ref) + '.json')
        def jail(ref): return runtime / 'j/firecracker' / name(ref)
        request = {'ttl_ms': 300000, 'limits': {'max_exec_ms': 60000, 'max_output_bytes': 8192}}

        def allocated():
            conn = UnixHTTP(state / 'metrics.sock')
            try:
                conn.request('GET', '/metrics')
                response = conn.getresponse(); raw = response.read(65537)
                assert response.status == 200 and len(raw) <= 65536
                assert token.encode() not in raw and str(root).encode() not in raw
                values = [line.split()[1] for line in raw.decode().splitlines() if line.startswith('xandbox_allocated ')]
                assert len(values) == 1 and values[0].isdigit()
                return int(values[0])
            finally:
                conn.close()

        def create(key):
            ref = call('POST', '/v1/sandboxes', request, expected=201, key=key)
            assert ref['state'] == 'READY'
            pids = (group(ref) / 'cgroup.procs').read_text().split()
            assert any('kvm-vm' in os.readlink(fd) for pid in pids for fd in Path('/proc', pid, 'fd').iterdir() if fd.exists())
            return ref

        def job(ref, argv, timeout=10000):
            return call('POST', path(ref) + '/exec', {'generation': ref['generation'], 'argv': argv,
                        'timeout_ms': timeout}, expected=202)

        def finish(ref, accepted, seconds=20):
            return wait(lambda: (v if (v := call('GET', path(ref) + '/executions/' + accepted['id']))['status'] != 'RUNNING' else None),
                        'storage fixture guest job', seconds=seconds)

        def execute(ref, argv):
            done = finish(ref, job(ref, argv))
            assert done['status'] == 'EXITED' and done['output']['exit_code'] == 0
            return done['output']

        def destroyed(ref):
            wait(lambda: call('GET', path(ref))['state'] == 'DESTROYED', 'storage durable destroy', seconds=30)
            assert not group(ref).exists() and not jail(ref).exists() and not owner(ref).exists()
            wait(lambda: allocated() == 0, 'storage allocation release after durable destroy')

        def remove(ref):
            call('DELETE', path(ref), {'generation': ref['generation']}, expected=202)
            destroyed(ref)

        process = start()
        first = create(secrets.token_hex(16))
        assert execute(first, ['id', '-u'])['stdout'].strip() == '65534'
        full = finish(first, job(first, ['sh', '-c',
            'dd if=/dev/zero of=guest-full bs=1048576 count=256; code=$?; wc -c < guest-full; exit "$code"'], timeout=60000), seconds=70)
        assert full['status'] == 'EXITED' and full['output']['exit_code'] != 0
        assert 'No space left on device' in full['output']['stderr']
        written = int(full['output']['stdout'].strip())
        assert 64 << 20 <= written < 128 << 20
        assert (jail(first) / 'root/workspace.ext4').stat().st_size == 128 << 20
        execute(first, ['rm', 'guest-full']); execute(first, ['true']); remove(first)
        result['guest_workspace_full'] = {'observed_enospc': True, 'written_bytes': written,
                                         'host_image_size_unchanged': True, 'exec_after_freeing_space_passed': True}
        result['checks'].append('unprivileged real guest reaches workspace ENOSPC without growing host image; freeing guest file restores execution and clean deletion')

        for mode, workload in itertools.product(('readonly',) if readonly else ('blocks', 'inodes'), ('busy', 'idle')):
            case = {'mode': mode, 'workload': workload, 'passed': False}; result['modes'].append(case)
            key = secrets.token_hex(16)
            ref = create(key)
            execute(ref, ['true'])
            busy = None
            if workload == 'busy':
                busy = job(ref, ['sh', '-c', 'sleep 120 & sleep 120 & echo ready > storage-busy-ready; wait'], timeout=60000)
                assert execute(ref, ['sh', '-c', 'while [ ! -f storage-busy-ready ]; do sleep 0.01; done; cat storage-busy-ready'])['stdout'].strip() == 'ready'
                assert call('GET', path(ref) + '/executions/' + busy['id'])['status'] == 'RUNNING'
            else:
                # The only preceding job completed. Do not let Exec's ambiguous
                # cancellation fence conceal the independent idle-VM stop path.
                case['no_pending_guest_execution'] = True
            ledger = state / 'ledger' / (ref['id'] + '.json')
            before = ledger.read_bytes()
            case['fault'] = volume.fill(mode)
            assert not cgroup_empty(group(ref)) and call('GET', path(ref))['state'] == 'READY'
            if busy is not None:
                assert call('GET', path(ref) + '/executions/' + busy['id'])['status'] == 'RUNNING'
            case['ready_and_host_populated_at_fault_start'] = True
            began = time.perf_counter()
            call('DELETE', path(ref), {'generation': ref['generation']}, expected=500)
            case['request_to_failed_durable_delete_ms'] = round((time.perf_counter() - began) * 1000, 3)
            call('POST', path(ref) + '/exec', {'generation': ref['generation'], 'argv': ['true']}, expected=409)
            wait(lambda: cgroup_empty(group(ref)), 'host stop despite storage fault', seconds=15)
            case['request_to_host_cgroup_empty_observed_ms'] = round((time.perf_counter() - began) * 1000, 3)
            if args.max_host_stop_ms:
                assert case['request_to_host_cgroup_empty_observed_ms'] <= args.max_host_stop_ms, 'experimental physical-stop observation guard exceeded'
            if busy is not None:
                terminal = finish(ref, busy)
                case['accepted_guest_job_terminal_status'] = terminal['status']
            assert ledger.read_bytes() == before and owner(ref).exists() and jail(ref).exists()
            assert call('GET', path(ref))['state'] != 'DESTROYED'
            # The node-capacity check precedes the tenant quota in this fixture
            # (both limits are one). Assert node503 AND retained allocation.
            denied, _ = call('POST', '/v1/sandboxes', request, expected=503,
                             key=secrets.token_hex(16), with_status=True)
            assert allocated() == 1
            case['create_while_recovery_incomplete_status'] = denied
            case['allocated_while_recovery_incomplete'] = 1
            case['no_false_durable_ack_or_capacity_release'] = True
            process.kill(); process.wait(timeout=10); process = None
            failed = subprocess.run(base, env=env, capture_output=True, timeout=15)
            (logs / (mode + '-' + workload + '-full-restart.log')).write_bytes(failed.stdout + failed.stderr)
            expected_error = b'read-only file system' if readonly else b'no space left on device'
            assert failed.returncode != 0 and expected_error in failed.stderr.lower()
            case['restart_while_readonly_refused_with_erofs' if readonly else 'restart_while_full_refused_with_enospc'] = True
            assert owner(ref).exists() and jail(ref).exists() and cgroup_empty(group(ref))
            volume.release()
            process = start(); destroyed(ref)
            call('POST', '/v1/sandboxes', request, expected=410, key=key)
            fresh = create(secrets.token_hex(16)); assert fresh != ref
            execute(fresh, ['true']); remove(fresh)
            case['same_state_restart_reclaims_old_and_rejects_old_key'] = True
            case['fresh_real_vm_create_exec_destroy_after_recovery'] = True
            case['passed'] = True
            result['checks'].append(mode + '/' + workload + ' ' + ('ledger EROFS' if readonly else 'ENOSPC') +
                ' refuses durable acknowledgement/admission and capacity reuse, independently stops host, refuses still-faulted restart, then reclaims on same-state recovery')
        assert not list((state / 'firecracker').glob('[0-9a-f]' * 64 + '.json'))
        assert not [p for p in cgroup.iterdir() if p.is_dir()]
        result['passed'] = True
    finally:
        safe = True
        try:
            volume.release()
        except BaseException:
            traceback.print_exc()  # Private diagnostics; never project raw paths/errors into public JSON.
            safe = False
        if process is not None and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=10)
        log.close()
        if cgroup.exists():
            for child in cgroup.iterdir():
                if not child.is_dir(): continue
                if not REF_NAME.fullmatch(child.name):
                    safe = False; continue
                try:
                    (child / 'cgroup.kill').write_text('1')
                    wait(lambda: cgroup_empty(child), 'owned storage fixture cleanup', seconds=15)
                    child.rmdir()
                except (OSError, AssertionError):
                    safe = False
            if safe:
                try: cgroup.rmdir()
                except OSError: safe = False
        try:
            volume.close()
            result['own_mount_removed_and_loop_binding_released'] = True
        except BaseException:
            traceback.print_exc()
            safe = False
        if safe: shutil.rmtree(root)
        result['cleanup_confirmed'] = safe and not root.exists() and not cgroup.exists()
        if not result['cleanup_confirmed']: result['passed'] = False
        private_json(report, result)
    assert result['passed'] and result['cleanup_confirmed'], 'storage acceptance failed; inspect private diagnostics'
    print(json.dumps({'passed': True, 'cases': len(result['checks']), 'cleanup_confirmed': True}))


if __name__ == '__main__':
    main()
