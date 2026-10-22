#!/usr/bin/env python3
"""Root-only real-KVM initialization fault acceptance, with exact child barriers.

Only a test binary wraps the existing durable-owner persistence seam and vsock
transport. The production driver/Initialize and recovery daemon are unmodified.
No seeds, nonce, identities, fixture paths or raw logs enter the public report.
"""
import argparse
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
import time

from kvm_driver_smoke import UnixHTTP, digest, wait
from kvm_snapshot_smoke import private_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('test-binary', 'daemon', 'admin', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd',
                 'export-dir', 'source-revision', 'report', 'log-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.uname().sysname != 'Linux' or os.uname().machine != 'x86_64':
        parser.error('requires dedicated root Linux amd64 KVM fixture')
    assert len(bytes.fromhex(args.source_revision)) == 20
    report, logs, export = (Path(v).resolve() for v in (args.report, args.log_dir, args.export_dir))
    assert not report.exists() and not logs.exists(), 'refusing report/log overwrite'
    logs.mkdir(mode=0o700, parents=True)
    inputs = {name: Path(getattr(args, name)).resolve() for name in
              ('daemon', 'admin', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd', 'test_binary')}
    manifest = json.loads((export / 'manifest.json').read_text())
    assert manifest['assignment'] == 'UNASSIGNED' and manifest['memory_mib'] == 512 and manifest['vcpus'] == 2
    suffix = secrets.token_hex(3)
    root = Path('/srv/i' + suffix)
    runtime, state, assets = root / 'r', root / 's', root / 'a'
    cgroup = Path('/sys/fs/cgroup/xandbox-initialization-proof-' + suffix)
    assert len(os.fsencode(runtime / 'j/firecracker' / ('0' * 64) / 'root/v.sock')) <= 107
    assert not root.exists() and not cgroup.exists()
    root.mkdir(mode=0o700)
    process = child = None
    result = {'test': 'experimental_real_kvm_initialization_faults', 'source_revision': args.source_revision,
              'harness_sha256': digest(__file__), 'production_ready': False,
              'validated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'architecture': os.uname().machine, 'host_kernel': os.uname().release,
              'guest_memory_mib': 512, 'vcpus': 2, 'workspace_bytes': 128 << 20,
              'artifacts_sha256': {name: digest(p) for name, p in inputs.items()},
              'builder_source_revision': manifest['source_revision'], 'cases': [],
              'fault_model': 'Test-only registry.persist wrapper completes the real file/directory fsync, then holds a pre-send barrier or renames the real Firecracker vsock listener and relays its framed traffic with selected ACK/epoch faults. No production fault flags, fake guest, host executor or new-seed retry.',
              'limitations': ['Finite same-host correctness cases, not production/SLO/load certification.',
                              'Post-sealed barrier withholds exact normal health before host READY, not a precise guest CLAIMED-to-marker or partial privileged initialization crash.',
                              'No full disk/power/dual-supervisor matrix or shared/private RAM accounting.',
                              'Private never-assigned builder export intentionally retained outside service runtime GC.']}
    controller_log = (logs / 'controller.log').open('ab', buffering=0)
    try:
        assets.mkdir(mode=0o700); state.mkdir(mode=0o700)
        copied = {}
        for name, source in inputs.items():
            target = assets / name
            shutil.copyfile(source, target); target.chmod(0o444 if name in ('kernel', 'initrd') else 0o555)
            assert digest(target) == result['artifacts_sha256'][name]
            copied[name] = target
        workspace = assets / 'workspace.ext4'
        shutil.copyfile(export / 'workspace.ext4', workspace); workspace.chmod(0o444)
        assert digest(workspace) == manifest['workspace_sha256']
        uid = 650000 + secrets.randbelow(30000)
        for value in range(uid, uid + 8):
            try: pwd.getpwuid(value)
            except KeyError: pass
            else: raise AssertionError('proof UID is assigned')
        cgroup.mkdir(mode=0o700)
        (cgroup / 'cgroup.subtree_control').write_text('+memory +pids +cpu')
        config = {'version': 2, 'runtime_root': str(runtime), 'cgroup_root': str(cgroup),
                  'uid_start': uid, 'uid_count': 8, 'reserved_uid_range': True,
                  'snapshot': {'version': 1, 'agent_sha256': manifest['agent_sha256'],
                               'memory_mib': 512, 'vcpus': 2, 'max_entries': 8, 'max_bytes': 4 << 30}}
        for name in ('warden', 'firecracker', 'jailer', 'kernel', 'initrd'):
            config[name] = {'path': str(copied[name]), 'sha256': digest(copied[name])}
            if name != 'warden': assert config[name]['sha256'] == manifest[name + '_sha256']
        config['workspace'] = {'path': str(workspace), 'sha256': digest(workspace)}
        cfg, auth = root / 'config.json', root / 'auth.json'
        token = secrets.token_hex(32)
        private_json(cfg, config)
        private_json(auth, {'version': 1, 'keys': [{'tenant_id': 'local', 'max_instances': 4,
                     'token_sha256': hashlib.sha256(token.encode()).hexdigest()}]})
        sock = state / 'api.sock'
        catalog = state / 'firecracker/catalog'
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}
        base = [str(copied['daemon']), '-backend', 'firecracker', '-state-dir', str(state),
                '-firecracker-config', str(cfg), '-auth-file', str(auth), '-max-instances', '4']

        def call(method, endpoint, body=None, expected=200, key=None):
            conn = UnixHTTP(sock)
            headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}
            if key: headers['Idempotency-Key'] = key
            try:
                conn.request(method, endpoint, None if body is None else json.dumps(body), headers)
                response = conn.getresponse(); raw = response.read()
                assert response.status in ((expected,) if isinstance(expected, int) else expected), (response.status, raw.decode())
                assert token.encode() not in raw
                return json.loads(raw)
            finally: conn.close()

        def start():
            proc = subprocess.Popen(base, env=env, stdout=controller_log, stderr=controller_log)
            def health():
                assert proc.poll() is None, 'controller exited; inspect private log'
                try:
                    value = call('GET', '/healthz')
                    assert value['isolation'] and not value['production_ready']
                    return True
                except (OSError, http.client.HTTPException): return False
            try: wait(health, 'ordinary recovery daemon ready', seconds=30)
            except BaseException:
                if proc.poll() is None: proc.kill()
                proc.wait(timeout=10); raise
            return proc

        def stop(proc):
            proc.terminate()
            assert proc.wait(timeout=20) == 0, 'ordinary controller shutdown failed'

        def admin(operation, *argv, manifest_path=None):
            command = [str(copied['admin']), '-state-dir', str(state), '-config', str(cfg)]
            if operation == 'publish':
                command += ['-manifest', str(manifest_path), '-memory', str(export / 'memory'), '-snapshot-state', str(export / 'state')]
            p = subprocess.run(command + [operation, *argv], env=env, capture_output=True, timeout=150)
            with (logs / 'admin.log').open('ab') as out: out.write(p.stdout + p.stderr)
            assert p.returncode == 0, 'admin failed; inspect private log'
            return json.loads(p.stdout)

        def item(template): return next(i for i in admin('status')['items'] if i['id'] == template)
        def key(ref): return ref['id'] + ref['generation']
        def group(ref): return cgroup / key(ref)
        def jail(ref): return runtime / 'j/firecracker' / key(ref)
        def owner(ref): return state / 'firecracker' / (key(ref) + '.json')
        def empty(g): return not g.exists() or 'populated 0' in (g / 'cgroup.events').read_text()
        def ledger(ref): return json.loads((state / 'ledger' / (ref['id'] + '.json')).read_text())['record']
        def prove_vm(ref):
            assert not empty(group(ref))
            found = False
            for pid in (group(ref) / 'cgroup.procs').read_text().split():
                for fd in Path('/proc', pid, 'fd').iterdir():
                    try: found |= 'kvm-vm' in os.readlink(fd)
                    except FileNotFoundError: pass
            assert found, 'no actual owned KVM fd at crash barrier'

        request = {'ttl_ms': 120000, 'limits': {'max_exec_ms': 5000, 'max_output_bytes': 16384, 'max_jobs': 64}}
        process = start(); stop(process); process = None  # Establish immutable binding only.
        modes = ('before_initialize', 'after_sealed_before_ready', 'drop_claim_ack', 'drop_health_ack', 'wrong_health_epoch')
        for mode in modes:
            declaration = dict(manifest)
            declaration['created_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            manifest_path = assets / (mode + '-manifest.json'); private_json(manifest_path, declaration)
            template = admin('publish', manifest_path=manifest_path)['template_id']; admin('activate', template)
            ref_path, barrier, child_result = (logs / (mode + suffix) for suffix in ('.ref.json', '.barrier.json', '.result.json'))
            create_key = secrets.token_hex(16)
            fixture = logs / (mode + '.fixture.json')
            private_json(fixture, {'StateDir': str(state), 'ConfigPath': str(cfg), 'RefPath': str(ref_path),
                         'BarrierPath': str(barrier), 'ResultPath': str(child_result), 'SourceRevision': args.source_revision,
                         'Mode': mode, 'CreateKey': create_key})
            child_env = dict(env, XANDBOX_KVM_INITIALIZATION='1', XANDBOX_KVM_INITIALIZATION_FIXTURE=str(fixture))
            with (logs / (mode + '.log')).open('xb', buffering=0) as log:
                child = subprocess.Popen([str(copied['test_binary']), '-test.run', '^TestKVMInitializationFault$', '-test.v', '-test.timeout', '50s'],
                                         env=child_env, stdout=log, stderr=log)
                if mode in modes[:2]:
                    def reached():
                        assert child.poll() is None, 'fault child exited before crash barrier; inspect private log'
                        return json.loads(barrier.read_text()) if barrier.exists() else None
                    reached_barrier = wait(reached, 'exact initialization crash barrier', seconds=30)
                    ref = reached_barrier['ref']; assert reached_barrier['phase'] == mode
                    assert reached_barrier['guest_waiting_confirmed' if mode == 'before_initialize' else 'guest_sealed_confirmed']
                    assert ledger(ref)['state'] == 'CREATING' and not child_result.exists()
                    owned = json.loads(owner(ref).read_text())
                    assert owned['initialization_attempted'] and owned['template_id'] == template
                    prove_vm(ref)
                    began = time.perf_counter()
                    child.kill(); assert child.wait(timeout=10) == -9; child = None
                    wait(lambda: empty(group(ref)), 'guardian stops crash candidate', seconds=10)
                    stopped_ms = round((time.perf_counter() - began) * 1000, 3)
                    admin('retire', template)
                    assert item(template)['pins'] == 1 and item(template)['phase'] == 'RETIRING'
                    admin('gc'); assert (catalog / 'objects' / template / 'memory').exists()
                    case = {'mode': mode, 'actual_kvm_and_creating_ledger_at_barrier': True,
                            'durable_initialization_attempt': True, 'child_sigkill_exit_status': -9,
                            'controller_sigkill_to_empty_cgroup_observed_ms': stopped_ms,
                            'offline_retiring_template_pin_reconstructed': True}
                else:
                    assert child.wait(timeout=45) == 0, 'fault child acceptance failed; inspect private log'
                    child = None
                    child_report = json.loads(child_result.read_text())
                    assert child_report['passed'] and child_report['mode'] == mode
                    assert child_report['initialize_requests'] == 1 and child_report['actual_sealed_health_replies_observed'] >= 1
                    assert child_report['create_returned_ready'] == (mode == 'drop_claim_ack')
                    ref = json.loads(ref_path.read_text())['ref']
                    assert ledger(ref)['state'] == 'DESTROYED'
                    assert not group(ref).exists() and not jail(ref).exists() and not owner(ref).exists()
                    assert item(template)['pins'] == 0
                    admin('retire', template)
                    case = dict(child_report)
                process = start()
                wait(lambda: call('GET', '/v1/sandboxes/' + ref['id'])['state'] == 'DESTROYED', 'ordinary daemon durable recovery', seconds=30)
                assert not group(ref).exists() and not jail(ref).exists() and not owner(ref).exists()
                call('POST', '/v1/sandboxes/' + ref['id'] + '/exec', {'generation': ref['generation'], 'argv': ['true']}, expected=(409, 410))
                call('POST', '/v1/sandboxes', request, key=create_key, expected=410)
                assert item(template)['pins'] == 0
                admin('gc'); assert item(template)['phase'] == 'RETIRED' and not (catalog / 'objects' / template).exists()
                stop(process); process = None
                case.update({'ordinary_daemon_recovery_closes_old_generation': True,
                             'same_creation_key_rejected_without_reinitialize': True,
                             'pin_released_only_after_private_cleanup': True, 'retired_source_removed': True, 'passed': True})
                result['cases'].append(case)
        final = admin('status')
        assert len(final['items']) == len(modes) and all(i['phase'] == 'RETIRED' and i['pins'] == 0 for i in final['items'])
        assert not any(g.is_dir() for g in cgroup.iterdir())
        result['passed'] = True
    finally:
        if child is not None and child.poll() is None: child.kill(); child.wait(timeout=10)
        if process is not None and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=20)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
        controller_log.close()
        safe = True
        if cgroup.exists():
            for g in cgroup.iterdir():
                if not g.is_dir(): continue
                try:
                    (g / 'cgroup.kill').write_text('1')
                    wait(lambda: empty(g), 'owned fault cleanup', seconds=10); g.rmdir()
                except (OSError, AssertionError): safe = False
            if safe:
                try: cgroup.rmdir()
                except OSError: safe = False
        if safe:
            for directory, _, _ in os.walk(root): os.chmod(directory, 0o700)
            shutil.rmtree(root)
        result['cleanup_confirmed'] = safe and not root.exists() and not cgroup.exists()
        if not result['cleanup_confirmed']: result['passed'] = False
        private_json(report, result)
    assert result.get('passed') and result['cleanup_confirmed'], 'fault acceptance failed; inspect private logs'
    print(json.dumps({'passed': True, 'cases': len(result['cases']), 'cleanup_confirmed': True}))


if __name__ == '__main__':
    main()
