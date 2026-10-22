#!/usr/bin/env python3
"""Finite root-only, same-host KVM acceptance of the experimental snapshot service.

Consumes only an operator-built UNASSIGNED export. Never executes tenant commands
on the host, adopts existing resources, or publishes raw runtime identities/logs.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import fcntl
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


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_json(path, value):
    with path.open('x') as out:
        os.chmod(path, 0o600)
        json.dump(value, out)
        out.flush()
        os.fsync(out.fileno())
    sync_dir(path.parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('daemon', 'admin', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd',
                 'export-dir', 'source-revision', 'report', 'log-dir'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--mixed-cycles', type=int, default=0, help='optional 1..256 fresh-VM switches PER tenant, two workers')
    parser.add_argument('--mixed-min-seconds', type=float, default=0, help='0..240 seconds of explicit closed-loop pacing')
    args = parser.parse_args()
    if (args.mixed_cycles != 0 and not 1 <= args.mixed_cycles <= 256) or not 0 <= args.mixed_min_seconds <= 240:
        parser.error('mixed cycles must be0..256; pacing0..240 seconds')
    if args.mixed_min_seconds and not args.mixed_cycles:
        parser.error('--mixed-min-seconds requires --mixed-cycles')
    os.umask(0o077)  # Explicitly exercise production-private creation policy, including child CLIs.
    if os.geteuid() != 0 or os.uname().sysname != 'Linux' or os.uname().machine != 'x86_64':
        parser.error('requires root Linux amd64 on the same isolated KVM builder node')
    assert len(bytes.fromhex(args.source_revision)) == 20
    report, logs, export = (Path(v).resolve() for v in (args.report, args.log_dir, args.export_dir))
    assert not report.exists() and not logs.exists(), 'refuse report/log overwrite'
    logs.mkdir(mode=0o700, parents=True)
    sources = {n: Path(getattr(args, n)).resolve() for n in
               ('daemon', 'admin', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd')}
    manifest = json.loads((export / 'manifest.json').read_text())
    assert manifest['assignment'] == 'UNASSIGNED' and manifest['memory_mib'] == 512 and manifest['vcpus'] == 2
    nonce = secrets.token_hex(3)
    root = Path('/srv/x' + nonce)
    cgroup = Path('/sys/fs/cgroup/xandbox-snapshot-service-proof-' + nonce)
    assert len(os.fsencode(root / 'r/j/firecracker' / ('0' * 64) / 'root/api.sock')) <= 107
    assert not root.exists() and not cgroup.exists()
    root.mkdir(mode=0o700)
    runtime, state, assets = root / 'r', root / 's', root / 'a'
    assets.mkdir(mode=0o700); state.mkdir(mode=0o700)
    result = {'test': 'experimental_snapshot_catalog_service', 'production_ready': False,
              'source_revision': args.source_revision, 'harness_sha256': digest(__file__),
              'builder_source_revision': manifest['source_revision'],
              'validated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'host_kernel': os.uname().release, 'architecture': os.uname().machine,
              'guest_memory_mib': 512, 'vcpus': 2, 'workspace_bytes': 128 << 20,
              'guest_network_interfaces': 0, 'template_memory_sha256': manifest['memory_sha256'],
              'template_state_sha256': manifest['state_sha256'], 'workspace_template_sha256': manifest['workspace_sha256'],
              'artifacts_sha256': {k: digest(v) for k, v in sources.items()},
              'checks': [], 'samples': {},
              'limitations': ['Finite same-host correctness probe, not sustained load, fairness, percentiles or SLO.',
                              'Shared catalog page cache and per-VM private RAM are not fully accounted here.',
                              'Publisher validates trusted builder declarations, not opaque-memory attestation.',
                              'No disk-failure or every-initialization-window crash matrix.']}
    process = None
    log = (logs / 'controller.log').open('ab', buffering=0)
    restored_owner = None
    try:
        copied = {}
        for name, source in sources.items():
            target = assets / name
            shutil.copyfile(source, target)
            target.chmod(0o444 if name in ('kernel', 'initrd') else 0o555)
            assert digest(target) == result['artifacts_sha256'][name]
            copied[name] = target
        workspace = assets / 'workspace.ext4'
        shutil.copyfile(export / 'workspace.ext4', workspace); workspace.chmod(0o444)
        assert digest(workspace) == manifest['workspace_sha256']
        uid = 600000 + secrets.randbelow(30000)
        for number in range(uid, uid + 16):
            try:
                pwd.getpwuid(number)
            except KeyError:
                pass
            else:
                raise AssertionError('proof UID assigned')
        cgroup.mkdir(mode=0o700)
        (cgroup / 'cgroup.subtree_control').write_text('+memory +pids +cpu')
        config = {'version': 2, 'runtime_root': str(runtime), 'cgroup_root': str(cgroup),
                  'uid_start': uid, 'uid_count': 16, 'reserved_uid_range': True,
                  'snapshot': {'version': 1, 'agent_sha256': manifest['agent_sha256'],
                               'memory_mib': 512, 'vcpus': 2, 'max_entries': 8, 'max_bytes': 4 << 30}}
        for name in ('warden', 'firecracker', 'jailer', 'kernel', 'initrd'):
            config[name] = {'path': str(copied[name]), 'sha256': digest(copied[name])}
            if name != 'warden':
                assert config[name]['sha256'] == manifest[name + '_sha256']
        config['workspace'] = {'path': str(workspace), 'sha256': digest(workspace)}
        cfg, auth = root / 'config.json', root / 'auth.json'
        private_json(cfg, config)
        tokens = {name: secrets.token_hex(32) for name in ('alpha', 'beta')}
        private_json(auth, {'version': 1, 'keys': [{'tenant_id': n, 'max_instances': 3 if args.mixed_cycles else 8,
                     'token_sha256': hashlib.sha256(t.encode()).hexdigest()} for n, t in tokens.items()]})
        sock = state / 'api.sock'
        catalog = state / 'firecracker/catalog'
        base = [str(copied['daemon']), '-backend', 'firecracker', '-state-dir', str(state),
                '-firecracker-config', str(cfg), '-auth-file', str(auth), '-max-instances', '8']
        if args.mixed_cycles:
            # Keep quota and metadata policy explicit; never raise session history.
            base += ['-metrics', '-max-records', '2048', '-max-tenant-records', '1024',
                     '-max-sessions', '32', '-max-tenant-sessions', '16']
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}

        def call(method, endpoint, body=None, expected=200, tenant='alpha', key=None):
            headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + tokens[tenant]}
            if key:
                headers['Idempotency-Key'] = key
            conn = UnixHTTP(sock)
            try:
                conn.request(method, endpoint, None if body is None else json.dumps(body), headers)
                response = conn.getresponse(); raw = response.read()
                assert response.status in ((expected,) if isinstance(expected, int) else expected), (response.status, raw.decode())
                assert all(t.encode() not in raw for t in tokens.values())
                return json.loads(raw)
            finally:
                conn.close()

        def start():
            proc = subprocess.Popen(base, env=env, stdout=log, stderr=log)
            def health():
                assert proc.poll() is None, 'controller exited; inspect private log'
                try:
                    v = call('GET', '/healthz')
                    assert v['isolation'] and v['backend'] == 'firecracker' and not v['production_ready']
                    return True
                except (OSError, http.client.HTTPException):
                    return False
            try:
                wait(health, 'controller ready', seconds=30)
            except BaseException:
                if proc.poll() is None: proc.kill()
                proc.wait(timeout=10)
                raise
            return proc

        def admin(operation, *args, ok=True, manifest_path=None):
            command = [str(copied['admin']), '-state-dir', str(state), '-config', str(cfg)]
            if operation == 'publish':
                command += ['-manifest', str(manifest_path or export / 'manifest.json'),
                            '-memory', str(export / 'memory'), '-snapshot-state', str(export / 'state')]
            p = subprocess.run(command + [operation, *args], env=env, capture_output=True, timeout=150)
            with (logs / 'admin.log').open('ab') as out:
                out.write(p.stdout + p.stderr)
            assert (p.returncode == 0) == ok, 'admin outcome mismatch; inspect private log'
            return json.loads(p.stdout) if ok else None

        def status_item(template):
            return next(i for i in admin('status')['items'] if i['id'] == template)

        def path(ref): return '/v1/sandboxes/' + ref['id']
        def name(ref): return ref['id'] + ref['generation']
        def group(ref): return cgroup / name(ref)
        def empty(g):
            try:
                return 'populated 0' in (g / 'cgroup.events').read_text()
            except FileNotFoundError:
                return not g.exists()
        def owner_path(ref): return state / 'firecracker' / (name(ref) + '.json')
        def jail(ref): return runtime / 'j/firecracker' / name(ref) / 'root'
        request = {'ttl_ms': 300000, 'limits': {'max_exec_ms': 60000, 'max_output_bytes': 16384, 'max_jobs': 128}}

        def create(tenant='alpha', expected=201):
            before = time.perf_counter()
            r = call('POST', '/v1/sandboxes', request, expected=expected, tenant=tenant, key=secrets.token_hex(16))
            if expected == 201:
                assert r['state'] == 'READY'
                result['samples'].setdefault('create_api_ready_ms', []).append(round((time.perf_counter() - before) * 1000, 3))
            return r

        def finish(ref, job, tenant='alpha'):
            j = wait(lambda: (v if (v := call('GET', path(ref) + '/executions/' + job['id'], tenant=tenant))['status'] != 'RUNNING' else None), 'guest job')
            assert j['status'] == 'EXITED' and j['output']['exit_code'] == 0, 'guest command failed'
            return j['output']

        def execute(ref, argv, tenant='alpha'):
            j = call('POST', path(ref) + '/exec', {'generation': ref['generation'], 'argv': argv, 'timeout_ms': 5000}, expected=202, tenant=tenant)
            return finish(ref, j, tenant)

        def destroyed(ref, tenant='alpha'):
            wait(lambda: call('GET', path(ref), tenant=tenant)['state'] == 'DESTROYED', 'durable destroy', seconds=30)
            assert not group(ref).exists() and not jail(ref).parent.exists() and not owner_path(ref).exists()

        def remove(ref, tenant='alpha'):
            call('DELETE', path(ref), {'generation': ref['generation']}, expected=202, tenant=tenant)
            destroyed(ref, tenant)

        def check_kvm(ref, template):
            pids = (group(ref) / 'cgroup.procs').read_text().split()
            assert any('kvm-vm' in os.readlink(fd) for pid in pids for fd in Path('/proc', pid, 'fd').iterdir()
                       if fd.exists()), 'no actual VM fd in owned cgroup'
            for source, local in (('memory', 'template.mem'), ('state', 'template.state')):
                a, b = (catalog / 'objects' / template / source).stat(), (jail(ref) / local).stat()
                assert (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) and a.st_mode & 0o222 == 0 and a.st_uid == 0
            owner = json.loads(owner_path(ref).read_text())
            assert owner['version'] == 2 and owner['initialization_attempted'] and owner['template_id'] == template

        process = start()
        create(expected=(500, 503))
        assert not any(g.is_dir() for g in cgroup.iterdir())
        assert not list((state / 'firecracker').glob('[0-9a-f]' * 64 + '.json'))
        result['checks'].append('empty schema2 catalog refuses Create without cold or host fallback and leaves no owner')
        template = admin('publish')['template_id']; admin('activate', template)
        if args.mixed_cycles:
            from kvm_mixed_load import run_mixed
            def metrics():
                conn = UnixHTTP(state / 'metrics.sock')
                try:
                    conn.request('GET', '/metrics')
                    response = conn.getresponse(); raw = response.read(65537)
                    assert response.status == 200 and len(raw) <= 65536
                    assert all(token.encode() not in raw for token in tokens.values())
                    return raw.decode()
                finally:
                    conn.close()
            result['mixed_load'] = {}
            result['mixed_harness_sha256'] = {p: digest(Path(__file__).with_name(p))
                                            for p in ('kvm_mixed_load.py', 'kvm_resources.py')}
            run_mixed(cycles=args.mixed_cycles, min_seconds=args.mixed_min_seconds,
                      call=call, finish=finish, destroyed=destroyed, group=group, empty=empty, wait=wait,
                      metrics=metrics, process=process, cgroup=cgroup, runtime=runtime,
                      memory=catalog / 'objects' / template / 'memory',
                      snapshot_state=catalog / 'objects' / template / 'state', backend=state / 'firecracker',
                      request=request, result=result['mixed_load'])
        first, second = create(), create('beta')
        check_kvm(first, template); check_kvm(second, template)
        a = execute(first, ['cat', '/proc/sys/kernel/random/boot_id'])['stdout'].strip()
        b = execute(second, ['cat', '/proc/sys/kernel/random/boot_id'], 'beta')['stdout'].strip()
        assert a != b and execute(first, ['id', '-u'])['stdout'].strip() == '65534'
        execute(first, ['sh', '-c', 'echo private > clone-marker'])
        execute(second, ['test', '!', '-e', 'clone-marker'], 'beta')
        call('GET', path(first), tenant='beta', expected=404)
        call('POST', path(first) + '/exec', {'generation': '0' * 32, 'argv': ['true']}, expected=409)
        assert status_item(template)['pins'] == 2
        result['checks'].append('two real restored KVM guests have fresh boot IDs, UID65534, isolated workspaces, exact read-only inodes and durable initialization-attempt pins')
        result['checks'].append('cross-tenant lookup and stale-generation execution are rejected')

        binding = call('POST', '/v1/sessions', request, expected=201, key=secrets.token_hex(16))
        endpoint = '/v1/sessions/' + binding['id']
        def session_exec(v, argv):
            accepted = call('POST', endpoint + '/exec', {'revision': v['revision'], 'argv': argv, 'timeout_ms': 5000}, expected=202)
            assert accepted['sandbox'] == v['current'] and accepted['revision'] == v['revision']
            return finish(accepted['sandbox'], accepted['job'])
        session_exec(binding, ['sh', '-c', 'echo old > session-marker'])
        call('POST', path(binding['current']) + '/exec', {'generation': binding['current']['generation'], 'argv': ['true']}, expected=409)
        call('GET', endpoint, tenant='beta', expected=404)
        result['samples']['session_switches'] = []
        for cycle in range(5):
            began = time.perf_counter()
            def observe_stop():
                wait(lambda: empty(group(binding['current'])), 'old session stopped', seconds=30)
                return round((time.perf_counter() - began) * 1000, 3)
            switch_key = secrets.token_hex(16)
            switch_request = {'expected_revision': binding['revision'], 'create': request}
            with ThreadPoolExecutor(max_workers=1) as observers:
                stopped = observers.submit(observe_stop)
                switched = call('POST', endpoint + '/switch', switch_request, key=switch_key)
                assert switched['revision'] == binding['revision'] + 1
                assert switched['previous'] == binding['current'] and switched['current'] != binding['current']
                bind_ms = round((time.perf_counter() - began) * 1000, 3)
                session_exec(switched, ['true'])
                first_ms = round((time.perf_counter() - began) * 1000, 3)
                old_stop_ms = stopped.result(timeout=30)
            destroyed(binding['current'])
            gc_ms = round((time.perf_counter() - began) * 1000, 3)
            session_exec(switched, ['test', '!', '-e', 'session-marker'])
            call('POST', endpoint + '/exec', {'revision': binding['revision'], 'argv': ['true']}, expected=409)
            assert call('POST', endpoint + '/switch', switch_request, key=switch_key)['current'] == switched['current']
            result['samples']['session_switches'].append({'cycle': cycle + 1, 'binding_response_ms': bind_ms,
                    'first_new_command_success_ms': first_ms, 'old_execution_stopped_observed_ms': old_stop_ms,
                    'old_durable_destroyed_observed_ms': gc_ms, 'server_phase_observations': switched['timings']})
            session_exec(switched, ['sh', '-c', 'echo old > session-marker'])
            binding = switched
        result['checks'].append('five closed-loop real snapshot session switches separate new-command success, old host stop and old durable GC; fresh workspace, stale revision and exact-key replay enforced')
        call('POST', endpoint + '/revoke', {'expected_revision': switched['revision']})
        destroyed(switched['current'])

        # Hold only this fixture's existing lock; Stop must not wait on catalog GC.
        with (catalog / '.lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            began = time.perf_counter()
            call('POST', path(first) + '/stop', {'generation': first['generation']})
            wait(lambda: empty(group(first)), 'stop while catalog lock held')
            result['samples']['stop_under_catalog_lock_ms'] = round((time.perf_counter() - began) * 1000, 3)
            assert owner_path(first).exists(), 'stop unexpectedly released durable pin under held lock'
            call('DELETE', path(first), {'generation': first['generation']}, expected=202)
            wait(lambda: not jail(first).parent.exists(), 'private GC reaches locked owner release')
            assert owner_path(first).exists() and call('GET', path(first))['state'] != 'DESTROYED'
            fcntl.flock(lock, fcntl.LOCK_UN)
        destroyed(first)
        execute(second, ['true'], 'beta')
        result['checks'].append('Stop confirms empty host cgroup while catalog lock is held; subsequent GC releases only its own pin and another clone still executes')
        assert digest(catalog / 'objects' / template / 'memory') == manifest['memory_sha256']
        assert digest(catalog / 'objects' / template / 'state') == manifest['state_sha256']
        result['checks'].append('shared catalog memory and VMM-state full SHA256 remain unchanged after guest writes and five switches')
        admin('retire', template)
        assert status_item(template)['phase'] == 'RETIRING' and status_item(template)['pins'] == 1
        create(expected=(500, 503))
        admin('gc')
        assert (catalog / 'objects' / template / 'memory').exists()
        execute(second, ['true'], 'beta')
        result['checks'].append('retirement clears active admission but preserves a live pinned clone and shared source')

        process.kill(); process.wait(timeout=10); process = None
        wait(lambda: empty(group(second)), 'guardian after controller SIGKILL')
        assert status_item(template)['pins'] == 1
        admin('gc'); assert (catalog / 'objects' / template / 'memory').exists()
        process = start()
        destroyed(second, 'beta')
        call('POST', endpoint + '/exec', {'revision': switched['revision'], 'argv': ['true']}, expected=410)
        assert status_item(template)['pins'] == 0
        admin('gc')
        assert status_item(template)['phase'] == 'RETIRED' and not (catalog / 'objects' / template).exists()
        admin('activate', template, ok=False); admin('publish', ok=False)
        result['checks'].append('actual controller SIGKILL stops owned KVM through guardian; offline GC reconstructs pin; restart closes old routes and reclaims before permanent retired tombstone')

        # A second trusted declaration of the SAME never-assigned source tests
        # lost ownership fail-closed behavior without corrupting a live guest.
        later = dict(manifest); later['created_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        next_manifest = root / 'next-manifest.json'; private_json(next_manifest, later)
        other = admin('publish', manifest_path=next_manifest)['template_id']; assert other != template
        admin('activate', other); third = create(); check_kvm(third, other)
        admin('retire', other)
        owner = owner_path(third); quarantine = root / 'owner-quarantine.json'
        os.rename(owner, quarantine); sync_dir(owner.parent); restored_owner = (owner, quarantine)
        admin('gc', ok=False)
        assert (catalog / 'objects' / other / 'memory').exists() and not empty(group(third))
        os.rename(quarantine, owner); sync_dir(owner.parent); restored_owner = None
        execute(third, ['true']); remove(third); admin('gc')
        assert status_item(other)['phase'] == 'RETIRED'
        result['checks'].append('missing exact ownership while actual KVM jail/cgroup exists makes GC refuse deletion; restoring ownership permits ordered reclamation')
        for field, value in (('host_abi', '0' * 64), ('agent_sha256', '0' * 64), ('assignment', 'ASSIGNED')):
            invalid = dict(later); invalid[field] = value
            bad = root / ('invalid-' + field + '.json'); private_json(bad, invalid)
            admin('publish', ok=False, manifest_path=bad)
        result['checks'].append('wrong host ABI, wrong pinned agent and assigned declarations are refused by real root publisher')
        assert all(empty(g) for g in cgroup.iterdir() if g.is_dir())
        assert not list((state / 'firecracker').glob('[0-9a-f]' * 64 + '.json'))
        result['passed'] = True
    finally:
        if restored_owner is not None:
            owner, quarantine = restored_owner
            os.rename(quarantine, owner); sync_dir(owner.parent)
        if process is not None and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=10)
        log.close()
        # Only this invocation's exclusive namespace may be killed/removed.
        safe = True
        if cgroup.exists():
            for g in cgroup.iterdir():
                if not g.is_dir(): continue
                try:
                    (g / 'cgroup.kill').write_text('1')
                    wait(lambda: empty(g), 'owned cleanup cgroup', seconds=10)
                    g.rmdir()
                except (OSError, AssertionError):
                    safe = False
            if safe:
                try: cgroup.rmdir()
                except OSError: safe = False
        if safe:
            # Published directories are deliberately read-only, including on failure.
            for directory, _, _ in os.walk(root): os.chmod(directory, 0o700)
            shutil.rmtree(root)
        result['cleanup_confirmed'] = safe and not cgroup.exists() and not root.exists()
        if not result['cleanup_confirmed']: result['passed'] = False
        private_json(report, result)
    assert result.get('passed') and result['cleanup_confirmed'], 'acceptance failed; inspect private logs'
    print(json.dumps({'passed': True, 'checks': len(result['checks']), 'cleanup_confirmed': True}))


if __name__ == '__main__':
    main()
