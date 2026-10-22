"""Bounded operator-only IO proof plus real guest pressure. No tenant host exec."""
import json
import mmap
import os
from pathlib import Path
import subprocess
import sys
import time

from kvm_driver_smoke import UnixHTTP, wait
from kvm_resources import cgroup_empty, start_ticks

BPS = 8 << 20
OPS = 4096
HOST_BYTES = 32 << 20
GUEST_BYTES = 64 << 20


def parse_wchar(raw):
    values = [line.split(':', 1)[1].strip() for line in raw.splitlines() if line.startswith('wchar:')]
    assert len(values) == 1 and values[0].isdigit(), 'invalid private proc IO observation'
    return int(values[0])


def own_vmm_counter(group):
    wanted = '0::/' + str(group.relative_to('/sys/fs/cgroup'))
    found = []
    for pid in (group / 'cgroup.procs').read_text().split():
        assert pid.isdigit()
        proc = Path('/proc', pid)
        before = start_ticks((proc / 'stat').read_text())
        assert wanted in (proc / 'cgroup').read_text().splitlines()
        vm = False
        for fd in (proc / 'fd').iterdir():
            try: vm = vm or 'kvm-vm' in os.readlink(fd)
            except FileNotFoundError: pass  # Unrelated RPC fd can close while scanning.
        assert start_ticks((proc / 'stat').read_text()) == before
        if vm: found.append((proc, before))
    assert len(found) == 1, 'exactly one VMM required in own generation'
    proc, identity = found[0]
    def observe():
        assert start_ticks((proc / 'stat').read_text()) == identity
        assert wanted in (proc / 'cgroup').read_text().splitlines()
        value = parse_wchar((proc / 'io').read_text())
        assert start_ticks((proc / 'stat').read_text()) == identity
        return value
    return observe


def startup_rejections(*, root, config, daemon, auth, logs, private_json):
    cgroup = Path(config['cgroup_root'])
    assert cgroup.parent == Path('/sys/fs/cgroup') and cgroup.name.startswith('xandbox-')
    assert not (cgroup / 'cgroup.procs').read_text().strip() and not any(p.is_dir() for p in cgroup.iterdir())
    cases = []
    for mode, error in (('wrong-backing-queue', b'IO policy must name the exact runtime backing queue'),
                        ('missing-io-delegation', b'configured IO policy requires delegated io controller')):
        policy = json.loads(json.dumps(config))
        if mode == 'wrong-backing-queue': policy['io']['device'] = '4095:1048575'
        cfg = root / (mode + '-config.json'); private_json(cfg, policy)
        if mode == 'missing-io-delegation': (cgroup / 'cgroup.subtree_control').write_text('-io')
        try:
            p = subprocess.run([str(daemon), '-backend', 'firecracker', '-state-dir', str(root / (mode + '-state')),
                '-auth-file', str(auth), '-firecracker-config', str(cfg)], env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'},
                capture_output=True, timeout=20)
            (logs / (mode + '.log')).write_bytes(p.stdout + p.stderr)
            assert p.returncode != 0 and error in p.stderr
            assert not any(p.is_dir() for p in cgroup.iterdir())
            cases.append({'case': mode, 'startup_refused': True, 'no_vm_child_cgroup': True})
        finally:
            if mode == 'missing-io-delegation': (cgroup / 'cgroup.subtree_control').write_text('+io')
    return cases


def bound_policy_rejection(*, root, config, base, logs, private_json):
    cgroup = Path(config['cgroup_root'])
    assert not any(p.is_dir() for p in cgroup.iterdir())
    changed = json.loads(json.dumps(config)); del changed['io']
    cfg = root / 'removed-io-config.json'; private_json(cfg, changed)
    command = list(base); command[command.index('-firecracker-config') + 1] = str(cfg)
    p = subprocess.run(command, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}, capture_output=True, timeout=20)
    (logs / 'removed-io-policy.log').write_bytes(p.stdout + p.stderr)
    assert p.returncode != 0 and b'backend binding changed' in p.stderr
    assert not any(p.is_dir() for p in cgroup.iterdir())
    return {'case': 'remove-bound-io-policy', 'startup_refused': True, 'no_vm_child_cgroup': True}


def fixture_io_policy(root, cgroup):
    """Call only after creating this invocation's exclusive empty fixture root."""
    assert root.is_dir() and cgroup.is_dir() and not (cgroup / 'cgroup.procs').read_text().strip()
    dev = root.stat().st_dev
    fsdev = str(os.major(dev)) + ':' + str(os.minor(dev))
    backing = (Path('/sys/dev/block') / fsdev).resolve(strict=True)
    if (backing / 'partition').exists(): backing = backing.parent
    assert str(backing).startswith('/sys/devices/') and '/virtual/' not in str(backing)
    assert not any((backing / name).exists() for name in ('loop', 'dm', 'md'))
    assert not list((backing / 'slaves').iterdir()) and (backing / 'queue').is_dir()
    (cgroup / 'cgroup.subtree_control').write_text('+io')
    assert 'io' in (cgroup / 'cgroup.subtree_control').read_text().split()
    return {'version': 1, 'filesystem_device': fsdev, 'device': (backing / 'dev').read_text().strip(),
            'bytes_per_second': BPS, 'operations_per_second': OPS}


def parse_io_stat(raw, device):
    rows = {}
    for line in raw.splitlines():
        fields = line.split()
        if not fields: continue
        assert fields[0] not in rows, 'duplicate kernel IO device'
        values = {}
        for field in fields[1:]:
            key, value = field.split('=')
            assert key not in values and value.isdigit()
            values[key] = int(value)
        rows[fields[0]] = values
    return {key: rows.get(device, {}).get(key, 0) for key in ('rbytes', 'wbytes', 'rios', 'wios')}


def verify_limits(group, api, policy):
    fields = (group / 'io.max').read_text().split()
    expected = {f'rbps={BPS}', f'wbps={BPS}', f'riops={OPS}', f'wiops={OPS}'}
    assert len(fields) == 5 and fields[0] == policy['device'] and set(fields[1:]) == expected
    conn = UnixHTTP(api)
    try:
        conn.request('GET', '/vm/config')
        response = conn.getresponse(); raw = response.read(65537)
        assert response.status == 200 and len(raw) <= 65536
        drives = json.loads(raw)['drives']
        assert len(drives) == 1 and drives[0]['drive_id'] == 'workspace'
        for kind, size in (('bandwidth', BPS), ('ops', OPS)):
            bucket = drives[0]['rate_limiter'][kind]
            assert bucket['size'] == size and bucket['refill_time'] == 1000
            assert bucket.get('one_time_burst') in (None, 0)
    finally:
        conn.close()


def direct_child(cgfd, fd):
    """Trusted fixed zero writer, inherited own FDs only, never user commands."""
    assert os.geteuid() == 0 and os.fstat(fd).st_size == 0
    procs = os.open('cgroup.procs', os.O_WRONLY, dir_fd=cgfd)
    try: os.write(procs, str(os.getpid()).encode())
    finally: os.close(procs)
    # Benchmark data starts only after this trusted probe joins the OWNED group.
    # This is not the VM birth protocol (warden still uses CLONE_INTO_CGROUP).
    began = time.perf_counter()
    with mmap.mmap(-1, 1 << 20) as block:
        for _ in range(HOST_BYTES >> 20):
            assert os.write(fd, block) == 1 << 20
    os.fsync(fd)
    print(json.dumps({'written_bytes': HOST_BYTES, 'elapsed_ms': round((time.perf_counter() - began) * 1000, 3)}))


def run_io_probe(*, root, group, api, policy, submit, status, delete, destroyed, result):
    """The caller supplies only its exact Ref-bound guest/API operations."""
    verify_limits(group, api, policy)
    assert not cgroup_empty(group)
    sample = lambda: parse_io_stat((group / 'io.stat').read_text(), policy['device'])
    result.update({'passed': False, 'kernel_and_frontend_readback_verified': True,
              'bytes_per_second': BPS, 'operations_per_second': OPS, 'steady_refill_ms': 1000,
              'extra_one_time_burst_bytes': 0, 'operator_probe_is_not_tenant_host_execution': True})
    before = sample()
    file = root / 'operator-direct-io-proof'
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_DIRECT, 0o600)
    cgfd = os.open(group, os.O_RDONLY | os.O_DIRECTORY)
    try:
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--direct-child', str(cgfd), str(fd)],
                               pass_fds=(cgfd, fd), capture_output=True, timeout=30, check=True)
        direct = json.loads(child.stdout)
        result['operator_direct_io'] = direct
        assert direct['written_bytes'] == HOST_BYTES and direct['elapsed_ms'] >= 2000
        after = sample()
        direct['own_cgroup_io_stat_delta'] = {key: after[key] - before[key] for key in before}
        assert direct['own_cgroup_io_stat_delta']['wbytes'] >= HOST_BYTES
        result['operator_direct_io'] = direct
    finally:
        os.close(fd); os.close(cgfd); file.unlink()

    def complete(argv):
        accepted = submit(argv, 60000)
        done = wait(lambda: (v if (v := status(accepted))['status'] != 'RUNNING' else None), 'guest IO pressure', seconds=70)
        assert done['status'] == 'EXITED' and done['output']['exit_code'] == 0, 'guest IO workload failed; inspect private state'
    before = sample()
    for mode, argv in (
        ('write', ['dd', 'if=/dev/zero', 'of=io-pressure', 'bs=1048576', 'count=64', 'oflag=direct', 'conv=fsync']),
        ('read', ['dd', 'if=io-pressure', 'of=/dev/null', 'bs=1048576', 'iflag=direct'])):
        began = time.perf_counter(); complete(argv)
        ms = round((time.perf_counter() - began) * 1000, 3)
        result['guest_direct_' + mode] = {'payload_bytes': GUEST_BYTES, 'elapsed_ms': ms}
        assert ms >= 5000, '64MiB transfer bypassed finite frontend observation guard'
    after = sample()
    result['guest_phase_own_io_stat_delta'] = {key: after[key] - before[key] for key in before}
    # Do not assert all buffered guest IO is charged here: staged inode/page
    # ownership can remain in the controller, and cache reads do not hit media.
    vmm_wchar = own_vmm_counter(group)
    old_wchar = vmm_wchar()
    busy = submit(['sh', '-c', 'echo ready > io-pressure-ready; while :; do dd if=/dev/zero of=io-pressure bs=1048576 count=64 oflag=direct 2>/dev/null || exit; done'], 60000)
    complete(['sh', '-c', 'while [ ! -f io-pressure-ready ]; do sleep 0.01; done'])
    # wchar counts VMM write syscalls, including buffered backing writes, not
    # media durability. A 4MiB advance cannot be the bounded tiny RPC replies.
    wait(lambda: vmm_wchar() - old_wchar >= 4 << 20, 'VMM actually issues busy backing IO before stop', seconds=20)
    result['busy_vmm_write_syscall_bytes_advanced'] = vmm_wchar() - old_wchar
    assert status(busy)['status'] == 'RUNNING' and not cgroup_empty(group)
    began = time.perf_counter(); delete()
    wait(lambda: cgroup_empty(group), 'owned IO busy host stop', seconds=15)
    result['busy_delete_to_host_cgroup_empty_ms'] = round((time.perf_counter() - began) * 1000, 3)
    destroyed()
    result['busy_delete_to_durable_destroyed_ms'] = round((time.perf_counter() - began) * 1000, 3)
    # Reclamation may already have dropped API job history. Host cgroup-empty
    # proof is authoritative; do not require stale job results to survive GC.
    result['busy_ready_and_populated_rechecked_before_delete'] = True
    result['passed'] = True
    return result


if __name__ == '__main__':
    assert len(sys.argv) == 4 and sys.argv[1] == '--direct-child'
    direct_child(int(sys.argv[2]), int(sys.argv[3]))
