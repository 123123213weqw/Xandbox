"""Finite two-tenant, paced closed-loop snapshot probe, NOT a fairness/SLO proof.

All argv below travel through the guest API; never run them on the host.
Resource observations are overlapping views, not additive memory accounting.
"""
from concurrent.futures import ThreadPoolExecutor
import math
import secrets
import threading
import time
import traceback

from kvm_resources import ResourceSampler

GAUGES = ('allocated', 'stop_queued', 'cleanup_queued', 'stop_running', 'cleanup_running')


def gauges(text):
    result = {}
    for name in GAUGES:
        prefix = 'xandbox_' + name + ' '
        values = [line[len(prefix):] for line in text.splitlines() if line.startswith(prefix)]
        if len(values) != 1 or not values[0].isdigit():
            raise ValueError('missing or invalid fixed-cardinality metric')
        result[name] = int(values[0])
    return result


def summarize(rows, keys):
    return {key: {'count': len(rows), **{
        'p' + str(p): sorted(row[key] for row in rows)[math.ceil(len(rows) * p / 100) - 1]
        for p in (50, 95, 99, 100)}} for key in keys}


def overlaps(left, right, prefix):
    return sum(a[prefix + '_start_ms'] < b[prefix + '_end_ms'] and
               b[prefix + '_start_ms'] < a[prefix + '_end_ms'] for a in left for b in right)


def workload(tenant):
    # /tmp is guest initramfs RAM; cwd is the guest's private ext4 workspace.
    ram, disk, rounds = (24, 8, 4) if tenant == 'alpha' else (4, 1, 1)
    return ['sh', '-c',
            'set -e; dd if=/dev/zero of=/tmp/mixed-memory bs=1048576 count=' + str(ram) + ' 2>/dev/null; '
            'dd if=/dev/zero of=mixed-disk bs=1048576 count=' + str(disk) + ' 2>/dev/null; '
            'test "$(wc -c < /tmp/mixed-memory)" -eq ' + str(ram << 20) + '; '
            'test "$(wc -c < mixed-disk)" -eq ' + str(disk << 20) + '; '
            'sync; i=0; while [ "$i" -lt ' + str(rounds) + ' ]; do '
            'sha256sum /tmp/mixed-memory mixed-disk >/dev/null || exit 1; i=$((i+1)); done; '
            'test -f mixed-disk && echo private > mixed-marker']


def run_mixed(*, cycles, min_seconds, call, finish, destroyed, group, empty, wait,
              metrics, process, cgroup, runtime, memory, snapshot_state, backend, request, result):
    assert 1 <= cycles <= 256 and 0 <= min_seconds <= 240
    result.update({'test': 'finite_two_tenant_paced_snapshot_switching', 'passed': False,
        'production_load_acceptance': False, 'cycles_per_tenant': cycles,
        'minimum_paced_seconds': min_seconds, 'configured_tenant_instance_quota': 3,
        'configured_node_instance_capacity': 8, 'workers': 2, 'session_rotation_every_switches': 48,
        'workloads': {'alpha': {'guest_tmpfs_mib': 24, 'guest_ext4_mib': 8, 'sha256_rounds': 4},
                      'beta': {'guest_tmpfs_mib': 4, 'guest_ext4_mib': 1, 'sha256_rounds': 1}},
        'sampling_target_seconds': 0.5, 'samples': {'alpha': [], 'beta': []}, 'resources': [],
        'checks': [], 'limitations': [
            'Two paced closed-loop workers, one per tenant; not open-loop saturation, scheduler fairness or an SLO.',
            'Shared developer host, no cache eviction; publishing hashes/copies and warms source pages.',
            'PSS, cgroup memory.current and backing mincore residency overlap. NEVER sum them as total RAM.',
            'smaps mapping Anonymous includes COW but is not uniquely billed RAM; RSS duplicates shared pages.',
            'Nontransactional 500ms observations miss peaks and include controller/sampler overhead.',
            'Private disk allocated blocks are separate from logical size and are not a disk-quota proof.',
            'Tombstone metadata grows within configured budgets; finite curves do not prove long-term stability.',
            'Empirical nearest-rank quantiles, not statistical tail bounds or production percentiles.']})

    def remove(ref, tenant):
        call('DELETE', '/v1/sandboxes/' + ref['id'], {'generation': ref['generation']}, expected=202, tenant=tenant)
        destroyed(ref, tenant)

    # Hold tenant alpha at quota while the node has spare capacity. Beta must
    # still execute. This proves quota isolation, not scheduler fairness.
    held = [call('POST', '/v1/sandboxes', request, expected=201, tenant='alpha', key=secrets.token_hex(16))
            for _ in range(3)]
    call('POST', '/v1/sandboxes', request, expected=429, tenant='alpha', key=secrets.token_hex(16))
    other = call('POST', '/v1/sandboxes', request, expected=201, tenant='beta', key=secrets.token_hex(16))
    job = call('POST', '/v1/sandboxes/' + other['id'] + '/exec',
               {'generation': other['generation'], 'argv': ['true']}, expected=202, tenant='beta')
    finish(other, job, 'beta')
    for ref in held:
        remove(ref, 'alpha')
    remove(other, 'beta')
    result['checks'].append('alpha fourth Create rejected at tenant quota while beta creates and executes with node capacity remaining')

    sampler = ResourceSampler(process=process, cgroup=cgroup, runtime=runtime, memory=memory,
                              snapshot_state=snapshot_state, backend=backend)
    began = time.perf_counter()
    stop_observer, abort = threading.Event(), threading.Event()
    barrier = threading.Barrier(2, timeout=40)
    observer_errors = []
    result['worker_errors'] = []

    def sample():
        started = time.perf_counter()
        value = {'elapsed_ms': round((started - began) * 1000, 3),
                 **sampler.sample(), **{'metric_' + k: v for k, v in gauges(metrics()).items()}}
        value['observation_duration_ms'] = round((time.perf_counter() - started) * 1000, 3)
        return value

    # Initial sample failure must be synchronous; do not label missing data zero.
    result['resources'].append(sample())

    def observe():
        try:
            while not stop_observer.wait(0.5):
                result['resources'].append(sample())
        except BaseException as error:
            traceback.print_exc()  # Private console only; report keeps the bounded error type.
            observer_errors.append(type(error).__name__)
            abort.set()

    observer = threading.Thread(target=observe, daemon=True)
    observer.start()

    def worker(tenant):
        binding = None
        endpoint = None
        sessions = 0

        def execute(value, argv):
            accepted = call('POST', endpoint + '/exec', {'revision': value['revision'],
                            'argv': argv, 'timeout_ms': 10000}, expected=202, tenant=tenant)
            assert accepted['sandbox'] == value['current'] and accepted['revision'] == value['revision']
            return finish(value['current'], accepted['job'], tenant)

        def revoke():
            revoked = call('POST', endpoint + '/revoke', {'expected_revision': binding['revision']}, tenant=tenant)
            assert revoked['admission_revoked']
            destroyed(binding['current'], tenant)

        barrier.wait()
        with ThreadPoolExecutor(max_workers=1) as stops:
            for index in range(cycles):
                assert not abort.is_set(), 'another worker or resource observer failed'
                if index % 48 == 0:
                    if binding is not None:
                        revoke()
                    binding = call('POST', '/v1/sessions', request, expected=201,
                                   key=secrets.token_hex(16), tenant=tenant)
                    endpoint = '/v1/sessions/' + binding['id']
                    sessions += 1
                row = {'iteration': index + 1, 'session_ordinal': sessions,
                       'workload_start_ms': round((time.perf_counter() - began) * 1000, 3)}
                # Preserve incomplete rows on failure, rather than filtering slow/errors.
                result['samples'][tenant].append(row)
                execute(binding, workload(tenant))
                row['workload_end_ms'] = round((time.perf_counter() - began) * 1000, 3)
                old, revision = binding['current'], binding['revision']
                origin = time.perf_counter()
                row['switch_start_ms'] = round((origin - began) * 1000, 3)

                def old_stop(ref=old, start=origin):
                    wait(lambda: empty(group(ref)), 'mixed old host stop', seconds=30)
                    return round((time.perf_counter() - start) * 1000, 3)

                stopped = stops.submit(old_stop)
                binding = call('POST', endpoint + '/switch', {'expected_revision': revision, 'create': request},
                               key=secrets.token_hex(16), tenant=tenant)
                row['request_to_binding_response_ms'] = round((time.perf_counter() - origin) * 1000, 3)
                assert binding['previous'] == old and binding['current'] != old and binding['revision'] == revision + 1
                execute(binding, ['sh', '-c', 'test ! -e mixed-marker && test ! -e mixed-disk && test ! -e /tmp/mixed-memory'])
                row['request_to_first_new_command_success_ms'] = round((time.perf_counter() - origin) * 1000, 3)
                row['request_to_old_host_stopped_observed_ms'] = stopped.result(timeout=35)
                destroyed(old, tenant)
                row['request_to_old_durable_destroyed_observed_ms'] = round((time.perf_counter() - origin) * 1000, 3)
                row['switch_end_ms'] = round((time.perf_counter() - began) * 1000, 3)
                assert binding['timings']['measured']
                row['server_phase_observations'] = binding['timings']
                call('POST', endpoint + '/exec', {'revision': revision, 'argv': ['true']}, expected=409, tenant=tenant)
                row['completed'] = True
                # Deliberate pacing is explicit, outside measured switch latency.
                remaining = began + min_seconds * (index + 1) / cycles - time.perf_counter()
                if remaining > 0:
                    assert not abort.wait(remaining), 'resource observer or other worker failed during pacing'
            revoke()

    def guarded_worker(tenant):
        try:
            worker(tenant)
        except BaseException as error:
            traceback.print_exc()  # Preserve the originating error, not just its peer's abort assertion.
            result['worker_errors'].append({'tenant': tenant, 'error_type': type(error).__name__})
            abort.set()
            barrier.abort()
            raise

    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(guarded_worker, tenant) for tenant in ('alpha', 'beta')]
            for future in futures:
                try:
                    future.result()
                except BaseException:
                    abort.set()
                    barrier.abort()
                    raise
    finally:
        stop_observer.set()
        observer.join(timeout=10)
        result['duration_seconds'] = round(time.perf_counter() - began, 3)
        result['observer_errors'] = observer_errors
    assert not observer.is_alive() and not observer_errors, 'resource observation failed'
    # DESTROYED persistence can precede a worker's deferred running-gauge
    # decrement. Wait for the independent queue view rather than racing it.
    wait(lambda: all(value == 0 for value in gauges(metrics()).values()), 'mixed final metric drain')
    final = sample()
    result['resources'].append(final)
    intervals = [result['resources'][i]['elapsed_ms'] - result['resources'][i - 1]['elapsed_ms']
                 for i in range(1, len(result['resources']))]
    result['resource_observation_interval_ms'] = {'min': min(intervals), 'max': max(intervals),
                                                'mean': round(sum(intervals) / len(intervals), 3)}
    assert final['owned_cgroup_count'] == final['durable_owner_files'] == final['private_workspace_logical_bytes'] == 0
    assert all(final['metric_' + name] == 0 for name in GAUGES)
    result['resource_peaks'] = {key: max(row[key] for row in result['resources']) for key in final if key != 'elapsed_ms'}
    keys = ('request_to_binding_response_ms', 'request_to_first_new_command_success_ms',
            'request_to_old_host_stopped_observed_ms', 'request_to_old_durable_destroyed_observed_ms')
    result['summaries_ms'] = {tenant: summarize(rows, keys) for tenant, rows in result['samples'].items()}
    alpha, beta = result['samples']['alpha'], result['samples']['beta']
    result['cross_tenant_overlapping_workload_interval_pairs'] = overlaps(alpha, beta, 'workload')
    result['cross_tenant_overlapping_switch_interval_pairs'] = overlaps(alpha, beta, 'switch')
    assert result['cross_tenant_overlapping_switch_interval_pairs'] > 0
    result['completed_by_30s_window'] = [{
        'end_seconds': end,
        **{tenant: sum((end - 30) * 1000 <= row['switch_end_ms'] < end * 1000 for row in rows)
           for tenant, rows in result['samples'].items()}}
        for end in range(30, math.ceil(result['duration_seconds'] / 30) * 30 + 1, 30)]
    result['checks'] += ['both tenants complete every requested switch with actual interval overlap',
        'every new guest rejects old workspace/tmpfs marker and executes exact current revision; old revision rejects',
        'each old generation independently host-stopped and durably reclaimed; sessions rotate within history budget',
        'separate operator metrics available during mixed work; final allocations, queues, cgroups, owners and private disks drain']
    result['passed'] = True
