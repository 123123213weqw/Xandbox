"""Bounded closed-loop KVM switching probe; not a production load/SLO test."""
from concurrent.futures import ThreadPoolExecutor
import math
from pathlib import Path
import threading
import time


def summaries(rows):
    result = {}
    for key in rows[0]:
        values = sorted(row[key] for row in rows)
        result[key] = {'count': len(values), 'min': values[0], 'max': values[-1],
                       **{'p' + str(p): values[math.ceil(len(values) * p / 100) - 1] for p in (50, 95, 99)}}
    return result


def run_load(*, cycles, call, finish, destroyed, group, stopped, wait, metrics, process, cgroup):
    assert 1 <= cycles <= 50
    binding = call('POST', '/v1/sessions', {'ttl_ms': 60000}, expected=201, key='load-session')
    endpoint = '/v1/sessions/' + binding['id']
    rows, resource_rows = [], []
    peaks = {'controller_rss_bytes': 0, 'owned_vm_process_rss_bytes': 0,
             'owned_cgroup_memory_current_bytes': 0, 'controller_fds': 0}
    stopped_observer = threading.Event()
    observer_errors = []

    def rss(pid):
        try:
            for line in Path('/proc', str(pid), 'status').read_text().splitlines():
                if line.startswith('VmRSS:'):
                    return int(line.split()[1]) * 1024
        except (FileNotFoundError, ProcessLookupError):
            return 0
        return 0

    def resources():
        assert process.poll() is None, 'controller exited during load'
        owned_memory, owned_rss = 0, 0
        for child in cgroup.iterdir():
            if not child.is_dir():
                continue
            try:
                owned_memory += int((child / 'memory.current').read_text())
                pids = (child / 'cgroup.procs').read_text().split()
            except FileNotFoundError:
                continue
            owned_rss += sum(rss(pid) for pid in pids)
        return {'controller_rss_bytes': rss(process.pid), 'owned_vm_process_rss_bytes': owned_rss,
                'owned_cgroup_memory_current_bytes': owned_memory,
                'controller_fds': len(list(Path('/proc', str(process.pid), 'fd').iterdir()))}

    def observe():
        try:
            while not stopped_observer.is_set():
                value = resources()
                for key in peaks:
                    peaks[key] = max(peaks[key], value[key])
                stopped_observer.wait(0.02)
        except BaseException as error:
            observer_errors.append(type(error).__name__)

    observer = threading.Thread(target=observe, daemon=True)
    observer.start()
    began_all = time.perf_counter()
    try:
        with ThreadPoolExecutor(max_workers=1) as observations:
            for index in range(cycles):
                old = binding['current']
                # This guest marker must never enter the next fresh VM.
                accepted = call('POST', endpoint + '/exec', {'revision': binding['revision'],
                    'argv': ['sh', '-c', 'echo private > load-note']}, expected=202)
                assert finish(old, accepted['job'])['output']['exit_code'] == 0
                began = time.perf_counter()
                def old_stop(ref=old, origin=began):
                    wait(lambda: stopped(group(ref)), 'load old host stop')
                    return round((time.perf_counter() - origin) * 1000, 3)
                stopping = observations.submit(old_stop)
                binding = call('POST', endpoint + '/switch', {'expected_revision': binding['revision'],
                    'create': {'ttl_ms': 60000}}, key='load-switch-' + str(index))
                response_ms = round((time.perf_counter() - began) * 1000, 3)
                assert binding['previous'] == old and binding['current'] != old
                accepted = call('POST', endpoint + '/exec', {'revision': binding['revision'], 'argv': ['true']}, expected=202)
                assert finish(binding['current'], accepted['job'])['output']['exit_code'] == 0
                first_ms = round((time.perf_counter() - began) * 1000, 3)
                accepted = call('POST', endpoint + '/exec', {'revision': binding['revision'],
                    'argv': ['test', '!', '-e', 'load-note']}, expected=202)
                assert finish(binding['current'], accepted['job'])['output']['exit_code'] == 0
                stop_ms = stopping.result(timeout=15)
                destroyed(old)
                row = {'request_to_binding_response_ms': response_ms, 'request_to_first_new_command_success_ms': first_ms,
                       'request_to_old_host_stopped_observed_ms': stop_ms,
                       'request_to_old_durable_destroyed_observed_ms': round((time.perf_counter() - began) * 1000, 3)}
                assert binding['timings']['measured']
                row.update({'server_' + k: v for k, v in binding['timings'].items() if k != 'measured'})
                rows.append(row)
                text = metrics()
                assert 'xandbox_allocated 1\n' in text
                assert 'xandbox_stop_queued 0\n' in text and 'xandbox_cleanup_queued 0\n' in text
                resource_rows.append({'iteration': index + 1, **resources()})
        result = call('POST', endpoint + '/revoke', {'expected_revision': binding['revision']})
        assert result['admission_revoked'] and not result['durable'] and not result['stop_confirmed']
        destroyed(binding['current'])
        final = resources()
        assert not [p for p in cgroup.iterdir() if p.is_dir()]
        final_metrics = metrics()
        assert 'xandbox_allocated 0\n' in final_metrics
    finally:
        stopped_observer.set()
        observer.join(timeout=5)
    assert not observer.is_alive() and not observer_errors, observer_errors
    return {'test': 'bounded_closed_loop_fresh_vm_switching', 'production_load_acceptance': False,
            'cycles': cycles, 'session_count': 1, 'maximum_live_generations': 2,
            'duration_seconds': round(time.perf_counter() - began_all, 3),
            'quantile_method': 'empirical nearest rank; P99 is max for fewer than100 samples, not a tail/SLO guarantee',
            'conditions': 'Fresh VM each time, no snapshot/prewarm; uncontrolled host load/page cache. Closed loop waits durable old GC before next switch; does NOT saturate queues or prove cross-tenant fairness. The private1ms diagnostic ledger scanner,5ms API polling and per-cycle metrics remain enabled; measured latency includes observer overhead.',
            'resource_note': '20ms observer. RSS is sampled proc-status resident memory, not PSS; owned-process sums and cgroup-memory-current are non-transactional and can miss peaks. Cgroup memory includes page cache/kernel, NOT guest RSS alone. Tombstone metadata intentionally grows up to configured budget. This finite probe does not prove asymptotic memory stability.',
            'summaries_ms': summaries(rows), 'samples_ms': rows, 'sampled_resource_peaks': peaks,
            'post_old_gc_resources': resource_rows, 'final_resources': final,
            'checks': ['every new VM has clean workspace and successful exact-revision guest execution',
                       'each old generation independently host-stopped then durably reclaimed before next switch',
                       'metrics scrapes remain available; per-pool queues drained at each iteration',
                       'final revoke reclaims last generation without VMM/cgroup residue']}
