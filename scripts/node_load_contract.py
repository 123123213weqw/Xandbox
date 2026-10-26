"""TEST ONLY closed forty-minute offered-load protocol, never a tenant API."""
import math

NODE_LOAD_MAX_FRAME = 1 << 20
NODE_LOAD_PHASE_COUNTS = (60, 300, 1200, 4800)
NODE_LOAD_OUTCOMES = ('completed', 'service_unavailable503', 'tenant_quota',
                     'generator_late_drop', 'generator_queue_drop', 'failed')
NODE_LOAD_METRICS = ('client_queue_delay_ms', 'api_reply_ms_all_started_outcomes',
                     'scheduled_due_to_reply_ms_all_started_outcomes',
                     'first_fresh_guest_command_ms', 'stop_or_switch_reply_ms',
                     'execution_domain_empty_ms', 'old_private_namespace_destroyed_ms',
                     'total_iteration_ms', 'server_measured_revocation_ms',
                     'quiescent_full_project_clear_ms')
NODE_LOAD_SUCCESS_FLAGS = (
    'real_nested_kvm', 'checkpoint_receipt_fsynced',
    'all_raw_and_canary_intents_accounted', 'fixed_offered_clock_not_completion_paced',
    'cross_tenant_lookup404_checked', 'coarse_one_fifth_equal_offer_progress_guard_passed',
    'high_rate_service_refusal_observed', 'all_pools_and_private_namespaces_empty',
    'quiescent_exact_project_clear_tail_passed',
    'accepted_private_replay_inventory_fsynced', 'cold_distinct_phase_armed',
    'no_operator_quota_sync_in_offered_window', 'post_drain_controller_fd_guard_passed')
NODE_LOAD_RECOVERY_FLAGS = (
    'all_accepted_raw_and_session_keys_cold_replayed410_before_new_guest',
    'private_load_inventory_validated_without_restoration')


def node_load_profile(enabled, *others):
    if type(enabled) is not bool or (enabled and any(others)):
        raise ValueError('fixed --node-load is exclusive; no other profile modifiers')


def nested_node_load_resources():
    return {'profile': 'node-load-v1', 'memory_mib': 8192,
            'disk_bytes': 12 << 30, 'cgroup_memory_max': 10 << 30}


def node_load_policy(base):
    value = dict(base)
    value.update(max_records=10000, max_sessions=512,
                 controller_memory_max=3840 << 20)
    return value


def integer(value, low, high):
    assert type(value) is int and low <= value <= high


def finite(value, low=0, high=4000000):
    assert type(value) in (int, float) and math.isfinite(value) and low <= value <= high


def quantile(value, maximum):
    assert type(value) is dict and set(value) == {'n', 'p50_ms', 'p95_ms', 'p99_ms', 'max_ms'}
    integer(value['n'], 1, maximum)
    numbers = [value[k] for k in ('p50_ms', 'p95_ms', 'p99_ms', 'max_ms')]
    for number in numbers:
        finite(number)
    assert numbers == sorted(numbers)


def validate_node_load_result(v):
    keys = {'planned_raw_intents', 'planned_canary_intents', 'planned_quiescent_tail',
            'observed_result_rows', 'accepted_replay_inventory_count', 'groups',
            'resource_samples', 'nearest_rank_no_zero_latency_for_drops',
            'quotas_checked_only_quiescent_not_attributed_across_active_reuse',
            'full_offered_window_ms', 'fixed_workers_each_tenant',
            'fixed_client_queue_each_tenant', 'production_slo_claim',
            'full_production_acceptance', 'load_window_completed', 'run_passed'} | set(NODE_LOAD_SUCCESS_FLAGS)
    assert type(v) is dict and set(v) == keys
    for key in NODE_LOAD_SUCCESS_FLAGS + ('nearest_rank_no_zero_latency_for_drops',
                                         'quotas_checked_only_quiescent_not_attributed_across_active_reuse',
                                         'load_window_completed', 'run_passed'):
        assert v[key] is True
    for key in ('production_slo_claim', 'full_production_acceptance'):
        assert v[key] is False
    for key, expected in {'planned_raw_intents': 6360, 'planned_canary_intents': 240,
                          'planned_quiescent_tail': 100, 'observed_result_rows': 6700,
                          'full_offered_window_ms': 2400000, 'fixed_workers_each_tenant': 4,
                          'fixed_client_queue_each_tenant': 16}.items():
        integer(v[key], expected, expected)
    integer(v['accepted_replay_inventory_count'], 108, 7200)
    groups = v['groups']
    assert type(groups) is list and len(groups) == 18
    expected = {(kind, phase, tenant) for kind in (0, 1) for phase in range(4) for tenant in (0, 1)}
    expected |= {(2, 0, tenant) for tenant in (0, 1)}
    seen = set()
    raw_completed = [[0, 0] for _ in range(4)]
    high_refused = 0
    for group in groups:
        assert type(group) is dict and set(group) == {'kind', 'phase', 'tenant', 'observed_intents',
                                                    'outcomes', 'finished_after_offered_window', 'quantiles'}
        for field, upper in (('kind', 2), ('phase', 3), ('tenant', 1)):
            integer(group[field], 0, upper)
        key = group['kind'], group['phase'], group['tenant']
        assert key in expected and key not in seen
        seen.add(key)
        kind, phase, tenant = key
        wanted = NODE_LOAD_PHASE_COUNTS[phase] // 2 if kind == 0 else 30 if kind == 1 else 50
        integer(group['observed_intents'], wanted, wanted)
        outcomes = group['outcomes']
        assert type(outcomes) is dict and set(outcomes) == set(NODE_LOAD_OUTCOMES)
        for count in outcomes.values():
            integer(count, 0, wanted)
        assert sum(outcomes.values()) == wanted and outcomes['failed'] == 0
        if kind == 1:
            assert outcomes['completed'] > 0
        if kind == 2:
            assert outcomes['completed'] == wanted
        integer(group['finished_after_offered_window'], 0, wanted)
        metrics = group['quantiles']
        assert type(metrics) is dict
        started = wanted - outcomes['generator_late_drop'] - outcomes['generator_queue_drop']
        required = {}
        if started:
            required.update(dict.fromkeys(NODE_LOAD_METRICS[:3], started))
        if outcomes['completed']:
            names = NODE_LOAD_METRICS[3:8] + ((NODE_LOAD_METRICS[8],) if kind == 1 else ()) + ((NODE_LOAD_METRICS[9],) if kind == 2 else ())
            required.update(dict.fromkeys(names, outcomes['completed']))
        assert set(metrics) == set(required)
        for name, count in required.items():
            quantile(metrics[name], wanted)
            assert metrics[name]['n'] == count
        if kind == 0:
            raw_completed[phase][tenant] = outcomes['completed']
            if phase == 3:
                high_refused += outcomes['service_unavailable503'] + outcomes['tenant_quota']
    assert seen == expected and high_refused > 0
    assert all(a > 0 and b > 0 and min(a, b) * 5 >= a + b for a, b in raw_completed)
    samples = v['resource_samples']
    assert type(samples) is list and 240 <= len(samples) <= 244
    resource_fields = {'elapsed_ms', 'observation_ms', 'Allocated', 'Records',
                       'StopQueued', 'CleanupQueued', 'StopRunning', 'CleanupRunning',
                       'NodeCurrent', 'NodePeak', 'ControlCurrent', 'ControlPeak',
                       'ControllerRSS', 'ControllerFDs', 'RootFree', 'QuotaSpace',
                       'QuotaInodes', 'QuotaNonempty', 'NodeMaxEvents', 'NodeOOM',
                       'NodeOOMKills', 'NodeOOMGroups', 'ControlMaxEvents', 'ControlOOM',
                       'ControlOOMKills', 'ControlOOMGroups'}
    previous = -1
    for sample in samples:
        assert type(sample) is dict and set(sample) == resource_fields
        finite(sample['elapsed_ms']); finite(sample['observation_ms'], high=5000)
        assert sample['elapsed_ms'] >= previous
        previous = sample['elapsed_ms']
        for key in resource_fields - {'elapsed_ms', 'observation_ms'}:
            integer(sample[key], 0, 1 << 50)
        assert sample['Allocated'] <= 4 and sample['Records'] <= 10000
        assert sample['StopQueued'] <= 4 and sample['CleanupQueued'] <= 4
        assert sample['StopRunning'] <= 4 and sample['CleanupRunning'] <= 2
        assert sample['ControllerFDs'] <= 128 and sample['RootFree'] >= 256 << 20
        assert sample['QuotaNonempty'] <= 4
        assert sample['NodeCurrent'] <= sample['NodePeak'] <= 7 << 30
        assert sample['ControlCurrent'] <= sample['ControlPeak'] <= 3840 << 20
        for key in ('NodeOOM', 'NodeOOMKills', 'NodeOOMGroups',
                    'ControlOOM', 'ControlOOMKills', 'ControlOOMGroups'):
            assert sample[key] == 0
    assert samples[0]['elapsed_ms'] < 5000 and samples[0]['Allocated'] == 2
    offered_samples = samples[:-1]
    assert offered_samples[-1]['elapsed_ms'] >= 2380000
    assert all(0 < b['elapsed_ms'] - a['elapsed_ms'] <= 20000
               for a, b in zip(offered_samples, offered_samples[1:]))
    assert samples[-1]['elapsed_ms'] >= 2400000
    assert samples[-1]['ControllerFDs'] <= samples[0]['ControllerFDs'] + 4
    assert all(samples[-1][key] == 0 for key in ('StopQueued', 'CleanupQueued', 'StopRunning', 'CleanupRunning'))
    assert samples[-1]['Allocated'] == samples[-1]['QuotaSpace'] == samples[-1]['QuotaInodes'] == samples[-1]['QuotaNonempty'] == 0
