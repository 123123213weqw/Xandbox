"""TEST ONLY closed forty-minute offered-load protocol, never a tenant API."""
import math
import json

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
    'real_nested_kvm', 'pid1_preflight_census_clean', 'owned_pid1_reaper_and_quiescent_pid_charge_checked', 'reused_guest_heartbeat_preflight_passed', 'checkpoint_receipt_fsynced',
    'all_raw_and_canary_intents_accounted', 'fixed_offered_clock_not_completion_paced',
    'cross_tenant_lookup404_checked', 'coarse_one_fifth_equal_offer_progress_guard_passed',
    'high_rate_service_refusal_observed', 'all_pools_and_private_namespaces_empty',
    'quiescent_exact_project_clear_tail_passed',
    'accepted_private_replay_inventory_fsynced', 'cold_distinct_phase_armed',
    'no_operator_quota_sync_in_offered_window', 'post_drain_controller_fd_guard_passed')
NODE_LOAD_RECOVERY_FLAGS = (
    'all_accepted_raw_and_session_keys_cold_replayed410_before_new_guest',
    'private_load_inventory_validated_without_restoration',
    'owned_pid1_reaper_fresh_guest_quiescence_checked')

NODE_LOAD_KERNEL_FIELDS = {
    'controller_threads', 'prepare_failed_io', 'prepare_failed_quota', 'prepare_failed_other',
} | {f'{group}_pids' for group in ('node', 'control')} | {
    f'{group}_pids_max_events' for group in ('node', 'control')
} | {f'{group}_cpu_{name}' for group in ('node', 'control')
     for name in ('usage_usec', 'throttled_usec', 'nr_throttled')} | {
    f'{group}_io_{name}' for group in ('node', 'control')
    for name in ('observed', 'rbytes', 'wbytes', 'rios', 'wios')}
NODE_LOAD_OBSERVATION_FIELDS = {
    'available', 'elapsed_ms', 'offered_origin_known', 'capture_ms', 'complete', 'record_found', 'record_state',
    'owner_present', 'cgroup_present', 'jail_present', 'workspace_present',
    'api_socket_present', 'vsocket_present', 'workspace_logical_bytes',
    'last_error_private', 'recent_errors_private', 'kernel', 'capacity',
    'diagnostic_sequence', 'diagnostic_records', 'stream_kind', 'intent_index', 'tenant',
    'diagnostic_read_ok', 'ledger_scan_truncated', 'ledger_candidates', 'ledger_inspected', 'ledger_read_errors', 'pid1_census'}
NODE_LOAD_CENSUS_FIELDS = {
    'available', 'complete', 'truncated', 'capture_ms', 'candidates', 'scanned',
    'vanished', 'read_errors', 'adopted_zombies', 'managed_controller_zombie',
    'vmm_zombies', 'warden_zombies', 'jailer_zombies', 'other_zombies',
    'reserved_uid_zombies', 'node_scoped_zombies', 'deleted_scoped_zombies',
    'membership_unknown_zombies', 'node_pids', 'control_pids'}


def validate_node_load_census(v, require_clean=False):
    assert type(v) is dict and set(v) in (NODE_LOAD_CENSUS_FIELDS, NODE_LOAD_CENSUS_FIELDS | {'init_reaper'})
    # Legacy negative controls remain readable; a passing new wire MUST prove
    # an active, error-free owned init, not merely omit its mechanism evidence.
    init = v.get('init_reaper')
    if init is not None:
        assert type(init) is dict and set(init) == {'active', 'sweeps', 'reaped', 'errors'}
        assert type(init['active']) is bool
        for name in ('sweeps', 'reaped', 'errors'):
            integer(init[name], 0, 1 << 32)
    booleans = {'available', 'complete', 'truncated', 'managed_controller_zombie'}
    for name in booleans:
        assert type(v[name]) is bool
    finite(v['capture_ms'])
    for name in NODE_LOAD_CENSUS_FIELDS - booleans - {'capture_ms', 'node_pids', 'control_pids'}:
        integer(v[name], 0, 16384 if name == 'read_errors' else 4096)
    integer(v['node_pids'], 0, 1 << 50); integer(v['control_pids'], 0, 1 << 50)
    assert v['scanned'] + v['vanished'] <= v['candidates']
    assert v['adopted_zombies'] == sum(v[n] for n in ('vmm_zombies', 'warden_zombies', 'jailer_zombies', 'other_zombies'))
    assert v['adopted_zombies'] <= v['scanned']
    assert v['reserved_uid_zombies'] <= v['adopted_zombies']
    assert v['deleted_scoped_zombies'] <= v['node_scoped_zombies']
    assert v['node_scoped_zombies'] + v['membership_unknown_zombies'] == v['adopted_zombies']
    if v['complete']:
        assert v['available'] and not v['truncated'] and v['read_errors'] == 0
        assert v['scanned'] > 0 and v['candidates'] > 0
        assert v['scanned'] + v['vanished'] == v['candidates']
    if require_clean:
        assert v['available'] and v['complete'] and v['adopted_zombies'] == 0
        assert not v['managed_controller_zombie']
        assert v['node_pids'] == v['control_pids']
        assert init is not None and init['active'] and init['sweeps'] > 0 and init['errors'] == 0


def validate_node_load_kernel(v):
    assert type(v) is dict and set(v) == NODE_LOAD_KERNEL_FIELDS
    for value in v.values():
        integer(value, 0, 1 << 50)
    assert v['node_pids'] <= 384 and v['control_pids'] <= 128
    integer(v['controller_threads'], 1, 128)
    for group in ('node', 'control'):
        integer(v[f'{group}_io_observed'], 0, 1)
        if v[f'{group}_io_observed'] == 0:
            assert all(v[f'{group}_io_{field}'] == 0 for field in ('rbytes', 'wbytes', 'rios', 'wios'))


NODE_LOAD_ACTOR_PHASES = (
    'raw_create', 'canary_rotate_close', 'canary_open_http', 'canary_open_verify',
    'canary_open_fresh', 'canary_open_work', 'busy_prepare', 'busy_start',
    'busy_progress', 'busy_verify', 'canary_switch_http', 'canary_new_fresh',
    'canary_new_work', 'canary_release')

NODE_LOAD_SERVER_PHASES = (
    'xa_core_admission', 'xa_core_owner_commit', 'xa_core_driver', 'xa_core_ready_commit',
    'xa_driver_slot', 'xa_driver_owner', 'xa_driver_quota_reserve', 'xa_driver_copy',
    'xa_driver_quota_verify', 'xa_driver_activation', 'xa_session_intent_commit',
    'xa_session_prepared_commit', 'xa_session_active_commit')
NODE_LOAD_ACTOR_STAGES = (
    'raw_create', 'raw_fresh', 'raw_work', 'raw_busy', 'raw_stop', 'raw_empty',
    'raw_destroy', 'raw_replay', 'canary_open', 'canary_start', 'canary_switch',
    'canary_release', 'canary_new', 'canary_old_gc', 'canary_replay')
NODE_LOAD_ACTOR_OUTCOMES = ('pending', 'ok', 'deadline', 'cancelled', 'other')


def validate_node_load_capacity(value):
    assert type(value) is dict and set(value) == {'queued', 'capacity', 'class_capacity'}
    integer(value['queued'], 0, 8)
    integer(value['capacity'], 8, 8)
    integer(value['class_capacity'], 4, 4)


def validate_node_load_actor(value):
    assert type(value) is dict and set(value) == {
        'kind', 'intent_index', 'tenant', 'worker', 'elapsed_ms', 'budget_known',
        'budget_ms', 'done', 'result_stage', 'outcome', 'invalid', 'phases', 'server'}
    integer(value['kind'], 0, 1); integer(value['tenant'], 0, 1)
    integer(value['intent_index'], 0, 6359 if value['kind'] == 0 else 239)
    assert value['intent_index'] % 2 == value['tenant']
    integer(value['worker'], 0, 3 if value['kind'] == 0 else 0)
    for name in ('budget_known', 'done', 'invalid'):
        assert type(value[name]) is bool
    assert value['invalid'] is False
    finite(value['elapsed_ms']); finite(value['budget_ms'])
    assert value['elapsed_ms'] <= 55 * 60 * 1000 and value['budget_ms'] <= 35000
    if not value['budget_known']:
        assert value['budget_ms'] == 0
    assert type(value['outcome']) is str and value['outcome'] in NODE_LOAD_ACTOR_OUTCOMES
    if value['done']:
        assert type(value['result_stage']) is str and value['result_stage'] in NODE_LOAD_ACTOR_STAGES
        assert value['outcome'] != 'pending'
    else:
        assert value['result_stage'] == '' and value['outcome'] == 'pending'
    assert type(value['phases']) is list and len(value['phases']) <= 16
    seen, end, last_phase = set(), 0, -1
    for n, phase in enumerate(value['phases']):
        assert type(phase) is dict and set(phase) == {'phase', 'begin_ms', 'end_ms', 'ended', 'outcome'}
        assert type(phase['phase']) is str and phase['phase'] in NODE_LOAD_ACTOR_PHASES and phase['phase'] not in seen
        ordinal = NODE_LOAD_ACTOR_PHASES.index(phase['phase'])
        assert ordinal > last_phase
        last_phase = ordinal
        if value['kind'] == 0:
            assert phase['phase'] in ('raw_create', 'busy_prepare', 'busy_start', 'busy_progress', 'busy_verify')
        else:
            assert phase['phase'] != 'raw_create'
        if phase['phase'] == 'canary_release':
            assert 'canary_switch_http' in seen and not {'canary_new_fresh', 'canary_new_work'} & seen
        seen.add(phase['phase'])
        assert type(phase['ended']) is bool
        finite(phase['begin_ms']); finite(phase['end_ms'])
        assert end <= phase['begin_ms'] <= value['elapsed_ms']
        assert type(phase['outcome']) is str and phase['outcome'] in NODE_LOAD_ACTOR_OUTCOMES
        if phase['ended']:
            assert phase['begin_ms'] <= phase['end_ms'] <= value['elapsed_ms']
            assert phase['outcome'] != 'pending'
            end = phase['end_ms']
        else:
            assert n == len(value['phases']) - 1 and not value['done']
            assert phase['end_ms'] == 0 and phase['outcome'] == 'pending'
    # Distinct gaps remain unmeasured; never relabel them capacity/IO waiting.
    validate_node_load_server(value)
    return (value['kind'], value['tenant'], value['worker'])


def validate_node_load_server(actor, require_present=False):
    calls = actor['server']
    assert type(calls) is list and len(calls) <= (1 if actor['kind'] == 0 else 2)
    points = {v['phase']: v for v in actor['phases'] if v['phase'] in (
        'raw_create', 'canary_open_http', 'canary_switch_http')}
    seen, last = set(), -1
    for call in calls:
        assert type(call) is dict and set(call) == {'phase', 'response_observed', 'timings_present', 'entries'}
        assert type(call['phase']) is str and call['phase'] in points and call['phase'] not in seen
        ordinal = NODE_LOAD_ACTOR_PHASES.index(call['phase'])
        assert ordinal > last
        last = ordinal; seen.add(call['phase'])
        assert type(call['response_observed']) is bool and type(call['timings_present']) is bool
        assert not call['timings_present'] or call['response_observed']
        assert type(call['entries']) is list and len(call['entries']) <= len(NODE_LOAD_SERVER_PHASES)
        if call['timings_present']:
            assert call['entries']
        else:
            assert not call['entries']
        point = points[call['phase']]
        elapsed = (point['end_ms'] if point['ended'] else actor['elapsed_ms']) - point['begin_ms']
        metrics, last_metric = {}, -1
        for entry in call['entries']:
            assert type(entry) is dict and set(entry) == {'phase', 'ms', 'calls'}
            assert type(entry['phase']) is str and entry['phase'] in NODE_LOAD_SERVER_PHASES
            index = NODE_LOAD_SERVER_PHASES.index(entry['phase'])
            assert index > last_metric
            last_metric = index
            finite(entry['ms']); integer(entry['calls'], 1, 1)
            assert entry['ms'] <= min(35001, elapsed + 1)  # header millisecond rounding, not clock synchronization
            if actor['kind'] == 0:
                assert not entry['phase'].startswith('xa_session_')
            metrics[entry['phase']] = entry['ms']
        for name, duration in metrics.items():
            if name.startswith('xa_driver_'):
                assert 'xa_core_driver' in metrics and duration <= metrics['xa_core_driver'] + 1
        if require_present:
            assert call['response_observed'] and call['timings_present']
    if require_present:
        assert seen == set(points)
    # Parent/child durations overlap. Do NOT sum them into a total or turn
    # missing responses into zero latency / proof of no server-side work.


def validate_node_load_actors(value, public):
    assert type(value) is dict and set(value) == {'version', 'invalid', 'latest', 'failure'}
    integer(value['version'], 2, 2)
    assert value['invalid'] is False
    assert type(value['latest']) is list and len(value['latest']) <= 10
    slots = [validate_node_load_actor(v) for v in value['latest']]
    assert len(slots) == len(set(slots))
    if value['failure'] is not None:
        validate_node_load_actor(value['failure'])
        failure = value['failure']
        assert failure['done'] and failure['outcome'] not in ('ok', 'pending')
        first = public.get('first_failure')
        assert type(first) is dict
        integer(first['Kind'], 0, 1); integer(first['Tenant'], 0, 1)
        integer(first['Index'], 0, 6359 if first['Kind'] == 0 else 239)
        assert type(first['Stage']) is str
        assert (failure['kind'], failure['intent_index'], failure['tenant'], failure['result_stage']) == (
            first['Kind'], first['Index'], first['Tenant'], first['Stage'])
    first = public.get('first_failure')
    if (public.get('observed_result_rows', 0) > 0 and type(first) is dict
            and first.get('Kind') in (0, 1) and first.get('Stage') in NODE_LOAD_ACTOR_STAGES):
        assert value['failure'] is not None
    if public.get('run_passed') is True:
        assert value['failure'] is None
        assert all(v['done'] and v['outcome'] == 'ok' for v in value['latest'])
        for actor in value['latest']:
            validate_node_load_server(actor, require_present=True)
        assert {(kind, tenant) for kind, tenant, worker in slots} == {(0, 0), (0, 1), (1, 0), (1, 1)}


def detach_node_load_private(value):
    """Return a public candidate plus an explicitly private, bounded sidecar.

    Detach BEFORE the ordinary success validator or producer report. This is
    also used on failure, so the original row/error survives outer cleanup.
    """
    assert type(value) is dict
    public = dict(value)
    private = public.pop('private_load_diagnostics', None)
    if private is None:
        assert public.get('run_passed') is not True  # passing new wire must retain both private preflight censuses
        integer(public.get('slow_create_probes_started', 0), 0, 0)
        integer(public.get('slow_create_probes_omitted', 0), 0, 0)
        return public, None
    assert type(private) is dict and set(private) == {'slow', 'omitted', 'failure', 'pid1_preflight_before', 'pid1_preflight_after', 'actors'}
    assert len(json.dumps(private, ensure_ascii=True).encode()) <= 192 << 10
    validate_node_load_actors(private['actors'], public)
    slow = [] if private['slow'] is None else private['slow']
    assert type(slow) is list and len(slow) <= 8
    integer(private['omitted'], 0, 6468)  # raw6360 + tail100 + preflight8; no canary Create probes
    integer(public['slow_create_probes_started'], len(slow), len(slow))
    integer(public['slow_create_probes_omitted'], private['omitted'], private['omitted'])
    for name in ('pid1_preflight_before', 'pid1_preflight_after'):
        census = private[name]
        if census is not None:
            validate_node_load_census(census, require_clean=public.get('run_passed') is True)
        else:
            assert public.get('run_passed') is not True
    if public.get('run_passed') is True:
        before, after = (private[name]['init_reaper']['reaped'] for name in ('pid1_preflight_before', 'pid1_preflight_after'))
        assert after >= before + 8  # actual eight original ordinary lifecycles, not synthetic waits
    observations = slow + ([] if private['failure'] is None else [private['failure']])
    for row in observations:
        assert type(row) is dict and set(row) == NODE_LOAD_OBSERVATION_FIELDS
        for name in ('available', 'complete', 'record_found', 'owner_present',
                     'cgroup_present', 'jail_present', 'workspace_present',
                     'api_socket_present', 'vsocket_present', 'diagnostic_read_ok', 'ledger_scan_truncated', 'offered_origin_known'):
            assert type(row[name]) is bool
        finite(row['elapsed_ms']); finite(row['capture_ms'])
        if not row['offered_origin_known']:
            assert row['elapsed_ms'] == 0  # preflight has no offered-clock origin
        integer(row['stream_kind'], -1, 3); integer(row['intent_index'], -1, 6359); integer(row['tenant'], -1, 1)
        integer(row['ledger_candidates'], 0, 10000); integer(row['ledger_inspected'], 0, 64); integer(row['ledger_read_errors'], 0, 64)
        assert row['record_state'] in ('', 'CREATING', 'READY', 'STOPPING', 'STOPPED', 'DESTROYED')
        integer(row['workspace_logical_bytes'], 0, 128 << 20)
        assert type(row['last_error_private']) is str and len(row['last_error_private'].encode()) <= 515
        errors = [] if row['recent_errors_private'] is None else row['recent_errors_private']
        assert type(errors) is list and len(errors) <= 4
        assert all(type(error) is str and len(error.encode()) <= 515 for error in errors)
        if row['kernel'] is not None:
            validate_node_load_kernel(row['kernel'])
        if row['capacity'] is not None:
            validate_node_load_capacity(row['capacity'])
        if row['complete']:
            assert row['capacity'] is not None
        if row['pid1_census'] is not None:
            validate_node_load_census(row['pid1_census'])
        if row['complete']:
            assert row['pid1_census'] is not None and row['pid1_census']['complete']
        integer(row['diagnostic_sequence'], 0, (1 << 64) - 1)
        records = [] if row['diagnostic_records'] is None else row['diagnostic_records']
        assert type(records) is list and len(records) <= 16
        for record in records:
            assert type(record) is dict and set(record) == {'sequence', 'kind', 'reason', 'time_unix_ns', 'dropped_before'}
            for name, high in (('sequence', (1 << 64) - 1), ('kind', 255), ('reason', 255),
                               ('time_unix_ns', (1 << 63) - 1), ('dropped_before', (1 << 64) - 1)):
                integer(record[name], 0, high)
    return public, private


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
            'full_production_acceptance', 'load_window_completed', 'run_passed',
            'slow_create_probes_started', 'slow_create_probes_omitted'} | set(NODE_LOAD_SUCCESS_FLAGS)
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
    integer(v['slow_create_probes_started'], 0, 8)
    integer(v['slow_create_probes_omitted'], 0, 6468)
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
                       'ControlOOMKills', 'ControlOOMGroups', 'kernel'}
    previous = -1
    for sample in samples:
        assert type(sample) is dict and set(sample) == resource_fields
        finite(sample['elapsed_ms']); finite(sample['observation_ms'], high=5000)
        assert sample['elapsed_ms'] >= previous
        previous = sample['elapsed_ms']
        for key in resource_fields - {'elapsed_ms', 'observation_ms', 'kernel'}:
            integer(sample[key], 0, 1 << 50)
        validate_node_load_kernel(sample['kernel'])
        assert all(sample['kernel'][field] == 0 for field in ('node_pids_max_events', 'control_pids_max_events', 'prepare_failed_io', 'prepare_failed_quota', 'prepare_failed_other'))
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
