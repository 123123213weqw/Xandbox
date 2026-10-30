"""Synthetic contract tests, NOT sustained-load or Linux/KVM evidence."""
import copy
import io
import math
import json
import re
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from build_nested_host import init_scripts
from kvm_nested_host import JSONSocket, nested_group_limits, node_budget_policy, preserve_node_load_reply
from node_load_contract import (NODE_LOAD_MAX_FRAME, NODE_LOAD_PHASE_COUNTS,
                                NODE_LOAD_OUTCOMES, NODE_LOAD_METRICS,
                                NODE_LOAD_SUCCESS_FLAGS, node_load_profile,
                                nested_node_load_resources, node_load_policy,
                                validate_node_load_result, NODE_LOAD_KERNEL_FIELDS, detach_node_load_private,
                                NODE_LOAD_CENSUS_FIELDS, validate_node_load_census,
                                validate_node_load_actors, validate_node_load_capacity, validate_node_load_creation_activity)
from node_load_contract import NODE_LOAD_SERVER_PHASES


class NodeLoadTests(unittest.TestCase):
    def good(self):
        groups = []
        for kind in range(3):
            for phase in range(1 if kind == 2 else 4):
                for tenant in (0, 1):
                    wanted = NODE_LOAD_PHASE_COUNTS[phase] // 2 if kind == 0 else 30 if kind == 1 else 50
                    completed = wanted // 2 if kind == 0 else wanted
                    refused = int(kind == 0 and phase == 3)
                    outcomes = dict.fromkeys(NODE_LOAD_OUTCOMES, 0)
                    outcomes.update(completed=completed, service_unavailable503=refused,
                                    generator_queue_drop=wanted - completed - refused)
                    counts = dict.fromkeys(NODE_LOAD_METRICS[:3], completed + refused)
                    counts.update(dict.fromkeys(NODE_LOAD_METRICS[3:8], completed))
                    if kind == 1:
                        counts[NODE_LOAD_METRICS[8]] = completed
                    if kind == 2:
                        counts[NODE_LOAD_METRICS[9]] = completed
                    groups.append({'kind': kind, 'phase': phase, 'tenant': tenant,
                                   'observed_intents': wanted, 'outcomes': outcomes,
                                   'finished_after_offered_window': 0,
                                   'quantiles': {key: {'n': n, 'p50_ms': 1, 'p95_ms': 2,
                                                       'p99_ms': 3, 'max_ms': 4}
                                                 for key, n in counts.items()}})
        sample = dict.fromkeys(('StopQueued', 'CleanupQueued', 'StopRunning', 'CleanupRunning',
                                'QuotaSpace', 'QuotaInodes', 'QuotaNonempty', 'NodeMaxEvents',
                                'NodeOOM', 'NodeOOMKills', 'NodeOOMGroups', 'ControlMaxEvents',
                                'ControlOOM', 'ControlOOMKills', 'ControlOOMGroups'), 0)
        sample.update(kernel={**dict.fromkeys(NODE_LOAD_KERNEL_FIELDS, 0), 'controller_threads': 2},
                      observation_ms=10, Allocated=2, Records=100,
                      NodeCurrent=256 << 20, NodePeak=512 << 20,
                      ControlCurrent=128 << 20, ControlPeak=256 << 20,
                      ControllerRSS=64 << 20, ControllerFDs=10, RootFree=1 << 30)
        samples = [{**sample, 'elapsed_ms': i * 10000} for i in range(240)]
        samples.append({**sample, 'elapsed_ms': 2401000, 'Allocated': 0})
        return {**dict.fromkeys(NODE_LOAD_SUCCESS_FLAGS, True),
                'slow_create_probes_started': 0, 'slow_create_probes_omitted': 0,
                'planned_raw_intents': 6360, 'planned_canary_intents': 240,
                'planned_quiescent_tail': 100, 'observed_result_rows': 6700,
                'accepted_replay_inventory_count': 1000, 'groups': groups,
                'resource_samples': samples, 'full_offered_window_ms': 2400000,
                'fixed_workers_each_tenant': 4, 'fixed_client_queue_each_tenant': 16,
                'nearest_rank_no_zero_latency_for_drops': True,
                'quotas_checked_only_quiescent_not_attributed_across_active_reuse': True,
                'load_window_completed': True, 'run_passed': True,
                'production_slo_claim': False, 'full_production_acceptance': False}

    def test_complete_synthetic_schema_and_all_positive_predicates_required(self):
        good = self.good()
        validate_node_load_result(good)
        for key in NODE_LOAD_SUCCESS_FLAGS + ('run_passed', 'load_window_completed'):
            for value in (False, 1, None, 'true'):
                bad = copy.deepcopy(good)
                bad[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(AssertionError):
                    validate_node_load_result(bad)
        for key in ('production_slo_claim', 'full_production_acceptance'):
            for value in (True, 0, None):
                with self.assertRaises(AssertionError):
                    validate_node_load_result({**good, key: value})

    def test_immutable_full_schedule_counts_workers_queues_and_no_short_success(self):
        for key in ('planned_raw_intents', 'planned_canary_intents', 'planned_quiescent_tail',
                    'observed_result_rows', 'full_offered_window_ms', 'fixed_workers_each_tenant',
                    'fixed_client_queue_each_tenant', 'accepted_replay_inventory_count'):
            for value in (True, 0, -1, math.inf, 100000):
                with self.subTest(key=key, value=value), self.assertRaises(AssertionError):
                    validate_node_load_result({**self.good(), key: value})
        bad = self.good()
        bad['groups'].pop()
        with self.assertRaises(AssertionError):
            validate_node_load_result(bad)
        bad = self.good()
        bad['groups'][1] = copy.deepcopy(bad['groups'][0])
        with self.assertRaises(AssertionError):
            validate_node_load_result(bad)

    def test_generator_drops_never_expand_api_denominator_or_zero_latency_success(self):
        for change in ('api_count', 'missing_metric', 'invented_full_gc', 'zero_count', 'failed'):
            bad = self.good()
            group = bad['groups'][0]
            if change == 'api_count':
                group['quantiles'][NODE_LOAD_METRICS[1]]['n'] = group['observed_intents']
            elif change == 'missing_metric':
                group['quantiles'].pop(NODE_LOAD_METRICS[1])
            elif change == 'invented_full_gc':
                group['quantiles'][NODE_LOAD_METRICS[9]] = copy.deepcopy(group['quantiles'][NODE_LOAD_METRICS[3]])
            elif change == 'zero_count':
                group['quantiles'][NODE_LOAD_METRICS[0]]['n'] = 0
            else:
                group['outcomes']['failed'] = 1
                group['outcomes']['generator_queue_drop'] -= 1
            with self.subTest(change=change), self.assertRaises(AssertionError):
                validate_node_load_result(bad)

    def test_fair_progress_canary_and_actual_service_refusal_are_separate_requirements(self):
        bad = self.good()
        # Keep the plan/outcome sums and all metric denominators coherent while
        # violating only the predeclared per-phase completion-share guard.
        group = bad['groups'][0]
        group['outcomes']['completed'] = 1
        group['outcomes']['generator_queue_drop'] = 29
        for q in group['quantiles'].values():
            q['n'] = 1
        with self.assertRaises(AssertionError):
            validate_node_load_result(bad)
        bad = self.good()
        canary = bad['groups'][8]
        canary['outcomes'].update(completed=0, generator_queue_drop=30)
        canary['quantiles'] = {}
        with self.assertRaises(AssertionError):
            validate_node_load_result(bad)
        bad = self.good()
        for group in bad['groups'][6:8]:
            group['outcomes']['service_unavailable503'] = 0
            group['outcomes']['generator_queue_drop'] += 1
            for key in NODE_LOAD_METRICS[:3]:
                group['quantiles'][key]['n'] -= 1
        with self.assertRaises(AssertionError):
            validate_node_load_result(bad)

    def test_resource_series_must_cover_window_and_remain_bounded_and_quiescent(self):
        for key, value in (('Allocated', 5), ('Records', 10001), ('ControllerFDs', 129),
                           ('StopQueued', 5), ('CleanupRunning', 3), ('RootFree', (256 << 20) - 1),
                           ('NodeOOM', 1), ('ControlOOMKills', 1), ('NodePeak', (7 << 30) + 1),
                           ('ControlPeak', (3840 << 20) + 1), ('NodeCurrent', 1 << 34),
                           ('QuotaNonempty', 5), ('observation_ms', 5001), ('elapsed_ms', math.nan)):
            bad = self.good()
            bad['resource_samples'][10][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                validate_node_load_result(bad)
        bad = self.good()
        bad['resource_samples'] = bad['resource_samples'][:2] + bad['resource_samples'][-1:]
        with self.assertRaises(AssertionError):
            validate_node_load_result(bad)
        for key, value in (('Allocated', 1), ('QuotaSpace', 4096), ('StopRunning', 1),
                           ('ControllerFDs', 15), ('elapsed_ms', 2399999)):
            bad = self.good()
            bad['resource_samples'][-1][key] = value
            with self.subTest(final=key), self.assertRaises(AssertionError):
                validate_node_load_result(bad)
        bad = self.good()
        bad['resource_samples'][10]['elapsed_ms'] = 1000
        with self.assertRaises(AssertionError):
            validate_node_load_result(bad)

    def test_nonfinite_timings_boolean_counts_unknown_fields_and_private_identity_rejected(self):
        for value in (-1, True, math.nan, math.inf, 4000001):
            bad = self.good()
            bad['groups'][0]['quantiles'][NODE_LOAD_METRICS[0]]['p50_ms'] = value
            with self.assertRaises(AssertionError):
                validate_node_load_result(bad)
        for value in (True, 0, 31):
            bad = self.good()
            bad['groups'][0]['quantiles'][NODE_LOAD_METRICS[0]]['n'] = value
            with self.assertRaises(AssertionError):
                validate_node_load_result(bad)
        for target in ('top', 'group', 'sample', 'quantile'):
            for field in ('pid', 'token', 'Ref', 'generation', 'stdout', 'first_failure'):
                bad = self.good()
                obj = bad if target == 'top' else bad['groups'][0] if target == 'group' else bad['resource_samples'][0] if target == 'sample' else bad['groups'][0]['quantiles'][NODE_LOAD_METRICS[0]]
                obj[field] = 'private'
                with self.subTest(target=target, field=field), self.assertRaises(AssertionError):
                    validate_node_load_result(bad)

    def test_new_profile_resources_and_metadata_plan_never_mutate_old_baseline(self):
        before = node_budget_policy()
        policy = node_load_policy(before)
        self.assertEqual(before, node_budget_policy())
        self.assertEqual((policy['max_records'], policy['max_sessions'], policy['controller_memory_max']),
                         (10000, 512, 3840 << 20))
        resources = nested_node_load_resources()
        self.assertEqual(resources, {'profile': 'node-load-v1', 'memory_mib': 8192,
                                     'disk_bytes': 12 << 30, 'cgroup_memory_max': 10 << 30})
        self.assertEqual(nested_group_limits(resources),
                         {'memory.max': str(10 << 30), 'memory.swap.max': '0',
                          'memory.oom.group': '1', 'pids.max': '256',
                          'cpu.max': '800000 100000'})
        node_load_profile(True, False, None)
        for enabled, others in ((1, []), (None, []), (True, [True]), (True, ['operator'])):
            with self.assertRaises(ValueError):
                node_load_profile(enabled, *others)
        _, service = init_scripts([], node_load=True)
        self.assertIn('rw,nosuid,prjquota', service)
        self.assertIn('-mode node-load', service)
        self.assertNotIn('-mode node-budget', service)
        for flag in ('node_budget', 'node_snapshot', 'quota_switch', 'quota_driver'):
            with self.assertRaises(ValueError):
                init_scripts([], node_load=True, **{flag: True})

    def test_closed_socket_frame_enlargement_is_opt_in_and_bounded(self):
        for kw, expected in (({}, 65536), ({'quota_switch': True}, 2 << 20),
                             ({'node_load': True}, NODE_LOAD_MAX_FRAME)):
            with mock.patch('kvm_nested_host.socket.socket') as factory:
                factory.return_value.makefile.return_value = io.BytesIO(b'{"ok":true}\n')
                channel = JSONSocket('/never-connected', **kw)
                self.assertEqual(channel.max_frame, expected)
                self.assertEqual(channel.read(), {'ok': True})
                channel.close()
        for kw in ({'quota_switch': True, 'node_load': True}, {'node_load': 1}):
            with self.assertRaises(AssertionError):
                JSONSocket('/never-connected', **kw)
        channel = JSONSocket.__new__(JSONSocket)
        channel.max_frame = NODE_LOAD_MAX_FRAME
        channel.file = io.BytesIO(b' ' * (NODE_LOAD_MAX_FRAME + 1) + b'\n')
        with self.assertRaises(AssertionError):
            channel.read()

    def test_private_actor_trace_is_versioned_bounded_and_removed_with_sidecar(self):
        value = {**self.good(), 'private_load_diagnostics': self.private_capsule()}
        public, private = detach_node_load_private(value)
        validate_node_load_result(public)
        self.assertEqual(private['actors']['version'], 2)
        self.assertNotIn('canary_switch_http', json.dumps(public))
        self.assertNotIn('budget_known', json.dumps(public))
        self.assertIn('actors', value['private_load_diagnostics'])  # no mutation
        bad = copy.deepcopy(value)
        del bad['private_load_diagnostics']['actors']
        with self.assertRaises(AssertionError):
            detach_node_load_private(bad)  # old source wire is not new evidence

    def test_private_actor_failed_snapshot_must_match_first_actual_worker(self):
        value = {**self.good(), 'run_passed': False, 'private_load_diagnostics': self.private_capsule()}
        failure = self.private_actor(1, 64, 0)
        failure.update(result_stage='canary_switch', elapsed_ms=35000.78, outcome='deadline')
        failure['phases'] = [
            {'phase': 'canary_open_http', 'begin_ms': 0, 'end_ms': 24225.451, 'ended': True, 'outcome': 'ok'},
            {'phase': 'canary_switch_http', 'begin_ms': 24225.451, 'end_ms': 35000.78, 'ended': True, 'outcome': 'deadline'}]
        failure['server'] = [
            {'phase': 'canary_open_http', 'response_observed': True, 'timings_present': True,
             'entries': [{'phase': 'xa_core_admission', 'ms': 20000, 'calls': 1}]},
            {'phase': 'canary_switch_http', 'response_observed': False, 'timings_present': False, 'entries': []}]
        value['first_failure'] = {'Kind': 1, 'Index': 64, 'Tenant': 0, 'Stage': 'canary_switch'}
        value['private_load_diagnostics']['actors']['failure'] = failure
        _, private = detach_node_load_private(value)
        self.assertEqual(private['actors']['failure'], failure)
        for field, replacement in (('Index', 66), ('Tenant', 1), ('Kind', 0), ('Stage', 'canary_new')):
            bad = copy.deepcopy(value); bad['first_failure'][field] = replacement
            with self.subTest(field=field), self.assertRaises(AssertionError):
                detach_node_load_private(bad)
        bad = copy.deepcopy(value); bad['private_load_diagnostics']['actors']['failure'] = None
        with self.assertRaises(AssertionError):
            detach_node_load_private(bad)

    def test_private_actor_schema_rejects_selector_identity_and_timing_fabrication(self):
        good = self.private_actors()
        cases = [
            ('top_version', lambda v: v.update(version=0)),
            ('boolean_version', lambda v: v.update(version=True)),
            ('invalid_registry', lambda v: v.update(invalid=True)),
            ('unknown_top', lambda v: v.update(token='private')),
            ('too_many', lambda v: v.update(latest=v['latest'] * 3)),
            ('duplicate_slot', lambda v: v['latest'].append(copy.deepcopy(v['latest'][0]))),
            ('worker', lambda v: v['latest'][0].update(worker=4)),
            ('intent_parity', lambda v: v['latest'][0].update(intent_index=1)),
            ('canary_bound', lambda v: v['latest'][2].update(intent_index=240)),
            ('tenant', lambda v: v['latest'][0].update(tenant=True)),
            ('actor_identity', lambda v: v['latest'][0].update(ref='private')),
            ('invalid_actor', lambda v: v['latest'][0].update(invalid=True)),
            ('nan', lambda v: v['latest'][0].update(elapsed_ms=float('nan'))),
            ('infinite', lambda v: v['latest'][0].update(budget_ms=float('inf'))),
            ('boolean_time', lambda v: v['latest'][0].update(elapsed_ms=True)),
            ('stretched_budget', lambda v: v['latest'][0].update(budget_ms=35001)),
            ('unknown_budget_invented', lambda v: v['latest'][0].update(budget_known=False)),
            ('raw_error', lambda v: v['latest'][0].update(outcome='context deadline with private path')),
            ('open_result_stage', lambda v: v['latest'][0].update(result_stage='arbitrary')),
            ('phase_selector', lambda v: v['latest'][0]['phases'][0].update(phase='private selector')),
            ('phase_identity', lambda v: v['latest'][0]['phases'][0].update(pid=99)),
            ('wrong_actor_phase', lambda v: v['latest'][0]['phases'][0].update(phase='canary_switch_http')),
            ('release_without_switch', lambda v: v['latest'][2]['phases'][0].update(phase='canary_release')),
            ('duplicate_phase', lambda v: v['latest'][0]['phases'].append(copy.deepcopy(v['latest'][0]['phases'][0]))),
            ('too_many_phases', lambda v: v['latest'][0].update(phases=v['latest'][0]['phases'] * 17)),
            ('end_before_start', lambda v: v['latest'][0]['phases'][0].update(begin_ms=2)),
            ('past_actor_end', lambda v: v['latest'][0]['phases'][0].update(end_ms=2)),
            ('done_pending_phase', lambda v: v['latest'][0]['phases'][0].update(ended=False, end_ms=0, outcome='pending')),
            ('done_pending_result', lambda v: v['latest'][0].update(outcome='pending')),
            ('nonboolean_done', lambda v: v['latest'][0].update(done=0)),
            ('nonboolean_ended', lambda v: v['latest'][0]['phases'][0].update(ended=1)),
            ('unknown_outcome', lambda v: v['latest'][0]['phases'][0].update(outcome='secret')),
            ('missing_canary', lambda v: v['latest'].pop()),
        ]
        for name, mutate in cases:
            v = copy.deepcopy(good); mutate(v)
            with self.subTest(name=name), self.assertRaises(AssertionError):
                validate_node_load_actors(v, {'run_passed': True})

    def test_private_actor_pending_and_unknown_deadline_never_invent_completion(self):
        actor = self.private_actor(0, 0, 0)
        actor.update(done=False, result_stage='', outcome='pending', budget_known=False, budget_ms=0)
        actor['phases'][0].update(ended=False, end_ms=0, outcome='pending')
        v = {'version': 2, 'invalid': False, 'latest': [actor], 'failure': None}
        validate_node_load_actors(v, {'run_passed': False})
        for change in ({'end_ms': 1}, {'outcome': 'ok'}):
            bad = copy.deepcopy(v); bad['latest'][0]['phases'][0].update(change)
            with self.assertRaises(AssertionError):
                validate_node_load_actors(bad, {'run_passed': False})

    def test_private_capacity_gauges_cannot_change_policy_or_project_wait_reason(self):
        good = {'queued': 3, 'capacity': 8, 'class_capacity': 4}
        validate_node_load_capacity(good)
        for changes in ({'queued': True}, {'queued': -1}, {'queued': 9}, {'capacity': 9},
                        {'class_capacity': 5}, {'prepare_wait_ms': 30}):
            bad = {**good, **changes}
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                validate_node_load_capacity(bad)
        value = {**self.good(), 'private_load_diagnostics': self.private_capsule(failure=self.private_observation())}
        value['private_load_diagnostics']['failure']['capacity'] = None
        with self.assertRaises(AssertionError):
            detach_node_load_private(value)  # complete cannot mean missing queue evidence
        value['private_load_diagnostics']['failure']['complete'] = False
        detach_node_load_private(value)  # incomplete observation stays explicit

    def private_census(self):
        value = dict.fromkeys(NODE_LOAD_CENSUS_FIELDS, 0)
        value.update(available=True, complete=True, truncated=False,
                     managed_controller_zombie=False, candidates=16, scanned=16,
                     capture_ms=10, node_pids=18, control_pids=18,
                     init_reaper={'active': True, 'sweeps': 1, 'reaped': 0, 'errors': 0})
        return value

    def test_private_server_phase_vocabulary_and_overlapping_children(self):
        root = Path(__file__).resolve().parents[1]
        for path, name in (('internal/telemetry/creation.go', 'creationNames'),
                           ('cmd/xandbox-host-fixture/node_load_server_linux.go', 'nodeLoadServerNames')):
            text = (root / path).read_text()
            start = text.index('var ' + name + ' = [...]string{')
            end = text.index('\n}', start)
            names = tuple(re.findall(r'"(xa_[a-z_]+)"', text[start:end]))
            self.assertEqual(names, NODE_LOAD_SERVER_PHASES)
        v = self.private_actors()
        entries = v['latest'][2]['server'][0]['entries']
        entries[:] = [{'phase': 'xa_core_admission', 'ms': 0.1, 'calls': 1},
                      {'phase': 'xa_core_driver', 'ms': 0.8, 'calls': 1},
                      {'phase': 'xa_driver_slot', 'ms': 0.7, 'calls': 1}]
        validate_node_load_actors(v, {'run_passed': True})
        self.assertGreater(sum(x['ms'] for x in entries), 1)  # parent includes child, not a serial sum

    def test_private_server_phase_schema_rejects_fabricated_or_missing_evidence(self):
        good = self.private_actors()
        changes = [
            lambda v: v.update(version=1),
            lambda v: v['latest'][0].pop('server'),
            lambda v: v['latest'][0]['server'].append(copy.deepcopy(v['latest'][0]['server'][0])),
            lambda v: v['latest'][0]['server'][0].update(phase='canary_switch_http'),
            lambda v: v['latest'][0]['server'][0].update(key='private'),
            lambda v: v['latest'][0]['server'][0].update(response_observed=False),
            lambda v: v['latest'][0]['server'][0].update(timings_present=1),
            lambda v: v['latest'][0]['server'][0].update(entries=[]),
            lambda v: v['latest'][0]['server'][0].update(timings_present=False),
            lambda v: v['latest'][0]['server'][0]['entries'][0].update(phase='private'),
            lambda v: v['latest'][0]['server'][0]['entries'][0].update(token='private'),
            lambda v: v['latest'][0]['server'][0]['entries'][0].update(calls=2),
            lambda v: v['latest'][0]['server'][0]['entries'][0].update(calls=True),
            lambda v: v['latest'][0]['server'][0]['entries'][0].update(ms=float('nan')),
            lambda v: v['latest'][0]['server'][0]['entries'][0].update(ms=float('inf')),
            lambda v: v['latest'][0]['server'][0]['entries'][0].update(ms=-1),
            lambda v: v['latest'][0]['server'][0]['entries'][0].update(ms=35002),
            lambda v: v['latest'][0]['server'][0]['entries'][0].update(ms=3),
            lambda v: v['latest'][0]['server'][0]['entries'][0].update(phase='xa_driver_slot'),
            lambda v: v['latest'][0]['server'][0]['entries'][0].update(phase='xa_session_intent_commit'),
            lambda v: v['latest'][0]['server'][0]['entries'].append(copy.deepcopy(v['latest'][0]['server'][0]['entries'][0])),
        ]
        for n, change in enumerate(changes):
            bad = copy.deepcopy(good); change(bad)
            with self.subTest(n=n), self.assertRaises(AssertionError):
                validate_node_load_actors(bad, {'run_passed': True})
        absent = copy.deepcopy(good)
        absent['latest'][0]['server'][0].update(response_observed=False, timings_present=False, entries=[])
        validate_node_load_actors(absent, {'run_passed': False})  # unknown is retained, not invented zero
        with self.assertRaises(AssertionError):
            validate_node_load_actors(absent, {'run_passed': True})

    def private_actor(self, kind, index, tenant, worker=0):
        return {'kind': kind, 'intent_index': index, 'tenant': tenant, 'worker': worker,
                'elapsed_ms': 1, 'budget_known': True, 'budget_ms': 35000,
                'done': True, 'result_stage': 'raw_replay' if kind == 0 else 'canary_replay',
                'outcome': 'ok', 'invalid': False,
                'server': [{'phase': 'raw_create' if kind == 0 else 'canary_switch_http',
                            'response_observed': True, 'timings_present': True,
                            'entries': [{'phase': 'xa_core_admission', 'ms': 0.5, 'calls': 1}]}],
                'phases': [{'phase': 'raw_create' if kind == 0 else 'canary_switch_http',
                            'begin_ms': 0, 'end_ms': 1, 'ended': True, 'outcome': 'ok'}]}

    def private_actors(self):
        return {'version': 2, 'invalid': False,
                'latest': [self.private_actor(kind, tenant, tenant)
                           for kind in (0, 1) for tenant in (0, 1)], 'failure': None}

    def private_capsule(self, slow=None, failure=None):
        after = self.private_census()
        after['init_reaper']['reaped'] = 8
        return {'slow': slow, 'omitted': 0, 'failure': failure, 'actors': self.private_actors(),
                'creation_activity_version': 1,
                'pid1_preflight_before': self.private_census(),
                'pid1_preflight_after': after}

    def private_observation(self):
        return {
            'available': True, 'elapsed_ms': 20000, 'offered_origin_known': True, 'capture_ms': 10, 'complete': True,
            'record_found': True, 'record_state': 'CREATING', 'stream_kind': 0,
            'intent_index': 627, 'tenant': 1, 'diagnostic_read_ok': True,
            'ledger_scan_truncated': False, 'ledger_candidates': 3, 'ledger_inspected': 1,
            'ledger_read_errors': 0, 'owner_present': True, 'cgroup_present': True,
            'jail_present': True, 'workspace_present': True, 'api_socket_present': False,
            'vsocket_present': False, 'workspace_logical_bytes': 128 << 20,
            'last_error_private': 'private-error-sentinel',
            'recent_errors_private': ['private-error-sentinel'],
            'kernel': copy.deepcopy(self.good()['resource_samples'][0]['kernel']),
            'capacity': {'queued': 3, 'capacity': 8, 'class_capacity': 4},
            'creation_activity_status': 'missing', 'creation_activity': None,
            'pid1_census': self.private_census(), 'diagnostic_sequence': 1,
            'diagnostic_records': [{'sequence': 1, 'kind': 2, 'reason': 1,
                                    'time_unix_ns': 1, 'dropped_before': 0}]}

    def activity_value(self):
        return {'version': 1, 'requests': [0, 0, 1], 'phases': [[0] * 15 for _ in range(3)]}

    def test_creation_activity_sealed_subprotocol_is_not_transactional(self):
        value = self.activity_value()
        value['requests'][2] = 0
        value['phases'][2][13] = 1
        validate_node_load_creation_activity('observed', value)
        # Independent loads can cross a request/phase transition; this is NOT
        # evidence of an impossible request or a uniquely identified actor.
        self.assertEqual(value['phases'][2][13], 1)

    def test_creation_activity_unknown_is_null_not_zero(self):
        for status in ('missing', 'disabled', 'invalid', 'malformed'):
            validate_node_load_creation_activity(status, None)
            with self.assertRaises(AssertionError):
                validate_node_load_creation_activity(status, self.activity_value())
        with self.assertRaises(AssertionError):
            validate_node_load_creation_activity('observed', None)
        with self.assertRaises(AssertionError):
            validate_node_load_creation_activity('unreviewed-secret', None)

    def test_creation_activity_refuses_version_labels_dimensions_and_bad_counts(self):
        variants = []
        for field, replacement in (('version', True), ('version', 2), ('requests', [0, 1]),
                                   ('phases', [[0] * 15] * 2), ('phases', [[0] * 14] * 3)):
            value = self.activity_value(); value[field] = replacement; variants.append(value)
        for replacement in (True, -1, 1.5, float('nan'), 1048577, '1'):
            value = self.activity_value(); value['requests'][0] = replacement; variants.append(value)
            value = self.activity_value(); value['phases'][0][0] = replacement; variants.append(value)
        value = self.activity_value(); value['tenant-key'] = 'private'; variants.append(value)
        for value in variants:
            with self.assertRaises(AssertionError):
                validate_node_load_creation_activity('observed', value)

    def test_creation_activity_new_observation_fields_do_not_reinterpret_old_wire(self):
        value = self.good(); value['slow_create_probes_started'] = 1
        value['private_load_diagnostics'] = self.private_capsule(slow=[self.private_observation()])
        detach_node_load_private(value)
        for field in ('creation_activity_status', 'creation_activity'):
            old = copy.deepcopy(value)
            del old['private_load_diagnostics']['slow'][0][field]
            with self.assertRaises(AssertionError):
                detach_node_load_private(old)  # old wire needs its frozen parser

    def test_creation_activity_version_discriminates_empty_old_capsules(self):
        value = self.good()
        value['private_load_diagnostics'] = self.private_capsule()
        detach_node_load_private(value)
        for version in (None, True, 0, 2, '1'):
            old = copy.deepcopy(value)
            if version is None:
                del old['private_load_diagnostics']['creation_activity_version']
            else:
                old['private_load_diagnostics']['creation_activity_version'] = version
            with self.assertRaises(AssertionError):
                detach_node_load_private(old)

    def test_creation_activity_is_detached_and_keeps_all_original_byte_bounds(self):
        value = self.good(); value['slow_create_probes_started'] = 1
        row = self.private_observation(); row['creation_activity_status'] = 'observed'
        row['creation_activity'] = self.activity_value()
        row['creation_activity']['phases'][2][14] = 1
        value['private_load_diagnostics'] = self.private_capsule(slow=[row])
        public, private = detach_node_load_private(value)
        validate_node_load_result(public)
        self.assertNotIn('creation_activity', json.dumps(public))
        self.assertEqual(private['slow'][0]['creation_activity']['phases'][2][14], 1)
        self.assertEqual(NODE_LOAD_MAX_FRAME, 1 << 20)
        self.assertLessEqual(len(json.dumps(private, ensure_ascii=True).encode()), 192 << 10)

    def test_private_shadow_is_detached_before_any_passing_public_projection(self):
        value = self.good()
        value['slow_create_probes_started'] = 1
        value['private_load_diagnostics'] = self.private_capsule(slow=[self.private_observation()])
        with self.assertRaises(AssertionError):
            validate_node_load_result(value)
        public, sidecar = detach_node_load_private(value)
        validate_node_load_result(public)
        self.assertNotIn('private_load_diagnostics', public)
        self.assertNotIn('private-error-sentinel', __import__('json').dumps(public))
        self.assertEqual(sidecar['slow'][0]['last_error_private'], 'private-error-sentinel')
        self.assertIn('private_load_diagnostics', value)  # no mutation/hidden loss
        with self.assertRaises(AssertionError):
            detach_node_load_private(self.good())  # new passing wire cannot omit both preflight censuses
        failed_without_census = {**self.good(), 'run_passed': False}
        public, sidecar = detach_node_load_private(failed_without_census)
        self.assertIsNone(sidecar)  # setup may fail before the first census
        value = self.good()
        value['run_passed'] = False
        value['private_load_diagnostics'] = self.private_capsule(failure=self.private_observation())
        public, sidecar = detach_node_load_private(value)
        self.assertEqual(sidecar['failure']['intent_index'], 627)
        with self.assertRaises(AssertionError):
            validate_node_load_result(public)

    def test_private_capsule_limits_unknown_fields_and_false_null_aliases_rejected(self):
        good = self.good()
        good['slow_create_probes_started'] = 1
        good['private_load_diagnostics'] = self.private_capsule(slow=[self.private_observation()])
        for name in ('extra', 'oversized', 'boolean_count', 'too_many', 'private_field',
                     'false_errors', 'false_records', 'bad_kind', 'bad_kernel'):
            bad = copy.deepcopy(good)
            cap = bad['private_load_diagnostics']
            row = cap['slow'][0]
            if name == 'extra':
                cap['unreviewed'] = 'private'
            elif name == 'oversized':
                row['last_error_private'] = 'x' * 516
            elif name == 'boolean_count':
                bad['slow_create_probes_started'] = True
            elif name == 'too_many':
                cap['slow'] *= 9
                bad['slow_create_probes_started'] = 9
            elif name == 'private_field':
                row['token'] = 'private'
            elif name == 'false_errors':
                row['recent_errors_private'] = False
            elif name == 'false_records':
                row['diagnostic_records'] = False
            elif name == 'bad_kind':
                row['stream_kind'] = -2
            else:
                row['kernel']['controller_threads'] = True
            with self.subTest(name=name), self.assertRaises(AssertionError):
                detach_node_load_private(bad)
        bad = self.good()
        bad['slow_create_probes_started'] = False
        with self.assertRaises(AssertionError):
            detach_node_load_private(bad)
        bad = copy.deepcopy(good)
        bad['private_load_diagnostics']['slow'] = False
        bad['slow_create_probes_started'] = 0
        with self.assertRaises(AssertionError):
            detach_node_load_private(bad)

    def test_private_reply_survives_schema_failure_without_overwrite_or_public_leak(self):
        value = self.good()
        value['private_load_diagnostics'] = self.private_capsule(failure=self.private_observation())
        reply = {'ok': False, 'result': value}
        for malformed in (False, True):
            sample = copy.deepcopy(reply)
            if malformed:
                sample['result']['private_load_diagnostics']['failure']['token'] = 'private'
            with tempfile.TemporaryDirectory() as root:
                logs = Path(root)
                if malformed:
                    with self.assertRaises(AssertionError):
                        preserve_node_load_reply(sample, logs)
                    self.assertFalse((logs/'node-load-diagnostics-private.json').exists())
                else:
                    clean = preserve_node_load_reply(sample, logs)
                    self.assertFalse(clean['ok'])
                    self.assertNotIn('private-error-sentinel', json.dumps(clean))
                    self.assertIn('private-error-sentinel', (logs/'node-load-diagnostics-private.json').read_text())
                saved = logs/'node-load-wire-private.json'
                self.assertEqual(json.loads(saved.read_text()), sample)
                self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o600)
                with self.assertRaises(FileExistsError):
                    preserve_node_load_reply(sample, logs)
                self.assertEqual(json.loads(saved.read_text()), sample)

    def test_preflight_private_time_never_impersonates_offered_window_origin(self):
        row = self.private_observation()
        row.update(stream_kind=3, offered_origin_known=False, elapsed_ms=0)
        value = {**self.good(), 'slow_create_probes_started': 1,
                 'private_load_diagnostics': self.private_capsule(slow=[row])}
        public, private = detach_node_load_private(value)
        validate_node_load_result(public)
        self.assertEqual(private['slow'][0]['stream_kind'], 3)
        for field, val in (('elapsed_ms', 1), ('offered_origin_known', 0), ('stream_kind', 4)):
            bad = copy.deepcopy(value)
            bad['private_load_diagnostics']['slow'][0][field] = val
            with self.subTest(field=field), self.assertRaises(AssertionError):
                detach_node_load_private(bad)

    def test_private_census_retains_zombies_as_failure_not_clean_success(self):
        census = self.private_census()
        census.update(adopted_zombies=8, vmm_zombies=8, reserved_uid_zombies=8,
                      membership_unknown_zombies=8, node_pids=26)
        validate_node_load_census(census)
        with self.assertRaises(AssertionError):
            validate_node_load_census(census, require_clean=True)
        value = {**self.good(), 'run_passed': False,
                 'private_load_diagnostics': self.private_capsule()}
        value['private_load_diagnostics']['pid1_preflight_after'] = census
        public, private = detach_node_load_private(value)
        self.assertEqual(private['pid1_preflight_after']['vmm_zombies'], 8)
        self.assertNotIn('adopted_zombies', json.dumps(public))
        with self.assertRaises(AssertionError):
            detach_node_load_private({**value, 'run_passed': True})
        before_missing = copy.deepcopy(value)
        before_missing['run_passed'] = True
        before_missing['private_load_diagnostics']['pid1_preflight_before'] = None
        with self.assertRaises(AssertionError):
            detach_node_load_private(before_missing)

    def test_census_schema_has_no_identity_or_unbounded_incomplete_success(self):
        good = self.private_census()
        validate_node_load_census(good, require_clean=True)
        for name, value in (('scanned', True), ('candidates', 4097), ('capture_ms', math.nan),
                            ('adopted_zombies', 1), ('read_errors', 1),
                            ('membership_unknown_zombies', 1), ('deleted_scoped_zombies', 1),
                            ('truncated', True), ('available', False), ('scanned', 0)):
            bad = {**good, name: value}
            with self.subTest(name=name, value=value), self.assertRaises(AssertionError):
                validate_node_load_census(bad)
        for name in ('pid', 'ppid', 'comm', 'uid', 'cgroup', 'startticks'):
            with self.subTest(name=name), self.assertRaises(AssertionError):
                validate_node_load_census({**good, name: 'private'})
        incomplete = {**good, 'complete': False, 'read_errors': 1}
        validate_node_load_census(incomplete)  # private lower-bound failure evidence is retained
        with self.assertRaises(AssertionError):
            validate_node_load_census(incomplete, require_clean=True)

    def test_owned_init_evidence_cannot_be_omitted_or_fake_success_on_new_wire(self):
        good = {**self.good(), 'private_load_diagnostics': self.private_capsule()}
        public, private = detach_node_load_private(good)
        validate_node_load_result(public)
        self.assertNotIn('init_reaper', json.dumps(public))
        for mode in ('absent', 'inactive', 'error', 'no_sweep', 'not_eight', 'charge_retained', 'identity', 'boolean_count'):
            bad = copy.deepcopy(good)
            census = bad['private_load_diagnostics']['pid1_preflight_after']
            init = census['init_reaper']
            if mode == 'absent':
                del census['init_reaper']
            elif mode == 'inactive':
                init['active'] = False
            elif mode == 'error':
                init['errors'] = 1
            elif mode == 'no_sweep':
                init['sweeps'] = 0
            elif mode == 'not_eight':
                init['reaped'] = 7
            elif mode == 'charge_retained':
                census['node_pids'] += 1
            elif mode == 'identity':
                init['pid'] = 123
            elif mode == 'boolean_count':
                init['reaped'] = True
            with self.subTest(mode=mode), self.assertRaises(AssertionError):
                detach_node_load_private(bad)
        legacy = self.private_census()
        del legacy['init_reaper']
        validate_node_load_census(legacy)  # old failed negative control is not re-signed
        with self.assertRaises(AssertionError):
            validate_node_load_census(legacy, require_clean=True)

    def test_kernel_series_reports_exact_device_observation_and_closed_counts(self):
        for name, value in (('controller_threads', 0), ('controller_threads', True),
                            ('node_pids', 385), ('control_pids', 129),
                            ('node_pids_max_events', 1), ('prepare_failed_other', 1),
                            ('node_io_observed', 2), ('control_io_wbytes', -1)):
            bad = self.good()
            bad['resource_samples'][10]['kernel'][name] = value
            with self.subTest(name=name, value=value), self.assertRaises(AssertionError):
                validate_node_load_result(bad)
        bad = self.good()
        bad['resource_samples'][10]['kernel']['node_io_wbytes'] = 9000
        with self.assertRaises(AssertionError):
            validate_node_load_result(bad)  # no observed row is not measured zero/9000
        good = self.good()
        good['resource_samples'][10]['kernel'].update(node_io_observed=1,
                                                      node_io_wbytes=9000)
        validate_node_load_result(good)


if __name__ == '__main__':
    unittest.main()
