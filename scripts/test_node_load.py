"""Synthetic contract tests, NOT sustained-load or Linux/KVM evidence."""
import copy
import io
import math
import unittest
from unittest import mock

from build_nested_host import init_scripts
from kvm_nested_host import JSONSocket, nested_group_limits, node_budget_policy
from node_load_contract import (NODE_LOAD_MAX_FRAME, NODE_LOAD_PHASE_COUNTS,
                                NODE_LOAD_OUTCOMES, NODE_LOAD_METRICS,
                                NODE_LOAD_SUCCESS_FLAGS, node_load_profile,
                                nested_node_load_resources, node_load_policy,
                                validate_node_load_result)


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
        sample.update(observation_ms=10, Allocated=2, Records=100,
                      NodeCurrent=256 << 20, NodePeak=512 << 20,
                      ControlCurrent=128 << 20, ControlPeak=256 << 20,
                      ControllerRSS=64 << 20, ControllerFDs=10, RootFree=1 << 30)
        samples = [{**sample, 'elapsed_ms': i * 10000} for i in range(240)]
        samples.append({**sample, 'elapsed_ms': 2401000, 'Allocated': 0})
        return {**dict.fromkeys(NODE_LOAD_SUCCESS_FLAGS, True),
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


if __name__ == '__main__':
    unittest.main()
