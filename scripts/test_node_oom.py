import copy
import math
import unittest

from kvm_nested_host import (NODE_OOM_CHECKPOINT_FLAGS, NODE_OOM_COUNTERS,
                             NODE_OOM_TIMES, node_oom_profile,
                             validate_node_oom_checkpoint)


class NodeOOMTests(unittest.TestCase):
    def good(self):
        return {**dict.fromkeys(NODE_OOM_CHECKPOINT_FLAGS, True),
                'fixed_helper_allocation_request_bytes': 1 << 30,
                'guest_workload_bytes_each': 96 << 20,
                'fixed_helper_guard_ms': 20000,
                'guest_host_anon_delta_bytes_each': [80 << 20] * 4,
                **dict.fromkeys(NODE_OOM_COUNTERS, 1),
                'oom_release_to_target_empty_observed_ms': 100.5,
                'neighbor_stop_to_empty_observed_ms': 110.25,
                'neighbor_stop_to_all_private_reclaimed_observed_ms': 200.5,
                'production_slo_claim': False, 'whole_node_saturation_claim': False}

    def test_all_positive_predicates_and_explicit_negative_claims_required(self):
        good = self.good()
        validate_node_oom_checkpoint(good)
        for field in NODE_OOM_CHECKPOINT_FLAGS:
            for value in (False, 1, None, 'true'):
                bad = copy.deepcopy(good)
                bad[field] = value
                with self.assertRaises(AssertionError):
                    validate_node_oom_checkpoint(bad)
            bad = copy.deepcopy(good)
            del bad[field]
            with self.assertRaises(AssertionError):
                validate_node_oom_checkpoint(bad)
        for field in ('production_slo_claim', 'whole_node_saturation_claim'):
            for value in (True, 0, None):
                bad = copy.deepcopy(good)
                bad[field] = value
                with self.assertRaises(AssertionError):
                    validate_node_oom_checkpoint(bad)

    def test_missing_kernel_evidence_boolean_numbers_overflow_and_nonfinite_fail(self):
        for field in NODE_OOM_COUNTERS:
            for value in (0, -1, True, math.nan, math.inf, 1 << 64):
                bad = self.good()
                bad[field] = value
                with self.assertRaises(AssertionError):
                    validate_node_oom_checkpoint(bad)
        for field in NODE_OOM_TIMES:
            for value in (-1, True, math.nan, math.inf, 200000):
                bad = self.good()
                bad[field] = value
                with self.assertRaises(AssertionError):
                    validate_node_oom_checkpoint(bad)
        for fields in ({'oom_release_to_target_empty_observed_ms': 20000},
                       {'neighbor_stop_to_empty_observed_ms': 201},
                       {'target_observed_oom_kills': 2, 'node_hierarchical_oom_kills': 1},
                       {'fixed_helper_guard_ms': 20001},
                       {'fixed_helper_allocation_request_bytes': True},
                       {'guest_workload_bytes_each': 8 << 20}):
            with self.assertRaises(AssertionError):
                validate_node_oom_checkpoint({**self.good(), **fields})

    def test_every_actual_resident_delta_required_no_sparse_allocation_claim(self):
        for values in ([80 << 20] * 3, [80 << 20] * 5,
                       [True] * 4, [0] * 4, [64 << 20] * 3 + [math.nan],
                       [80 << 20] * 3 + [(64 << 20) - 1],
                       [80 << 20] * 3 + [(768 << 20) + 1]):
            bad = self.good()
            bad['guest_host_anon_delta_bytes_each'] = values
            with self.assertRaises(AssertionError):
                validate_node_oom_checkpoint(bad)

    def test_exact_schema_never_exports_raw_identity_or_easier_success_extensions(self):
        for name in ('pid', 'uid', 'argv', 'stdout', 'token', 'generation',
                     'boot_id', 'cgroup', 'raw_receipt', 'new_success_flag'):
            bad = self.good()
            bad[name] = 'private'
            with self.assertRaises(AssertionError):
                validate_node_oom_checkpoint(bad)

    def test_modifier_is_explicit_and_exclusive_without_expanding_old_profiles(self):
        node_oom_profile(True, True)
        node_oom_profile(True, True, False, None, False)
        node_oom_profile(False, False)
        for budget, enabled, others in ((False, True, []), (True, True, [True]),
                                        (True, True, ['pre-file']), (True, True, ['gateway']),
                                        (1, True, []), (True, 1, []), (True, None, [])):
            with self.assertRaises(ValueError):
                node_oom_profile(budget, enabled, *others)


if __name__ == '__main__':
    unittest.main()
