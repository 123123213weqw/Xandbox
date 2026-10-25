import copy
import unittest
from kvm_nested_host import (NODE_OPERATOR_CHECKPOINT_FLAGS, NODE_OPERATOR_RECOVERY_FLAGS,
    node_operator_profile, validate_node_operator_checkpoint, validate_node_operator_recovery)


def checkpoint():
    return {**{k: True for k in NODE_OPERATOR_CHECKPOINT_FLAGS},
        'stop_execution_domain_observed_ms': 1.0, 'private_reclaim_observed_ms': 2.0,
        'operator_filesystem_fault_or_physical_media_failure_claim': False, 'production_slo_claim': False}


class NodeOperatorTests(unittest.TestCase):
    def test_fixed_no_snapshot_profile_only(self):
        for budget, enabled in ((False, False), (True, False), (True, True)):
            node_operator_profile(budget, enabled)
        with self.assertRaises(ValueError):
            node_operator_profile(False, True)

    def test_all_checkpoint_witnesses_required_no_dac_or_mock_shortcut(self):
        value = checkpoint()
        validate_node_operator_checkpoint(value)
        for key in NODE_OPERATOR_CHECKPOINT_FLAGS:
            for action in ('missing', 'false', 'integer'):
                bad = copy.deepcopy(value)
                if action == 'missing': del bad[key]
                else: bad[key] = False if action == 'false' else 1
                with self.assertRaises(AssertionError): validate_node_operator_checkpoint(bad)
        for key in ('operator_filesystem_fault_or_physical_media_failure_claim', 'production_slo_claim'):
            bad = dict(value, **{key: True})
            with self.assertRaises(AssertionError): validate_node_operator_checkpoint(bad)
        for key in ('raw_epoch', 'raw_peer_pid', 'token', 'socket_path'):
            bad = dict(value, **{key: 'private'})
            with self.assertRaises(AssertionError): validate_node_operator_checkpoint(bad)

    def test_stop_and_private_reclaim_timings_not_credit_or_slo(self):
        for key in ('stop_execution_domain_observed_ms', 'private_reclaim_observed_ms'):
            for number in (True, -1, float('nan'), float('inf'), 200000):
                bad = checkpoint(); bad[key] = number
                with self.assertRaises(AssertionError): validate_node_operator_checkpoint(bad)
        bad = checkpoint(); bad['stop_execution_domain_observed_ms'] = 3
        with self.assertRaises(AssertionError): validate_node_operator_checkpoint(bad)

    def test_cold_requires_pre_daemon_state_owner_quota_and_no_route_resurrection(self):
        good = {k: True for k in NODE_OPERATOR_RECOVERY_FLAGS}
        validate_node_operator_recovery(good)
        for key in good:
            bad = dict(good); bad[key] = False
            with self.assertRaises(AssertionError): validate_node_operator_recovery(bad)
        with self.assertRaises(AssertionError): validate_node_operator_recovery(dict(good, raw_state='private'))


if __name__ == '__main__':
    unittest.main()
