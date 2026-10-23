import copy
import unittest
from kvm_nested_host import (NODE_OPERATOR_STORE_FLAGS, NODE_OPERATOR_STORE_RECOVERY_FLAGS,
    node_operator_store_profile, validate_node_operator_store_checkpoint, validate_node_operator_store_recovery)


def checkpoint(mode):
    post = mode == 'post-root'
    return {**{k: True for k in NODE_OPERATOR_STORE_FLAGS}, 'mode': mode,
        'file_sync_entries': 1, 'admission_dir_sync_entries': int(post), 'root_dir_sync_entries': int(post),
        'target_errno_eio_replies': 1, 'other_fsync_continue_replies_while_held': 5,
        'execution_domain_stop_observed_ms': 1.0, 'private_destroy_quota_zero_observed_ms': 2.0,
        'expected_cold_mode': 'drained' if post else 'open',
        'filesystem_d_or_physical_eio_claim': False, 'production_slo_claim': False}


def recovery(mode):
    post = mode == 'post-root'
    return {**{k: True for k in NODE_OPERATOR_STORE_RECOVERY_FLAGS}, 'mode': mode,
        'expected_recovered_mode': 'drained' if post else 'open',
        'precommit_failed_unacknowledged_drain_may_reopen_old_open_not_fabricated_persistence': not post,
        'postcommit_drained_exact_retry_and_explicit_resume_checked': post}


class OperatorStoreTests(unittest.TestCase):
    def test_fixed_modifier_excludes_other_profile_and_healthy_operator(self):
        node_operator_store_profile(False, False, None)
        for mode in ('pre-file', 'post-root'):
            node_operator_store_profile(True, False, mode)
            for budget, operator in ((False, False), (True, True)):
                with self.assertRaises(ValueError): node_operator_store_profile(budget, operator, mode)
        for mode in ('', 'other'):
            with self.assertRaises(ValueError): node_operator_store_profile(True, False, mode)

    def test_every_witness_and_exact_one_errno_sequence_required(self):
        for mode in ('pre-file', 'post-root'):
            good = checkpoint(mode); validate_node_operator_store_checkpoint(good, mode)
            for key in NODE_OPERATOR_STORE_FLAGS:
                bad = dict(good); bad[key] = False
                with self.assertRaises(AssertionError): validate_node_operator_store_checkpoint(bad, mode)
            for key in ('file_sync_entries', 'admission_dir_sync_entries', 'root_dir_sync_entries', 'target_errno_eio_replies'):
                for value in (True, 99):
                    bad = dict(good); bad[key] = value
                    with self.assertRaises(AssertionError): validate_node_operator_store_checkpoint(bad, mode)
            for key in ('filesystem_d_or_physical_eio_claim', 'production_slo_claim'):
                bad = dict(good); bad[key] = True
                with self.assertRaises(AssertionError): validate_node_operator_store_checkpoint(bad, mode)

    def test_bounded_separate_observations_and_no_private_export(self):
        for mode in ('pre-file', 'post-root'):
            good = checkpoint(mode)
            for key in ('execution_domain_stop_observed_ms', 'private_destroy_quota_zero_observed_ms'):
                for value in (True, -1, float('nan'), float('inf'), 20000):
                    bad = dict(good); bad[key] = value
                    with self.assertRaises(AssertionError): validate_node_operator_store_checkpoint(bad, mode)
            for value in (0, 8193, True):
                bad = dict(good, other_fsync_continue_replies_while_held=value)
                with self.assertRaises(AssertionError): validate_node_operator_store_checkpoint(bad, mode)
            with self.assertRaises(AssertionError): validate_node_operator_store_checkpoint(dict(good, raw_fd='private'), mode)

    def test_recovery_does_not_promote_failed_precommit_to_durable_drained(self):
        for mode in ('pre-file', 'post-root'):
            good = recovery(mode); validate_node_operator_store_recovery(good, mode)
            for key in NODE_OPERATOR_STORE_RECOVERY_FLAGS:
                bad = dict(good); bad[key] = False
                with self.assertRaises(AssertionError): validate_node_operator_store_recovery(bad, mode)
            bad = dict(good, expected_recovered_mode='open' if mode == 'post-root' else 'drained')
            with self.assertRaises(AssertionError): validate_node_operator_store_recovery(bad, mode)
            with self.assertRaises(AssertionError): validate_node_operator_store_recovery(dict(good, epoch='private'), mode)


if __name__ == '__main__':
    unittest.main()
