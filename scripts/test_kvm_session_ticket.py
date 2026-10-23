import unittest
from kvm_nested_host import (NODE_SESSION_TICKET_FLAGS, NODE_SESSION_TICKET_RECOVERY_FLAGS,
    node_session_ticket_profile, validate_node_session_ticket_checkpoint, validate_node_session_ticket_recovery)


def checkpoint():
    return {**{k: True for k in NODE_SESSION_TICKET_FLAGS}, 'initial_file_sync_entries': 1,
        'target_continue_replies': 1, 'target_errno_replies': 0, 'pending_before_continue': 1,
        'existing_active_before_continue': 2, 'core_records_before_continue': 2,
        'pending_after_continue': 0, 'core_records_after_continue': 3, 'acknowledged_drain_revision': 2,
        'hold_deadline_ms': 20000, 'original_http_budget_ms': 40000, 'prepare_timeout_ms_unchanged': 30000,
        'other_fsync_continue_replies_while_held': 5, 'execution_domain_stop_observed_ms': 1.0,
        'private_destroy_quota_zero_observed_ms': 2.0, 'original_session_request_to_ready_observed_ms': 10.0,
        'filesystem_d_or_physical_media_claim': False, 'production_slo_claim': False}


class SessionTicketTests(unittest.TestCase):
    def test_modifier_is_exclusive_budget_not_generic_mode(self):
        node_session_ticket_profile(True, False, None, True)
        for budget, operator, store in [(False, False, None), (True, True, None), (True, False, 'pre-file'), (True, False, 'post-root')]:
            with self.assertRaises(ValueError): node_session_ticket_profile(budget, operator, store, True)
        node_session_ticket_profile(False, True, 'pre-file', False)

    def test_all_witnesses_and_exact_accepted_not_cancelled_accounting(self):
        good = checkpoint(); validate_node_session_ticket_checkpoint(good)
        for key in NODE_SESSION_TICKET_FLAGS:
            bad = dict(good); bad[key] = False
            with self.assertRaises(AssertionError): validate_node_session_ticket_checkpoint(bad)
        for key, value in good.items():
            if type(value) is int:
                for bad_value in (True, value + 1 if key != 'other_fsync_continue_replies_while_held' else 0):
                    bad = dict(good); bad[key] = bad_value
                    with self.assertRaises(AssertionError): validate_node_session_ticket_checkpoint(bad)
        for key in ('filesystem_d_or_physical_media_claim', 'production_slo_claim'):
            with self.assertRaises(AssertionError): validate_node_session_ticket_checkpoint(dict(good, **{key: True}))
        with self.assertRaises(AssertionError): validate_node_session_ticket_checkpoint(dict(good, private_ticket='secret'))

    def test_measurements_bounded_and_separate_not_slo(self):
        good = checkpoint()
        for key in ('execution_domain_stop_observed_ms', 'private_destroy_quota_zero_observed_ms', 'original_session_request_to_ready_observed_ms'):
            for value in (True, -1, float('nan'), float('inf'), 40000):
                with self.assertRaises(AssertionError): validate_node_session_ticket_checkpoint(dict(good, **{key: value}))
        with self.assertRaises(AssertionError): validate_node_session_ticket_checkpoint(dict(good, execution_domain_stop_observed_ms=3))
        for value in (0, 8193, True):
            with self.assertRaises(AssertionError): validate_node_session_ticket_checkpoint(dict(good, other_fsync_continue_replies_while_held=value))

    def test_cold_ack_drain_no_route_ticket_or_metadata_repair(self):
        good = {k: True for k in NODE_SESSION_TICKET_RECOVERY_FLAGS}
        validate_node_session_ticket_recovery(good)
        for key in good:
            with self.assertRaises(AssertionError): validate_node_session_ticket_recovery(dict(good, **{key: False}))
        with self.assertRaises(AssertionError): validate_node_session_ticket_recovery(dict(good, epoch='secret'))


if __name__ == '__main__': unittest.main()
