import copy
import unittest
from kvm_nested_host import (DIAGNOSTIC_CHECKPOINT_FLAGS, DIAGNOSTIC_RECOVERY_FLAGS,
    node_diagnostics_profile, validate_diagnostic_checkpoint, validate_diagnostic_recovery)


def checkpoint(mode):
    return {**{k: True for k in DIAGNOSTIC_CHECKPOINT_FLAGS}, 'mode': mode,
        'producer_failures': 80, 'queued': 64, 'dropped': 15,
        'observed_sequence_before_cold': 5 if mode == 'header-publish' else 4,
        'ring_fsync_entries': 2 if mode == 'header-publish' else 1,
        'data_fsync_continue_submissions': int(mode == 'header-publish'),
        'target_reply_submissions': 0, 'exit_group_continue_submissions': 1,
        'other_continue_submissions': 1000, 'other_continue_while_held': 100,
        'hold_bound_ms': 20000, 'delete_to_execution_empty_observed_ms': 10.,
        'delete_to_private_quota0_observed_ms': 20., 'signal_to_exit_group_entry_observed_ms': 300.,
        'filesystem_d_or_physical_media_fault_claim': False, 'durable_audit_or_production_slo_claim': False}


class DiagnosticsTests(unittest.TestCase):
    def test_profiles(self):
        for mode in ('record-data', 'header-publish'):
            node_diagnostics_profile(True, mode, False, None)
            for budget, others in ((False, ()), (True, (True,)), (True, ('pre-file',))):
                with self.assertRaises(ValueError): node_diagnostics_profile(budget, mode, *others)
        with self.assertRaises(ValueError): node_diagnostics_profile(True, 'arbitrary')

    def test_checkpoint_closed_schema(self):
        for mode in ('record-data', 'header-publish'):
            good = checkpoint(mode); validate_diagnostic_checkpoint(good, mode)
            for key in DIAGNOSTIC_CHECKPOINT_FLAGS:
                bad = copy.deepcopy(good); bad[key] = False
                with self.assertRaises(AssertionError): validate_diagnostic_checkpoint(bad, mode)
            for key, value in (('queued', 63), ('dropped', 0), ('target_reply_submissions', 1),
                               ('producer_failures', 96), ('observed_sequence_before_cold', 6),
                               ('signal_to_exit_group_entry_observed_ms', 249.),
                               ('delete_to_execution_empty_observed_ms', 30.),
                               ('filesystem_d_or_physical_media_fault_claim', True),
                               ('durable_audit_or_production_slo_claim', True), ('unrecognized', True)):
                bad = copy.deepcopy(good); bad[key] = value
                with self.assertRaises(AssertionError): validate_diagnostic_checkpoint(bad, mode)

    def test_cold_visibility_is_not_durable_audit_ack(self):
        for mode in ('record-data', 'header-publish'):
            for seq in (4, 5):
                good = {**{k: True for k in DIAGNOSTIC_RECOVERY_FLAGS}, 'mode': mode,
                        'observed_sequence_before_start': seq, 'retained_destroyed_records': 83}
                if mode == 'record-data' and seq == 5:
                    with self.assertRaises(AssertionError): validate_diagnostic_recovery(good, mode)
                else:
                    validate_diagnostic_recovery(good, mode)
                    for key in DIAGNOSTIC_RECOVERY_FLAGS:
                        bad = copy.deepcopy(good); bad[key] = False
                        with self.assertRaises(AssertionError): validate_diagnostic_recovery(bad, mode)
