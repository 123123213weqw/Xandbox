import unittest
from kvm_nested_host import (node_tls_policy_profile,TLS_POLICY_CHECKPOINT_FLAGS,TLS_POLICY_RECOVERY_FLAGS,TLS_POLICY_TIMINGS,validate_tls_policy_checkpoint,validate_tls_policy_recovery)
def checkpoint(mode):
    return {**{k:True for k in TLS_POLICY_CHECKPOINT_FLAGS},'file_fsync_entries':1,'directory_fsync_entries':int(mode=='post-commit'),'policy_memfd_entries':int(mode=='post-commit'),'target_continue_or_errno_replies':0,'other_continue_submissions':9,'other_continue_while_held':0,'policy_revision_before_cold':1 if mode=='pre-file' else 2,'hold_bound_ms':20000,**dict(zip(TLS_POLICY_TIMINGS,(2900.0,60.0,300.0))),'filesystem_d_or_physical_media_fault_claim':False,'production_slo_or_all_policy_windows_claim':False}
def recovery(mode):
    return {**{k:True for k in TLS_POLICY_RECOVERY_FLAGS},'pre_file_old_revision1_then_production_commit2':mode=='pre-file','post_commit_revision2_old_config1_refused_and_exact_replay':mode=='post-commit','policy_revision_before_start':1 if mode=='pre-file' else 2}
class TLSPolicyTests(unittest.TestCase):
    def test_only_fixed_exclusive_profile(self):
        for mode in ('pre-file','post-commit'):node_tls_policy_profile(mode,False)
        node_tls_policy_profile(None,True)
        for mode,enabled in [('anything',False),('',False),('pre-file',True),('post-commit',True)]:
            with self.assertRaises(ValueError):node_tls_policy_profile(mode,enabled)
    def test_exact_checkpoint_flags_counters_and_no_private_projection(self):
        for mode in ('pre-file','post-commit'):
            good=checkpoint(mode);validate_tls_policy_checkpoint(good,mode)
            for k,v in good.items():
                if type(v) is bool:
                    with self.assertRaises(AssertionError):validate_tls_policy_checkpoint(dict(good,**{k:not v}),mode)
            for k in ('file_fsync_entries','directory_fsync_entries','policy_memfd_entries','target_continue_or_errno_replies','policy_revision_before_cold','hold_bound_ms'):
                for v in (True,good[k]+1):
                    with self.assertRaises(AssertionError):validate_tls_policy_checkpoint(dict(good,**{k:v}),mode)
            for v in (True,-1,8193):
                with self.assertRaises(AssertionError):validate_tls_policy_checkpoint(dict(good,other_continue_while_held=v),mode)
            with self.assertRaises(AssertionError):validate_tls_policy_checkpoint(dict(good,private_receipt={}),mode)
            with self.assertRaises(AssertionError):validate_tls_policy_checkpoint(good,'unknown')
    def test_watchdog_sampling_and_stop_gc_not_slo(self):
        good=checkpoint('pre-file')
        for k in TLS_POLICY_TIMINGS:
            for v in (True,-1,float('nan'),float('inf'),20000):
                with self.assertRaises(AssertionError):validate_tls_policy_checkpoint(dict(good,**{k:v}),'pre-file')
        with self.assertRaises(AssertionError):validate_tls_policy_checkpoint(dict(good,held_to_child_gone_observed_ms=9000),'pre-file')
        with self.assertRaises(AssertionError):validate_tls_policy_checkpoint(dict(good,delete_to_execution_empty_observed_ms=301),'pre-file')
    def test_cold_unacknowledged_old_vs_committed_new_semantics(self):
        for mode in ('pre-file','post-commit'):
            good=recovery(mode);validate_tls_policy_recovery(good,mode)
            for k,v in good.items():
                with self.assertRaises(AssertionError):validate_tls_policy_recovery(dict(good,**{k:not v if type(v) is bool else v+1}),mode)
            with self.assertRaises(AssertionError):validate_tls_policy_recovery(dict(good,token='TEST'),mode)
if __name__=='__main__':unittest.main()
