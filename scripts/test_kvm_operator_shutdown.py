import unittest
from kvm_nested_host import (NODE_OPERATOR_SHUTDOWN_FLAGS, NODE_OPERATOR_SHUTDOWN_RECOVERY_FLAGS,
    NODE_OPERATOR_SHUTDOWN_TIMINGS, node_operator_shutdown_profile,
    validate_node_operator_shutdown_checkpoint, validate_node_operator_shutdown_recovery)

def checkpoint():
    return {**{k:True for k in NODE_OPERATOR_SHUTDOWN_FLAGS},'file_sync_entries':1,
        'file_sync_continue_or_errno_replies':0,'exit_group_continue_replies':1,'ordinary_process_exit_code':1,
        'other_fsync_continue_replies_while_held':8,'other_exit_group_continue_replies':2,
        'hold_deadline_ms':20000,'control_close_timeout_ms_unchanged':5000,
        **dict(zip(NODE_OPERATOR_SHUTDOWN_TIMINGS,(50.0,600.0,5600.0,5700.0))),
        'filesystem_d_or_physical_media_claim':False,'production_slo_claim':False}

class ShutdownTests(unittest.TestCase):
    def test_fixed_exclusive_modifier(self):
        node_operator_shutdown_profile(True,False,None,False,True)
        for args in ((False,False,None,False),(True,True,None,False),(True,False,'pre-file',False),(True,False,None,True)):
            with self.assertRaises(ValueError):node_operator_shutdown_profile(*args,True)
        node_operator_shutdown_profile(False,True,'post-root',True,False)
    def test_exact_all_witnesses_and_counts(self):
        good=checkpoint();validate_node_operator_shutdown_checkpoint(good)
        for k,v in good.items():
            if type(v) is bool:
                with self.assertRaises(AssertionError):validate_node_operator_shutdown_checkpoint(dict(good,**{k:not v}))
            if type(v) is int:
                with self.assertRaises(AssertionError):validate_node_operator_shutdown_checkpoint(dict(good,**{k:True}))
                if k.startswith('other_'):
                    for n in (0,8193):
                        with self.assertRaises(AssertionError):validate_node_operator_shutdown_checkpoint(dict(good,**{k:n}))
                else:
                    with self.assertRaises(AssertionError):validate_node_operator_shutdown_checkpoint(dict(good,**{k:v+1}))
        with self.assertRaises(AssertionError):validate_node_operator_shutdown_checkpoint(dict(good,private_pid=123))
    def test_ordered_separate_observations_original_deadlines(self):
        good=checkpoint()
        for k in NODE_OPERATOR_SHUTDOWN_TIMINGS:
            for n in (-1,True,float('nan'),float('inf'),20000):
                with self.assertRaises(AssertionError):validate_node_operator_shutdown_checkpoint(dict(good,**{k:n}))
        for k,n in ((NODE_OPERATOR_SHUTDOWN_TIMINGS[0],700),(NODE_OPERATOR_SHUTDOWN_TIMINGS[2],4999),(NODE_OPERATOR_SHUTDOWN_TIMINGS[3],5500)):
            with self.assertRaises(AssertionError):validate_node_operator_shutdown_checkpoint(dict(good,**{k:n}))
    def test_cold_only_real_old_open_not_fabricated_fence(self):
        good={k:True for k in NODE_OPERATOR_SHUTDOWN_RECOVERY_FLAGS};validate_node_operator_shutdown_recovery(good)
        for k in good:
            with self.assertRaises(AssertionError):validate_node_operator_shutdown_recovery(dict(good,**{k:False}))
        with self.assertRaises(AssertionError):validate_node_operator_shutdown_recovery(dict(good,epoch='secret'))

if __name__=='__main__':unittest.main()
