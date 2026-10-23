import copy
import unittest
from kvm_nested_host import node_prepare_cancel_profile,validate_node_prepare_cancel,NODE_PREPARE_CANCEL_FLAGS

def valid():
 rows=[('enter',1),('selected',1),('ok',1),('node_ok',1),('enter',2),('enter',3),('selected',2),('cancel',2),('release',1),('released',1),('selected',3),('ok',3),('node_ok',3),('release',3),('released',3)]
 trace=[dict(point=p,goroutine_index=g,**({'selected_case':1 if g==2 else 0} if p=='selected' else {})) for p,g in rows]
 return {**{k:True for k in NODE_PREPARE_CANCEL_FLAGS},'held_workspace_prefix_bytes':16<<20,'hold_deadline_ms':20000,'prepare_timeout_ms_unchanged':30000,'http_budget_ms_unchanged':40000,'held_continue_response_count':1,'other_continue_replies_during_keeper_cleanup':4,'keeper_delete_to_execution_domain_empty_observed_ms':1.2,'keeper_delete_to_full_reclaim_observed_ms':4.5,'held_write_to_continue_reply_observed_ms':200.0,'holder_request_to_ready_observed_ms':1000.,'survivor_request_to_ready_observed_ms':1200.,'filesystem_D_or_physical_media_fault_claim':False,'exact_copy_stage_timing_scheduler_fairness_or_slo_claim':False,'trace':{'exact_ordinary_elf_sha256':'3ea1e247d0d32ede5ac0f33fb1284bbeb367f9717c49f06a08a7733d22af2af2','instruction_entry_probes':9,'event_count':15,'completed_preparations':2,'cancelled_waiters_without_token':1,'all_eight_cpu_loss_counters_zero':True,'all_nine_probe_hits_equal_trace':True,'live_incarnation_inode_control_event_tgid_checked':True,'exact_channel_linearization_or_slo_claim':False,'normalized_transitions':trace}}

class NodePrepareCancelTests(unittest.TestCase):
 def test_modifier_requires_same_explicit_snapshot_profile(self):
  for snapshot,enabled in ((False,False),(True,False),(True,True)):node_prepare_cancel_profile(snapshot,enabled)
  with self.assertRaises(ValueError):node_prepare_cancel_profile(False,True)
 def test_exact_policy_all_witnesses_and_no_inflated_timeout(self):
  v=valid();validate_node_prepare_cancel(v)
  for k in NODE_PREPARE_CANCEL_FLAGS:
   bad=copy.deepcopy(v);bad[k]=False
   with self.assertRaises(AssertionError):validate_node_prepare_cancel(bad)
  for k in ('held_workspace_prefix_bytes','hold_deadline_ms','prepare_timeout_ms_unchanged','http_budget_ms_unchanged','held_continue_response_count','other_continue_replies_during_keeper_cleanup'):
   bad=copy.deepcopy(v);bad[k]=True
   with self.assertRaises(AssertionError):validate_node_prepare_cancel(bad)
  for k in ('filesystem_D_or_physical_media_fault_claim','exact_copy_stage_timing_scheduler_fairness_or_slo_claim'):
   bad=copy.deepcopy(v);bad[k]=True
   with self.assertRaises(AssertionError):validate_node_prepare_cancel(bad)
 def test_public_trace_no_missing_private_foreign_or_consumed_cancel_transition(self):
  v=valid()
  for i in range(15):
   for action in ('omit','duplicate','private','foreign'):
    bad=copy.deepcopy(v);r=bad['trace']['normalized_transitions']
    if action=='omit':r.pop(i)
    elif action=='duplicate':r.append(dict(r[i]))
    elif action=='private':r[i]['raw_register']='not-exportable'
    else:r[i]['goroutine_index']=4
    with self.assertRaises(AssertionError):validate_node_prepare_cancel(bad)
  for i in (1,6,10):
   for value in (True,False,9):
    bad=copy.deepcopy(v);bad['trace']['normalized_transitions'][i]['selected_case']=value
    with self.assertRaises(AssertionError):validate_node_prepare_cancel(bad)
  bad=copy.deepcopy(v);r=bad['trace']['normalized_transitions'];r[8],r[10]=r[10],r[8]
  with self.assertRaises(AssertionError):validate_node_prepare_cancel(bad)
 def test_timings_are_separate_bounded_observations_not_slo(self):
  v=valid()
  for k in ('keeper_delete_to_execution_domain_empty_observed_ms','keeper_delete_to_full_reclaim_observed_ms','held_write_to_continue_reply_observed_ms','holder_request_to_ready_observed_ms','survivor_request_to_ready_observed_ms'):
   for value in (True,-1,float('inf'),float('nan'),40000):
    bad=copy.deepcopy(v);bad[k]=value
    with self.assertRaises(AssertionError):validate_node_prepare_cancel(bad)
  bad=copy.deepcopy(v);bad['keeper_delete_to_execution_domain_empty_observed_ms']=6
  with self.assertRaises(AssertionError):validate_node_prepare_cancel(bad)
if __name__=='__main__':unittest.main()
