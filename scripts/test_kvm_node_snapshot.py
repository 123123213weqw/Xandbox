import copy
import unittest
from build_nested_host import init_scripts
from kvm_nested_host import (nested_node_resources,nested_group_limits,node_snapshot_format_options,
 validate_node_snapshot_setup,validate_node_snapshot_checkpoint,validate_node_snapshot_recovery,
 NODE_SNAPSHOT_CHECKPOINT_FLAGS,NODE_SNAPSHOT_RECOVERY_FLAGS,validate_prepare_calibration,PREPARE_CALIBRATION_FLAGS,PREPARE_TRACE_ELF_SHA256)
def calibration():
 return {**{k:True for k in PREPARE_CALIBRATION_FLAGS},'exact_ordinary_elf_sha256':PREPARE_TRACE_ELF_SHA256,'instruction_entry_probes':9,'event_count':12,'completed_preparations':2,'queued_request_cancellation_and_cleanup_isolation_claim':False,'exact_channel_linearization_or_latency_slo_claim':False,'normalized_transitions':[{'point':p,'goroutine_index':g} for p,g in [('enter',1),('selected',1),('ok',1),('node_ok',1),('enter',2),('release',1),('selected',2),('released',1),('ok',2),('node_ok',2),('release',2),('released',2)]]}

class NodeSnapshotTests(unittest.TestCase):
 def test_fixed_new_trace_pin_matches_go_and_rejects_old_elf(self):
  import re
  from pathlib import Path
  go=(Path(__file__).resolve().parent.parent/'cmd/xandbox-host-fixture/node_prepare_trace_linux.go').read_text()
  match=re.search(r'const prepareTraceELFSHA = "([0-9a-f]{64})"',go)
  self.assertIsNotNone(match);self.assertEqual(match[1],PREPARE_TRACE_ELF_SHA256)
  bad=calibration();bad['exact_ordinary_elf_sha256']='d163a628036f4ecc2a6345bc8936500ad8b68368bd37337e916a9dfa761a6a26'
  with self.assertRaises(AssertionError):validate_prepare_calibration(bad)
 def test_explicit_profile_and_inode_format_leave_old_modes_unchanged(self):
  r=nested_node_resources(True);self.assertEqual(r,{'profile':'node-snapshot-v1','memory_mib':8192,'disk_bytes':12<<30,'cgroup_memory_max':10<<30})
  self.assertEqual(nested_group_limits(r)['cpu.max'],'800000 100000');self.assertEqual(nested_group_limits(r)['pids.max'],'256')
  self.assertEqual(node_snapshot_format_options(True),['-N','131072']);self.assertEqual(node_snapshot_format_options(False),[])
  _,s=init_scripts([],node_snapshot=True);self.assertIn('-mode node-snapshot',s);self.assertIn('prjquota',s)
  for old in ('node_budget','quota_snapshot','quota_driver','state_io','quota_switch'):
   with self.assertRaises(ValueError):init_scripts([],node_snapshot=True,**{old:True})
 def test_setup_requires_actual_builder_and_control_placement(self):
  v={k:True for k in ('genuine_l1_unassigned_template_built','l1_host_abi_checked','builder_two_independent_clones_checked','builder_runtime_reclaimed','ordinary_catalog_published_and_activated','publisher_inside_node_control','offline_builder_outside_node_envelope_not_a_node_pressure_claim')};v['snapshot_memory_bytes']=512<<20
  validate_node_snapshot_setup(v)
  for k in tuple(v):
   bad=dict(v);bad[k]=False
   with self.assertRaises(AssertionError):validate_node_snapshot_setup(bad)
 def test_checkpoint_requires_separate_pressure_and_cleanup_not_permit_claim(self):
  v={**{k:True for k in NODE_SNAPSHOT_CHECKPOINT_FLAGS},'guest_memory_touched_bytes_each':8<<20,'inode_filler_files':125000,'byte_filler_allocated_bytes':7<<30,'free_byte_guard':3362619392,'free_inode_guard':5776,'observed_free_bytes':2800000000,'inode_pressure_free_before_delete':5200,'inode_pressure_free_after_delete':5220,'prepare_permit_hardware_trace_claim':False,'prepare_entry_calibration':calibration()}
  validate_node_snapshot_checkpoint(v)
  for k in NODE_SNAPSHOT_CHECKPOINT_FLAGS:
   bad=copy.deepcopy(v);bad[k]=False
   with self.assertRaises(AssertionError):validate_node_snapshot_checkpoint(bad)
  for k,x in [('inode_filler_files',150001),('byte_filler_allocated_bytes',(10<<30)+1),('observed_free_bytes',3362619392),('inode_pressure_free_after_delete',5776),('inode_pressure_free_before_delete',1000),('free_byte_guard',True),('inode_filler_files',1.0),('prepare_permit_hardware_trace_claim',True)]:
   bad=dict(v);bad[k]=x
   with self.assertRaises(AssertionError):validate_node_snapshot_checkpoint(bad)
 def test_calibration_cannot_be_promoted_to_cancel_cleanup_or_latency_proof(self):
  v=calibration();validate_prepare_calibration(v)
  for k in tuple(v):
   bad=dict(v);bad[k]=not v[k] if type(v[k]) is bool else True
   with self.assertRaises(AssertionError):validate_prepare_calibration(bad)
  for k in ('instruction_entry_probes','event_count','completed_preparations'):
   bad=dict(v);bad[k]=float(v[k])
   with self.assertRaises(AssertionError):validate_prepare_calibration(bad)
 def test_normalized_transitions_reject_missing_private_reordered_or_overlapping_rows(self):
  v=calibration()
  for i in range(12):
   for mode in ('omit','duplicate','foreign','private'):
    bad=copy.deepcopy(v);rows=bad['normalized_transitions']
    if mode=='omit':rows.pop(i)
    elif mode=='duplicate':rows.append(dict(rows[i]))
    elif mode=='foreign':rows[i]['goroutine_index']=3
    else:rows[i]['raw_pointer']='not-exportable'
    with self.assertRaises(AssertionError):validate_prepare_calibration(bad)
  bad=copy.deepcopy(v);r=bad['normalized_transitions'];r[5],r[6]=r[6],r[5]
  with self.assertRaises(AssertionError):validate_prepare_calibration(bad)
 def test_recovery_requires_low_free_startup_and_ordinary_reclamation(self):
  v={k:True for k in NODE_SNAPSHOT_RECOVERY_FLAGS};validate_node_snapshot_recovery(v)
  for k in v:
   bad=dict(v);bad[k]=False
   with self.assertRaises(AssertionError):validate_node_snapshot_recovery(bad)
if __name__=='__main__':unittest.main()
