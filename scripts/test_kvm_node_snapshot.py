import copy
import unittest
from build_nested_host import init_scripts
from kvm_nested_host import (nested_node_resources,nested_group_limits,node_snapshot_format_options,
 validate_node_snapshot_setup,validate_node_snapshot_checkpoint,validate_node_snapshot_recovery,
 NODE_SNAPSHOT_CHECKPOINT_FLAGS,NODE_SNAPSHOT_RECOVERY_FLAGS)
class NodeSnapshotTests(unittest.TestCase):
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
  v={**{k:True for k in NODE_SNAPSHOT_CHECKPOINT_FLAGS},'guest_memory_touched_bytes_each':8<<20,'inode_filler_files':125000,'byte_filler_allocated_bytes':7<<30,'free_byte_guard':3362619392,'free_inode_guard':5776,'observed_free_bytes':2800000000,'inode_pressure_free_before_delete':5200,'inode_pressure_free_after_delete':5220,'prepare_permit_hardware_trace_claim':False}
  validate_node_snapshot_checkpoint(v)
  for k in NODE_SNAPSHOT_CHECKPOINT_FLAGS:
   bad=copy.deepcopy(v);bad[k]=False
   with self.assertRaises(AssertionError):validate_node_snapshot_checkpoint(bad)
  for k,x in [('inode_filler_files',150001),('byte_filler_allocated_bytes',(10<<30)+1),('observed_free_bytes',3362619392),('inode_pressure_free_after_delete',5776),('inode_pressure_free_before_delete',1000),('free_byte_guard',True),('inode_filler_files',1.0),('prepare_permit_hardware_trace_claim',True)]:
   bad=dict(v);bad[k]=x
   with self.assertRaises(AssertionError):validate_node_snapshot_checkpoint(bad)
 def test_recovery_requires_low_free_startup_and_ordinary_reclamation(self):
  v={k:True for k in NODE_SNAPSHOT_RECOVERY_FLAGS};validate_node_snapshot_recovery(v)
  for k in v:
   bad=dict(v);bad[k]=False
   with self.assertRaises(AssertionError):validate_node_snapshot_recovery(bad)
if __name__=='__main__':unittest.main()
