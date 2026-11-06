from pathlib import Path
import base64,hashlib,json,os,stat,tempfile,threading,time,types,unittest
# Every byte below is generated synthetic input, never a saved runtime console.
import creation_cost_delivery as d
from test_creation_cost_trace_analyzer import packet,frames,abi
ABI=b'XANDBOX_CREATION_COST_ABI_PRIVATE ';NORMAL=b'XANDBOX_CREATION_COST_PRIVATE '
def generated_console(scope):
 value=packet();value['scope']=scope
 if scope=='cold':value['http_create_elapsed']=[dict(ordinal=0,phase='cold-fresh',elapsed_ns=1000000,success=True)]
 return frames(abi(value),ABI.decode())+frames(value,NORMAL.decode())
A=generated_console('checkpoint');C=generated_console('cold');BROKEN=A[:-100]
class FakeTime:
 def __init__(self):self.value=0
 def now(self):return self.value
 def sleep(self,n):self.value+=n
class Tests(unittest.TestCase):
 def test_generated_originals_complete_and_byte_exact(self):
  for data,scope in [(A,'checkpoint'),(C,'cold')]:
   out=d.inspect_console(data,scope);self.assertTrue(out['complete'])
   for key,value in out['payloads'].items():self.assertEqual(hashlib.sha256(value).hexdigest(),out['payload_sha256'][key]);json.loads(value)
 def test_generated_truncated_frames_do_not_become_valid_with_wait(self):
  self.assertFalse(d.inspect_console(BROKEN,'checkpoint')['complete']);clock=FakeTime()
  with self.assertRaises(d.DeliveryTimeout):d.await_delivery(lambda:BROKEN,'checkpoint',now=clock.now,sleep=clock.sleep)
  self.assertEqual(clock.value,2.0)
 def test_known_generated_suffix_appended_to_its_own_valid_prefix(self):
  for missing in (1,100,1000,3000,5000,len(A)-1):
   snapshots=[A[:-missing],A[:-missing],A];clock=FakeTime()
   def read():return snapshots.pop(0) if len(snapshots)>1 else snapshots[0]
   out=d.await_delivery(read,'checkpoint',now=clock.now,sleep=clock.sleep);self.assertTrue(out['complete']);self.assertEqual(out['snapshot_reads'],3)
 def test_newline_terminated_malformed_frame_hard_fails(self):
  with self.assertRaises(d.InvalidDelivery):d.inspect_console(BROKEN+b'\n','checkpoint')
 def test_complete_wrong_hash_rejected_even_if_other_set_incomplete(self):
  rows=[x for x in A.splitlines(keepends=True) if x.startswith(ABI)];first=json.loads(rows[0][len(ABI):]);bad=b''.join(rows).replace(first['sha256'].encode(),b'0'*64)
  with self.assertRaises(d.InvalidDelivery):d.inspect_console(bad,'checkpoint')
 def test_duplicate_reordered_and_wrong_scope_rejected(self):
  lines=A.splitlines(keepends=True);frames=[x for x in lines if x.startswith(NORMAL)]
  for data,scope in [(A+frames[-1],'checkpoint'),(b''.join(reversed(lines)),'checkpoint'),(A,'cold')]:
   with self.assertRaises(d.InvalidDelivery):d.inspect_console(data,scope)
 def test_missing_final_frame_stays_pending(self):
  lines=A.splitlines(keepends=True);last=next(i for i in range(len(lines)-1,-1,-1) if lines[i].startswith(NORMAL));self.assertFalse(d.inspect_console(b''.join(lines[:last]),'checkpoint')['complete'])
 def test_producer_failure_or_extra_partial_is_not_ignored(self):
  for data in [A+b'XANDBOX_CREATION_COST_SETUP_FAILURE_PRIVATE {}\n',A+b'XANDBOX_CREATION_COST_PRIVATE {']:
   with self.assertRaises(d.InvalidDelivery):d.inspect_console(data,'checkpoint')
 def test_append_only_and_fixed_bounds(self):
  clock=FakeTime();rows=[A[:100],A[:50]]
  with self.assertRaises(d.InvalidDelivery):d.await_delivery(lambda:rows.pop(0),'checkpoint',now=clock.now,sleep=clock.sleep)
  for value in (False,0,-1,2.01,float('nan'),float('inf')):
   with self.assertRaises(d.InvalidDelivery):d.await_delivery(lambda:A,'checkpoint',timeout=value)
  with self.assertRaises(d.InvalidDelivery):d.inspect_console(b'X'*(d.MAX_CONSOLE+1),'checkpoint')
 def test_late_complete_reader_not_accepted_after_deadline(self):
  clock=FakeTime()
  def read():clock.value=2.001;return A
  with self.assertRaises(d.DeliveryTimeout):d.await_delivery(read,'checkpoint',now=clock.now,sleep=clock.sleep)
 def test_closed_schema_no_boolean_or_duplicated_fields(self):
  prefix=A.split(ABI,1)[0];line=next(x for x in A.splitlines() if x.startswith(ABI));row=json.loads(line[len(ABI):])
  for key,value in [('index',False),('chunks',True),('bytes',True),('sha256',[]),('data',False),('data','%%%%'),('scope','wrong'),('unknown',1)]:
   bad=dict(row);bad[key]=value
   with self.assertRaises(d.InvalidDelivery):d.inspect_console(prefix+ABI+json.dumps(bad).encode()+b'\n','checkpoint')
  duplicate=line[:-1]+b',"index":0}\n'
  with self.assertRaises(d.InvalidDelivery):d.inspect_console(prefix+duplicate,'checkpoint')
 def test_normal_frames_cannot_precede_ABI(self):
  line=next(x for x in A.splitlines(keepends=True) if x.startswith(NORMAL))
  with self.assertRaises(d.InvalidDelivery):d.inspect_console(line,'checkpoint')
 def test_same_inode_append_is_received_with_real_file_reader(self):
  with tempfile.TemporaryDirectory(prefix='xandbox-delivery-unit-') as directory:
   p=Path(directory)/'console';p.write_bytes(A[:-5000]);p.chmod(0o600);reader=d.bounded_file_reader(p,expected_uid=os.geteuid())
   def append():time.sleep(.025);p.open('ab').write(A[-5000:])
   t=threading.Thread(target=append);t.start()
   try:out=d.await_delivery(reader,'checkpoint');self.assertTrue(out['complete']);self.assertGreater(out['snapshot_reads'],1)
   finally:t.join()
 def test_private_file_mode_links_uid_and_inode_are_checked(self):
  with tempfile.TemporaryDirectory(prefix='xandbox-delivery-unit-') as directory:
   p=Path(directory)/'console';p.write_bytes(A);p.chmod(0o600);reader=d.bounded_file_reader(p,expected_uid=os.geteuid());self.assertEqual(reader(),A)
   p.chmod(0o644)
   with self.assertRaises(d.InvalidDelivery):reader()
   p.chmod(0o600);link=Path(directory)/'link';os.link(p,link)
   with self.assertRaises(d.InvalidDelivery):reader()
   link.unlink();new=Path(directory)/'new';new.write_bytes(A);new.chmod(0o600);os.replace(new,p)
   with self.assertRaises(d.InvalidDelivery):reader()
   with self.assertRaises(d.InvalidDelivery):d.bounded_file_reader(p,expected_uid=os.geteuid()+1)()
   p.unlink();p.symlink_to(Path(directory)/'absent')
   with self.assertRaises(OSError):d.bounded_file_reader(p,expected_uid=os.geteuid())()
 def test_only_opt_in_healthy_baseline_allows_wait(self):
  okay=types.SimpleNamespace(creation_cost_diagnostics='observe',node_budget=True,fixture='x',source_revision='x',report='x',log_dir='x',node_oom=False,node_operator_store=None);d.validate_creation_cost_profile(okay)
  for name,value in [('node_budget',False),('node_oom',True),('node_load',True),('node_operator_store','pre-file'),('unknown_future_fault',True)]:
   bad=types.SimpleNamespace(**vars(okay));setattr(bad,name,value)
   with self.assertRaises(d.InvalidDelivery):d.validate_creation_cost_profile(bad)
  okay.creation_cost_diagnostics=None;okay.node_oom=True;d.validate_creation_cost_profile(okay)
 def test_receipt_contains_no_raw_payload_and_excludes_API_Stop_time(self):
  with tempfile.TemporaryDirectory(prefix='xandbox-delivery-unit-') as directory:
   p=Path(directory)/'console';p.write_bytes(A);p.chmod(0o600);out=d.record_delivery(p,Path(directory),'checkpoint',expected_uid=os.geteuid());self.assertNotIn('payloads',out);self.assertTrue(out['not_part_of_API_or_stop_latency']);self.assertTrue(out['observation_method_changed_may_allow_background_IO_progress']);json.dumps(out)
 def test_missing_expected_owner_never_defaults_to_root_or_file_owner(self):
  with self.assertRaises(TypeError):d.bounded_file_reader(Path('/not-read'))
  with self.assertRaises(TypeError):d.record_delivery(Path('/not-read'),Path('/not-written'),'checkpoint')
  for uid in (False,-1,1.0,'850000',(1<<32)-1):
   with self.assertRaises(d.InvalidDelivery):d.bounded_file_reader(Path('/not-read'),expected_uid=uid)

 def test_inferred_actual_owner_is_not_a_permitted_fallback(self):
  with tempfile.TemporaryDirectory(prefix='xandbox-delivery-uid-unit-') as directory:
   p=Path(directory)/'console';p.write_bytes(A);p.chmod(0o600)
   with self.assertRaises(d.InvalidDelivery):d.record_delivery(p,Path(directory),'checkpoint',expected_uid=os.geteuid()+1)
 def test_uid_fix_does_not_accept_wrong_mode_hardlinks_or_replacement(self):
  with tempfile.TemporaryDirectory(prefix='xandbox-delivery-uid-unit-') as directory:
   p=Path(directory)/'console';p.write_bytes(A);p.chmod(0o644)
   with self.assertRaises(d.InvalidDelivery):d.record_delivery(p,Path(directory),'checkpoint',expected_uid=os.geteuid())
 def test_exact_trusted_harness_UID_passed_in_both_call_sites(self):
  text=Path(__file__).with_name('kvm_nested_host.py').read_text()
  for scope in ('checkpoint','cold'):self.assertIn("record_delivery(root/'console.log',logs,"+repr(scope)+",expected_uid=uid)",text)
  self.assertIn('uid = 850000 + secrets.randbelow(30000)',text)
 def test_success_receipt_contains_actual_fd_metadata_not_inferred_trust(self):
  with tempfile.TemporaryDirectory(prefix='xandbox-fd-proof-') as directory:
   p=Path(directory)/'console';p.write_bytes(A);p.chmod(0o600);out=d.record_delivery(p,Path(directory),'checkpoint',expected_uid=os.geteuid());st=p.stat();self.assertEqual(out['expected_uid'],os.geteuid());self.assertEqual(out['fd_metadata'],dict(file_type=stat.S_IFMT(st.st_mode),uid=st.st_uid,gid=st.st_gid,mode=stat.S_IMODE(st.st_mode),nlink=st.st_nlink,size=st.st_size,device=st.st_dev,inode=st.st_ino))
 def test_wrong_owner_failure_preserves_exact_fstat_and_original_error(self):
  with tempfile.TemporaryDirectory(prefix='xandbox-fd-proof-') as directory:
   p=Path(directory)/'console';p.write_bytes(A);p.chmod(0o600)
   with self.assertRaises(d.InvalidDelivery):d.record_delivery(p,Path(directory),'checkpoint',expected_uid=os.geteuid()+1)
   proof=Path(directory)/'diagnostic-delivery-checkpoint-failure.json';v=json.loads(proof.read_bytes());self.assertEqual(v['expected_uid'],os.geteuid()+1);self.assertEqual(v['fd_metadata']['uid'],os.geteuid());self.assertEqual(v['exception_class'],'InvalidDelivery');self.assertTrue(v['failed_not_qualified']);self.assertEqual(stat.S_IMODE(proof.stat().st_mode),0o600);self.assertNotIn('payload',v);self.assertNotIn('path',v)
 def test_wrong_mode_failure_has_actual_mode_not_repaired(self):
  with tempfile.TemporaryDirectory(prefix='xandbox-fd-proof-') as directory:
   p=Path(directory)/'console';p.write_bytes(A);p.chmod(0o644)
   with self.assertRaises(d.InvalidDelivery):d.record_delivery(p,Path(directory),'cold',expected_uid=os.geteuid())
   v=json.loads((Path(directory)/'diagnostic-delivery-cold-failure.json').read_bytes());self.assertEqual(v['fd_metadata']['mode'],0o644);self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o644)
 def test_open_failure_records_errno_without_invented_fstat(self):
  with tempfile.TemporaryDirectory(prefix='xandbox-fd-proof-') as directory:
   p=Path(directory)/'absent'
   with self.assertRaises(FileNotFoundError):d.record_delivery(p,Path(directory),'checkpoint',expected_uid=os.geteuid())
   v=json.loads((Path(directory)/'diagnostic-delivery-checkpoint-failure.json').read_bytes());self.assertIsNone(v['fd_metadata']);self.assertEqual(v['errno'],2)
 def test_timeout_receipt_never_qualifies_truncated_original(self):
  with tempfile.TemporaryDirectory(prefix='xandbox-fd-proof-') as directory:
   p=Path(directory)/'console';p.write_bytes(BROKEN);p.chmod(0o600);old=d.await_delivery
   def fail(reader,scope):reader();raise d.DeliveryTimeout('fixed synthetic timeout')
   d.await_delivery=fail
   try:
    with self.assertRaises(d.DeliveryTimeout):d.record_delivery(p,Path(directory),'checkpoint',expected_uid=os.geteuid())
   finally:d.await_delivery=old
   v=json.loads((Path(directory)/'diagnostic-delivery-checkpoint-failure.json').read_bytes());self.assertEqual(v['exception_class'],'DeliveryTimeout');self.assertTrue(v['failed_not_qualified']);self.assertEqual(v['fd_metadata']['size'],len(BROKEN));self.assertEqual(p.read_bytes(),BROKEN)
 def test_failure_export_does_not_overwrite_or_mask_original(self):
  import contextlib,io
  with tempfile.TemporaryDirectory(prefix='xandbox-fd-proof-') as directory:
   proof=Path(directory)/'diagnostic-delivery-checkpoint-failure.json';proof.write_bytes(b'original');p=Path(directory)/'absent'
   with contextlib.redirect_stderr(io.StringIO()) as warning:
    with self.assertRaises(FileNotFoundError):d.record_delivery(p,Path(directory),'checkpoint',expected_uid=os.geteuid())
   self.assertEqual(proof.read_bytes(),b'original');self.assertIn('PRIVATE_DELIVERY_FAILURE_RECEIPT_WRITE_FAILED',warning.getvalue())
 def test_failure_export_scope_cannot_select_arbitrary_file(self):
  with self.assertRaises(d.InvalidDelivery):d.record_delivery(Path('/never-read'),Path('/never-write'),'../../bad',expected_uid=os.geteuid())
 def test_FIFO_is_rejected_before_waiting_for_a_writer(self):
  import subprocess,sys
  with tempfile.TemporaryDirectory(prefix='xandbox-generated-FIFO-') as directory:
   fifo=Path(directory)/'fifo';os.mkfifo(fifo,0o600)
   code="from pathlib import Path;import os,sys;sys.path.insert(0,sys.argv[1]);from creation_cost_delivery import bounded_file_reader,InvalidDelivery\ntry:bounded_file_reader(Path(sys.argv[2]),expected_uid=os.geteuid())()\nexcept InvalidDelivery:print('NONREGULAR_REFUSED')\nelse:raise AssertionError('FIFO accepted')"
   result=subprocess.run([sys.executable,'-I','-B','-c',code,str(Path(__file__).resolve().parent),str(fifo)],capture_output=True,timeout=5);self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(result.stdout,b'NONREGULAR_REFUSED\n')
if __name__=='__main__':unittest.main(verbosity=2)
