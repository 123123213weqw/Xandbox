import base64,copy,hashlib,json,unittest
from pathlib import Path
import types,sys
import creation_cost_trace_analyzer as a

def packet():
 p={'schema':3,'asset_writeback_window_bytes':8<<20,'http_create_elapsed':[dict(ordinal=i,phase='checkpoint-fresh' if i==4 else 'initial',elapsed_ns=1_000_000+i,success=True) for i in range(5)],'scope':'checkpoint','target_pid':10,'ordinary_elf_sha256':'d748d8cf7216980582720c1618e1b0473a9228e371ae850257059a8980e98e01','event_formats':{x:'name: '+x.split('/')[1]+'\n' for x in a.EVENTS},'cpu_stats':{str(x):'overrun: 0\ncommit overrun: 0\ndropped events: 0\n' for x in range(8)},'initial_stopped_threads':['10','11'],'runtime_anchor_before':{'3':{'fd':3,'device':8,'inode':20,'mount_id':30}},'runtime_anchor_after':{'3':{'fd':3,'device':8,'inode':20,'mount_id':30}}}
 lines=['task-10 [000] d... 1.000001: task_newtask: pid=12 comm=sandboxd clone_flags=10000 oom_score_adj=0','task-12 [000] d... 1.000002: sys_quotactl_fd(fd: 3, cmd: 80000102, id: 0, addr: 1234)','task-12 [000] d... 1.000003: sys_quotactl_fd -> 0x0','task-10 [000] d... 1.000004: sys_quotactl_fd(fd: 3, cmd: 80000702, id: a, addr: 2345)','task-10 [000] d... 1.000005: sys_quotactl_fd -> 0x0','task-10 [000] d... 1.000006: sys_syncfs(fd: 3)','task-11 [001] d... 1.000007: sys_syncfs(fd: 3)','task-10 [000] d... 1.000009: sys_syncfs -> 0x0','task-11 [001] d... 1.000010: sys_syncfs -> 0x0','task-11 [000] d... 1.000011: sys_fsync(fd: 4)','task-11 [000] d... 1.000012: sys_fsync -> 0x0','task-10 [000] d... 1.000013: task_newtask: pid=13 comm=firecracker clone_flags=11 oom_score_adj=0','task-13 [001] d... 1.000014: sys_fsync(fd: 5)']
 lines+=['task-10 [000] d... 1.000017: sys_sync_file_range(fd: 8, offset: 0, nbytes: 800000, flags: 2)','task-10 [000] d... 1.000018: sys_sync_file_range -> 0x0']
 p['event_formats']['syscalls/sys_enter_sync_file_range']='name: sys_enter_sync_file_range\nfield:int fd; offset:16; size:8; signed:0;\nfield:loff_t offset; offset:24; size:8; signed:0;\nfield:loff_t nbytes; offset:32; size:8; signed:0;\nfield:unsigned int flags; offset:40; size:8; signed:0;\n'
 p['raw']=base64.b64encode(('# entries-in-buffer/entries-written: '+str(len(lines))+'/'+str(len(lines))+'   #P:8\n'+'\n'.join(lines)+'\n').encode()).decode()
 counts={str(cpu):sum(('[%03d]'%cpu) in line for line in lines) for cpu in range(8)}
 for cpu in range(8):p['cpu_stats'][str(cpu)]='entries: '+str(counts[str(cpu)])+'\n'+p['cpu_stats'][str(cpu)]
 return p

class Tests(unittest.TestCase):
 def test_valid_lineage_parent_threads_and_child_boundary(self):
  v=a.analyze(packet());self.assertEqual(v['matched_daemon_syscall_pairs'],6);self.assertEqual(v['child_syscall_events_excluded_from_daemon_timings'],1);self.assertEqual(v['syncfs_observed_positive_quantum_overlap_lower_bound'],2)
 def test_no_false_overlap_at_quantized_tie(self):self.assertEqual(a.positive_overlap([{'start_ns':1,'end_ns':2},{'start_ns':2,'end_ns':3}]),1)
 def test_raw_mutation_rejections(self):
  original=packet();raw=base64.b64decode(original['raw']).decode()
  for label,old,new in [('missing-entry','task-11 [001] d... 1.000007: sys_syncfs(fd: 3)\n',''),('bad-cpu','[000]','[008]'),('unknown-thread','task-12','task-999'),('wrong-selector','80000102','80000101'),('unknown-syscall','sys_fsync','sys_open'),('wrong-pair','1.000009: sys_syncfs ->','1.000009: sys_fsync ->'),('unknown-field','fd: 3)','fd: 3, extra: 1)'),('missing-task','task-10 [000] d... 1.000001: task_newtask: pid=12 comm=sandboxd clone_flags=10000 oom_score_adj=0\n','')]:
   p=copy.deepcopy(original);p['raw']=base64.b64encode(raw.replace(old,new,1).encode()).decode()
   with self.subTest(label=label),self.assertRaises(a.InvalidObservation):a.analyze(p)
 def test_loss_rejections(self):
  for cpu in range(8):
   for name in ('overrun','commit overrun','dropped events'):
    p=packet();p['cpu_stats'][str(cpu)]=p['cpu_stats'][str(cpu)].replace(name+': 0',name+': 1')
    with self.subTest(cpu=cpu,name=name),self.assertRaises(a.InvalidObservation):a.analyze(p)
 def test_anchor_metadata_rejection(self):
  p=packet();p['runtime_anchor_after']['3']['inode']+=1
  with self.assertRaises(a.InvalidObservation):a.analyze(p)
 def test_console_frames_reassemble_and_refuse_mutation(self):
  p=packet();b=json.dumps(p).encode();sha=hashlib.sha256(b).hexdigest();n=(len(b)+2047)//2048;rows=[a.PREFIX+json.dumps(dict(scope='checkpoint',index=i,chunks=n,sha256=sha,bytes=len(b),data=base64.b64encode(b[i*2048:(i+1)*2048]).decode())) for i in range(n)];console=('\n'.join(rows)+'\n').encode();self.assertEqual(a.packets(console,'checkpoint'),p)
  for broken in [b'',('\n'.join(rows+rows[:1])+'\n').encode(),('\n'.join(reversed(rows))+'\n').encode(),console.replace(sha.encode(),b'0'*64)]:
   with self.assertRaises(a.InvalidObservation):a.packets(broken,'checkpoint')
 def test_complete_pair_or_cpu_count_cannot_be_silently_dropped(self):
  for kind in ('drop-pair','comment-pair','wrong-cpu','wrong-header','wrong-cpu-counter'):
   p=packet();text=base64.b64decode(p['raw']).decode()
   if kind in ('drop-pair','comment-pair'):
    for line in list(text.splitlines()):
     if '1.000007: sys_syncfs' in line or '1.000010: sys_syncfs' in line:text=text.replace(line+'\n',('' if kind=='drop-pair' else '# '+line+'\n'))
   elif kind=='wrong-cpu':text=text.replace('task-11 [001] d... 1.000007','task-11 [000] d... 1.000007')
   elif kind=='wrong-header':text=text.replace('15/15','14/14')
   else:p['cpu_stats']['0']='entries: 999\n'+'\n'.join(p['cpu_stats']['0'].splitlines()[1:])+'\n'
   p['raw']=base64.b64encode(text.encode()).decode()
   with self.subTest(kind=kind),self.assertRaises(a.InvalidObservation):a.analyze(p)
 def test_signed_error_is_recorded_not_hidden(self):
  p=packet();raw=base64.b64decode(p['raw']).decode().replace('1.000009: sys_syncfs -> 0x0','1.000009: sys_syncfs -> 0xfffffffffffffffb');p['raw']=base64.b64encode(raw.encode()).decode();self.assertEqual(a.analyze(p)['metrics']['syncfs']['return_counts'],{'-5':1,'0':1})

class RangeAndCreates(unittest.TestCase):
 def test_fixed_positive_write_only_ranges(self):
  for old,new in [('flags: 2','flags: 0'),('flags: 2','flags: 1'),('flags: 2','flags: 4'),('nbytes: 800000','nbytes: 0'),('nbytes: 800000','nbytes: 800001'),('offset: 0','offset: ffffffffffffffff')]:
   p=packet();raw=base64.b64decode(p['raw']).decode();p['raw']=base64.b64encode(raw.replace(old,new).encode()).decode()
   with self.subTest(new=new),self.assertRaises(a.InvalidObservation):a.analyze(p)
 def test_fixed_B_program_window_and_raw_request(self):
  p=packet();p['ordinary_elf_sha256']='596a7db7480d57f904fa35240cddbc0bc8eb9f2ff8c4059f9335f83d25b71f69'
  with self.assertRaises(a.InvalidObservation):a.analyze(p)
  p['asset_writeback_window_bytes']=1<<20
  with self.assertRaises(a.InvalidObservation):a.analyze(p)
  raw=base64.b64decode(p['raw']).decode().replace('nbytes: 800000','nbytes: 100000');p['raw']=base64.b64encode(raw.encode()).decode();self.assertEqual(a.analyze(p)['writeback_requested_bytes'],1<<20)
 def test_all_create_rows_and_phases_are_required(self):
  for mode in ['missing','order','bool-time','failed','phase','extra','unknown-field','wrong-scope']:
   p=packet()
   if mode=='missing':p['http_create_elapsed'].pop()
   elif mode=='order':p['http_create_elapsed'].reverse()
   elif mode=='bool-time':p['http_create_elapsed'][0]['elapsed_ns']=True
   elif mode=='failed':p['http_create_elapsed'][0]['success']=False
   elif mode=='phase':p['http_create_elapsed'][4]['phase']='initial'
   elif mode=='extra':p['http_create_elapsed'].append(p['http_create_elapsed'][0])
   elif mode=='unknown-field':p['http_create_elapsed'][0]['key']='not allowed'
   else:p['scope']='other'
   with self.subTest(mode=mode),self.assertRaises(a.InvalidObservation):a.analyze(p)
 def test_fixed_range_kernel_format_not_name_only(self):
  p=packet();p['event_formats']['syscalls/sys_enter_sync_file_range']='name: sys_enter_sync_file_range\n'
  with self.assertRaises(a.InvalidObservation):a.analyze(p)
  p=packet();p['event_formats']['syscalls/sys_enter_sync_file_range']+='field:int extra; offset:48; size:8; signed:0;\n'
  with self.assertRaises(a.InvalidObservation):a.analyze(p)
def frames(value,prefix):
 b=json.dumps(value).encode();sha=hashlib.sha256(b).hexdigest();n=(len(b)+2047)//2048
 return ('\n'.join(prefix+json.dumps(dict(scope=value['scope'],index=i,chunks=n,sha256=sha,bytes=len(b),data=base64.b64encode(b[i*2048:(i+1)*2048]).decode())) for i in range(n))+'\n').encode()
def abi(p):return dict(schema=1,kind='qualified_before_trace_and_create',scope=p['scope'],ordinary_elf_sha256=p['ordinary_elf_sha256'],asset_writeback_window_bytes=p['asset_writeback_window_bytes'],event_formats=p['event_formats'],tracing_off_before_measured_create=True)
class ABIBinding(unittest.TestCase):
 def test_actual_receipt_and_normal_packet_both_required(self):
  p=packet();console=frames(abi(p),a.ABI_PREFIX)+frames(p,a.PREFIX);v=a.analyze_console(console,'checkpoint');self.assertTrue(v['actual_kernel_ABI_receipt_required_before_create']);self.assertTrue(v['ABI_and_final_packet_full_formats_byte_equal'])
 def test_missing_or_rejected_or_partial_ABI_not_performance(self):
  p=packet()
  for name in p['event_formats']:p['event_formats'][name]+='# fixed framing-only test padding\n'*100
  normal=frames(p,a.PREFIX);qualified=frames(abi(p),a.ABI_PREFIX);self.assertGreater(len(qualified.splitlines()),1)
  for console in (normal,qualified+normal+(a.SETUP_FAILURE_PREFIX+'{}\n').encode(),qualified.splitlines()[0]+b'\n'+normal,qualified+qualified+normal):
   with self.assertRaises(a.InvalidObservation):a.analyze_console(console,'checkpoint')
 def test_receipt_fields_scope_hash_window_and_actual_formats_bound(self):
  for field,value in [('schema',True),('kind','setup_rejected_no_valid_measurement'),('scope','cold'),('ordinary_elf_sha256','0'*64),('asset_writeback_window_bytes',0),('tracing_off_before_measured_create',False),('event_formats',{})]:
   p=packet();v=abi(p);v[field]=value
   with self.subTest(field=field),self.assertRaises(a.InvalidObservation):a.analyze_console(frames(v,a.ABI_PREFIX)+frames(p,a.PREFIX),'checkpoint')
 def test_C_typedef_signed1_is_not_storage_signedness(self):
  p=packet();p['event_formats']['syscalls/sys_enter_sync_file_range']=p['event_formats']['syscalls/sys_enter_sync_file_range'].replace('signed:0;','signed:1;',1)
  with self.assertRaises(a.InvalidObservation):a.analyze_console(frames(abi(p),a.ABI_PREFIX)+frames(p,a.PREFIX),'checkpoint')
if __name__=='__main__':unittest.main()
