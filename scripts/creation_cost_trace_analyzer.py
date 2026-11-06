"""TEST ONLY offline diagnostic integrity. Kernel elapsed time is not pure IO or SLO."""
import base64,collections,hashlib,json,math,re
from creation_cost_delivery import inspect_console, InvalidDelivery, bounded_file_reader
from creation_cost_server import validate_create_server

MAX_RAW=512<<10
PREFIX='XANDBOX_CREATION_COST_PRIVATE '
EVENTS={'syscalls/sys_enter_quotactl_fd','syscalls/sys_exit_quotactl_fd','syscalls/sys_enter_syncfs','syscalls/sys_exit_syncfs','syscalls/sys_enter_fsync','syscalls/sys_exit_fsync','syscalls/sys_enter_sync_file_range','syscalls/sys_exit_sync_file_range','task/task_newtask'}
LINE=re.compile(r'^\s*.+-([1-9][0-9]*)\s+\[([0-9]{3})\]\s+\S+\s+([0-9]+)\.([0-9]{6}):\s+(.+)$')
TASK=re.compile(r'^task_newtask:\s+pid=([1-9][0-9]*) comm=(.{1,16}) clone_flags=([0-9a-f]+) oom_score_adj=(-?[0-9]+)$')
ENTER=re.compile(r'^sys_(quotactl_fd|syncfs|fsync|sync_file_range)\((.+)\)$')
EXIT=re.compile(r'^sys_(quotactl_fd|syncfs|fsync|sync_file_range) -> 0x([0-9a-f]{1,16})$')

class InvalidObservation(ValueError):pass

def need(x,msg):
 if not x:raise InvalidObservation(msg)

def unique_object(pairs):
 out={}
 for key,value in pairs:
  need(key not in out,'duplicate JSON object field')
  out[key]=value
 return out

def packets(console,scope):
 need(scope in ('checkpoint','cold'),'fixed console scope')
 selected=[]
 for line in console.decode('utf-8').splitlines():
  if line.startswith(PREFIX):
   v=json.loads(line[len(PREFIX):],object_pairs_hook=unique_object);need(set(v)=={'scope','index','chunks','sha256','bytes','data'},'unknown frame fields')
   if v['scope']==scope:selected.append(v)
 need(selected,'no original private frame set')
 first=selected[0];n=first['chunks'];size=first['bytes'];h=first['sha256']
 need(type(n) is int and 1<=n<=512 and len(selected)==n and type(size) is int and 0<size<=1<<20 and re.fullmatch('[0-9a-f]{64}',h),'frame set bounds')
 out=[]
 for i,v in enumerate(selected):
  need(v['index']==i and type(v['index']) is int and v['chunks']==n and v['bytes']==size and v['sha256']==h,'missing/duplicate/reordered/mixed frame')
  data=base64.b64decode(v['data'],validate=True);need(len(data)==min(2048,size-i*2048),'noncanonical frame range');out.append(data)
 data=b''.join(out);need(len(data)==size and hashlib.sha256(data).hexdigest()==h,'whole original payload digest')
 value=json.loads(data,object_pairs_hook=unique_object);need(value['scope']==scope,'scope differs');return value

def stats_check(stats):
 need(set(stats)==set(map(str,range(8))),'all eight CPU stats required')
 counts={}
 for cpu,raw in stats.items():
  seen={}
  entries=[]
  for line in raw.splitlines():
   if ':' not in line:continue
   k,v=map(str.strip,line.split(':',1))
   if k=='entries':
    need(re.fullmatch('[0-9]+',v),'invalid entry counter');entries.append(int(v))
   if k in ('overrun','commit overrun','dropped events'):
    need(k not in seen and v=='0','nonzero/duplicate loss counter');seen[k]=v
  need(len(seen)==3 and len(entries)==1,'missing loss or entry counter');counts[cpu]=entries[0]
 return counts

def arg_values(text,name):
 expected=['fd','cmd','id','addr'] if name=='quotactl_fd' else ['fd','offset','nbytes','flags'] if name=='sync_file_range' else ['fd']
 rows=text.split(', ');need(len(rows)==len(expected),'unknown syscall argument shape');out={}
 for key,row in zip(expected,rows):
  match=re.fullmatch(re.escape(key)+r': (?:0x)?([0-9a-f]{1,16})',row);need(match,'unexpected argument name/value');out[key]=int(match[1],16)
 need(out['fd']<1<<31,'invalid syscall FD')
 if name=='quotactl_fd':need(out['cmd'] in (0x80000102,0x80000402,0x80000702,0x80000802) and out['id']<1<<32,'noncanonical project quota selector')
 return out

def signed64(value):return value-(1<<64) if value&(1<<63) else value

def positive_overlap(intervals):
 # Text timestamps are quantized to microseconds. Exit-before-entry ties
 # produce a lower bound; never invent overlap or ordering within one quantum.
 sweep=[]
 for row in intervals:
  if row['end_ns']>row['start_ns']:sweep.extend([(row['start_ns'],1),(row['end_ns'],-1)])
 active=maximum=0
 for _,delta in sorted(sweep,key=lambda x:(x[0],x[1])):active+=delta;maximum=max(maximum,active);need(active>=0,'negative interval sweep')
 need(active==0,'unclosed interval sweep');return maximum

def summary(values):
 need(values,'empty metric distribution');v=sorted(values);rank=lambda p:v[max(0,math.ceil(p*len(v))-1)]/1e6
 return dict(count=len(v),sum_ms=sum(v)/1e6,min_ms=v[0]/1e6,max_ms=v[-1]/1e6,p50_ms=rank(.5),p99_ms=rank(.99))

def analyze(packet):
 need(type(packet.get('schema')) is int and packet['schema'] in (3,4) and type(packet.get('target_pid')) is int and packet['target_pid']>0,'fixed observer schema/target')
 schema=packet['schema']
 programs={'d748d8cf7216980582720c1618e1b0473a9228e371ae850257059a8980e98e01':8<<20,'596a7db7480d57f904fa35240cddbc0bc8eb9f2ff8c4059f9335f83d25b71f69':1<<20}
 need(packet.get('ordinary_elf_sha256') in programs,'fixed A/B ordinary daemon only');window=programs[packet['ordinary_elf_sha256']];need(type(packet.get('asset_writeback_window_bytes')) is int and packet['asset_writeback_window_bytes']==window,'fixed source/ELF cadence')
 scope=packet['scope'];need(scope in ('checkpoint','cold'),'fixed observation scope');creates=packet.get('http_create_elapsed');need(type(creates) is list and len(creates)==(5 if scope=='checkpoint' else 1),'all original successful create timings required')
 for i,row in enumerate(creates):
  phase='cold-fresh' if scope=='cold' else 'checkpoint-fresh' if i==4 else 'initial'
  fields={'ordinal','phase','elapsed_ns','success'}|({'server_timing'} if schema==4 else set())
  need(type(row) is dict and set(row)==fields and type(row['ordinal']) is int and row['ordinal']==i and row['phase']==phase and type(row['elapsed_ns']) is int and 0<row['elapsed_ns']<=900_000_000_000 and row['success'] is True,'invalid/failed/reordered/missing fixed create timing')
  if schema==4:
   try:validate_create_server(row['server_timing'],row['elapsed_ns'])
   except ValueError as error:raise InvalidObservation('invalid fixed create server timings') from error
 need(set(packet['event_formats'])==EVENTS,'exact six syscall and one lineage formats')
 for path,text in packet['event_formats'].items():need('name: '+path.split('/')[1]+'\n' in text,'event format name mismatch')
 range_text=packet['event_formats']['syscalls/sys_enter_sync_file_range']
 allowed_fields={'common_type','common_flags','common_preempt_count','common_pid','__syscall_nr','fd','offset','nbytes','flags'};seen_fields=set()
 for line in range_text.splitlines():
  if line.strip().startswith('field:'):
   declaration=re.match(r'^\s*field:([^;]+);',line);need(declaration,'malformed fixed field declaration');name=declaration[1].split()[-1];need(name in allowed_fields and name not in seen_fields,'unknown/duplicate fixed event field');seen_fields.add(name)
 for typ,name,offset,signed in [('int','fd',16,0),('loff_t','offset',24,0),('loff_t','nbytes',32,0),('unsigned int','flags',40,0)]:
  need(len(re.findall(r'^\s*field:'+re.escape(typ)+' '+name+r';\s+offset:'+str(offset)+r';\s+size:8;\s+signed:'+str(signed)+r';\s*$',range_text,re.M))==1,'range syscall fixed kernel ABI')
 entry_counts=stats_check(packet['cpu_stats']);target=packet['target_pid'];tasks=packet['initial_stopped_threads']
 need(type(tasks) is list and 1<=len(tasks)<=128 and len(set(tasks))==len(tasks) and all(type(t) is str and re.fullmatch('[1-9][0-9]*',t) for t in tasks) and str(target) in tasks,'exact stopped daemon task seed')
 lineage={int(t):target for t in tasks};pending={};completed=[];last=-1;foreign=0;newtasks=0;pid_reuses=0;rows=0
 raw=base64.b64decode(packet['raw'],validate=True);need(0<len(raw)<=MAX_RAW,'raw observation bound');per_cpu=collections.Counter();header=[]
 for line in raw.decode('utf-8').splitlines():
  if line.startswith('# entries-in-buffer/entries-written:'):
   hm=re.fullmatch(r'# entries-in-buffer/entries-written: ([0-9]+)/([0-9]+)\s+#P:8',line);need(hm,'noncanonical trace count header');header.append((int(hm[1]),int(hm[2])))
  if not line.strip() or line.lstrip().startswith('#'):continue
  match=LINE.fullmatch(line);need(match,'unknown trace line');tid,cpu=int(match[1]),int(match[2]);nanos=int(match[3])*1_000_000_000+int(match[4])*1000;event=match[5]
  need(cpu<8 and nanos>=last and tid in lineage,'unknown CPU/thread or regressed clock');last=nanos;rows+=1;per_cpu[str(cpu)]+=1;need(rows<=8192,'trace event bound')
  task=TASK.fullmatch(event)
  if task:
   child=int(task[1]);flags=int(task[3],16);need(child!=target,'target PID cannot be reused');need(child not in pending,'PID reuse during selected syscall')
   if child in lineage:pid_reuses+=1
   lineage[child]=lineage[tid] if flags&0x10000 else child;newtasks+=1;continue
  entry=ENTER.fullmatch(event);exit_=EXIT.fullmatch(event);need(bool(entry)!=bool(exit_),'unknown/malformed selected event')
  name=(entry or exit_)[1]
  if lineage[tid]!=target:foreign+=1;continue # Boundary child pairs are NOT daemon latency samples.
  if entry:
   need(tid not in pending,'nested/duplicate selected daemon entry');pending[tid]=dict(name=name,start_ns=nanos,args=arg_values(entry[2],name))
  else:
   need(tid in pending and pending[tid]['name']==name,'missing/reordered selected daemon pair');row=pending.pop(tid);ret=signed64(int(exit_[2],16));need(-4095<=ret<=0,'unknown selected syscall return');row.update(end_ns=nanos,elapsed_ns=nanos-row['start_ns'],ret=ret)
   if name=='sync_file_range':need(row['args']['flags']==2 and 0<=row['args']['offset']<1<<63 and 0<row['args']['nbytes']<=window and row['args']['offset']+row['args']['nbytes']<1<<63,'WRITE-only strictly positive bounded already-written request shape')
   completed.append(row)
 need(not pending and completed and newtasks>0,'unclosed daemon pair or missing real child lineage')
 need(len(header)==1 and header[0]==(rows,rows) and all(per_cpu[cpu]==count for cpu,count in entry_counts.items()),'raw/header/per-CPU entry counts differ')
 syncs=[v for v in completed if v['name']=='syncfs'];need(syncs,'missing ordinary Syncfs observations')
 before=packet['runtime_anchor_before'];after=packet['runtime_anchor_after'];need(before and after,'runtime anchor metadata required')
 for row in syncs:
  fd=str(row['args']['fd']);need(fd in before and fd in after and before[fd]==after[fd],'Syncfs FD not the same sampled live runtime anchor');need(set(before[fd])=={'fd','device','inode','mount_id'} and all(type(v) is int and v>=0 for v in before[fd].values()) and before[fd]['inode']>0 and before[fd]['mount_id']>0,'invalid runtime anchor metadata')
 groups=collections.defaultdict(list)
 for v in completed:
  label='Q_SYNC' if v['name']=='quotactl_fd' and v['args']['cmd']==0x80000102 else 'quota_other' if v['name']=='quotactl_fd' else 'WRITE_range' if v['name']=='sync_file_range' else v['name'];groups[label].append(v)
 metrics={k:summary([v['elapsed_ns'] for v in values])|dict(return_counts=dict(collections.Counter(str(v['ret']) for v in values))) for k,values in groups.items()}
 need(set(metrics)=={'Q_SYNC','quota_other','syncfs','fsync','WRITE_range'},'missing selected syscall class')
 return dict(schema=schema,server_creation_stage_observations_available=(schema==4),server_spans_are_nested_and_not_pure_queue_or_physical_io=True,no_per_create_kernel_clock_anchors_or_syscall_critical_path_attribution=True,asset_writeback_window_bytes=window,http_create_elapsed=creates,http_create_elapsed_sum_ns=sum(x['elapsed_ns'] for x in creates),writeback_requested_bytes=sum(v['args']['nbytes'] for v in completed if v['name']=='sync_file_range'),writeback_per_fd_lifetime_not_observed_no_file_identity_or_coverage_claim=True,scope=packet['scope'],ordinary_elf_sha256=packet['ordinary_elf_sha256'],raw_trace_sha256=hashlib.sha256(raw).hexdigest(),raw_trace_bytes=len(raw),total_trace_events=rows,matched_daemon_syscall_pairs=len(completed),recorded_task_newtask_events=newtasks,recorded_pid_reuse_transitions=pid_reuses,child_syscall_events_excluded_from_daemon_timings=foreign,all8_cpu_loss_counters_zero=True,all_raw_header_and_per_cpu_entry_counts_equal=True,all_daemon_pairs_closed=True,identity_reconstructed_from_time_ordered_kernel_clone_flags_not_cached_tgid=True,syncfs_anchor_before_after_verified=True,syncfs_observed_positive_quantum_overlap_lower_bound=positive_overlap(syncs),metrics=metrics,timestamps_quantized_ns=1000,kernel_syscall_elapsed_includes_scheduler_wait_not_pure_io=True,not_a_throughput_slo_or_original40m_or_causal_speedup_proof=True)

ABI_PREFIX='XANDBOX_CREATION_COST_ABI_PRIVATE '
SETUP_FAILURE_PREFIX='XANDBOX_CREATION_COST_SETUP_FAILURE_PRIVATE '

def abi_packets(console,scope):
 rows=[]
 for line in console.decode('utf-8').splitlines():
  if line.startswith(ABI_PREFIX):
   frame=json.loads(line[len(ABI_PREFIX):],object_pairs_hook=unique_object);need(frame.get('scope')==scope,'unexpected extra ABI scope in one original console');rows.append(PREFIX+line[len(ABI_PREFIX):])
 return packets(('\n'.join(rows)+'\n').encode(),scope)

def validate_abi_receipt(abi,packet):
 need(type(abi) is dict and set(abi)=={'schema','kind','scope','ordinary_elf_sha256','asset_writeback_window_bytes','event_formats','tracing_off_before_measured_create'},'closed actual kernel ABI receipt')
 need(type(abi['schema']) is int and abi['schema']==1 and abi['kind']=='qualified_before_trace_and_create' and abi['tracing_off_before_measured_create'] is True,'ABI qualified outside measured trace before create')
 for key in ('scope','ordinary_elf_sha256','asset_writeback_window_bytes','event_formats'):need(abi[key]==packet[key],'precreate ABI differs from measured packet')

def analyze_console(console,scope,mode='observe'):
 need(mode in ('observe','maximum'),'closed observe/maximum mode')
 try:delivery=inspect_console(console,scope)
 except (InvalidDelivery,ValueError,TypeError) as error:raise InvalidObservation('invalid bounded original frame sets') from error
 need(delivery['complete'],'incomplete original frame sets; never repair')
 normal=delivery['payloads']['normal'];text=normal.decode('utf-8');_,end=json.JSONDecoder(object_pairs_hook=unique_object).raw_decode(text);prefix=text[:end].encode('utf-8');suffix=normal[len(prefix):]
 if mode=='observe':need(not suffix,'observe must not silently consume maximum-mode padding')
 else:need(len(normal)==1<<20 and delivery['received_frames']['normal']==512 and 0<len(prefix)<1<<20 and suffix==b' '*len(suffix),'explicit maximum transport requires original JSON plus ASCII spaces to existing bound')
 need(not any(line.startswith(SETUP_FAILURE_PREFIX) for line in console.decode('utf-8').splitlines()),'setup-rejected metadata is not a valid performance sample')
 packet=packets(console,scope);abi=abi_packets(console,scope);validate_abi_receipt(abi,packet);out=analyze(packet)
 first=next(json.loads(line[len(ABI_PREFIX):],object_pairs_hook=unique_object) for line in console.decode('utf-8').splitlines() if line.startswith(ABI_PREFIX));out.update(actual_kernel_ABI_receipt_required_before_create=True,ABI_and_final_packet_full_formats_byte_equal=True,qualified_ABI_original_payload_sha256=first['sha256'],diagnostic_transport_mode=mode,normal_JSON_prefix_bytes=len(prefix),explicit_synthetic_ASCII_whitespace_bytes=len(suffix),offline_console_integrity_only_not_pre_cut_delivery_or_full_KVM_qualification=True);return out


def main():
 import argparse,os,stat
 from pathlib import Path
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--console',required=True)
 parser.add_argument('--scope',required=True,choices=('checkpoint','cold'))
 parser.add_argument('--mode',required=True,choices=('observe','maximum'))
 parser.add_argument('--output',required=True,help='new private JSON file in an existing owned0700 directory')
 args=parser.parse_args();data=bounded_file_reader(Path(args.console),expected_uid=os.geteuid())()
 result=analyze_console(data,args.scope,args.mode)
 output=Path(args.output);directory=os.open(output.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
 try:
  info=os.fstat(directory);need(info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700,'owned private output directory required')
  fd=os.open(output.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600,dir_fd=directory)
  with os.fdopen(fd,'w') as target:json.dump(result,target,indent=2);target.write('\n')
 finally:os.close(directory)
 print('Private offline integrity summary saved; not performance or full KVM qualification.')

if __name__=='__main__':main()
