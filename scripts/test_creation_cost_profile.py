import ast,base64,copy,hashlib,json,os,stat,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from build_nested_host import init_scripts,validate_creation_cost_image_mode
from creation_cost_delivery import validate_creation_cost_profile,InvalidDelivery
from test_creation_cost_delivery import generated_console
from test_creation_cost_trace_analyzer import packet,frames,abi
from creation_cost_trace_analyzer import ABI_PREFIX,PREFIX
from creation_cost_trace_analyzer import analyze_console,InvalidObservation

class ProfileTests(unittest.TestCase):
 def test_all_legacy_default_bootstrap_and_service_match_original_D_golden_bytes(self):
  # Frozen from original D sources, not runtime/console bytes or current-output self-comparison.
  golden={'default': ['d07af469f30ff32d385bb2534b8349fe0ea940810409493832d8bb08c6342b60', '944bea67a8696894732fa490effeefa5516a44bbec6f44c5e57420bdb37581e7'], 'state_io': ['d07af469f30ff32d385bb2534b8349fe0ea940810409493832d8bb08c6342b60', 'ebd5033bf0cad9147a5e33f8fd6bd6677902cd7266579166bb83ac8549fef11f'], 'quota_probe': ['d07af469f30ff32d385bb2534b8349fe0ea940810409493832d8bb08c6342b60', '535c1ecfff2957398145844ddae2b06c592f60ffd3873a8cc38313b4580a2448'], 'quota_driver': ['d07af469f30ff32d385bb2534b8349fe0ea940810409493832d8bb08c6342b60', '08423bd02b7bbb42086fe8c4fa40775b129d504be966c112cc86b68aea557578'], 'quota_snapshot': ['d07af469f30ff32d385bb2534b8349fe0ea940810409493832d8bb08c6342b60', '834327dc376c245c4e48b86c481dee8eb007da5b104d4e0ca63ad42f1b99e583'], 'quota_unenforced': ['d07af469f30ff32d385bb2534b8349fe0ea940810409493832d8bb08c6342b60', '3f83047a518979d17336c4661f0c3fafe532a9c4861794c399370de0d2d28632'], 'quota_state_io': ['d07af469f30ff32d385bb2534b8349fe0ea940810409493832d8bb08c6342b60', 'd12fcb2de76b1e96b17736814f2329c0333c2884032aa3eb3f2f019253717c20'], 'quota_switch': ['d07af469f30ff32d385bb2534b8349fe0ea940810409493832d8bb08c6342b60', '4940bdbca6081e4ae26a57c10ce07a9c0487cbc7bf2bd760aa0af2ee0c8186fd'], 'node_budget': ['d07af469f30ff32d385bb2534b8349fe0ea940810409493832d8bb08c6342b60', 'ad5b94669f402a22121a19b0eac66a56d467b8163c44206fd8bd97310ee0a8c6'], 'node_snapshot': ['d07af469f30ff32d385bb2534b8349fe0ea940810409493832d8bb08c6342b60', '86fdd2a8c3dd140c1fefdc268da6084a5f977cc11a4d82b7a7d2e2776cbc7878'], 'node_load': ['d07af469f30ff32d385bb2534b8349fe0ea940810409493832d8bb08c6342b60', 'afa7f742118464fa198bc1036733c7e2f78805f2cfebe403e0cd3098e8ed69c5']}
  for profile,wanted in golden.items():
   options={} if profile=="default" else {profile:True}
   actual=init_scripts((),**options)
   with self.subTest(profile=profile):self.assertEqual([hashlib.sha256(value.encode()).hexdigest() for value in actual],wanted)
 def test_default_image_service_is_original_byte_exact(self):
  _,service=init_scripts((),node_budget=True)
  self.assertIn('exec /usr/bin/xandbox-host-fixture -mode node-budget >/dev/console 2>&1\n',service);self.assertNotIn('creation-cost',service)
 def test_explicit_closed_modes_only_modify_trusted_L1_startup(self):
  off=init_scripts((),node_budget=True)
  for mode in ('observe','maximum'):
   on=init_scripts((),node_budget=True,creation_cost_mode=mode);self.assertEqual(on[0],off[0]);self.assertEqual(on[1].replace(' -creation-cost-mode '+mode,''),off[1])
 def test_image_mode_rejects_before_root_or_assets(self):
  for mode,budget in [('bad',True),('observe;exit',True),(True,True),('observe',1),('observe',False),('maximum',False)]:
   with self.assertRaises(ValueError):validate_creation_cost_image_mode(mode,budget)
 def test_host_profile_closes_unknown_modifiers_and_modes(self):
  base=types.SimpleNamespace(creation_cost_diagnostics=None,node_budget=True,node_load=False,node_snapshot=False,node_oom=False,fixture='x',daemon='y',log_dir='x',report='y',source_revision='x')
  validate_creation_cost_profile(base)
  for mode in ('observe','maximum'):
   okay=types.SimpleNamespace(**vars(base));okay.creation_cost_diagnostics=mode;validate_creation_cost_profile(okay)
   for key,value in [('node_budget',False),('node_load',True),('node_snapshot',True),('node_oom',True),('new_future_modifier',True),('creation_cost_diagnostics','bad')]:
    bad=types.SimpleNamespace(**vars(okay));setattr(bad,key,value)
    with self.assertRaises(InvalidDelivery):validate_creation_cost_profile(bad)
 def test_both_delivery_sites_explicitly_bind_launch_UID_before_kill(self):
  path=Path(__file__).with_name('kvm_nested_host.py');text=path.read_text();tree=ast.parse(text);calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='record_delivery'];self.assertEqual(len(calls),2)
  for call in calls:self.assertEqual([(x.arg,ast.unparse(x.value)) for x in call.keywords],[('expected_uid','uid')])
  self.assertLess(text.index('validate_creation_cost_profile(args)'),text.index('assert os.geteuid() == 0'));self.assertLess(text.index("record_delivery(root/'console.log',logs,'checkpoint'"),text.index('cut_began=time.monotonic()'))
 def test_analyzer_requires_explicit_noninterchangeable_shapes(self):
  self.assertEqual(analyze_console(generated_console('checkpoint'),'checkpoint','observe')['explicit_synthetic_ASCII_whitespace_bytes'],0)
  with self.assertRaises(InvalidObservation):analyze_console(generated_console('checkpoint'),'checkpoint','maximum')

def generated_normal_bytes(value,data):
 sha=hashlib.sha256(data).hexdigest();count=(len(data)+2047)//2048
 return frames(abi(value),ABI_PREFIX)+b''.join((PREFIX+json.dumps(dict(scope=value['scope'],index=i,chunks=count,bytes=len(data),sha256=sha,data=base64.b64encode(data[i*2048:(i+1)*2048]).decode()))+'\n').encode() for i in range(count))

class StrictShapeTests(unittest.TestCase):
 def test_generated_maximum_shape_and_observe_are_not_interchangeable(self):
  value=packet();original=json.dumps(value).encode();normal=original+b' '*((1<<20)-len(original));console=generated_normal_bytes(value,normal);result=analyze_console(console,'checkpoint','maximum');self.assertEqual(result['normal_JSON_prefix_bytes'],len(original));self.assertEqual(result['explicit_synthetic_ASCII_whitespace_bytes'],(1<<20)-len(original))
  with self.assertRaises(InvalidObservation):analyze_console(console,'checkpoint','observe')
 def test_valid_JSON_noncanonical_suffix_refused_even_with_correct_SHA(self):
  value=packet();original=json.dumps(value).encode();data=original+b' '*((1<<20)-len(original)-1)+b'\t'
  with self.assertRaises(InvalidObservation):analyze_console(generated_normal_bytes(value,data),'checkpoint','maximum')
 def test_duplicate_inner_payload_key_is_not_silently_normalized(self):
  value=packet();data=json.dumps(value).encode();data=b'{"schema":0,'+data[1:]
  with self.assertRaises(InvalidObservation):analyze_console(generated_normal_bytes(value,data),'checkpoint','observe')
 def test_incomplete_final_newline_is_not_an_observation(self):
  with self.assertRaises(InvalidObservation):analyze_console(generated_console('checkpoint')[:-1],'checkpoint','observe')

class OfflineCLITests(unittest.TestCase):
 def test_private_console_summary_and_no_overwrite(self):
  with tempfile.TemporaryDirectory(prefix='xandbox-generated-cli-') as directory:
   root=Path(directory);root.chmod(0o700);console=root/'synthetic-console';console.write_bytes(generated_console('checkpoint'));console.chmod(0o600);output=root/'summary.json';script=Path(__file__).with_name('creation_cost_trace_analyzer.py');argv=[sys.executable,'-B',str(script),'--console',str(console),'--scope','checkpoint','--mode','observe','--output',str(output)];result=subprocess.run(argv,capture_output=True,timeout=10);self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(stat.S_IMODE(output.stat().st_mode),0o600);self.assertTrue(json.loads(output.read_bytes())['offline_console_integrity_only_not_pre_cut_delivery_or_full_KVM_qualification']);old=output.read_bytes();self.assertNotEqual(subprocess.run(argv,capture_output=True,timeout=10).returncode,0);self.assertEqual(output.read_bytes(),old)
 def test_nonprivate_input_refused(self):
  with tempfile.TemporaryDirectory(prefix='xandbox-generated-cli-') as directory:
   root=Path(directory);root.chmod(0o700);console=root/'console';console.write_bytes(generated_console('checkpoint'));console.chmod(0o644);output=root/'summary';script=Path(__file__).with_name('creation_cost_trace_analyzer.py');result=subprocess.run([sys.executable,'-B',str(script),'--console',str(console),'--scope','checkpoint','--mode','observe','--output',str(output)],capture_output=True,timeout=10);self.assertNotEqual(result.returncode,0);self.assertFalse(output.exists())
