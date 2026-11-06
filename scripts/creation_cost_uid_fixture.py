#!/usr/bin/env python3
"""EXPLICIT Linux/root synthetic FD-owner mechanism. Not a KVM or production test."""
import argparse,base64,hashlib,json,os,platform,stat,sys,tempfile
from pathlib import Path

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-owned-uid-fixture',action='store_true',required=True);parser.parse_args()
 if os.geteuid()!=0 or platform.system()!='Linux':raise SystemExit('explicit Linux/root fixture required; nothing executed')
 sys.path.insert(0,str(Path(__file__).resolve().parent))
 from creation_cost_delivery import record_delivery,InvalidDelivery
 payload=b'{"scope":"checkpoint","synthetic_ownership_fixture":true}';sha=hashlib.sha256(payload).hexdigest();wire=b''
 for prefix in ('XANDBOX_CREATION_COST_ABI_PRIVATE ','XANDBOX_CREATION_COST_PRIVATE '):wire+=prefix.encode()+json.dumps(dict(scope='checkpoint',index=0,chunks=1,bytes=len(payload),sha256=sha,data=base64.b64encode(payload).decode())).encode()+b'\n'
 with tempfile.TemporaryDirectory(prefix='xandbox-explicit-owned-uid-') as directory:
  root=Path(directory);console=root/'console';console.write_bytes(wire);console.chmod(0o600);os.chown(console,850123,850123)
  result=record_delivery(console,root,'checkpoint',expected_uid=850123)
  assert result['fd_metadata']['uid']==850123 and result['complete_original_payloads_received']
  for wrong in (0,850124):
   logs=root/str(wrong);logs.mkdir(mode=0o700)
   try:record_delivery(console,logs,'checkpoint',expected_uid=wrong)
   except InvalidDelivery:
    proof=json.loads((logs/'diagnostic-delivery-checkpoint-failure.json').read_bytes());assert proof['fd_metadata']['uid']==850123 and proof['expected_uid']==wrong and proof['failed_not_qualified']
   else:raise AssertionError('incorrect owner accepted')
  assert console.stat().st_uid==850123 and stat.S_IMODE(console.stat().st_mode)==0o600 and console.read_bytes()==wire
 print('Explicit synthetic FD ownership positive/negative controls passed; not KVM qualification.')

if __name__=='__main__':main()
