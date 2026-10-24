"""Bounded, closed failure metadata for process tests; never export raw logs."""
import json
from pathlib import Path
import subprocess
import tempfile

KINDS = frozenset(('unknown','service_mock','service_kvm','prepare_failed','cleanup_unfinished','session_unfinished',
                   'control_unfinished','operator_unfinished','listener_failed','process_failed','process_stopped','collector_closed'))
REASONS = frozenset(('other','deadline','cancelled','configuration','state_lock','auth_mode','diagnostics_unavailable','io',
                     'quota','no_space','read_only','node_admission','node_placement','io_backing_queue','io_delegation',
                     'backend_binding','quota_capabilities','quota_filesystem','quota_ownership','quota_mount'))
MAX_VIEW = 32768


def project_view(raw):
    if len(raw)>MAX_VIEW:raise ValueError('oversized diagnostic view')
    value=json.loads(raw)
    if not isinstance(value,dict) or type(value.get('version')) is not int or value.get('version')!=1 or not isinstance(value.get('records'),list) or len(value['records'])>128:
        raise ValueError('invalid closed diagnostic view')
    records=[]
    for row in value['records']:
        if not isinstance(row,dict) or not isinstance(row.get('event'),dict):raise ValueError('invalid closed record')
        event=row['event'];kind=event.get('kind');reason=event.get('reason')
        if not isinstance(kind,str) or kind not in KINDS or not isinstance(reason,str) or reason not in REASONS:
            raise ValueError('unknown closed enum')
        records.append({'kind':kind,'reason':reason})
    return records[-6:]


def failure_summary(status,node,state):
    result={'exit_status':status,'diagnostic_view':'unavailable','closed_records':[]}
    # Temp file bounds memory even if a buggy CLI emits more than its contract.
    # No console, path, credentials, timestamp, sequence or third-party error is relayed.
    try:
        with tempfile.TemporaryFile() as output:
            proc=subprocess.run([str(Path(node).resolve()),'-state-dir',str(state),'diagnostics'],
                                stdout=output,stderr=subprocess.DEVNULL,timeout=10)
            result['view_exit_status']=proc.returncode
            output.seek(0);raw=output.read(MAX_VIEW+1)
        if proc.returncode==0:
            result['closed_records']=project_view(raw);result['diagnostic_view']='closed'
    except (OSError,ValueError,TypeError,subprocess.TimeoutExpired):pass
    return result


def require_clean_exit(process,node,state):
    try:status=process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        raise AssertionError(json.dumps({'exit_status':None,'wait_timeout':True},sort_keys=True)) from None
    if status!=0:
        raise AssertionError(json.dumps(failure_summary(status,node,state),sort_keys=True))
