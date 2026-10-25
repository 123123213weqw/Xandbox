#!/usr/bin/env python3
"""TEST ONLY same-PID closed pre-exec observation, not an acceptance entrypoint."""
import errno
import fcntl
import json
import os
from pathlib import Path
import sys

MARKER='Xandbox owned systemd ingress fixture v1\n'
UNIT_ROOT='/sys/fs/cgroup/system.slice/xandbox-ingress.service'


def guard():
    if os.geteuid()!=0 or Path('/etc/xandbox-systemd-ingress-fixture').read_text()!=MARKER or Path('/proc/1/comm').read_text().strip()!='systemd':
        raise RuntimeError('owned ingress L1 marker required')


def observe():
    guard()
    raw=Path('/proc/self/cgroup').read_text().strip()
    placement='expected' if raw=='0::/system.slice/xandbox-ingress.service' else ('private_root' if raw=='0::/' else 'unexpected')
    fields=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    caps={key:int(fields[key],16) for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')}
    try:relation='same' if os.path.samefile('/proc/self/ns/cgroup','/proc/1/ns/cgroup') else 'different'
    except OSError:relation='unobservable'
    inheritable=0
    for name in os.listdir('/proc/self/fd'):
        number=int(name)
        if number<=2:continue
        try:flags=fcntl.fcntl(number,fcntl.F_GETFD)
        except OSError as error:
            if error.errno==errno.EBADF:continue
            raise
        if not flags&fcntl.FD_CLOEXEC:inheritable+=1
    return {'placement_class':placement,'cgroup_namespace_relation':relation,'absolute_unit_group_visible':Path(UNIT_ROOT).is_dir(),
            'uids_all_root':fields['Uid'].split()==['0']*4,'gids_all_root':fields['Gid'].split()==['0']*4,
            'no_new_privileges':fields['NoNewPrivs'].strip()=='1','caps':caps,'inheritable_nonstdio_fds':inheritable}


def entry():
    if len(sys.argv)!=1:raise RuntimeError('fixed probe has no arguments')
    observation=observe()
    print('XANDBOX_INGRESS_GUARD_OBSERVATION '+json.dumps(observation,sort_keys=True),file=sys.stderr,flush=True)
    # Fixed guard only, same PID. There is no tenant argv or host-task fallback.
    os.execve('/usr/libexec/xandbox-ingress-launch',['/usr/libexec/xandbox-ingress-launch','-manifest','/etc/xandbox/ingress-launch.json'],
              {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LANG':'C'})


if __name__=='__main__':entry()
