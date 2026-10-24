"""TEST ONLY explicit 8GiB/12GiB ordinary Go-launcher deployment profile."""
import json
import os
from pathlib import Path
import re
import shutil
from build_nested_host import digest, static_elf

ASSETS=('launcher','daemon','warden','firecracker','jailer','kernel','initrd','workspace','node')
MAX_ASSET={'launcher':64<<20,'daemon':64<<20,'warden':32<<20,'firecracker':32<<20,'jailer':32<<20,'kernel':64<<20,'initrd':64<<20,'workspace':128<<20,'node':32<<20}


def load_assets(path):
    return validate_assets(json.loads(Path(path).read_text()))


def validate_assets(value):
    if set(value)!=set(ASSETS):raise ValueError('exact frozen deployment assets required')
    for name,asset in value.items():
        if set(asset)!={'path','sha256'} or not re.fullmatch('[0-9a-f]{64}',asset['sha256']):raise ValueError('fixed asset schema required')
        source=Path(asset['path'])
        if not source.is_absolute() or source.is_symlink() or not source.is_file() or not 0<source.stat().st_size<=MAX_ASSET[name] or digest(source)!=asset['sha256']:
            raise ValueError('pinned regular bounded deployment asset required')
        if name=='workspace' and source.stat().st_size!=128<<20:raise ValueError('fixed 128MiB workspace required')
        if name in ('launcher','daemon','warden','firecracker','jailer','node'):static_elf(source.read_bytes())
    return value


def deployment_units():
    service='''[Unit]
Description=Xandbox experimental pinned Go launch and ordinary KVM daemon
After=local-fs.target
[Service]
Type=exec
ExecStart=/usr/libexec/xandbox-launch -manifest /etc/xandbox/launch.json
Delegate=cpu io memory pids
DelegateSubgroup=bootstrap
RuntimeDirectory=xandbox-inputs
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=no
MemoryMax=8053063680
MemorySwapMax=0
TasksMax=512
CPUQuota=800%
CPUQuotaPeriodSec=100ms
IOReadBandwidthMax=/dev/vda 536870912
IOWriteBandwidthMax=/dev/vda 536870912
IOReadIOPSMax=/dev/vda 16384
IOWriteIOPSMax=/dev/vda 16384
CapabilityBoundingSet=~CAP_SYS_RESOURCE
NoNewPrivileges=yes
UMask=0077
StandardInput=null
StandardOutput=null
StandardError=journal
KillMode=mixed
TimeoutStopSec=12s
Restart=no
'''
    operator='''[Unit]
Description=Xandbox TEST ONLY independent ordinary deployment operator
After=local-fs.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/xandbox/systemd_deployment_guest.py
MemoryMax=268435456
MemorySwapMax=0
TasksMax=32
CPUQuota=100%
UMask=0077
StandardInput=null
StandardOutput=null
StandardError=journal
Restart=no
[Install]
WantedBy=multi-user.target
'''
    return service,operator


def configure(root,assets):
    for name in ('srv/assets','srv/xb/s','srv/xb/r','etc/xandbox','usr/libexec'):
        target=root/name;target.mkdir(parents=True,exist_ok=True);target.chmod(0o700 if name in ('srv/xb/s','srv/xb/r','etc/xandbox') else 0o755)
    result={}
    for name in ASSETS:
        filename='sandboxd' if name=='daemon' else name
        relative='usr/libexec/xandbox-launch' if name=='launcher' else 'srv/assets/'+filename
        target=root/relative;shutil.copyfile(assets[name]['path'],target)
        target.chmod(0o555 if name in ('launcher','daemon','warden','firecracker','jailer','node') else 0o444)
        if digest(target)!=assets[name]['sha256']:raise ValueError('copied deployment asset changed')
        result[name]={'path':'/'+relative,'sha256':assets[name]['sha256']}
    (root/'etc/xandbox/assets.json').write_text(json.dumps(result,sort_keys=True)+'\n');(root/'etc/xandbox/assets.json').chmod(0o600)
    (root/'etc/xandbox-systemd-deployment-fixture').write_text('Xandbox owned Go launch deployment fixture v1\n')
    source=Path(__file__).with_name('systemd_deployment_guest.py')
    shutil.copyfile(source,root/'opt/xandbox/systemd_deployment_guest.py');(root/'opt/xandbox/systemd_deployment_guest.py').chmod(0o444)
    old=root/'etc/systemd/system/multi-user.target.wants/xandbox-systemd-operator.service'
    if os.path.lexists(old):old.unlink()
    service,operator=deployment_units()
    (root/'etc/systemd/system/xandbox.service').write_text(service)
    (root/'etc/systemd/system/xandbox-deployment-operator.service').write_text(operator)
    (root/'etc/systemd/system/multi-user.target.wants/xandbox-deployment-operator.service').symlink_to('../xandbox-deployment-operator.service')
