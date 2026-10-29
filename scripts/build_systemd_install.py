"""TEST ONLY fresh installer L1. No ordinary service/config/state is preinstalled."""
import json
from pathlib import Path
import re
import shutil
from build_nested_host import digest, static_elf
from build_systemd_deployment import ASSETS as BACKEND_ASSETS, validate_assets

ROLES=('daemon','firecracker','gateway','ingress','initrd','jailer','kernel','launcher','node','ready','template','warden','workspace')
ASSETS=ROLES+('install','release','setup')
MARKER='Xandbox owned initial installer fixture v1\n'
CONFIG='etc/xandbox-install-fixture'
# These thirteen program/data inputs retain the actual byte-equal production
# source qualification. The outer report separately binds this new harness.
from systemd_fixture_provenance import SOURCE_REVISION as PRODUCTION_SOURCE
SCRIPTS=('systemd_install_guest.py','install_fixture_trace.py','systemd_deployment_guest.py','systemd_ingress_guest.py','systemd_drain_probe.py')

def load_assets(path):
    a=json.loads(Path(path).read_bytes())
    if type(a) is not dict or set(a)!=set(ASSETS):raise ValueError('exact sixteen installer fixture assets required')
    validate_assets({k:a[k] for k in BACKEND_ASSETS})
    for role in set(ASSETS)-set(BACKEND_ASSETS):
        v=a[role]
        if type(v) is not dict or set(v)!={'path','sha256'} or not re.fullmatch('[0-9a-f]{64}',v['sha256']):raise ValueError('closed extra program pin required')
        p=Path(v['path'])
        if not p.is_absolute() or p.is_symlink() or not p.is_file() or not 0<p.stat().st_size<=64<<20 or digest(p)!=v['sha256']:raise ValueError('bounded pinned regular installer fixture program required')
        static_elf(p.read_bytes())
    return a

def configure(root,a):
    if set(a)!=set(ASSETS):raise ValueError('fixed installer fixture inventory required')
    units=root/'etc/systemd/system'
    for p in ('etc/xandbox-install','etc/xandbox-install-fixture','srv/install-bootstrap','srv/xi','srv/xandbox-releases','usr/libexec/xandbox-install','etc/systemd/system/xandbox.service','etc/systemd/system/xandbox-ingress.service'):
        if (root/p).exists() or (root/p).is_symlink():raise ValueError('fresh image only, not an existing deployment')
    for d in ('usr','usr/libexec'):
        p=root/d;p.mkdir(parents=True,exist_ok=True);p.chmod(0o755)
    config=root/CONFIG;config.mkdir(mode=0o700)
    stage=root/'srv/install-bootstrap';stage.mkdir(mode=0o700,parents=True)
    staged={};programs={}
    for role in ASSETS:
        relative=('srv/install-bootstrap/'+role) if role in ROLES else 'usr/libexec/'+{'install':'xandbox-install-bootstrap','release':'xandbox-release','setup':'xandbox-install-fixture'}[role]
        p=root/relative;shutil.copyfile(a[role]['path'],p);p.chmod(0o400 if role in ('kernel','initrd','workspace') else (0o500 if role in ROLES else 0o555))
        if digest(p)!=a[role]['sha256']:raise ValueError('copied installer asset drift')
        (staged if role in ROLES else programs)[role]={'path':'/'+relative,'sha256':a[role]['sha256']}
    for name,value in (('source-assets.json',staged),('programs.json',programs),('production-source.json',{'source_revision':PRODUCTION_SOURCE})):
        p=config/name;p.write_text(json.dumps(value,sort_keys=True)+'\n');p.chmod(0o600)
    (root/'etc/xandbox-systemd-install-fixture').write_text(MARKER)
    for name in SCRIPTS:
        p=root/'opt/xandbox'/name;shutil.copyfile(Path(__file__).with_name(name),p);p.chmod(0o444)
    # Replace only configure_root's TEST operator, not a production service.
    (units/'xandbox-systemd-operator.service').write_text('''[Unit]
Description=Xandbox TEST ONLY initial installer operator
After=local-fs.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/xandbox/systemd_install_guest.py
MemoryMax=536870912
MemorySwapMax=0
TasksMax=64
CPUQuota=200%
UMask=0077
LimitCORE=0
StandardInput=null
StandardOutput=null
StandardError=journal
Restart=no
[Install]
WantedBy=multi-user.target
''')
