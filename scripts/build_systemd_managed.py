"""TEST ONLY fresh managed-v2 owned L1, never an existing deployment upgrade."""
import json
from pathlib import Path
import shutil
from build_nested_host import digest
from build_systemd_install import ASSETS, ROLES, load_assets

MARKER='Xandbox owned managed policy fixture v1\n'
CONFIG='etc/xandbox-managed-fixture'
MAINTENANCE_CASES=('populated-gate','active-stop','supersession-repeat','supersession-visible-recovery','hot-rotation','draft-discard','draft-discard-cut','draft-kernel-guard')
# The launcher must independently compare every ELF to this source's native
# qualification. This is a composition pin, not inheritance of an old report.
from systemd_fixture_provenance import SOURCE_REVISION as PRODUCTION_SOURCE
SCRIPTS=('systemd_managed_guest.py','managed_fixture_trace.py','install_fixture_trace.py','systemd_install_guest.py','systemd_deployment_guest.py','systemd_ingress_guest.py','systemd_drain_probe.py')

def configure(root,assets,maintenance_case='populated-gate'):
    if maintenance_case not in MAINTENANCE_CASES:raise ValueError('fixed managed maintenance case required')
    if set(assets)!=set(ASSETS):raise ValueError('closed sixteen managed fixture assets required')
    for name in ('etc/xandbox-install','etc/xandbox-install-fixture',CONFIG,'etc/xandbox-systemd-install-fixture','etc/xandbox-systemd-managed-fixture','srv/install-bootstrap','srv/xi','srv/xandbox-releases','usr/libexec/xandbox-install','usr/libexec/xandbox-install-bootstrap','usr/libexec/xandbox-managed-fixture','usr/libexec/xandbox-release','etc/systemd/system/xandbox.service','etc/systemd/system/xandbox-ingress.service'):
        p=root/name
        if p.exists() or p.is_symlink():raise ValueError('fresh configure_root-only managed image required')
    for name in ('usr','usr/libexec'):
        p=root/name
        if p.is_symlink():raise ValueError('real image program directory required')
        p.mkdir(parents=True,exist_ok=True);p.chmod(0o755)
    config=root/CONFIG;config.mkdir(mode=0o700)
    stage=root/'srv/install-bootstrap';stage.mkdir(mode=0o700,parents=True)
    staged={};programs={}
    for role in ASSETS:
        relative='srv/install-bootstrap/'+role if role in ROLES else 'usr/libexec/'+{'install':'xandbox-install-bootstrap','release':'xandbox-release','setup':'xandbox-managed-fixture'}[role]
        p=root/relative;shutil.copyfile(assets[role]['path'],p)
        p.chmod(0o400 if role in ('kernel','initrd','workspace') else 0o500 if role in ROLES else 0o555)
        if digest(p)!=assets[role]['sha256']:raise ValueError('copied managed asset drift')
        (staged if role in ROLES else programs)[role]={'path':'/'+relative,'sha256':assets[role]['sha256']}
    for name,value in (('source-assets.json',staged),('programs.json',programs),('production-source.json',{'source_revision':PRODUCTION_SOURCE}),('maintenance-case.json',{'version':1,'case':maintenance_case})):
        p=config/name;p.write_text(json.dumps(value,sort_keys=True)+'\n');p.chmod(0o600)
    (root/'etc/xandbox-systemd-managed-fixture').write_text(MARKER)
    for name in SCRIPTS:
        p=root/'opt/xandbox'/name;shutil.copyfile(Path(__file__).with_name(name),p);p.chmod(0o444)
    (root/'etc/systemd/system/xandbox-systemd-operator.service').write_text('''[Unit]
Description=Xandbox TEST ONLY fresh managed policy operator
After=local-fs.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/xandbox/systemd_managed_guest.py
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
