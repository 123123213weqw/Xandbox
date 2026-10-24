"""TEST ONLY owned16GiB/CPU12/24GiB L1 with ordinary daemon + separate ingress."""
import json
from pathlib import Path
import shutil
from build_systemd_deployment import ASSETS as BASE_ASSETS, validate_assets, configure as base_configure
from build_nested_host import digest, static_elf

EXTRA=('gateway','ingress','helper')
ASSETS=BASE_ASSETS+EXTRA
MARKER='Xandbox owned systemd ingress fixture v1\n'


def load_assets(path):
    value=json.loads(Path(path).read_text())
    if set(value)!=set(ASSETS):raise ValueError('exact ingress deployment asset schema required')
    validate_assets({k:value[k] for k in BASE_ASSETS})
    for name in EXTRA:
        a=value[name]
        if set(a)!={'path','sha256'}:raise ValueError('fixed extra asset required')
        p=Path(a['path'])
        if not p.is_absolute() or p.is_symlink() or not p.is_file() or not 0<p.stat().st_size<=64<<20 or digest(p)!=a['sha256']:
            raise ValueError('pinned bounded regular ingress asset required')
        static_elf(p.read_bytes())
    return value


def operator_unit():
    return '''[Unit]
Description=Xandbox TEST ONLY separate ingress/TLS/KVM deployment operator
After=local-fs.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/xandbox/systemd_ingress_guest.py
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


def configure(root,assets):
    base_configure(root,{k:assets[k] for k in BASE_ASSETS})
    result={}
    for name,relative in (('gateway','srv/assets/xandbox-gateway'),('ingress','usr/libexec/xandbox-ingress-launch'),('helper','usr/libexec/xandbox-deploy-fixture')):
        target=root/relative;shutil.copyfile(assets[name]['path'],target);target.chmod(0o555)
        if digest(target)!=assets[name]['sha256']:raise ValueError('copied ingress asset changed')
        result[name]={'path':'/'+relative,'sha256':assets[name]['sha256']}
    config=root/'etc/xandbox/ingress-assets.json';config.write_text(json.dumps(result,sort_keys=True)+'\n');config.chmod(0o600)
    (root/'etc/xandbox-systemd-ingress-fixture').write_text(MARKER)
    source=Path(__file__).with_name('systemd_ingress_guest.py')
    shutil.copyfile(source,root/'opt/xandbox/systemd_ingress_guest.py');(root/'opt/xandbox/systemd_ingress_guest.py').chmod(0o444)
    (root/'etc/systemd/system/multi-user.target.wants/xandbox-deployment-operator.service').unlink()
    (root/'etc/systemd/system/xandbox-ingress-operator.service').write_text(operator_unit())
    (root/'etc/systemd/system/multi-user.target.wants/xandbox-ingress-operator.service').symlink_to('../xandbox-ingress-operator.service')
