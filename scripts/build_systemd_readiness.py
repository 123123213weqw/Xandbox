"""TEST ONLY new readiness/enablement composition; legacy profiles are untouched."""
import json
from pathlib import Path
import shutil
from build_systemd_ingress import ASSETS as BASE_ASSETS,configure as base_configure,validate_ingress_assets
from build_nested_host import digest,static_elf
ASSETS=BASE_ASSETS+('ready',)
MARKER='Xandbox owned systemd readiness fixture v1\n'
def load_assets(path):
    value=json.loads(Path(path).read_bytes())
    if set(value)!=set(ASSETS):raise ValueError('exact readiness asset schema required')
    validate_ingress_assets({k:value[k] for k in BASE_ASSETS})
    for role in ('ready',):
        a=value[role]
        if set(a)!={'path','sha256'}:raise ValueError('fixed readiness asset required')
        p=Path(a['path'])
        if not p.is_absolute() or p.is_symlink() or not p.is_file() or not 0<p.stat().st_size<=64<<20 or digest(p)!=a['sha256']:raise ValueError('pinned bounded readiness program required')
        static_elf(p.read_bytes())
    return value

def configure(root,assets):
    base_configure(root,{k:assets[k] for k in BASE_ASSETS})
    p=root/'usr/libexec/xandbox-ready';shutil.copyfile(assets['ready']['path'],p);p.chmod(0o555)
    if digest(p)!=assets['ready']['sha256']:raise ValueError('copied readiness asset changed')
    p=root/'etc/xandbox/readiness-assets.json';p.write_text(json.dumps({'ready':{'path':'/usr/libexec/xandbox-ready','sha256':assets['ready']['sha256']}},sort_keys=True)+'\n');p.chmod(0o600)
    (root/'etc/xandbox-systemd-readiness-fixture').write_text(MARKER)
    for name in ('systemd_readiness_guest.py','readiness_fixture_gate.py','systemd_drain_probe.py'):
        shutil.copyfile(Path(__file__).with_name(name),root/'opt/xandbox'/name);(root/'opt/xandbox'/name).chmod(0o444)
    (root/'etc/xandbox-systemd-drain-fixture').write_text('Xandbox owned systemd drain extension v1\n')
    unit=root/'etc/systemd/system/xandbox-ingress-operator.service';raw=unit.read_text();assert raw.count('systemd_ingress_guest.py')==1;unit.write_text(raw.replace('systemd_ingress_guest.py','systemd_readiness_guest.py'))
