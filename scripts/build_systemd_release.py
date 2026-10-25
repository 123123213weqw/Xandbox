"""TEST ONLY release publisher plus the complete readiness/drain/TLS/KVM profile."""
import json
from pathlib import Path
import shutil
from build_systemd_readiness import ASSETS as BASE_ASSETS,configure as base_configure
from build_nested_host import digest,static_elf
ASSETS=BASE_ASSETS+('release','template')
MARKER='Xandbox owned ordinary release publication fixture v1\n'


def load_assets(path):
    value=json.loads(Path(path).read_bytes())
    if type(value) is not dict or set(value)!=set(ASSETS):raise ValueError('exact fifteen publication profile assets required')
    # Reuse the unchanged role/size/hash validator without a permissive role filter.
    from build_systemd_ingress import validate_ingress_assets
    from build_systemd_readiness import BASE_ASSETS as INGRESS_ASSETS
    validate_ingress_assets({k:value[k] for k in INGRESS_ASSETS})
    for role in ('ready','release','template'):
        a=value[role]
        if type(a) is not dict or set(a)!={'path','sha256'}:raise ValueError('fixed publication program asset required')
        p=Path(a['path'])
        if not p.is_absolute() or p.is_symlink() or not p.is_file() or not 0<p.stat().st_size<=64<<20 or digest(p)!=a['sha256']:raise ValueError('pinned bounded regular publication program required')
        static_elf(p.read_bytes())
    return value


def configure(root,assets):
    if set(assets)!=set(ASSETS):raise ValueError('exact publication configure roles required')
    base_configure(root,{k:assets[k] for k in BASE_ASSETS})
    # data_filter ignores directory modes; private umask can leave /usr0700.
    # Only this owned profile's non-secret executable ancestry is searchable.
    for relative in ('usr','usr/libexec'):
        p=root/relative
        if p.is_symlink() or not p.is_dir():raise ValueError('actual guest executable directory required')
        p.chmod(0o755)
    for role,relative in (('release','usr/libexec/xandbox-release'),('template','srv/assets/xandbox-template')):
        p=root/relative;shutil.copyfile(assets[role]['path'],p);p.chmod(0o555)
        if digest(p)!=assets[role]['sha256']:raise ValueError('copied publication program changed')
    source=json.loads((root/'etc/xandbox/assets.json').read_bytes())
    source.update(json.loads((root/'etc/xandbox/ingress-assets.json').read_bytes()))
    source.update(json.loads((root/'etc/xandbox/readiness-assets.json').read_bytes()))
    source['template']={'path':'/srv/assets/xandbox-template','sha256':assets['template']['sha256']}
    source['release']={'path':'/usr/libexec/xandbox-release','sha256':assets['release']['sha256']}
    del source['helper']
    config=root/'etc/xandbox-release';config.mkdir(mode=0o700)
    p=config/'assets.json';p.write_text(json.dumps(source,sort_keys=True)+'\n');p.chmod(0o600)
    (root/'etc/xandbox-systemd-release-fixture').write_text(MARKER)
    p=root/'opt/xandbox/systemd_release_guest.py';shutil.copyfile(Path(__file__).with_name(p.name),p);p.chmod(0o444)
    unit=root/'etc/systemd/system/xandbox-ingress-operator.service';raw=unit.read_text()
    if raw.count('systemd_readiness_guest.py')!=1:raise ValueError('one fixed readiness operator required')
    unit.write_text(raw.replace('systemd_readiness_guest.py','systemd_release_guest.py'))
