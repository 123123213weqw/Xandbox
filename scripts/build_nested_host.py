"""TEST ONLY minimal L1 initrd. Never execute/chroot the rootfs on L0."""
import gzip
import hashlib
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile

from build_guest_image import ALPINE_SHA256, safe_guest_filter
from build_guest_fault_fixture import static_elf


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_manifest(manifest):
    modules = ('kernel/virt/lib/irqbypass.ko', 'kernel/arch/x86/kvm/kvm.ko',
               'kernel/arch/x86/kvm/kvm-intel.ko', 'kernel/drivers/char/hw_random/virtio-rng.ko')
    if manifest.get('test_only') is not True or manifest.get('architecture') != 'x86_64':
        raise ValueError('explicit test-only architecture required')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic', manifest.get('l1_kernel_release', '')):
        raise ValueError('kernel release is not a canonical generic build')
    if tuple(manifest.get('modules_sha256', {})) != modules:
        raise ValueError('only the fixed ordered KVM/rng module set is supported')
    quota_modules = ('kernel/fs/quota/quota_tree.ko', 'kernel/fs/quota/quota_v2.ko')
    if tuple(manifest.get('quota_modules_sha256', {})) != quota_modules:
        raise ValueError('only the fixed ordered quota module set is supported')
    for value in [manifest.get('l1_kernel_sha256', ''), manifest.get('qemu_sha256', ''),
                  *manifest['modules_sha256'].values(), *manifest['quota_modules_sha256'].values()]:
        if not re.fullmatch('[0-9a-f]{64}', value): raise ValueError('explicit artifact digest required')


def init_scripts(modules, state_io=False, quota_probe=False, quota_driver=False, quota_snapshot=False, quota_unenforced=False):
    if sum((bool(state_io), bool(quota_probe), bool(quota_driver), bool(quota_snapshot), bool(quota_unenforced))) > 1: raise ValueError('mutually exclusive L1 image profiles')
    # Linux 6.8 cannot pivot_root from its special initramfs rootfs. Move to
    # a bounded, ordinary tmpfs mount BEFORE starting the unmodified jailer.
    # Both scripts execute only as PID1 inside the owned L1, never on L0.
    bootstrap = '#!/bin/sh\nset -eu\nexport PATH=/usr/sbin:/usr/bin:/sbin:/bin\n'
    bootstrap += 'mkdir /newroot\nmount -t tmpfs -o mode=755,size=256m tmpfs /newroot\n'
    bootstrap += 'for entry in /*; do\n[ "$entry" = /newroot ] || cp -a "$entry" /newroot/\ndone\n'
    bootstrap += 'exec switch_root -c /dev/console /newroot /sbin/xandbox-host-init\n'
    service = '#!/bin/sh\nset -eu\nexport PATH=/usr/sbin:/usr/bin:/sbin:/bin\n'
    service += 'mount -t devtmpfs devtmpfs /dev\nmount -t proc proc /proc\nmount -t sysfs sysfs /sys\n'
    service += 'mkdir -p /run /tmp /srv /sys/fs/cgroup\nmount -t tmpfs -o mode=755,size=32m tmpfs /run\nmount -t cgroup2 cgroup2 /sys/fs/cgroup\n'
    service += ''.join('insmod /lib/fixture/' + name + '\n' for name in modules)
    service += 'i=0\nwhile [ ! -b /dev/vda ]; do i=$((i+1)); [ "$i" -lt 100 ]; sleep 0.1; done\n'
    if state_io:
        service += 'exec /usr/bin/xandbox-host-fixture -mode node-io >/dev/console 2>&1\n'
    elif quota_unenforced:
        service += 'mount -t ext4 -o rw,nosuid /dev/vda /srv\nexec /usr/bin/xandbox-host-fixture -mode node-quota-unenforced >/dev/console 2>&1\n'
    elif quota_snapshot:
        service += 'mount -t ext4 -o rw,nosuid,prjquota /dev/vda /srv\nexec /usr/bin/xandbox-host-fixture -mode node-quota-snapshot >/dev/console 2>&1\n'
    elif quota_driver:
        service += 'mount -t ext4 -o rw,nosuid,prjquota /dev/vda /srv\nexec /usr/bin/xandbox-host-fixture -mode node-quota-driver >/dev/console 2>&1\n'
    elif quota_probe:
        service += 'mount -t ext4 -o rw,nosuid,prjquota /dev/vda /srv\nexec /usr/bin/xandbox-host-fixture -mode node-quota >/dev/console 2>&1\n'
    else:
        service += 'mount -t ext4 -o rw,nosuid /dev/vda /srv\nexec /usr/bin/xandbox-host-fixture -mode node >/dev/console 2>&1\n'
    return bootstrap, service


def build_initrd(*, alpine, fixture, manifest, output, state_io=False, quota_probe=False, quota_driver=False, quota_snapshot=False, quota_unenforced=False):
    validate_manifest(manifest)
    if sum((bool(state_io), bool(quota_probe), bool(quota_driver), bool(quota_snapshot), bool(quota_unenforced))) > 1: raise ValueError('mutually exclusive L1 image profiles')
    assert os.geteuid() == 0 and not output.exists()
    assert digest(alpine) == ALPINE_SHA256
    static_elf(fixture.read_bytes())
    release = manifest['l1_kernel_release']
    with tempfile.TemporaryDirectory(prefix='xb-nested-initrd-') as temporary:
        root = Path(temporary) / 'root'; root.mkdir(mode=0o755)
        with tarfile.open(alpine, 'r:gz') as source:
            members = source.getmembers()
            assert len(members) <= 10000 and sum(m.size for m in members) <= 64 << 20
            source.extractall(root, members=members, filter=safe_guest_filter)
        root.chmod(0o755)
        for directory in root.rglob('*'):
            if directory.is_dir() and not directory.is_symlink(): directory.chmod(0o755)
        for name in ('dev', 'proc', 'sys', 'run', 'tmp', 'srv', 'usr/bin', 'lib/fixture'):
            (root / name).mkdir(mode=0o755, parents=True, exist_ok=True)
        (root / 'tmp').chmod(0o1777); (root / 'root').chmod(0o700)
        shutil.copyfile(fixture, root / 'usr/bin/xandbox-host-fixture'); (root / 'usr/bin/xandbox-host-fixture').chmod(0o555)
        (root / 'etc/xandbox-host-fixture').write_text('Xandbox nested host fixture v1\n')
        (root / 'etc/xandbox-host-fixture').chmod(0o600)
        modules = []
        selected_modules = dict(manifest['modules_sha256'])
        if quota_probe or quota_driver or quota_snapshot or quota_unenforced: selected_modules.update(manifest['quota_modules_sha256'])
        for name, wanted in selected_modules.items():
            source = Path('/lib/modules', release, name)
            assert source.is_file() and not source.is_symlink() and source.stat().st_size <= 8<<20 and digest(source) == wanted
            target = root / 'lib/fixture' / source.name
            shutil.copyfile(source, target); target.chmod(0o444); modules.append(target.name)
        bootstrap, service = init_scripts(modules, state_io, quota_probe, quota_driver, quota_snapshot, quota_unenforced)
        (root / 'init').write_text(bootstrap); (root / 'init').chmod(0o755)
        (root / 'sbin/xandbox-host-init').write_text(service); (root / 'sbin/xandbox-host-init').chmod(0o755)
        for name, major, minor in (('console', 5, 1), ('null', 1, 3), ('tty', 5, 0)):
            target = root / 'dev' / name
            if not target.exists(): os.mknod(target, stat.S_IFCHR | 0o600, os.makedev(major, minor))
        (root / 'dev/null').chmod(0o666)
        entries = ['.'] + sorted(str(p.relative_to(root)) for p in root.rglob('*'))
        for name in entries: os.utime(root / name, (0, 0), follow_symlinks=False)
        with tempfile.TemporaryFile() as archive:
            subprocess.run(['cpio', '--null', '-o', '--format=newc', '--owner=0:0', '--reproducible'], cwd=root,
                input=b'\0'.join(os.fsencode(p) for p in entries) + b'\0', stdout=archive, check=True, timeout=30)
            archive.seek(0)
            with output.open('xb') as raw:
                with gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as packed: shutil.copyfileobj(archive, packed)
                raw.flush(); os.fsync(raw.fileno())
