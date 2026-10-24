#!/usr/bin/env python3
"""TEST ONLY owned-L1 Ubuntu/systemd root disk and Alpine switch-root initrd.

Never chroot, execute guest tools, mount disks or change services/modules on L0.
The caller must use an exclusive private build directory and the bounded launcher.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tarfile
import tempfile

from build_guest_image import ALPINE_SHA256, safe_guest_filter
from build_nested_host import digest, validate_manifest

ROOT_BYTES = 2 << 30
MAX_ROOT_ARCHIVE = 160 << 20
MAX_ROOT_MEMBERS = 50000
MAX_ROOT_CONTENTS = 1 << 30
MARKER = 'Xandbox owned systemd delegation fixture v1\n'
OMITTED_DEVICES = {'dev/console':(5,1),'dev/full':(1,7),'dev/null':(1,3),'dev/ptmx':(5,2),
                   'dev/random':(1,8),'dev/tty':(5,0),'dev/urandom':(1,9),'dev/zero':(1,5)}


def validate_root_members(members):
    if len(members) > MAX_ROOT_MEMBERS or sum(m.size for m in members) > MAX_ROOT_CONTENTS:
        raise ValueError('bounded systemd rootfs required')
    regular = []
    for member in members:
        # The official root tar has eight device headers. Verify and OMIT them,
        # never ask tarfile to create downloaded devices on the build host.
        if member.ischr() and (member.devmajor,member.devminor)==OMITTED_DEVICES.get(str(PurePosixPath(member.name))) and member.size==0:
            continue
        if member.isdev() or member.isfifo() or not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
            raise ValueError('no undeclared special rootfs members')
        regular.append(member)
    return regular


def units():
    probe = '''[Unit]
Description=Xandbox TEST ONLY delegated node primitive
After=local-fs.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/xandbox/systemd_delegate_probe.py main
ExecReload=/usr/bin/python3 /opt/xandbox/systemd_delegate_probe.py reload
Delegate=cpu io memory pids
DelegateSubgroup=bootstrap
MemoryMax=1073741824
MemorySwapMax=0
TasksMax=128
CPUQuota=400%
CPUQuotaPeriodSec=100ms
CapabilityBoundingSet=~CAP_SYS_RESOURCE
NoNewPrivileges=yes
UMask=0077
StandardInput=null
StandardOutput=null
StandardError=journal
KillMode=mixed
TimeoutStopSec=3s
Restart=no
'''
    operator = '''[Unit]
Description=Xandbox TEST ONLY independent serial operator
After=local-fs.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/xandbox/systemd_delegate_probe.py operator
UMask=0077
StandardInput=null
StandardOutput=null
StandardError=journal
Restart=no
[Install]
WantedBy=multi-user.target
'''
    return probe, operator


def configure_root(root, probe):
    for directory in ('opt/xandbox', 'etc/systemd/system/multi-user.target.wants', 'var/lib/xandbox-delegate-probe'):
        (root/directory).mkdir(mode=0o755, parents=True, exist_ok=True)
    shutil.copyfile(probe, root/'opt/xandbox/systemd_delegate_probe.py')
    (root/'opt/xandbox/systemd_delegate_probe.py').chmod(0o444)
    (root/'etc/xandbox-systemd-fixture').write_text(MARKER)
    (root/'etc/cloud/cloud-init.disabled').touch()
    # Guest-only masks: no NIC, login, key generation, package work or telemetry.
    for name in ('cloud-init-local.service', 'cloud-init.service', 'cloud-config.service', 'cloud-final.service',
                 'ssh.service', 'ssh.socket', 'sshd.service', 'serial-getty@ttyS0.service', 'serial-getty@ttyS1.service',
                 'apt-daily.timer', 'apt-daily-upgrade.timer', 'snapd.service', 'snapd.socket', 'snapd.seeded.service',
                 'systemd-networkd.service', 'systemd-networkd.socket', 'systemd-networkd-wait-online.service',
                 'systemd-resolved.service', 'systemd-timesyncd.service', 'ua-timer.timer', 'pollinate.service'):
        target = root/'etc/systemd/system'/name
        if os.path.lexists(target): target.unlink()
        # Relative guest symlink: never a host path traversal during assembly.
        target.symlink_to('../../../dev/null')
    main, operator = units()
    for name, value in (('xandbox-delegate-probe.service', main), ('xandbox-systemd-operator.service', operator)):
        (root/'etc/systemd/system'/name).write_text(value)
    (root/'etc/systemd/system/multi-user.target.wants/xandbox-systemd-operator.service').symlink_to('../xandbox-systemd-operator.service')
    # systemd generates a machine ID in the owned guest, never on L0.
    (root/'etc/machine-id').write_text('')
    (root/'etc/fstab').write_text('/dev/vda / ext4 defaults,nosuid,prjquota 0 0\n')


def init_script(modules):
    return '''#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
''' + ''.join('insmod /lib/fixture/'+name+'\n' for name in modules) + '''i=0
while [ ! -b /dev/vda ]; do i=$((i+1)); [ "$i" -lt 100 ]; sleep 0.1; done
mkdir /newroot
mount -t ext4 -o rw,nosuid,prjquota /dev/vda /newroot
mkdir -p /newroot/dev /newroot/proc /newroot/sys
mount --move /dev /newroot/dev
mount --move /proc /newroot/proc
mount --move /sys /newroot/sys
exec switch_root -c /dev/console /newroot /sbin/init
'''


def build(*, ubuntu, alpine, probe, output_disk, output_initrd, deployment_assets=None, ingress_assets=None, readiness_assets=None, release_assets=None, install_assets=None):
    if sum(a is not None for a in (deployment_assets,ingress_assets,readiness_assets,release_assets,install_assets))>1:raise ValueError("exclusive systemd deployment profile required")
    disk_bytes = 24<<30 if ingress_assets is not None or readiness_assets is not None or release_assets is not None or install_assets is not None else (12<<30 if deployment_assets is not None else ROOT_BYTES)
    lock = json.loads(Path(__file__).with_name('systemd_host_assets.json').read_text())
    policy = json.loads(Path(__file__).with_name('nested_host_assets.json').read_text())
    validate_manifest(policy)
    if os.geteuid() != 0 or os.uname().sysname != 'Linux':
        raise ValueError('Linux root build required only for owned image metadata/device nodes')
    if output_disk.exists() or output_initrd.exists() or ubuntu.stat().st_size > MAX_ROOT_ARCHIVE:
        raise ValueError('exclusive new bounded outputs required')
    if digest(ubuntu) != lock['rootfs_sha256'] or digest(alpine) != ALPINE_SHA256:
        raise ValueError('pinned rootfs checksum required')
    with tempfile.TemporaryDirectory(prefix='xandbox-systemd-build-') as private:
        root = Path(private)/'root'; root.mkdir(mode=0o755)
        with tarfile.open(ubuntu, 'r:xz') as source:
            members = source.getmembers(); regular = validate_root_members(members)
            omitted_devices = len(members)-len(regular)
            source.extractall(root, members=regular, filter=safe_guest_filter)
        root.chmod(0o755)
        configure_root(root, probe)
        if deployment_assets is not None:
            from build_systemd_deployment import configure
            configure(root, deployment_assets)
        if ingress_assets is not None:
            from build_systemd_ingress import configure
            configure(root, ingress_assets)
        if readiness_assets is not None:
            from build_systemd_readiness import configure
            configure(root, readiness_assets)
        if release_assets is not None:
            from build_systemd_release import configure
            configure(root, release_assets)
        if install_assets is not None:
            from build_systemd_install import configure
            configure(root, install_assets)
        with output_disk.open('xb') as out:
            os.posix_fallocate(out.fileno(), 0, disk_bytes); os.fsync(out.fileno())
        subprocess.run(['mke2fs', '-q', '-t', 'ext4', '-F', '-m', '0', '-O', 'project,quota', '-E',
                        'root_owner=0:0,quotatype=prjquota', '-I', '256', '-b', '4096', '-d', str(root), str(output_disk)],
                       check=True, timeout=120)
        with output_disk.open('rb') as out: os.fsync(out.fileno())
        boot = Path(private)/'boot'; boot.mkdir(mode=0o755)
        with tarfile.open(alpine, 'r:gz') as source:
            members = source.getmembers()
            if len(members)>10000 or sum(m.size for m in members)>64<<20: raise ValueError('bounded Alpine required')
            source.extractall(boot, members=members, filter=safe_guest_filter)
        boot.chmod(0o755)
        for name in ('dev', 'proc', 'sys', 'lib/fixture'): (boot/name).mkdir(mode=0o755, parents=True, exist_ok=True)
        modules = []
        for name, wanted in {**policy['modules_sha256'], **policy['quota_modules_sha256']}.items():
            path = Path('/lib/modules')/policy['l1_kernel_release']/name
            if path.is_symlink() or not path.is_file() or path.stat().st_size>8<<20 or digest(path)!=wanted:
                raise ValueError('pinned regular module required')
            target=boot/'lib/fixture'/path.name; shutil.copyfile(path,target); target.chmod(0o444); modules.append(path.name)
        (boot/'init').write_text(init_script(modules)); (boot/'init').chmod(0o755)
        for name, major, minor in (('console',5,1),('null',1,3),('tty',5,0)):
            if not (boot/'dev'/name).exists(): os.mknod(boot/'dev'/name,stat.S_IFCHR|0o600,os.makedev(major,minor))
        (boot/'dev/null').chmod(0o666)
        entries=['.']+sorted(str(p.relative_to(boot)) for p in boot.rglob('*'))
        for name in entries: os.utime(boot/name,(0,0),follow_symlinks=False)
        with tempfile.TemporaryFile() as cpio:
            subprocess.run(['cpio','--null','-o','--format=newc','--owner=0:0','--reproducible'],cwd=boot,
                           input=b'\0'.join(os.fsencode(n) for n in entries)+b'\0',stdout=cpio,check=True,timeout=30)
            cpio.seek(0)
            with output_initrd.open('xb') as out:
                with gzip.GzipFile(filename='',fileobj=out,mode='wb',mtime=0) as packed: shutil.copyfileobj(cpio,packed)
                out.flush();os.fsync(out.fileno())
    return {'test_only':True,'rootfs_sha256':lock['rootfs_sha256'],'root_disk_bytes':disk_bytes,'downloaded_device_headers_omitted':omitted_devices,
            'initrd_sha256':digest(output_initrd),'probe_sha256':digest(probe),'kernel_sha256':policy['l1_kernel_sha256'],
            'host_chroot_or_guest_execution':False,'host_mount_or_service_or_module_change':False}
