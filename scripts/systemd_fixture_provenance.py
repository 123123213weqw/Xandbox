"""TEST ONLY fixed, qualified systemd composition; never execute an input.

00dc Native22 and BF Native21 independently qualified byte-equal publication
roles. These declarations do not re-sign their hardware records or certify a
new build: CI must reproduce the program bytes, and KVM inputs must pass the
complete role/hash gate before an owned image is assembled.
"""
import argparse
import hashlib
import os
from pathlib import Path
import stat

SOURCE_REVISION = '00dc99de10b52d6988b52f12760f61e3fd43fb3d'
RELEASE_SOURCES = ('bf405dccbead973eacadfa89a0c6866fcc266e36', SOURCE_REVISION)
PROGRAM_FILES = {
    'daemon': 'sandboxd', 'gateway': 'xandbox-gateway',
    'ingress': 'xandbox-ingress-launch', 'launcher': 'xandbox-launch',
    'node': 'xandbox-node', 'ready': 'xandbox-ready',
    'template': 'xandbox-template', 'warden': 'xandbox-warden',
    'install': 'xandbox-install', 'release': 'xandbox-release',
    'helper': 'deploy-helper', 'setup': 'setup', 'managed-setup': 'managed-setup',
}
PINS = {
    'daemon': '896840d6d41066bb222d617f9a65cec463bc1a93918ae29e41eecd0e0028d768',
    'gateway': '17e2e0d524cd86acb576a26e10b78869ca345370347fd564fe8fcbdc8cbf641f',
    'ingress': 'b325c8d44987a46308933e7e62d2b6d839a504c4a39694c7c745b71197a7f94c',
    'launcher': 'e1146b304a82c60ecb301d57e388417755e7d5bedcc1d1170c804c72e495a160',
    'node': '5b5476c793fa41e3d11ed66e3bacd2a5dfc1780e1b0fa8f394cb26a1e3926ba3',
    'ready': 'ae66e173f45a1609150fd58d78c52ad69557c04be417d6952895aa6d965af8cf',
    'template': 'b3f623dd633041be12a7727ee21614d11bfeeb4c02569e748323c4e6caa976d6',
    'warden': 'b290a5edda8115f99aaf67cc339fa299ba0fe62817ab366001eaecc09780c7c0',
    'install': 'd6236fd2fd169b4bac0041f489bdc58a604c58bfaf69b815c94dd57b09ce31f7',
    'release': 'fa3538fd2ea124f86f147c883127b070918e370796f4c5e4a5ddc63913336dfb',
    'helper': '784902b72a868f897fb8c58d4ee5ff971c0447edc296e8f68114680470d9a80b',
    'setup': '19d4cd28460608766bb361c7b096ae4ebeb016d8b1e6529de9f846a963b3d122',
    'managed-setup': '0af1b6ec635316488cdab9a1ef3f7b63cd9bf3432db5d49007887240a14d6007',
    'firecracker': '99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5',
    'jailer': '65ef226e96f0ceda55ba643f445801ef2cc0ea667ef67cad8ac4f406c9c8434f',
    'kernel': '1e86630c63d61fd37b5a4d23cb66056286bdcc00ebca217c7ef95689575a4bb3',
    'initrd': '2cf3a83a1855daabb9c0da3820fc9e65d707236862350985bcfa5e3406f668c9',
    'workspace': '64b8fef846938745be3c9a4367b0dff437481e1c48e97077902d73e16e613954',
}
DEPLOYMENT = ('launcher', 'daemon', 'warden', 'firecracker', 'jailer', 'kernel', 'initrd', 'workspace', 'node')
INGRESS = DEPLOYMENT + ('gateway', 'ingress', 'helper')
READINESS = INGRESS + ('ready',)
PUBLICATION = ('daemon', 'firecracker', 'gateway', 'ingress', 'initrd', 'jailer',
               'kernel', 'launcher', 'node', 'ready', 'template', 'warden', 'workspace')
PROFILES = {'deployment': DEPLOYMENT, 'ingress': INGRESS, 'readiness': READINESS,
            'release': READINESS + ('release', 'template'),
            'install': PUBLICATION + ('install', 'release', 'setup'),
            'managed': PUBLICATION + ('install', 'release', 'setup')}


def read_pinned(path, expected, *, program, workspace=False):
    """Hash a stable bounded FD without executing it or exposing its content.

    Existing builders separately rehash each copy before using it; pathname
    replacement after this read is not mistaken for a persistent file lease.
    """
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('absolute fixed input required')
    limit = (128 if workspace else 64) << 20
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('bounded regular fixed input required')
        if workspace and before.st_size != 128 << 20:
            raise ValueError('fixed workspace size required')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            data = source.read(limit + 1)
        after = os.fstat(fd)
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if len(data) != before.st_size or identity(before) != identity(after):
            raise ValueError('fixed input changed during read')
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('fixed qualified input differs')
        if program:
            # Lazy import: the release guest imports only the declaration above.
            from build_guest_fault_fixture import static_elf
            static_elf(data)
        return before.st_size
    finally:
        os.close(fd)


def validate_assets(value, profile):
    if type(profile) is not str or profile not in PROFILES:
        raise ValueError('fixed systemd profile required')
    if type(value) is not dict or set(value) != set(PROFILES[profile]):
        raise ValueError('complete fixed systemd composition required')
    # Check every declaration BEFORE reading any file, let alone assembling it.
    for role, item in value.items():
        pin_role = 'managed-setup' if role == 'setup' and profile == 'managed' else role
        if type(item) is not dict or set(item) != {'path', 'sha256'} or item['sha256'] != PINS[pin_role] or type(item['path']) is not str:
            raise ValueError('fixed qualified role declaration differs')
    for role, item in value.items():
        read_pinned(item['path'], item['sha256'], program=role in PROGRAM_FILES or role in ('firecracker', 'jailer'), workspace=role == 'workspace')
    return SOURCE_REVISION


def verify_programs(directory):
    """Fresh canonical Go builds only; not external images or KVM acceptance."""
    directory = Path(directory).resolve()
    for role, filename in PROGRAM_FILES.items():
        read_pinned(directory / filename, PINS[role], program=True)
    return SOURCE_REVISION


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--programs-dir', required=True)
    args = parser.parse_args()
    try:
        verify_programs(args.programs_dir)
    except (OSError, ValueError, TypeError):
        parser.exit(1, 'fixed systemd fixture provenance rejected\n')
    print('fixed systemd program provenance passed (not KVM acceptance)')


if __name__ == '__main__':
    main()
