"""TEST ONLY fixed, qualified systemd composition; never execute an input.

The two revisions below have actual byte-equal native canonical publication
programs. This is source/artifact coherence, not full software or KVM acceptance.
Old hardware records keep their original sources. CI must reproduce all program
bytes; KVM inputs must pass the full role/hash gate before image assembly.
"""
import argparse
import hashlib
import os
from pathlib import Path
import stat

SOURCE_REVISION = 'bdcfef042396b920c345bcd74b8428b31d074009'
RELEASE_SOURCES = ('ee77e8e2dc7c2be0d03647dfa2b99c3b50ae26af', SOURCE_REVISION)
PROGRAM_FILES = {
    'daemon': 'sandboxd', 'gateway': 'xandbox-gateway',
    'ingress': 'xandbox-ingress-launch', 'launcher': 'xandbox-launch',
    'node': 'xandbox-node', 'ready': 'xandbox-ready',
    'template': 'xandbox-template', 'warden': 'xandbox-warden',
    'install': 'xandbox-install', 'release': 'xandbox-release',
    'helper': 'deploy-helper', 'setup': 'setup', 'managed-setup': 'managed-setup',
}
PINS = {
    'daemon': 'd748d8cf7216980582720c1618e1b0473a9228e371ae850257059a8980e98e01',
    'gateway': 'f30f69852a8d7a2db133d0abda7478767b9d1bb6816ef8bc30806fbffda5a84c',
    'ingress': 'ee23ee79d9e795a5972530ba14f2057184637a0023e203bd5bf06a3525ebc076',
    'launcher': '7518d65924fb05470bc86f305b97e25dc7aa5817ff6723870e7b49b056c6cf88',
    'node': '41015af6af5c6594f4ceea08a03766898e004575d27aa4f44dc175a2cae3586a',
    'ready': '60da9aeccb2a1bc9c5ae4fcb694fcd5346265998f0fac491331cde30ae0ea776',
    'template': '5da61709cff42dc4eb39ed4edaba68c8f640b1520d7d5e981f5d16b930ec5cfe',
    'warden': 'b290a5edda8115f99aaf67cc339fa299ba0fe62817ab366001eaecc09780c7c0',
    'install': 'bd8114ba0b8b12fd7cf1a0d80195ef2a299ab648d99a9303008bd2e46855c30f',
    'release': 'fa3538fd2ea124f86f147c883127b070918e370796f4c5e4a5ddc63913336dfb',
    'helper': '06e1ef60f8c381bbb05a35e86ea74ea2ba536cca2b318bcd03d32b7cac2c8247',
    'setup': 'cb133da908d65c77042f7cf24eb45bba4cd834d8f924f4123a2d277589cb7769',
    'managed-setup': 'd938564bf1ad1a1d98ce02dcc28a69c44059535b223b86282b0c43ff5b980be1',
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
            raise ValueError('fixed source-bound input differs')
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
            raise ValueError('fixed source-bound role declaration differs')
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
