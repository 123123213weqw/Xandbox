"""Linux-only, fixture-scoped resident-memory observations, not billing data.

PSS, shared-file residency and cgroup charges are DIFFERENT overlapping views.
Never add them to manufacture total unique RAM or claim memory.current is all
guest RAM. No PID/path/Ref escapes the numeric result.
"""
import ctypes
import errno
import os
from pathlib import Path
import re
import stat

KB_FIELDS = ('Rss', 'Pss', 'Pss_Anon', 'Pss_File', 'Pss_Shmem',
             'Private_Clean', 'Private_Dirty', 'Shared_Clean', 'Shared_Dirty', 'Anonymous')
HEADER = re.compile(r'^[0-9a-f]+-[0-9a-f]+\s+\S+\s+[0-9a-f]+\s+([0-9a-f]+):([0-9a-f]+)\s+(\d+)(?:\s|$)')
REF_NAME = re.compile(r'^[0-9a-f]{64}$')


def cgroup_empty(path):
    try:
        lines = (path / 'cgroup.events').read_text().splitlines()
        if 'populated 0' in lines:
            return True
        if 'populated 1' in lines:
            return False
        raise ValueError('missing cgroup populated observation')
    except OSError as error:
        if error.errno not in (errno.ENOENT, errno.ENODEV):
            raise
        # kernfs can return ENODEV on a previously opened FD after rmdir.
        # Never interpret ENODEV alone as stop proof for a still-existing group.
        return not path.exists()


def parse_kb(text):
    values = {}
    for line in text.splitlines():
        name, sep, tail = line.partition(':')
        if sep and name in KB_FIELDS:
            parts = tail.split()
            if len(parts) != 2 or parts[1] != 'kB' or not parts[0].isdigit():
                raise ValueError('invalid proc memory counter')
            values[name] = int(parts[0]) * 1024
    return values


def mapped_backing(text, identity):
    """Sum ONLY mappings matching exact dev/inode, never filename suffix."""
    result = {key: 0 for key in KB_FIELDS}
    active = False
    for line in text.splitlines():
        match = HEADER.match(line)
        if match:
            active = tuple(int(x, 16) for x in match.groups()[:2]) + (int(match.group(3)),) == identity
        elif active:
            for key, value in parse_kb(line).items():
                result[key] += value
    return result


def start_ticks(text):
    after = text.rfind(') ')
    fields = text[after + 2:].split()
    if after < 0 or len(fields) <= 19 or not fields[19].isdigit():
        raise ValueError('invalid proc process identity')
    return fields[19]


def _regular(path, expected_size=None):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or (expected_size is not None and info.st_size != expected_size):
        raise ValueError('unexpected fixture backing')
    return info


def workspace_observation(path):
    # Prepare copies directly to an exclusive final filename. A concurrent
    # observer must include partial allocation, not reject or silently drop it.
    info = _regular(path)
    if info.st_size > 128 << 20 or info.st_nlink != 1:
        raise ValueError('private workspace oversized or unexpectedly shared')
    return info, int(info.st_size < 128 << 20)


def file_resident_bytes(path, expected_size):
    """PROT_NONE mapping + mincore: inspect page-cache residency without reading.

    This is whole-file residency, not unique process memory and not a cgroup
    charge. No global drop_caches, page touching or host setting changes.
    """
    if expected_size <= 0:
        raise ValueError('backing must be nonempty')
    path = Path(path)
    before = _regular(path, expected_size)
    page = os.sysconf('SC_PAGE_SIZE')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long)
    libc.mmap.restype = ctypes.c_void_p
    libc.mincore.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)
    libc.mincore.restype = ctypes.c_int
    libc.munmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or after.st_size != expected_size:
            raise ValueError('backing changed during observation')
        address = libc.mmap(None, expected_size, 0, 2, fd, 0)  # PROT_NONE, MAP_PRIVATE
        if address == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_errno(), 'fixture mincore mapping failed')
        try:
            vector = (ctypes.c_ubyte * ((expected_size + page - 1) // page))()
            if libc.mincore(address, expected_size, vector) != 0:
                raise OSError(ctypes.get_errno(), 'fixture mincore failed')
            return min(expected_size, sum(bool(v & 1) for v in vector) * page)
        finally:
            if libc.munmap(address, expected_size) != 0:
                raise OSError(ctypes.get_errno(), 'fixture munmap failed')
    finally:
        os.close(fd)


class ResourceSampler:
    def __init__(self, *, process, cgroup, runtime, memory, snapshot_state, backend):
        self.process, self.cgroup, self.runtime = process, Path(cgroup), Path(runtime)
        self.memory, self.snapshot_state, self.backend = Path(memory), Path(snapshot_state), Path(backend)
        self.controller_identity = start_ticks(Path('/proc', str(process.pid), 'stat').read_text())
        info = _regular(self.memory, 512 << 20)
        self.backing_identity = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
        self.transient_misses = 0

    def _process(self, pid, expected_group=None):
        root = Path('/proc', str(pid))
        try:
            before = start_ticks((root / 'stat').read_text())
            if expected_group is not None:
                relative = '/' + str(expected_group.relative_to('/sys/fs/cgroup'))
                if ('0::' + relative) not in (root / 'cgroup').read_text().splitlines():
                    self.transient_misses += 1
                    return None
            counters = parse_kb((root / 'smaps_rollup').read_text())
            if 'Rss' not in counters or 'Pss' not in counters:
                raise ValueError('kernel lacks required PSS observation')
            backing = mapped_backing((root / 'smaps').read_text(), self.backing_identity)
            if start_ticks((root / 'stat').read_text()) != before:
                self.transient_misses += 1
                return None
            return before, counters, backing
        except (FileNotFoundError, ProcessLookupError):
            self.transient_misses += 1
            return None  # Expected removal/reaping; permission/parse errors NOT zero.

    def sample(self):
        if self.process.poll() is not None:
            raise AssertionError('controller exited during resource observation')
        current = self._process(self.process.pid)
        if current is None or current[0] != self.controller_identity:
            raise AssertionError('controller observation identity changed')
        row = {'controller_rss_bytes': current[1]['Rss'], 'controller_pss_bytes': current[1]['Pss'],
               'controller_fds': len(list(Path('/proc', str(self.process.pid), 'fd').iterdir())),
               'owned_process_count': 0, 'owned_process_rss_sum_bytes': 0, 'owned_process_pss_sum_bytes': 0,
               'owned_cgroup_memory_current_bytes': 0, 'owned_cgroup_count': 0,
               'template_mapping_rss_sum_bytes': 0, 'template_mapping_pss_sum_bytes': 0,
               'template_mapping_anonymous_sum_bytes': 0,
               'private_workspace_allocated_bytes': 0, 'private_workspace_logical_bytes': 0,
               'private_workspace_preparing_files': 0}
        seen = set()
        for group in list(self.cgroup.iterdir()):
            if not group.is_dir():
                continue
            if not REF_NAME.fullmatch(group.name):
                raise ValueError('unknown resource namespace in own fixture')
            try:
                row['owned_cgroup_count'] += 1
                row['owned_cgroup_memory_current_bytes'] += int((group / 'memory.current').read_text())
                pids = (group / 'cgroup.procs').read_text().split()
            except OSError as error:
                if error.errno in (errno.ENOENT, errno.ENODEV) and not group.exists():
                    self.transient_misses += 1
                    continue
                raise
            for pid in pids:
                value = self._process(pid, group)
                if value is None or (pid, value[0]) in seen:
                    continue
                seen.add((pid, value[0]))
                _, counters, mapping = value
                row['owned_process_count'] += 1
                row['owned_process_rss_sum_bytes'] += counters['Rss']
                row['owned_process_pss_sum_bytes'] += counters['Pss']
                row['template_mapping_rss_sum_bytes'] += mapping['Rss']
                row['template_mapping_pss_sum_bytes'] += mapping['Pss']
                row['template_mapping_anonymous_sum_bytes'] += mapping['Anonymous']
        workspaces = set()
        parent = self.runtime / 'j/firecracker'
        if parent.exists():
            for jail in list(parent.iterdir()):
                if not REF_NAME.fullmatch(jail.name) or not jail.is_dir():
                    raise ValueError('unknown jail namespace')
                try:
                    value, preparing = workspace_observation(jail / 'root/workspace.ext4')
                except FileNotFoundError:
                    continue
                identity = (value.st_dev, value.st_ino)
                if identity in workspaces or value.st_nlink != 1:
                    raise ValueError('private workspace unexpectedly shared')
                workspaces.add(identity)
                row['private_workspace_preparing_files'] += preparing
                row['private_workspace_allocated_bytes'] += value.st_blocks * 512
                row['private_workspace_logical_bytes'] += value.st_size
        memory = _regular(self.memory, 512 << 20)
        state = _regular(self.snapshot_state)
        row.update({'catalog_memory_resident_bytes': file_resident_bytes(self.memory, memory.st_size),
                    'catalog_state_resident_bytes': file_resident_bytes(self.snapshot_state, state.st_size),
                    'catalog_backing_allocated_bytes': (memory.st_blocks + state.st_blocks) * 512,
                    'durable_owner_files': sum(REF_NAME.fullmatch(p.stem) is not None for p in self.backend.glob('*.json')),
                    'transient_identity_misses_total': self.transient_misses})
        return row
