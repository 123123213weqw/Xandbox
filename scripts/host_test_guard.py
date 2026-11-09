"""TEST ONLY host headroom guard. Never starts workloads or selects business PIDs.

Sampling cannot reserve host resources or replace the fixture's kernel limits.
An abort uses only the current fixture's retained kill FD and lifetime pipe.
"""
from dataclasses import dataclass
import fcntl
import math
import os
from pathlib import Path
import stat
import threading
import time


GIB = 1 << 30


class UnsafeHost(RuntimeError):
    pass


@dataclass(frozen=True)
class Budget:
    memory: int
    disk: int
    cpus: int
    seconds: int = 900

    def __post_init__(self):
        for value in (self.memory, self.disk, self.cpus, self.seconds):
            if type(value) is not int or value <= 0:
                raise ValueError('positive integral test budget required')
        if self.memory > 18 * GIB or self.disk > 48 * GIB or self.cpus > 12 or self.seconds > 3600:
            raise ValueError('test budget exceeds fixed safety envelope')


def pressure(text, kind):
    rows = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] in rows:
            raise UnsafeHost('invalid pressure observation')
        values = {}
        for item in fields[1:]:
            key, sep, value = item.partition('=')
            if not sep or key in values:
                raise UnsafeHost('invalid pressure observation')
            values[key] = value
        value = float(values['avg10'])
        if not math.isfinite(value) or not 0 <= value <= 100:
            raise UnsafeHost('invalid pressure observation')
        rows[fields[0]] = value
    return rows[kind]


def cgroup_headroom():
    """Conservative current-process cgroup-v2 ancestor headroom, not RAM billing."""
    lines = Path('/proc/self/cgroup').read_text().splitlines()
    if len(lines) != 1 or not lines[0].startswith('0::/'):
        raise UnsafeHost('unified cgroup observation required')
    relative = lines[0][3:]
    if '..' in Path(relative).parts:
        raise UnsafeHost('unresolved cgroup namespace')
    root = Path('/sys/fs/cgroup')
    current = root / relative.lstrip('/')
    limits = []
    while True:
        maximum = current / 'memory.max'
        # The real cgroup root lacks a memory.max file. Missing non-root
        # observations must not become infinite headroom.
        if current != root or maximum.exists():
            raw = maximum.read_text().strip()
            used = int((current / 'memory.current').read_text().strip())
            if used < 0:
                raise UnsafeHost('invalid cgroup memory observation')
            if raw != 'max':
                cap = int(raw)
                if cap <= 0:
                    raise UnsafeHost('invalid cgroup memory ceiling')
                limits.append(max(0, cap - used))
        if current == root:
            break
        current = current.parent
    return min(limits) if limits else None


def sample(paths):
    values = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, _, tail = line.partition(':')
        if key in ('MemTotal', 'MemAvailable'):
            fields = tail.split()
            if key in values or len(fields) != 2 or fields[1] != 'kB':
                raise UnsafeHost('invalid memory observation')
            values[key] = int(fields[0]) * 1024
    disks = []
    for path in paths:
        fs = os.statvfs(path)
        disks.append((fs.f_blocks * fs.f_frsize, fs.f_bavail * fs.f_frsize,
                      fs.f_files, fs.f_favail))
    return {'total': values['MemTotal'], 'available': values['MemAvailable'],
            'cgroup_available': cgroup_headroom(),
            'cpus': len(os.sched_getaffinity(0)), 'disks': disks,
            'memory_full': pressure(Path('/proc/pressure/memory').read_text(), 'full'),
            'io_full': pressure(Path('/proc/pressure/io').read_text(), 'full')}


def reasons(budget, view, *, starting):
    """Closed reason codes only. Strictly reject unavailable or malformed data."""
    for key in ('total', 'available', 'cpus'):
        if type(view[key]) is not int or view[key] <= 0:
            raise UnsafeHost('invalid host observation')
    if view['available'] > view['total'] or not view['disks']:
        raise UnsafeHost('invalid host observation')
    result = []
    reserve = max(8 * GIB, view['total'] // 5)
    if view['available'] < reserve + (budget.memory if starting else 0):
        result.append('host_memory_headroom')
    headroom = view['cgroup_available']
    if headroom is not None:
        if type(headroom) is not int or headroom < 0:
            raise UnsafeHost('invalid ancestor observation')
        if headroom < 2 * GIB + (budget.memory if starting else 0):
            result.append('ancestor_memory_headroom')
    if budget.memory > view['total'] // 4:
        result.append('test_memory_fraction')
    if budget.cpus > view['cpus'] // 2:
        result.append('host_cpu_reserve')
    for total, free, inodes, free_inodes in view['disks']:
        if any(type(v) is not int or v < 0 for v in (total, free, inodes, free_inodes)) or not total or not inodes or free > total or free_inodes > inodes:
            raise UnsafeHost('invalid filesystem observation')
        if free < max(8 * GIB, total // 10) + (budget.disk if starting else 0):
            result.append('host_disk_headroom')
        if free_inodes < max(65536, inodes // 10) + (150000 if starting else 0):
            result.append('host_inode_headroom')
    for name, ceiling in (('memory_full', 0.5), ('io_full', 10.0)):
        value = view[name]
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 100:
            raise UnsafeHost('invalid pressure observation')
        if value >= ceiling:
            result.append(name + '_pressure')
    return tuple(sorted(set(result)))


def serial_lock():
    """One cooperating privileged fixture at a time; never unlink lock inodes."""
    return _serial_lock_at('/run/xandbox-test-guard', 0)


def _serial_lock_at(parent, owner):
    try:
        os.mkdir(parent, 0o700)
    except FileExistsError:
        pass
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    fd = None
    try:
        info = os.fstat(directory)
        if info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
            raise UnsafeHost('untrusted test coordination directory')
        fd = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=directory)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size != 0:
            raise UnsafeHost('untrusted test coordination lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


class OwnedAbort:
    """Own exactly one new lifetime pipe and retained generation kill FD."""
    def __init__(self, group, lifetime):
        self.lock = threading.Lock()
        self.lifetime, self.kill = lifetime, None
        self.attempted = False
        directory = os.open(group, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.kill = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        finally:
            os.close(directory)

    def abort(self):
        with self.lock:
            # EOF also fences a launcher that has not yet created QEMU.
            if self.lifetime is not None:
                fd, self.lifetime = self.lifetime, None
                os.close(fd)
            if self.kill is not None and not self.attempted:
                self.attempted = True
                os.write(self.kill, b'1')

    def close(self):
        with self.lock:
            for name in ('lifetime', 'kill'):
                fd = getattr(self, name)
                setattr(self, name, None)
                if fd is not None:
                    os.close(fd)


class HostGuard:
    """Fail-closed monitor. Callback is restricted by its trusted fixture caller."""
    def __init__(self, budget, paths, *, _sample=None, _clock=None):
        self.budget, self.paths = budget, paths
        self.read = _sample or (lambda: sample(paths))
        self.clock = _clock or time.monotonic
        self.lock, self.done = threading.Lock(), threading.Event()
        self.failure, self.abort = None, None
        self.lease, self.thread = None, None
        self._active = False

    def start(self):
        if self.lease is not None or self.thread is not None or self.done.is_set():
            raise UnsafeHost('test monitor is single-use')
        try:
            self.lease = serial_lock()
            self.check_sample(starting=True)
            self.deadline = self.clock() + self.budget.seconds
            self._active = True
            self.thread = threading.Thread(target=self._watch, daemon=True, name='owned-test-headroom')
            self.thread.start()
        except BaseException:
            self.close()
            raise

    def check_sample(self, *, starting=False):
        denied = reasons(self.budget, self.read(), starting=starting)
        if denied:
            raise UnsafeHost(','.join(denied))

    def _watch(self):
        while not self.done.wait(1):
            try:
                if self.clock() >= self.deadline:
                    raise UnsafeHost('test_wall_clock_limit')
                self.check_sample()
            except Exception:
                self.trip()
                return

    def trip(self):
        with self.lock:
            if self.failure is None:
                self.failure = 'host safety guard aborted; retain private failure evidence'
                if self.abort is not None:
                    try:
                        self.abort()
                    except Exception:
                        self.failure = 'host safety abort unconfirmed; inspect owned domain'

    def check(self):
        with self.lock:
            if self.failure is not None:
                raise UnsafeHost(self.failure)

    def launch(self, handle, start):
        # A trip before spawn rejects launch; a trip after spawn closes this
        # generation's pipe and kills only its already-open execution domain.
        with self.lock:
            if self.failure is not None or not self._active or self.done.is_set():
                # A never-started or already-closed monitor is not launch
                # authority, even if it has never observed a pressure failure.
                raise UnsafeHost(self.failure or 'active host monitor required')
            self.abort = handle.abort
            return start()

    def stop(self):
        self.done.set()
        with self.lock:
            self._active = False
            self.abort = None
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                # Never prevent the fixture's independent owned-domain cleanup.
                with self.lock:
                    self.failure = 'test monitor stop unconfirmed'

    def close(self):
        self.stop()
        if self.lease is not None:
            fd, self.lease = self.lease, None
            os.close(fd)
