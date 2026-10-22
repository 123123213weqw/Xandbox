"""Disposable bounded ext4 fault volume, only inside a PRIVATE mount namespace.

Never fill a host directory, remount a shared filesystem or detach an arbitrary
loop device. A loop binding is trusted only while it names our exclusive image.
"""
import errno
import os
from pathlib import Path
import subprocess
import time

VOLUME_BYTES = 64 << 20


def require_private_namespace(parent):
    current = os.readlink('/proc/self/ns/mnt')
    if current == parent or os.readlink('/proc/' + str(os.getppid()) + '/ns/mnt') != parent:
        raise RuntimeError('requires re-exec in own mount namespace')
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        optional = line.split(' - ', 1)[0].split()[6:]
        if any(item.startswith(('shared:', 'master:')) for item in optional):
            raise RuntimeError('mount propagation is not private')


def backing_file(device):
    try:
        value = (Path('/sys/dev/block') / device / 'loop/backing_file').read_text().strip()
    except FileNotFoundError:
        return None
    return Path('/' + value.lstrip('/')).resolve() if value else None


class BoundedExt4:
    def __init__(self, root, mount_name='m'):
        # The ledger-only variant leaves the controller's writable lock/socket
        # on healthy storage. Never bind-over a directory with pre-opened FDs.
        if mount_name not in ('m', 'ledger'):
            raise ValueError('unknown exclusive fault mount layout')
        self.root = Path(root)
        self.mount = self.root / mount_name
        self.image = self.root / 'fault.ext4'
        self.mounted = False
        self.device = None
        self.fillers = []

    def create(self):
        self.mount.mkdir(mode=0o700)
        with self.image.open('xb') as out:
            os.posix_fallocate(out.fileno(), 0, VOLUME_BYTES)
            os.fsync(out.fileno())
        subprocess.run(['mkfs.ext4', '-q', '-F', '-m', '0', '-N', '512', str(self.image)], check=True, timeout=30)
        # mount's loop mappings are autoclear; never use an existing mapping.
        subprocess.run(['mount', '-n', '-t', 'ext4', '-o', 'loop,nosuid,nodev,noexec',
                        str(self.image), str(self.mount)], check=True, timeout=15)
        self.mounted = True
        self.mount.chmod(0o700)
        info = self.mount.stat()
        self.device = str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev))
        assert info.st_dev != self.root.stat().st_dev and backing_file(self.device) == self.image.resolve()
        assert (Path('/sys/dev/block') / self.device / 'loop/autoclear').read_text().strip() == '1'
        assert subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(self.mount)], text=True).strip() == 'ext4'
        self._check()

    def _check(self):
        if not self.mounted or self.device is None or not os.path.ismount(self.mount):
            raise RuntimeError('not an owned mounted fault volume')
        if backing_file(self.device) != self.image.resolve():
            raise RuntimeError('loop binding identity changed')
        info = self.mount.stat()
        if self.device != str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev)):
            raise RuntimeError('fault mount identity changed')
        usage = os.statvfs(self.mount)
        if not 0 < usage.f_blocks * usage.f_frsize <= VOLUME_BYTES:
            raise RuntimeError('refuse to fill an unbounded filesystem')
        return usage

    def fill(self, mode):
        usage = self._check()
        if self.fillers:
            raise RuntimeError('previous filler not released')
        if usage.f_flag & os.ST_RDONLY:
            raise RuntimeError('previous read-only fault not released')
        if mode == 'readonly':
            # Keep this pre-fault directory FD through the real superblock
            # remount; a path-only bind-over could leave old FDs writable.
            fd = os.open(self.mount, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self._remount(True)
                usage = self._check()
                return {'mode': mode, 'volume_total_bytes': usage.f_blocks * usage.f_frsize,
                        'available_bytes': usage.f_bavail * usage.f_frsize,
                        'available_inodes': usage.f_favail,
                        'statvfs_readonly': bool(usage.f_flag & os.ST_RDONLY),
                        'write_probe': self.probe(errno.EROFS),
                        'preopened_directory_write_probe': self.probe(errno.EROFS, dir_fd=fd)}
            finally:
                os.close(fd)
        observed = False
        count = 0
        if mode == 'blocks':
            path = self.mount / '.block-filler'
            with path.open('xb', buffering=0) as out:
                self.fillers.append(path)
                while count <= VOLUME_BYTES:
                    try:
                        written = out.write(b'\0' * (1 << 20))
                        if not written:
                            raise RuntimeError('zero-progress fault filler')
                        count += written
                    except OSError as error:
                        if error.errno != errno.ENOSPC:
                            raise
                        observed = True
                        break
                try:
                    os.fsync(out.fileno())
                except OSError as error:
                    if error.errno != errno.ENOSPC:
                        raise
                    observed = True
        elif mode == 'inodes':
            for number in range(1024):
                path = self.mount / ('.inode-filler-' + str(number))
                try:
                    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                except OSError as error:
                    if error.errno != errno.ENOSPC:
                        raise
                    observed = True
                    break
                os.close(fd)
                self.fillers.append(path)
                count += 1
        else:
            raise ValueError('unknown bounded fault mode')
        assert observed, 'bounded filler did not reach ENOSPC'
        usage = self._check()
        if mode == 'inodes':
            assert usage.f_favail == 0 and usage.f_bavail * usage.f_frsize > 8 << 20
        return {'mode': mode, 'filler_bytes' if mode == 'blocks' else 'filler_files': count,
                'volume_total_bytes': usage.f_blocks * usage.f_frsize,
                'available_bytes': usage.f_bavail * usage.f_frsize, 'available_inodes': usage.f_favail,
                'write_probe': self.probe()}

    def _remount(self, readonly):
        self._check()  # Identity/capacity check BEFORE every mount mutation.
        subprocess.run(['mount', '-n', '-o', 'remount,' + ('ro' if readonly else 'rw') + ',nosuid,nodev,noexec',
                        str(self.mount)], check=True, timeout=15)
        usage = self._check()
        if bool(usage.f_flag & os.ST_RDONLY) != readonly:
            raise RuntimeError('owned fault remount flags did not take effect')

    def probe(self, expected_errno=errno.ENOSPC, *, dir_fd=None):
        self._check()
        path = self.mount / '.enospc-probe'
        fd = None
        phase = 'open'
        try:
            fd = os.open(path if dir_fd is None else path.name,
                         os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=dir_fd)
            phase = 'write'
            os.write(fd, b'x' * 4096)
            phase = 'fsync'
            os.fsync(fd)
        except OSError as error:
            if error.errno != expected_errno:
                raise
            return {'errno': error.errno, 'phase': phase}
        finally:
            if fd is not None:
                os.close(fd)
                os.unlink(path if dir_fd is None else path.name, dir_fd=dir_fd)
        if expected_errno == 0:
            return {'errno': 0, 'phase': phase}
        raise AssertionError('fault volume still accepts a durable new block')

    def release(self):
        if self.mounted:
            usage = self._check()
            # Inspect actual flags rather than a Python bool: even a timed-out
            # mount helper might already have changed this OWNED filesystem.
            if usage.f_flag & os.ST_RDONLY:
                self._remount(False)
                self.probe(expected_errno=0)
        if self.fillers:
            self._check()
            for path in self.fillers:
                path.unlink()
            self.fillers.clear()
            fd = os.open(self.mount, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def close(self):
        self.release()
        if self.mounted:
            subprocess.run(['umount', '-n', str(self.mount)], check=True, timeout=15)
            self.mounted = False
        if self.device is not None:
            end = time.monotonic() + 5
            while backing_file(self.device) == self.image.resolve() and time.monotonic() < end:
                time.sleep(0.01)
            # A reused loop number belongs to someone else; NEVER detach it.
            assert backing_file(self.device) != self.image.resolve(), 'owned loop image still attached; retain it'
