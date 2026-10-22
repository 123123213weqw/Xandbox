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
    def __init__(self, root):
        self.root = Path(root)
        self.mount = self.root / 'm'
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
        self._check()
        if self.fillers:
            raise RuntimeError('previous filler not released')
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

    def probe(self):
        self._check()
        path = self.mount / '.enospc-probe'
        fd = None
        phase = 'open'
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            phase = 'write'
            os.write(fd, b'x' * 4096)
            phase = 'fsync'
            os.fsync(fd)
        except OSError as error:
            if error.errno != errno.ENOSPC:
                raise
            return {'errno': error.errno, 'phase': phase}
        finally:
            if fd is not None:
                os.close(fd)
                path.unlink()
        raise AssertionError('fault volume still accepts a durable new block')

    def release(self):
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
