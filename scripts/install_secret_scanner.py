#!/usr/bin/env python3
"""Install one hash-pinned scanner in an explicit private tool directory."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_ARCHIVE = 32 << 20
MAX_BINARY = 64 << 20


class InstallError(Exception):
    pass


def native_pin():
    lock = json.loads(Path(__file__).with_name('secret_scanner.json').read_text())
    if not isinstance(lock, dict) or set(lock) != {'version', 'release', 'artifacts'}:
        raise InstallError('invalid scanner lock')
    version = lock['version']
    if not isinstance(version, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise InstallError('invalid scanner version')
    expected = {'linux-x86_64': 'linux_x64', 'darwin-arm64': 'darwin_arm64'}
    if lock['release'] != 'https://github.com/gitleaks/gitleaks/releases/tag/v'+version or not isinstance(lock['artifacts'], dict) or set(lock['artifacts']) != set(expected):
        raise InstallError('invalid scanner platform/release inventory')
    for name, suffix in expected.items():
        value = lock['artifacts'][name]
        if not isinstance(value, dict) or set(value) != {'archive', 'archive_sha256', 'binary_sha256'}:
            raise InstallError('invalid scanner artifact lock')
        if value['archive'] != 'gitleaks_'+version+'_'+suffix+'.tar.gz' or not all(isinstance(value[k], str) and re.fullmatch('[a-f0-9]{64}', value[k]) for k in ('archive_sha256', 'binary_sha256')):
            raise InstallError('invalid scanner artifact identity')
    name = platform.system().lower() + '-' + platform.machine().lower()
    if name not in lock['artifacts']:
        raise InstallError('unsupported scanner platform')
    return lock['version'], lock['artifacts'][name]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_archive(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_ARCHIVE:
            raise InstallError('bounded regular scanner archive required')
        return source.read(MAX_ARCHIVE + 1)


def binary_from_archive(data, pin):
    if len(data) > MAX_ARCHIVE or digest(data) != pin['archive_sha256']:
        raise InstallError('scanner archive hash mismatch')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        entries = [v for v in archive.getmembers() if v.name == 'gitleaks']
        if len(entries) != 1 or not entries[0].isfile() or not 0 < entries[0].size <= MAX_BINARY:
            raise InstallError('invalid scanner member')
        binary = archive.extractfile(entries[0]).read(MAX_BINARY + 1)
    if len(binary) > MAX_BINARY or digest(binary) != pin['binary_sha256']:
        raise InstallError('scanner binary hash mismatch')
    return binary


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        if url.scheme != 'https' or url.hostname not in ('github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'):
            raise InstallError('unexpected scanner download redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url):
    opener = urllib.request.build_opener(HTTPSOnly())
    for attempt, delay in enumerate((0, 1, 3)):
        if delay:
            time.sleep(delay)
        try:
            with opener.open(url, timeout=40) as response:
                data = response.read(MAX_ARCHIVE + 1)
            if len(data) > MAX_ARCHIVE:
                raise InstallError('scanner download exceeds bound')
            return data
        except urllib.error.HTTPError as error:
            if error.code not in (408, 429, 500, 502, 503, 504) or attempt == 2:
                raise InstallError('scanner download unavailable') from None
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise InstallError('scanner download unavailable') from None
    raise InstallError('scanner download unavailable')


def install(destination, data, pin):
    # No extraction of archive paths and no overwriting/reusing unknown tools.
    binary = binary_from_archive(data, pin)
    parent = destination.parent
    st = parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise InstallError('private caller-owned tool directory required')
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
    with os.fdopen(fd, 'wb') as output:
        output.write(binary)
        output.flush()
        os.fsync(output.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--archive', type=Path, help='offline pre-downloaded archive; same pinned hashes required')
    args = parser.parse_args()
    version, pin = native_pin()
    data = read_archive(args.archive) if args.archive else download('https://github.com/gitleaks/gitleaks/releases/download/v' + version + '/' + pin['archive'])
    install(args.destination, data, pin)
    print(json.dumps({'installed_scanner_version': version, 'binary_sha256': pin['binary_sha256']}))


if __name__ == '__main__':
    try:
        main()
    except (InstallError, OSError, ValueError, tarfile.TarError):
        raise SystemExit('secret scanner installation failed; use an exclusive private directory and the pinned archive')
