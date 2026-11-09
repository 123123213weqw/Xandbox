#!/usr/bin/env python3
"""Read-only preview distribution verifier. No extraction, execution or install.

The expected SHA/source must come from a separately trusted release record.
A matching archive is not a signature, node readiness or rollback certificate.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import PurePosixPath
import re
import stat
import struct
import sys
import tarfile


MAX_COMPRESSED = 128 << 20
MAX_EXPANDED = 256 << 20
MAX_MEMBERS = 2048
SHA = re.compile(r'^[0-9a-f]{64}$')
COMMIT = re.compile(r'^[0-9a-f]{40}$')
VERSION = re.compile(r'^v[0-9]+\.[0-9]+\.[0-9]+-preview\.[0-9]+$')
COMMON = frozenset(('sandboxctl', 'sandboxd', 'xandbox-doctor', 'xandbox-guestctl',
                    'xandbox-ingress-launch', 'xandbox-install', 'xandbox-keygen',
                    'xandbox-launch', 'xandbox-node', 'xandbox-ready',
                    'xandbox-release', 'xandbox-template'))
LINUX = COMMON | {'xandbox-agent', 'xandbox-gateway', 'xandbox-warden'}
REQUIRED_TEXT = frozenset(('BUILD_INFO.json', 'README_PREVIEW.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md'))


def require(condition):
    if not condition:
        raise ValueError('invalid preview distribution')


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


class BoundedInflate(io.RawIOBase):
    def __init__(self, stream):
        self.stream, self.total = stream, 0
        self.tail = b''

    def read(self, size=-1):
        require(type(size) is int and size >= 0)
        data = self.stream.read(min(size, MAX_EXPANDED - self.total + 1))
        self.total += len(data)
        require(self.total <= MAX_EXPANDED)
        self.tail = (self.tail + data)[-65536:]
        return data


def architecture(prefix, target):
    osname, arch = target.split('-')
    if osname == 'linux':
        require(len(prefix) >= 64 and prefix[:6] == b'\x7fELF\x02\x01')
        require(struct.unpack_from('<HH', prefix, 16) == (2, 62 if arch == 'amd64' else 183))
    else:
        require(len(prefix) >= 32 and prefix[:4] == b'\xcf\xfa\xed\xfe')
        require(struct.unpack_from('<I', prefix, 4)[0] == (0x1000007 if arch == 'amd64' else 0x100000c))


def _verify(file, version, target, source):
    names, programs, info, docs = set(), {}, None, 0
    root = f'Xandbox-{version}-{target}/'
    last_end = 0
    expected_programs = LINUX if target.startswith('linux-') else COMMON
    with gzip.GzipFile(fileobj=file, mode='rb') as compressed:
        bounded = BoundedInflate(compressed)
        with tarfile.open(fileobj=bounded, mode='r|') as archive:
            for member in archive:
                require(len(names) < MAX_MEMBERS and member.name.startswith(root) and len(member.name) <= 480)
                name = member.name[len(root):]
                require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*', name) is not None)
                parts = name.split('/')
                require(all(part not in ('', '.', '..') for part in parts))
                require(name not in names and member.type == tarfile.REGTYPE)
                if member.pax_headers:
                    # Published preview archives use a single canonical PAX
                    # path record for long public documentation names only.
                    require(member.pax_headers == {'path': member.name} and len(member.name) > 100)
                    require(member.offset_data - member.offset == 1536)
                else:
                    require(member.offset_data - member.offset == 512)
                require(member.uid == member.gid == 0 and member.size > 0)
                names.add(name)
                binary = name.startswith('bin/')
                if binary:
                    require(len(parts) == 2 and parts[1] in expected_programs)
                    require(member.mode == 0o755 and member.size <= 32 << 20)
                else:
                    allowed = name in REQUIRED_TEXT or (len(parts) >= 2 and parts[0] in ('docs', 'LICENSES') and PurePosixPath(name).suffix in ('.md', '.json', '.txt'))
                    require(allowed and member.mode == 0o644 and member.size <= 2 << 20)
                    if name == 'BUILD_INFO.json': require(member.size <= 32768)
                stream = archive.extractfile(member)  # returns bytes only; never extract/extractall
                digest, count, prefix, metadata = hashlib.sha256(), 0, b'', bytearray()
                while True:
                    block = stream.read(65536)
                    if not block: break
                    count += len(block)
                    require(count <= member.size)
                    digest.update(block)
                    if len(prefix) < 64: prefix = (prefix + block)[:64]
                    if name == 'BUILD_INFO.json': metadata.extend(block)
                require(count == member.size)
                last_end = member.offset_data + ((member.size + 511) // 512) * 512
                if binary:
                    architecture(prefix, target)
                    programs[parts[1]] = {'bytes': count, 'sha256': digest.hexdigest()}
                elif name == 'BUILD_INFO.json':
                    info = json.loads(metadata, object_pairs_hook=unique_object)
                elif parts[0] == 'docs': docs += 1
            # tarfile may have read ahead past the end marker. Check those
            # already-inflated bytes too, not only the unread gzip suffix.
            tail_start = bounded.total - len(bounded.tail)
            require(tail_start <= last_end <= bounded.total)
            require(not any(bounded.tail[last_end - tail_start:]))
        # Check gzip CRC/truncation and the entire bounded expanded stream,
        # including any concatenated member. Nonzero trailing payload is refused.
        while True:
            block = bounded.read(65536)
            if not block: break
            require(not any(block))
    require(REQUIRED_TEXT <= names and docs > 0 and set(programs) == expected_programs)
    require(type(info) is dict and set(info) == {
        'CGO_ENABLED', 'TEST_ONLY_helpers_included', 'build_flags', 'experimental_preview',
        'go_toolchain', 'guest_images_or_Firecracker_included', 'new_KVM_or_performance_qualification',
        'production_ready', 'programs', 'source_commit', 'source_tree', 'target', 'version'})
    require(info['version'] == version and info['target'] == target and info['source_commit'] == source)
    require(type(info['source_tree']) is str and COMMIT.fullmatch(info['source_tree']))
    require(type(info['go_toolchain']) is str and re.fullmatch(r'go1\.[0-9]+\.[0-9]+', info['go_toolchain']))
    require(type(info['CGO_ENABLED']) is int and info['CGO_ENABLED'] == 0)
    require(info['build_flags'] == ['-trimpath', '-buildvcs=false'])
    require(info['experimental_preview'] is True)
    for key in ('TEST_ONLY_helpers_included', 'guest_images_or_Firecracker_included',
                'new_KVM_or_performance_qualification', 'production_ready'):
        require(info[key] is False)
    # Python bool == int: compare types explicitly before inventory equality.
    require(type(info['programs']) is dict and set(info['programs']) == expected_programs)
    for value in info['programs'].values():
        require(type(value) is dict and set(value) == {'bytes', 'sha256'})
        require(type(value['bytes']) is int and type(value['sha256']) is str and SHA.fullmatch(value['sha256']))
    require(info['programs'] == programs)
    return {'version': version, 'target': target, 'source_commit': source,
            'archive_verified': True, 'programs_verified': len(programs),
            'files_verified': len(names), 'installed': False, 'production_ready': False}


def verify(path, sha256, version, target, source):
    require(type(sha256) is str and SHA.fullmatch(sha256))
    require(type(source) is str and COMMIT.fullmatch(source))
    require(type(version) is str and VERSION.fullmatch(version))
    require(target in ('linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64'))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as file:
        before = os.fstat(file.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_COMPRESSED)
        digest = hashlib.sha256()
        size = 0
        while True:
            block = file.read(65536)
            if not block: break
            size += len(block); require(size <= MAX_COMPRESSED)
            digest.update(block)
        require(size == before.st_size and digest.hexdigest() == sha256)
        file.seek(0)
        result = _verify(file, version, target, source)
        after = os.fstat(file.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'sha256', 'version', 'target', 'source-commit'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.archive, args.sha256, args.version, args.target, args.source_commit)
    except (ValueError, OSError, EOFError, tarfile.TarError, KeyError, TypeError, struct.error):
        print('release bundle verification failed; nothing installed', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
