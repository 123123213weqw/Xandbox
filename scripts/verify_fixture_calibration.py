"""TEST ONLY: reject stale fixed ELF pins before spending a KVM test boot.

Inputs are explicit, bounded, read-only artifacts; they are never executed.
This is not runtime acceptance or attestation against source/workflow changes.
"""
import argparse
import ast
import hashlib
import os
from pathlib import Path
import re
import stat

from build_guest_fault_fixture import static_elf

MAX_BYTES = 32 << 20


def read_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_BYTES:
            raise ValueError('bounded regular input required')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            data = source.read(MAX_BYTES + 1)
        after = os.fstat(fd)
        if len(data) != before.st_size or (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('input changed during read')
        return data
    finally:
        os.close(fd)


def go_pin(root, filename, symbol):
    source = read_regular(root / 'cmd/xandbox-host-fixture' / filename).decode('utf-8')
    values = re.findall(r'^const ' + re.escape(symbol) + r' = "([0-9a-f]{64})"$',
                        source, re.MULTILINE)
    if len(values) != 1:
        raise ValueError('one exact Go pin required')
    return values[0]


def python_daemon_pin(root):
    tree = ast.parse(read_regular(root / 'scripts/kvm_nested_host.py'))
    values = [n.value for n in tree.body if isinstance(n, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == 'PREPARE_TRACE_ELF_SHA256' for t in n.targets)]
    if len(values) != 1 or not isinstance(values[0], ast.Constant) or not isinstance(
            values[0].value, str) or not re.fullmatch('[0-9a-f]{64}', values[0].value):
        raise ValueError('one literal Python pin required')
    return values[0].value


def verify(root, daemon, gateway):
    root = Path(root)
    pins = {
        'daemon': go_pin(root, 'node_prepare_trace_linux.go', 'prepareTraceELFSHA'),
        'gateway': go_pin(root, 'node_tls_policy_notify_linux.go', 'tlsPolicyGatewaySHA'),
    }
    if python_daemon_pin(root) != pins['daemon']:
        raise ValueError('Go/Python daemon calibration differs')
    for role, path in (('daemon', daemon), ('gateway', gateway)):
        data = read_regular(path)
        static_elf(data)
        if hashlib.sha256(data).hexdigest() != pins[role]:
            raise ValueError('fixed artifact calibration differs')
    return pins


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--daemon', required=True)
    parser.add_argument('--gateway', required=True)
    args = parser.parse_args()
    try:
        verify(Path(__file__).resolve().parent.parent, args.daemon, args.gateway)
    except (OSError, ValueError, SyntaxError, UnicodeError):
        # Never include raw source, artifact paths or exception payloads in CI.
        parser.exit(1, 'fixed fixture artifact calibration rejected\n')
    print('fixed fixture artifact calibration passed (not KVM acceptance)')


if __name__ == '__main__':
    main()
