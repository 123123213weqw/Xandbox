#!/usr/bin/env python3
"""Build an experimental initramfs; requires Linux root, cpio, and a guest agent.

Never chroots into or executes the downloaded guest filesystem on the host.
"""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile

ALPINE_SHA256 = "f8e1cafba9b1b283b5d30d06f9885c8d2bc161ffe9083ade8e2e157813a53407"


def safe_guest_filter(member, destination):
    if member.isdev() or member.isfifo():
        raise ValueError("guest archive contains special files")
    if member.issym():
        actual = member.linkname
        parent = str(PurePosixPath(member.name).parent)
        if actual.startswith("/"):
            actual = posixpath.relpath(actual.lstrip("/") or ".", parent)
        base = os.path.realpath(destination)
        target = os.path.realpath(os.path.join(base, parent, actual))
        if os.path.commonpath([base, target]) != base:
            raise ValueError("guest symlink escapes the build tree")
        # Some security-backported Python 3.10 data_filter implementations
        # incorrectly interpret symlink targets relative to the archive root.
        # Independently validate the actual parent-relative destination above,
        # use a root-relative validation proxy, then restore correct semantics.
        proxy = member.replace(linkname=os.path.relpath(target, base))
        filtered = tarfile.data_filter(proxy, destination)
        return filtered.replace(linkname=actual)
    return tarfile.data_filter(member, destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alpine-tar", required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.uname().sysname != "Linux":
        parser.error("build only on a Linux node with root for guest device nodes")
    archive, agent, output = [Path(p).resolve() for p in (args.alpine_tar, args.agent, args.output)]
    if output.exists():
        parser.error("output already exists; use a new path")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ALPINE_SHA256:
        parser.error("Alpine archive checksum mismatch")
    elf = agent.read_bytes()
    if len(elf) < 64 or elf[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", elf, 18)[0] != 62:
        parser.error("this image fixture requires a Linux x86_64 ELF agent")
    phoff = struct.unpack_from("<Q", elf, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", elf, 54)
    if phsize < 56 or phnum > 256 or phoff + phsize * phnum > len(elf):
        parser.error("invalid agent ELF program headers")
    if any(struct.unpack_from("<I", elf, phoff + i * phsize)[0] == 3 for i in range(phnum)):
        parser.error("agent must be statically linked; rebuild with CGO_ENABLED=0")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="xb-image-") as temp:
        # Keep the host build parent private while giving the guest root its
        # actual 0755 mode. Archiving TemporaryDirectory's 0700 root would
        # silently make all guest paths inaccessible to the task UID.
        root = Path(temp) / "rootfs"
        root.mkdir(mode=0o755)

        with tarfile.open(archive, "r:gz") as source:
            members = source.getmembers()
            if len(members) > 10000 or sum(m.size for m in members) > 64 * 1024 * 1024:
                raise ValueError("guest archive exceeds build bounds")
            source.extractall(root, members=members, filter=safe_guest_filter)
        root.chmod(0o755)
        for directory in root.rglob("*"):
            if directory.is_dir() and not directory.is_symlink():
                directory.chmod(0o755)
        for name in ("tmp", "var/tmp"):
            (root / name).mkdir(exist_ok=True, parents=True)
            (root / name).chmod(0o1777)
        (root / "root").chmod(0o700)
        for name in ("proc", "sys", "dev", "workspace", "usr/bin", "etc"):
            (root / name).mkdir(exist_ok=True, parents=True)
        shutil.copyfile(agent, root / "usr/bin/xandbox-agent")
        (root / "usr/bin/xandbox-agent").chmod(0o755)
        (root / "etc/xandbox-guest").write_text("Xandbox guest image v1\n")
        (root / "etc/inittab").write_text(
            "::sysinit:/bin/mount -t proc proc /proc\n"
            "::sysinit:/bin/mount -t sysfs sysfs /sys\n"
            "::sysinit:/bin/mount -t devtmpfs devtmpfs /dev\n"
            "::respawn:/usr/bin/xandbox-agent\n"
        )
        for name, major, minor in (("console", 5, 1), ("null", 1, 3), ("tty", 5, 0)):
            path = root / "dev" / name
            if not path.exists():
                os.mknod(path, stat.S_IFCHR | 0o600, os.makedev(major, minor))
        # Tasks are UID 65534. /dev/null is intentionally usable by them.
        (root / "dev/null").chmod(0o666)
        entries = ["."] + sorted(str(p.relative_to(root)) for p in root.rglob("*"))
        for name in entries:
            os.utime(root / name, (0, 0), follow_symlinks=False)
        with tempfile.TemporaryFile() as cpio:
            subprocess.run(["cpio", "--null", "-o", "--format=newc", "--owner=0:0", "--reproducible"],
                           cwd=root, input=b"\0".join(os.fsencode(n) for n in entries) + b"\0", stdout=cpio, check=True)
            cpio.seek(0)
            with output.open("xb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as packed:
                shutil.copyfileobj(cpio, packed)
    print(json.dumps({"experimental_guest_image": True, "initrd_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                      "agent_sha256": hashlib.sha256(agent.read_bytes()).hexdigest(), "alpine_sha256": ALPINE_SHA256}))


if __name__ == "__main__":
    main()
