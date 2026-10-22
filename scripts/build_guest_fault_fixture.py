#!/usr/bin/env python3
"""Build TEST-ONLY guest filesystem faults; never used for production images.

Reads a pinned project newc initrd, keeps device/ownership metadata, adds a
build-tag-only read-only observer, and injects exactly one reviewed image fault.
For crash-before-marker also prepares a pinned-source Go compiler overlay; no
production agent file or production runtime flag is modified.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import zlib

INITIALIZE_SOURCE_SHA = 'd794fc3b6b341fd7c507b32de646d93795e645a6096c87822a0f8e94f121ef42'


def sha(data): return hashlib.sha256(data).hexdigest()

def entries(raw):
    out = {}; offset = 0
    while True:
        if offset + 110 > len(raw) or raw[offset:offset+6] != b'070701': raise ValueError('expected bounded newc archive')
        fields = [int(raw[offset+6+i*8:offset+14+i*8], 16) for i in range(13)]
        offset += 110
        size, namesize = fields[6], fields[11]
        if not 1 <= namesize <= 4096 or size > 64 << 20: raise ValueError('entry bounds')
        name = raw[offset:offset+namesize]
        if len(name) != namesize or name[-1:] != b'\0': raise ValueError('bad name')
        name = name[:-1].decode('utf-8'); offset = (offset+namesize+3) & ~3
        data = raw[offset:offset+size]
        if len(data) != size: raise ValueError('truncated entry')
        offset = (offset+size+3) & ~3
        if name == 'TRAILER!!!': break
        if name in out or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts: raise ValueError('unsafe/duplicate name')
        out[name] = (fields, data)
        if len(out) > 10000: raise ValueError('too many entries')
    if any(raw[offset:]): raise ValueError('unexpected concatenated archive')
    return out


def pack(items):
    data = bytearray()
    for name, (original, content) in list(sorted(items.items())) + [('TRAILER!!!', ([0]*13, b''))]:
        fields = list(original); fields[6] = len(content); fields[11] = len(name.encode())+1; fields[12] = 0
        data.extend(b'070701'+b''.join(f'{v:08x}'.encode() for v in fields))
        data.extend(name.encode()+b'\0'); data.extend(b'\0'*(-len(data)%4))
        data.extend(content); data.extend(b'\0'*(-len(data)%4))
    data.extend(b'\0'*(-len(data)%512))
    return bytes(data)


def fixture_entry(ino, mode, content=b''):
    return ([ino, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0, len(content), 0, 0, 0, 0, 0, 0], content)


def static_elf(blob):
    if len(blob)<64 or blob[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',blob,18)[0]!=62: raise ValueError('requires Linux amd64 ELF')
    off=struct.unpack_from('<Q',blob,32)[0];size,count=struct.unpack_from('<HH',blob,54)
    if size<56 or count>256 or off+size*count>len(blob): raise ValueError('ELF bounds')
    if any(struct.unpack_from('<I',blob,off+i*size)[0]==3 for i in range(count)): raise ValueError('fixture binary must be static')


def prepare_overlay(root, destination):
    destination.mkdir(mode=0o700)
    source = root/'internal/guest/initialize_linux.go'; text=source.read_bytes()
    if sha(text)!=INITIALIZE_SOURCE_SHA: raise ValueError('reviewed source changed; do not silently patch another function')
    needle=b'\tif _, e := privatefile.EnsureDirectory(initDir); e != nil {'
    assert text.count(needle)==1
    injection=b'\t// TEST COMPILER OVERLAY ONLY: exact post-CLAIMED/pre-marker process death.\n\tif _, e := os.Stat("/etc/xandbox-fixture-crash-before-marker"); e == nil { os.Exit(97) }\n'
    patched=destination/'initialize_linux.go';patched.write_bytes(text.replace(needle,injection+needle))
    patched.chmod(0o600)
    overlay=destination/'overlay.json';overlay.write_text(json.dumps({'Replace':{str(source.resolve()):str(patched.resolve())}}));overlay.chmod(0o600)
    print(json.dumps({'test_only':True,'production_source_sha256':sha(text),'patched_source_sha256':sha(patched.read_bytes()),'overlay_path':str(overlay.resolve())}))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepare-overlay');p.add_argument('--source-root',default='.')
    p.add_argument('--base');p.add_argument('--expected-base-sha256');p.add_argument('--observer');p.add_argument('--agent')
    p.add_argument('--mode',choices=('machine-id-directory','crash-before-marker'));p.add_argument('--output')
    a=p.parse_args();os.umask(0o077)
    if a.prepare_overlay:
        prepare_overlay(Path(a.source_root).resolve(),Path(a.prepare_overlay).resolve());return
    if not all((a.base,a.expected_base_sha256,a.observer,a.mode,a.output)):p.error('explicit pinned base, observer, mode and new output required')
    base=Path(a.base).read_bytes()
    if len(base)>64<<20 or sha(base)!=a.expected_base_sha256:raise ValueError('base initrd digest/bounds mismatch')
    dec=zlib.decompressobj(16+zlib.MAX_WBITS);raw=dec.decompress(base,96<<20)
    if not dec.eof or dec.unused_data or len(raw)>=96<<20:raise ValueError('compressed fixture bounds')
    items=entries(raw);observer=Path(a.observer).read_bytes();static_elf(observer)
    ino=max(i[0][0] for i in items.values())+1
    def put(name,mode,data=b''):
        nonlocal ino
        items[name]=fixture_entry(ino,mode,data);ino+=1
    put('usr/bin/xandbox-fixture-observer',stat.S_IFREG|0o755,observer)
    put('etc/xandbox-fixture-observer',stat.S_IFREG|0o600,b'Xandbox fixture observer v1\n')
    fields,inittab=items['etc/inittab'];assert b'::respawn:/usr/bin/xandbox-agent\n' in inittab
    items['etc/inittab']=(fields,inittab+b'::once:/usr/bin/xandbox-fixture-observer\n')
    if a.mode=='machine-id-directory':
        if a.agent:raise ValueError('filesystem-failure case must use UNMODIFIED production agent')
        put('etc/machine-id',stat.S_IFDIR|0o755)
    else:
        if not a.agent:raise ValueError('explicit compiler-overlay agent required')
        agent=Path(a.agent).read_bytes();static_elf(agent)
        put('usr/bin/xandbox-agent',stat.S_IFREG|0o755,agent)
        put('etc/xandbox-fixture-crash-before-marker',stat.S_IFREG|0o600,b'test-only fixed before-marker exit\n')
    output=Path(a.output).resolve()
    with output.open('xb') as raw_file:
        with gzip.GzipFile(filename='',fileobj=raw_file,mode='wb',mtime=0) as gz:gz.write(pack(items))
        raw_file.flush();os.fsync(raw_file.fileno())
    info={'test_only':True,'fault_mode':a.mode,'base_initrd_sha256':sha(base),'initrd_sha256':sha(output.read_bytes()),
          'observer_sha256':sha(observer),'agent_sha256':sha(items['usr/bin/xandbox-agent'][1]),
          'production_agent_modified':a.mode=='crash-before-marker','not_production_image':True}
    sidecar=output.with_suffix(output.suffix+'.json')
    with sidecar.open('x') as f:json.dump(info,f);f.write('\n')
    print(json.dumps(info))


if __name__=='__main__':main()
