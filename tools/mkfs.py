#!/usr/bin/env python3
"""Create a new KFS v1 image; never replace an existing path."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import struct
import sys
import uuid

BLOCK = 4096
COUNT = 16384
TABLE = []
for n in range(256):
    for _ in range(8):
        n = (n >> 1) ^ (0x82F63B78 if n & 1 else 0)
    TABLE.append(n)


def crc(data):
    value = 0xFFFFFFFF
    for byte in data:
        value = TABLE[(value ^ byte) & 255] ^ (value >> 8)
    return value ^ 0xFFFFFFFF


def sealed(data):
    struct.pack_into('<I', data, len(data)-4, crc(data[:-4]))
    return data


def valid_name(name):
    return 1 <= len(name) <= 47 and name not in (b'.', b'..') and all(
        ord('a') <= c <= ord('z') or ord('A') <= c <= ord('Z') or
        ord('0') <= c <= ord('9') or c in b'_.-' for c in name)


def create(path, volume, files):
    if len(files) > 256:
        raise ValueError('at most 256 files are supported')
    contents = []
    names = set()
    for name, source in files:
        raw_name = name.removeprefix('/').encode('ascii')
        if not name.startswith('/') or not valid_name(raw_name):
            raise ValueError(f'invalid root filename: {name!r}')
        if raw_name in names:
            raise ValueError(f'duplicate filename: {name!r}')
        names.add(raw_name)
        with open(source, 'rb') as stream:
            content = stream.read(4194305)
        if len(content) > 4194304:
            raise ValueError(f'file exceeds 4 MiB: {source}')
        contents.append((raw_name, content))
    contents.sort(key=lambda item: item[0])
    needed = 32 + sum((len(data)+4095)//4096 + (len(data)>12*4096) for _, data in contents)
    if needed > COUNT:
        raise ValueError('seed contents exceed image capacity')
    superblock = bytearray(BLOCK)
    superblock[:8] = b'KFS00001'
    struct.pack_into('<IIQ', superblock, 8, 1, BLOCK, COUNT)
    superblock[24:40] = volume
    struct.pack_into('<14I', superblock, 40, 512, 256, 256, 16, 1, 2, 3, 19, 20, 8, 28, 4, 32, 0)
    sealed(superblock)
    bitmap = bytearray(BLOCK)
    bitmap[:4] = b'\xff'*4
    inodes = bytearray(8*BLOCK)
    directory = bytearray(4*BLOCK)
    for i in range(256):
        inodes[i*128:(i+1)*128] = sealed(bytearray(128))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            stream.truncate(BLOCK*COUNT)
            next_block = 32
            for index, (name, data) in enumerate(contents):
                pointers = list(range(next_block, next_block+(len(data)+4095)//4096))
                next_block += len(pointers)
                indirect = 0
                if len(pointers) > 12:
                    indirect = next_block
                    next_block += 1
                for pointer in pointers + ([indirect] if indirect else []):
                    bitmap[pointer//8] |= 1 << (pointer%8)
                for i, pointer in enumerate(pointers):
                    stream.seek(pointer*BLOCK)
                    stream.write(data[i*BLOCK:(i+1)*BLOCK].ljust(BLOCK, b'\0'))
                if indirect:
                    block = bytearray(BLOCK)
                    for i, pointer in enumerate(pointers[12:]):
                        struct.pack_into('<I', block, i*4, pointer)
                    stream.seek(indirect*BLOCK)
                    stream.write(block)
                inode = bytearray(128)
                inode[0] = 1
                struct.pack_into('<IQ', inode, 4, len(data), 1)
                for i, pointer in enumerate(pointers[:12]):
                    struct.pack_into('<I', inode, 16+i*4, pointer)
                struct.pack_into('<I', inode, 64, indirect)
                inodes[index*128:(index+1)*128] = sealed(inode)
                entry = bytearray(64)
                struct.pack_into('<HBBQ', entry, 0, index+1, len(name), 0, 1)
                entry[12:12+len(name)] = name
                directory[index*64:(index+1)*64] = sealed(entry)
            sealed(bitmap)
            for block, data in [(0, superblock), (19, bitmap), (20, inodes), (28, directory)]:
                stream.seek(block*BLOCK)
                stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        parent = os.open(str(Path(path).resolve().parent), os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except BaseException:
        os.unlink(path)
        raise
    return {'format': 1, 'bytes': BLOCK*COUNT, 'uuid': str(uuid.UUID(bytes=volume)), 'files': len(contents), 'used_blocks': needed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--uuid', type=uuid.UUID, help='explicit deterministic fixture UUID')
    parser.add_argument('--file', '--import', action='append', default=[], metavar='/NAME=SOURCE')
    args = parser.parse_args()
    try:
        files = []
        for value in args.file:
            name, separator, source = value.partition('=')
            if not separator or not source:
                raise ValueError('--file requires /NAME=SOURCE')
            files.append((name, Path(source)))
        print(json.dumps(create(args.image, (args.uuid or uuid.uuid4()).bytes, files), sort_keys=True))
        return 0
    except (OSError, ValueError, UnicodeError) as error:
        print(f'mkfs: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
