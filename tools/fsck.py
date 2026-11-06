#!/usr/bin/env python3
"""Independent read-only KFS v1 decoder and complete consistency oracle.

A committed journal is validated and overlaid in memory before metadata checks.
No input image is repaired, cleared or otherwise modified by this tool.
"""
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import struct
import sys
import uuid

BLOCK = 4096
BLOCKS = 16384
CRC_TABLE = []
for _index in range(256):
    _value = _index
    for _ in range(8):
        _value = (_value >> 1) ^ (0x82F63B78 if _value & 1 else 0)
    CRC_TABLE.append(_value)


class Corruption(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Corruption(reason)


def checksum(data):
    value = 0xFFFFFFFF
    for byte in data:
        value = (value >> 8) ^ CRC_TABLE[(value ^ byte) & 255]
    return value ^ 0xFFFFFFFF


def checked(data, context):
    require(checksum(data[:-4]) == struct.unpack_from('<I', data, len(data)-4)[0], f'{context}: CRC32C mismatch')


def name_valid(name):
    return 0 < len(name) < 48 and name not in (b'.', b'..') and all(
        65 <= x <= 90 or 97 <= x <= 122 or 48 <= x <= 57 or x in (95, 45, 46) for x in name)


def bitmap_decode(block):
    checked(block, 'allocation block')
    require(block[:4] == b'\xff'*4, 'reserved blocks not allocated')
    require(not any(block[2056:4092]), 'allocation padding is nonzero')
    return struct.unpack_from('<Q', block, 2048)[0]


class Image:
    def __init__(self, stream):
        self.stream = stream
        self.overlay = {}
        stream.seek(0, 2)
        require(stream.tell() == BLOCK*BLOCKS, 'image size must be exactly 64 MiB')

    def block(self, number):
        require(0 <= number < BLOCKS, f'block pointer out of bounds: {number}')
        if number in self.overlay:
            return self.overlay[number]
        self.stream.seek(number*BLOCK)
        data = self.stream.read(BLOCK)
        require(len(data) == BLOCK, 'short read')
        return data

    def journal(self, volume):
        container = self.block(1)
        require(not any(container[512:]), 'commit container padding is nonzero')
        commit = container[:512]
        if not any(commit):
            return False
        checked(commit, 'commit sector')
        require(commit[:8] == b'KJCOM001', 'invalid commit magic')
        require(commit[8:24] == volume, 'commit UUID mismatch')
        version, count, sequence, descriptor_crc = struct.unpack_from('<IIQI', commit, 24)
        require(version == 1 and 1 <= count <= 16 and sequence > 0, 'invalid commit fields')
        require(not any(commit[44:508]), 'commit padding is nonzero')
        desc = self.block(2)
        checked(desc, 'journal descriptor')
        require(desc[:8] == b'KJDES001' and desc[8:24] == volume, 'journal descriptor identity mismatch')
        require(struct.unpack_from('<QII', desc, 24) == (sequence, count, 1), 'journal descriptor fields mismatch')
        require(struct.unpack_from('<I', desc, 4092)[0] == descriptor_crc, 'commit/descriptor checksum mismatch')
        require(not any(desc[40:64]) and not any(desc[64+count*16:4092]), 'descriptor padding is nonzero')
        overlay = {}
        previous = 18
        for i in range(count):
            target, slot, crc, reserved = struct.unpack_from('<4I', desc, 64+i*16)
            require(previous < target < BLOCKS and target >= 19, 'journal targets not legal and strictly sorted')
            require(slot == i and reserved == 0, 'invalid journal slot or reserved field')
            data = self.block(3+i)
            require(checksum(data) == crc, f'journal image {i}: checksum mismatch')
            overlay[target] = data
            previous = target
        require(19 in overlay, 'journal omits allocation block')
        require(bitmap_decode(overlay[19]) == sequence, 'journal/allocation sequence mismatch')
        self.overlay = overlay
        return True

    def inspect(self):
        superblock = self.block(0)
        checked(superblock, 'superblock')
        require(superblock[:8] == b'KFS00001', 'invalid superblock magic')
        require(struct.unpack_from('<IIQ', superblock, 8) == (1, BLOCK, BLOCKS), 'unsupported superblock geometry/version')
        require(struct.unpack_from('<14I', superblock, 40) == (512,256,256,16,1,2,3,19,20,8,28,4,32,0), 'unsupported superblock layout/features')
        require(not any(superblock[96:4092]), 'superblock padding is nonzero')
        volume = superblock[24:40]
        replay = self.journal(volume)
        allocation = self.block(19)
        sequence = bitmap_decode(allocation)
        allocated = {n for n in range(BLOCKS) if allocation[n//8] & (1 << (n%8))}
        owners = {n: 'reserved' for n in range(32)}
        inodes = {}

        def claim(pointer, owner):
            require(32 <= pointer < BLOCKS, f'{owner}: invalid pointer {pointer}')
            require(pointer not in owners, f'block {pointer} has duplicate owners: {owners.get(pointer)} and {owner}')
            owners[pointer] = owner

        for index in range(256):
            raw = self.block(20+index//32)[(index%32)*128:(index%32+1)*128]
            checked(raw, f'inode {index+1}')
            state, flags, reserved, size, generation = struct.unpack_from('<BBHIQ', raw)
            direct = list(struct.unpack_from('<12I', raw, 16))
            indirect = struct.unpack_from('<I', raw, 64)[0]
            require(state in (0,1) and flags == reserved == 0 and not any(raw[68:124]), f'inode {index+1}: bad state/padding')
            require(size <= 4194304, f'inode {index+1}: oversized file')
            if state == 0:
                require(size == indirect == 0 and not any(direct), f'free inode {index+1} owns storage')
                continue
            require(generation != 0, f'inode {index+1}: zero generation')
            count = (size+4095)//4096
            require(bool(indirect) == (count>12), f'inode {index+1}: invalid indirect shape')
            pointers = direct
            if indirect:
                claim(indirect, f'inode {index+1} indirect')
                indirect_data = self.block(indirect)
                words = struct.unpack('<1024I', indirect_data)
                require(not any(words[1012:]), f'inode {index+1}: indirect trailing pointers')
                pointers += list(words[:1012])
            require(not any(pointers[count:]), f'inode {index+1}: unused nonzero pointer')
            used = pointers[:count]
            require(len(used) == count, f'inode {index+1}: missing pointers')
            for pointer in used:
                claim(pointer, f'inode {index+1} data')
            if size%4096:
                require(not any(self.block(used[-1])[size%4096:]), f'inode {index+1}: nonzero bytes after EOF')
            inodes[index+1] = {'generation': generation, 'size': size, 'pointers': used}
        names = set()
        linked = set()
        files = []
        for index in range(256):
            raw = self.block(28+index//64)[index%64*64:(index%64+1)*64]
            if not any(raw):
                continue
            checked(raw, f'directory {index}')
            inode, length, flags, generation = struct.unpack_from('<HBBQ', raw)
            require(1 <= inode <= 256 and 1 <= length <= 47 and flags == 0, f'directory {index}: invalid fields')
            name = raw[12:12+length]
            require(name_valid(name) and not any(raw[12+length:60]), f'directory {index}: invalid name/padding')
            require(name not in names, f'duplicate name {name!r}')
            require(inode in inodes and inode not in linked and inodes[inode]['generation'] == generation, f'directory {index}: generation/bijection mismatch')
            names.add(name)
            linked.add(inode)
            record = inodes[inode]
            digest = hashlib.sha256()
            remaining = record['size']
            for pointer in record['pointers']:
                chunk = self.block(pointer)[:min(remaining,4096)]
                digest.update(chunk)
                remaining -= len(chunk)
            files.append({'name': '/'+name.decode('ascii'), 'inode': inode, 'generation': generation, 'size': record['size'], 'sha256': digest.hexdigest()})
        require(linked == set(inodes), 'live inode without exactly one directory entry')
        require(allocated == set(owners), f'allocation mismatch: leaked={sorted(allocated-set(owners))[:8]}, missing={sorted(set(owners)-allocated)[:8]}')
        return {'format':1, 'uuid':str(uuid.UUID(bytes=volume)), 'sequence':sequence, 'read_only':sequence == 2**64-1, 'needs_replay':replay, 'used_blocks':len(owners), 'files':sorted(files,key=lambda f:f['name']), 'result':'PASS'}


def inspect(path):
    with open(path, 'rb') as stream:
        fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
        return Image(stream).inspect()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--json', action='store_true', help='emit machine-readable inspection (also the default)')
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(args.image), sort_keys=True))
        return 0
    except (OSError, ValueError, struct.error) as error:
        print(json.dumps({'result':'FAIL','error':str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
