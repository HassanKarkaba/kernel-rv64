"""Host image codec checks. These do not qualify the actual VirtIO boundary."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


mkfs = module('mkfs')
fsck = module('fsck')


class StorageTools(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kfs-test-')
        self.root = Path(self.temp.name)
        self.image = self.root / 'test.img'

    def tearDown(self):
        self.temp.cleanup()

    def block(self, number):
        with self.image.open('rb') as stream:
            stream.seek(number*4096)
            return bytearray(stream.read(4096))

    def write_block(self, number, data):
        with self.image.open('r+b') as stream:
            stream.seek(number*4096)
            stream.write(data)

    def test_crc_golden_and_empty_format(self):
        self.assertEqual(mkfs.crc(b'123456789'), 0xE3069283)
        self.assertEqual(fsck.checksum(b'123456789'), 0xE3069283)
        mkfs.create(self.image, bytes(range(16)), [])
        report = fsck.inspect(self.image)
        self.assertEqual(report['files'], [])
        self.assertEqual(report['used_blocks'], 32)
        self.assertEqual(report['sequence'], 0)
        self.assertFalse(report['needs_replay'])
        with self.assertRaises(FileExistsError):
            mkfs.create(self.image, bytes(range(16)), [])

    def test_seed_indirect_file_and_hash(self):
        data = bytes(range(256))*210
        source = self.root / 'payload'
        source.write_bytes(data)
        mkfs.create(self.image, bytes(16), [('/big', source)])
        result = fsck.inspect(self.image)
        self.assertEqual(result['files'][0]['size'], len(data))
        self.assertEqual(result['files'][0]['sha256'], fsck.hashlib.sha256(data).hexdigest())
        self.assertEqual(result['used_blocks'], 32+(len(data)+4095)//4096+1)

    def test_stray_allocation_and_padding_rejected(self):
        mkfs.create(self.image, bytes(16), [])
        bitmap = self.block(19)
        bitmap[7] |= 1
        self.write_block(19, mkfs.sealed(bitmap))
        with self.assertRaisesRegex(fsck.Corruption, 'allocation mismatch'):
            fsck.inspect(self.image)
        bitmap[7] = 0
        bitmap[3000] = 1
        self.write_block(19, mkfs.sealed(bitmap))
        with self.assertRaisesRegex(fsck.Corruption, 'padding'):
            fsck.inspect(self.image)

    def test_nonzero_bytes_after_eof_rejected(self):
        source = self.root / 'payload'
        source.write_bytes(b'x')
        mkfs.create(self.image, bytes(16), [('/a', source)])
        block = self.block(32)
        block[1] = 1
        self.write_block(32, block)
        with self.assertRaisesRegex(fsck.Corruption, 'after EOF'):
            fsck.inspect(self.image)

    def test_committed_journal_overlay_precedes_mutable_metadata_scan(self):
        volume = bytes(range(16))
        mkfs.create(self.image, volume, [])
        after = self.block(19)
        struct.pack_into('<Q', after, 2048, 1)
        mkfs.sealed(after)
        descriptor = bytearray(4096)
        descriptor[:8] = b'KJDES001'
        descriptor[8:24] = volume
        struct.pack_into('<QII', descriptor, 24, 1, 1, 1)
        struct.pack_into('<4I', descriptor, 64, 19, 0, mkfs.crc(after), 0)
        mkfs.sealed(descriptor)
        commit = bytearray(512)
        commit[:8] = b'KJCOM001'
        commit[8:24] = volume
        struct.pack_into('<IIQI', commit, 24, 1, 1, 1, struct.unpack_from('<I', descriptor, 4092)[0])
        mkfs.sealed(commit)
        self.write_block(1, commit+bytes(3584))
        self.write_block(2, descriptor)
        self.write_block(3, after)
        self.write_block(19, bytes(4096))
        before = self.image.read_bytes()
        report = fsck.inspect(self.image)
        self.assertTrue(report['needs_replay'])
        self.assertEqual(report['sequence'], 1)
        self.assertEqual(self.image.read_bytes(), before, 'fsck must not mutate input')
        after[33] ^= 1
        self.write_block(3, after)
        with self.assertRaisesRegex(fsck.Corruption, 'checksum'):
            fsck.inspect(self.image)

    def test_bad_image_sizes_refused(self):
        self.image.write_bytes(b'')
        with self.assertRaisesRegex(fsck.Corruption, 'size'):
            fsck.inspect(self.image)


if __name__ == '__main__':
    unittest.main()
