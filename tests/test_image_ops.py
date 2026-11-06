import fcntl
from pathlib import Path
import sys
import tempfile
import unittest

TOOLS=Path(__file__).resolve().parents[1]/'tools'
sys.path.insert(0,str(TOOLS))
import fsck
import image_ops
import mkfs


class ImageOperations(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='kfs-ops-')
        self.root=Path(self.temp.name)
        self.image=self.root/'disk.img'
        self.input=self.root/'payload'
        self.input.write_bytes(b'export-exact-bytes')
        mkfs.create(self.image,bytes(16),[('/example',self.input)])

    def tearDown(self):
        self.temp.cleanup()

    def test_export_is_exact_and_never_overwrites(self):
        destination=self.root/'export'
        report=image_ops.export_image(self.image,destination)
        self.assertEqual((destination/'files'/'example').read_bytes(),self.input.read_bytes())
        self.assertEqual(report['files'][0]['name'],'/example')
        with self.assertRaises(FileExistsError):
            image_ops.export_image(self.image,destination)

    def test_locked_reset_refused_and_old_contents_retained(self):
        before=fsck.inspect(self.image)
        with self.image.open('r+b') as stream:
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                image_ops.reset(self.image,[],bytes([1])*16)
        self.assertEqual(fsck.inspect(self.image),before)

    def test_reset_replaces_only_explicit_path(self):
        copy=self.root/'other.img'
        mkfs.create(copy,bytes([2])*16,[])
        before=fsck.inspect(copy)
        image_ops.reset(self.image,[],bytes([3])*16)
        self.assertEqual(fsck.inspect(self.image)['files'],[])
        self.assertEqual(fsck.inspect(copy),before)

    def test_seed_failure_preserves_old_image(self):
        before=fsck.inspect(self.image)
        with self.assertRaises(FileNotFoundError):
            image_ops.reset(self.image,[('/bad',self.root/'missing')],bytes(16))
        self.assertEqual(fsck.inspect(self.image),before)


if __name__=='__main__':
    unittest.main()
