"""Host image isolation tests; these do not qualify guest behavior."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))
import run


class RunnerIsolation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.image = self.root / "disk.img"
        with self.image.open("xb") as f:
            f.truncate(run.IMAGE_SIZE)

    def tearDown(self):
        self.tmp.cleanup()

    def test_symlink_refused_without_mutation(self):
        link = self.root / "alias.img"
        link.symlink_to(self.image)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            with run.locked_image(link):
                self.fail("symlink admitted")
        self.assertEqual(self.image.stat().st_size, run.IMAGE_SIZE)

    def test_test_root_cannot_admit_development_image(self):
        isolated = self.root / "tests"
        isolated.mkdir()
        with self.assertRaisesRegex(ValueError, "outside"):
            with run.locked_image(self.image, isolated):
                self.fail("development image admitted")

    def test_existing_lock_refused(self):
        with run.locked_image(self.image):
            script = "import fcntl,sys; f=open(sys.argv[1],'r+b'); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)"
            result = subprocess.run([sys.executable, "-c", script, str(self.image)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
        with run.locked_image(self.image):
            pass

    def test_wrong_size_refused_without_truncation(self):
        self.image.write_bytes(b"retained")
        with self.assertRaisesRegex(ValueError, "64 MiB"):
            with run.locked_image(self.image):
                self.fail("wrong-size image admitted")
        self.assertEqual(self.image.read_bytes(), b"retained")

    def test_read_only_descriptor_still_exclusively_locks_image(self):
        with run.locked_image(self.image, read_only=True) as (_, fd):
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
            with self.assertRaises(OSError):
                os.write(fd, b"x")
            script = "import fcntl,sys; f=open(sys.argv[1],'r+b'); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)"
            result = subprocess.run([sys.executable, "-c", script, str(self.image)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
        with run.locked_image(self.image):
            pass

    def test_locked_digest_uses_original_inode_without_seek_effect(self):
        import hashlib
        with run.locked_image(self.image) as (_,fd):
            os.lseek(fd,17,os.SEEK_SET)
            original=self.root/'original.img';self.image.rename(original)
            self.image.write_bytes(b'replacement')
            self.assertEqual(run.image_digest(fd),hashlib.sha256(original.read_bytes()).hexdigest())
            self.assertEqual(os.lseek(fd,0,os.SEEK_CUR),17)

    def test_inherited_descriptor_pins_backing_inode(self):
        cmd=run.command("qemu","kernel","fw",self.image,self.root/"qmp",image_fd=9)
        backend=json.loads(cmd[cmd.index("-blockdev")+1])
        self.assertEqual(backend["filename"],"/dev/fdset/1")
        self.assertIn("fd=9,set=1,opaque=kernel-image-lock",cmd)

    def test_backend_filename_is_json_data(self):
        hostile = self.root / 'file,cache.no-flush=on;$(echo bad)".img'
        cmd = run.command("qemu", "kernel", "fw", hostile, self.root / "qmp")
        file_backend = json.loads(cmd[cmd.index("-blockdev") + 1])
        self.assertEqual(file_backend["filename"], str(hostile))
        self.assertFalse(file_backend["cache"]["no-flush"])
        self.assertEqual(file_backend["locking"], "off")
        self.assertNotIn("-snapshot", cmd)
        self.assertIn("virtio-mmio.force-legacy=false", cmd)


if __name__ == "__main__":
    unittest.main()
