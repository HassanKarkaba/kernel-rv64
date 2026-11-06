import struct
import tempfile
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from check_elf import check, scan_integer_code


class StaticElfChecks(unittest.TestCase):
    def test_integer_compressed_and_ecall(self):
        self.assertEqual(scan_integer_code(b"\x01\x00\x73\x00\x00\x00\x00\x00", 0x10000), 3)

    def test_all_float_vector_major_opcodes_rejected(self):
        for opcode in (0x07, 0x27, 0x43, 0x47, 0x4B, 0x4F, 0x53, 0x57):
            with self.subTest(opcode=opcode), self.assertRaisesRegex(ValueError, "floating-point or vector"):
                scan_integer_code(opcode.to_bytes(4, "little"), 0x10000)

    def test_rv64_compressed_floating_load_store_rejected(self):
        for quadrant in (0, 2):
            for func in (1, 5):
                with self.assertRaisesRegex(ValueError, "compressed floating"):
                    scan_integer_code(((func << 13) | quadrant).to_bytes(2, "little"), 0x10000)
        for quadrant in (0, 2):
            for func in (3, 7):
                self.assertEqual(scan_integer_code(((func << 13) | quadrant).to_bytes(2, "little"), 0x10000), 1)

    def test_long_and_truncated_instructions_rejected(self):
        for code in (b"\x1f\x00\x00\x00\x00\x00", b"\x73\x00", b"\x00"):
            with self.assertRaises(ValueError):
                scan_integer_code(code, 0x10000)

    def test_text_scan_and_permission_boundary(self):
        def elf(code, flags=5):
            data = bytearray(4096) + code
            data[:7] = b"\x7fELF\x02\x01\x01"
            struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 243, 1, 0x10000, 64, 0, 1, 64, 56, 1, 64, 0, 0)
            struct.pack_into("<IIQQQQQQ", data, 64, 1, flags, 4096, 0x10000, 0x10000, len(code), len(code), 4096)
            return data
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "program"
            path.write_bytes(elf(b"\x73\x00\x00\x00"))
            self.assertEqual(check(path)["instructions_scanned"], 1)
            path.write_bytes(elf(b"\x53\x00\x00\x00"))
            with self.assertRaisesRegex(ValueError, "floating-point"):
                check(path)
            path.write_bytes(elf(b"\x73\x00\x00\x00", 7))
            with self.assertRaisesRegex(ValueError, "permissions"):
                check(path)


if __name__ == "__main__":
    unittest.main()
