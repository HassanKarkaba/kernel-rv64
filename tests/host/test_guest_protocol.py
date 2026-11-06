import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from guest_test import validate_records
from smoke import Guest


class TrustedProtocol(unittest.TestCase):
    def records(self):
        shared = dict(schema=1, run_id="a" * 32, boot_id="b" * 32, case_id="guest-selftest")
        return [dict(shared, event="start", sequence=1),
                dict(shared, event="result", sequence=2, result="PASS", child_kind=0, child_code=0)]

    def encode(self, records):
        return b"\n".join(b"KTEST " + json.dumps(r).encode() for r in records) + b"\n"

    def test_escaped_child_claim_is_not_authoritative(self):
        fake = b'UOUT {"data":"KTEST {\\"result\\":\\"PASS\\"}"}\n'
        self.assertEqual(len(validate_records(fake + self.encode(self.records()), "a" * 32, "b" * 32)), 2)
        with self.assertRaises(ValueError):
            validate_records(fake, "a" * 32, "b" * 32)

    def test_duplicate_terminal_and_out_of_order_rejected(self):
        r = self.records()
        for records in (r + [r[-1]], list(reversed(r)), r[:1]):
            with self.assertRaises(ValueError):
                validate_records(self.encode(records), "a" * 32, "b" * 32)

    def test_wrong_identity_failure_and_faulted_child_rejected(self):
        for field, value in [("run_id", "c" * 32), ("case_id", "other"), ("sequence", 3), ("result", "FAIL"), ("child_kind", 1)]:
            records = self.records()
            records[-1][field] = value
            with self.assertRaises(ValueError):
                validate_records(self.encode(records), "a" * 32, "b" * 32)

    def test_fatal_detection_retains_full_line_and_ignores_escaped_text(self):
        class NoEvents:
            def select(self, _timeout):
                return []
        for data, fatal in ((b'BOOT_FAILED phase=ker', False),
                            (b'UOUT {"data":"BOOT_FAILED"}\n', False),
                            (b'BOOT_FAILED phase=kernel reason=SUPERVISOR_TRAP\r\n', True)):
            guest = Guest.__new__(Guest)
            guest.sel = NoEvents()
            guest.data = bytearray(data)
            guest.fatal_scan_cursor = 0
            guest.fatal_line_start = 0
            if fatal:
                with self.assertRaises(RuntimeError):
                    guest.pump(0)
            else:
                guest.pump(0)
