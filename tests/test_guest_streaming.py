"""Complete-line diagnostics must remain linear under large serial exports."""
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from smoke import Guest
from crash_test import NbdGuest


class NoEvents:
    def select(self, _timeout):
        return []


class CountedCapture(bytearray):
    """Count candidate bytes presented to delimiter/prefix checks, not wall time."""
    examined = 0

    def find(self, sub, start=0, end=None):
        stop = len(self) if end is None else end
        result = super().find(sub, start, stop)
        self.examined += max(0, (stop if result < 0 else result + len(sub)) - start)
        return result

    def startswith(self, prefix, start=0, end=None):
        stop = len(self) if end is None else end
        self.examined += min(len(prefix), max(0, stop - start))
        return super().startswith(prefix, start, stop)


def guest():
    result = Guest.__new__(Guest)
    result.sel = NoEvents()
    result.data = CountedCapture()
    result.fatal_scan_cursor = 0
    result.fatal_line_start = 0
    return result


class GuestStreaming(unittest.TestCase):
    def test_fatal_prefix_and_terminator_split_across_reads(self):
        for marker in (b'BOOT_FAILED', b'KERNEL_PANIC'):
            g = guest()
            for chunk in (b'ordinary\n' + marker[:3], marker[3:] + b' reason=detail', b'\r'):
                g.data.extend(chunk)
                g.pump(0)
            g.data.extend(b'\n')
            with self.assertRaisesRegex(RuntimeError, 'fatal boot/kernel'):
                g.pump(0)
            self.assertTrue(g.data.endswith(marker + b' reason=detail\r\n'))

    def test_escaped_and_embedded_diagnostics_do_not_abort_stream(self):
        g = guest()
        data = b'UOUT {"data":"\\nBOOT_FAILED reason=pretend\\nKERNEL_PANIC"}\nordinary KERNEL_PANIC\n'
        for i in range(0, len(data), 3):
            g.data.extend(data[i:i + 3])
            g.pump(0)
        self.assertEqual(bytes(g.data), data)

    def test_nbd_constructor_initializes_inherited_capture_state(self):
        # Exercise the actual alternate constructor up to launch, without a
        # QEMU dependency. It must initialize every state field used by pump.
        with tempfile.TemporaryDirectory() as directory:
            g = NbdGuest.__new__(NbdGuest)
            with patch('crash_test.subprocess.run', side_effect=RuntimeError('fixture stop before launch')):
                with self.assertRaisesRegex(RuntimeError, 'fixture stop before launch'):
                    g.__init__('qemu', Path('kernel'), Path('firmware'), Path('nbd.sock'), Path(directory) / 'guest')
            self.assertEqual(g.fatal_scan_cursor, 0)
            self.assertEqual(g.fatal_line_start, 0)
            g.sel = NoEvents()
            g.data.extend(b'ordinary\nBOOT_')
            g.pump(0)
            g.data.extend(b'FAILED reason=fixture\n')
            with self.assertRaisesRegex(RuntimeError, 'fatal boot/kernel'):
                g.pump(0)

    def test_large_stream_and_unterminated_line_are_scanned_linearly(self):
        # The old cumulative-regex scan examines about128MiB for this1MiB
        # fixture. Count actual input spans rather than machine-dependent time.
        for payload in (b'x' * (1024 * 1024) + b'\n',
                        b'KTEST {"event":"sample","value":12345678901234567890}\n' * 20000):
            g = guest()
            regex_bytes = 0
            original_search = re.search

            def measured_search(pattern, data, *args, **kwargs):
                nonlocal regex_bytes
                regex_bytes += len(data)
                return original_search(pattern, data, *args, **kwargs)

            with patch('smoke.re.search', side_effect=measured_search):
                for i in range(0, len(payload), 4096):
                    g.data.extend(payload[i:i + 4096])
                    g.pump(0)
                # QMP-only/idle pumps must not scan the previous export again.
                for _ in range(20):
                    g.pump(0)
            self.assertEqual(bytes(g.data), payload)
            self.assertLessEqual(g.data.examined + regex_bytes, 2 * len(payload))
            g.data.extend(b'BOOT_FAILED reason=after-large-export\n')
            with self.assertRaises(RuntimeError):
                g.pump(0)


if __name__ == '__main__':
    unittest.main()
