"""Exercise real terminated-child stream capture without requiring QEMU."""
from contextlib import ExitStack
import json
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from smoke import Guest


class GuestCapture(unittest.TestCase):
    def test_exited_child_preserves_buffered_terminal_record_and_qmp_eof(self):
        payload = b"x" * 9000 + b'\nKTEST {"event":"result","result":"PASS"}\n'
        with tempfile.TemporaryDirectory() as directory:
            guest = Guest.__new__(Guest)
            guest.output = Path(directory)
            guest.stack = ExitStack()
            guest.closed = False
            guest.data = bytearray()
            guest.cursor = 0
            guest.fatal_scan_cursor = 0
            guest.fatal_line_start = 0
            guest.qmp_events = []
            guest.qmp_buffer = bytearray()
            guest.identity = {"fixture": "terminated child with buffered serial tail"}
            guest.started = time.monotonic()
            guest.log = guest.stack.enter_context((guest.output / "serial.log").open("xb"))
            guest.sel = guest.stack.enter_context(selectors.DefaultSelector())
            serial_reader, serial_writer = socket.socketpair()
            guest.stack.enter_context(serial_reader)
            # A socket stream avoids platform-specific anonymous-pipe capacities.
            # The entire payload fits the send buffer before any parent read.
            serial_writer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            guest.child = subprocess.Popen(
                [sys.executable, "-c", "import sys; sys.stdout.buffer.write(" + repr(payload) + "); sys.stdout.buffer.flush()"],
                stdin=subprocess.PIPE, stdout=serial_writer, stderr=subprocess.DEVNULL,
            )
            serial_writer.close()
            guest.child.stdout = serial_reader.makefile("rb", buffering=0)
            guest.qmp, qmp_writer = socket.socketpair()
            guest.stack.enter_context(guest.qmp)
            guest.qmp.setblocking(False)
            qmp_writer.sendall(b'{"event":"SHUTDOWN","data":{"guest":true}}\n')
            qmp_writer.close()
            guest.sel.register(guest.child.stdout, selectors.EVENT_READ, "serial")
            guest.sel.register(guest.qmp, selectors.EVENT_READ, "qmp")
            try:
                # Crucially, the child has exited before wait_for_shutdown starts.
                # The old single-pump implementation captured only the first4096 bytes.
                self.assertEqual(guest.child.wait(timeout=5), 0)
                guest.wait_for_shutdown(1)
                self.assertEqual(bytes(guest.data), payload)
                self.assertEqual((guest.output / "serial.log").read_bytes(), payload)
                self.assertTrue(guest.closed)
                result = json.loads((guest.output / "result.json").read_text())
                self.assertFalse(result["forced_termination"])
                self.assertEqual(result["qmp"][-1]["event"], "SHUTDOWN")
            finally:
                guest.close()


if __name__ == "__main__":
    unittest.main()
