#!/usr/bin/env python3
"""Exercise real shell, isolated workers, pipes, and reboot persistence in a new image.

This is a release smoke journey, not the adversarial or crash acceptance suite.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import fsck
import mkfs
from doctor import probe, sha256
from run import command, locked_image, image_digest


class Guest:
    def __init__(self, qemu, kernel, firmware, image, output, start_paused=False, icount=False, read_only=False):
        self.output = output
        output.mkdir()
        self.stack = ExitStack()
        self.closed = False
        self.data = bytearray()
        self.cursor = 0
        self.fatal_scan_cursor = 0
        self.fatal_line_start = 0
        self.qmp_events = []
        self.qmp_buffer = bytearray()
        self.identity = {}
        try:
            canonical, image_fd = self.stack.enter_context(locked_image(image, output.parent, read_only=read_only))
            control = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="krv-smoke-")))
            qmp_path = control / "qmp.sock"
            self.cmd = command(qemu, kernel, firmware, canonical, qmp_path, icount=icount, image_fd=image_fd)
            if start_paused:
                self.cmd.append("-S")
            dtb_cmd = self.cmd.copy()
            dtb_cmd[dtb_cmd.index("virt,aia=none")] += ",dumpdtb=" + str(control / "machine.dtb")
            dtb = subprocess.run(dtb_cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=15, pass_fds=(image_fd,))
            if dtb.returncode != 0:
                raise RuntimeError("DTB preflight failed: " + dtb.stderr.decode("utf8", "replace"))
            (output / "machine.dtb").write_bytes((control / "machine.dtb").read_bytes())
            # Reuse the exact recorded input blob: a second implicit DTB would
            # contain newly generated seed bytes and have a different identity.
            self.cmd += ["-dtb", str(output / "machine.dtb")]
            self.log = self.stack.enter_context((output / "serial.log").open("xb"))
            self.child = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, pass_fds=(image_fd,))
            self.started = time.monotonic()
            self.sel = self.stack.enter_context(selectors.DefaultSelector())
            self.sel.register(self.child.stdout, selectors.EVENT_READ, "serial")
            self.qmp = self.stack.enter_context(socket.socket(socket.AF_UNIX))
            self.qmp.settimeout(0.1)
            deadline = time.monotonic() + 10
            while True:
                try:
                    self.qmp.connect(str(qmp_path))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    if time.monotonic() > deadline or self.child.poll() is not None:
                        raise RuntimeError("QMP did not become available")
                    time.sleep(0.02)
            self.qmp.setblocking(False)
            self.sel.register(self.qmp, selectors.EVENT_READ, "qmp")
            self.qmp.sendall(b'{"execute":"qmp_capabilities"}\n')
            self.identity = {"schema": 1, "command": self.cmd, "kernel_sha256": sha256(kernel),
                             "firmware_sha256": sha256(firmware), "image_sha256_before": image_digest(image_fd),
                             "dtb_input_sha256": sha256(output / "machine.dtb"),
                             "dtb_scope": "Exact QEMU input blob; identified OpenSBI may apply its normal fixups"}
            (output / "launch.json").write_text(json.dumps(self.identity, indent=2) + "\n")
            if start_paused:
                deadline = time.monotonic() + 5
                while not any("return" in event for event in self.qmp_events):
                    if time.monotonic() > deadline:
                        raise RuntimeError("QMP capability negotiation timed out")
                    self.pump(0.1)
                self.qmp.sendall(b'{"execute":"cont"}\n')
        except Exception:
            self.close()
            raise

    def pump(self, timeout):
        for key, _ in self.sel.select(timeout):
            if key.data == "serial":
                chunk = os.read(self.child.stdout.fileno(), 4096)
                if not chunk:
                    self.sel.unregister(self.child.stdout)
                else:
                    self.log.write(chunk)
                    self.log.flush()
                    self.data.extend(chunk)
                    if len(self.data) > 4 * 1024 * 1024:
                        raise RuntimeError("guest exceeded bounded smoke output")
            else:
                chunk = self.qmp.recv(8192)
                if not chunk:
                    self.sel.unregister(self.qmp)
                self.qmp_buffer.extend(chunk)
                while b"\n" in self.qmp_buffer:
                    line, _, self.qmp_buffer = self.qmp_buffer.partition(b"\n")
                    self.qmp_events.append(json.loads(line))
        # Inspect each serial byte only once, including incomplete long lines.
        # Rescanning the cumulative capture here creates quadratic host work and
        # can backpressure bounded guest UART writes during large trace exports.
        while True:
            end = self.data.find(b"\n", self.fatal_scan_cursor)
            if end < 0:
                self.fatal_scan_cursor = len(self.data)
                break
            start = self.fatal_line_start
            self.fatal_line_start = end + 1
            self.fatal_scan_cursor = end + 1
            # Retain the complete diagnostic and ignore words inside escaped
            # UOUT records. Unterminated diagnostics still reach the watchdog.
            if (self.data.startswith(b"BOOT_FAILED", start, end)
                    or self.data.startswith(b"KERNEL_PANIC", start, end)):
                raise RuntimeError("guest reported fatal boot/kernel failure")

    def expect(self, expression, timeout=60):
        deadline = time.monotonic() + timeout
        while True:
            found = re.search(expression, self.data[self.cursor:])
            if found:
                end = self.cursor + found.end()
                result = bytes(self.data[self.cursor:end])
                self.cursor = end
                return result
            if time.monotonic() >= deadline:
                raise TimeoutError(f"guest did not emit {expression!r}")
            self.pump(0.1)
            if self.child.poll() is not None:
                self.pump(0)
                if not re.search(expression, self.data[self.cursor:]):
                    raise RuntimeError("guest exited before expected observation")

    def boot(self):
        self.expect(rb"(?:^|\n)READY\r?\n")
        self.expect(rb"> ")

    def issue(self, line, expected=None):
        self.child.stdin.write(line.encode("ascii") + b"\r")
        self.child.stdin.flush()
        result = self.expect(rb"> ")
        if b"error " in result or b"BOOT_FAILED" in result:
            raise AssertionError("command failed: " + result.decode("ascii", "replace"))
        if expected is not None and expected not in result:
            raise AssertionError(f"missing command observation {expected!r}: {result!r}")
        return result

    def shutdown(self):
        self.child.stdin.write(b"shutdown\r")
        self.child.stdin.flush()
        self.wait_for_shutdown(15)

    def wait_for_shutdown(self, timeout=60):
        deadline = time.monotonic() + timeout
        while self.child.poll() is None and time.monotonic() < deadline:
            self.pump(0.1)
        if self.child.poll() is None:
            raise TimeoutError("guest shutdown watchdog expired")
        # Process exit does not imply that its pipes/sockets have been drained.
        # A final protocol record can still span multiple 4096-byte serial reads.
        # Observe EOF on both streams before closing either capture endpoint.
        drain_deadline = time.monotonic() + 5
        while self.sel.get_map():
            remaining = drain_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("guest exited but serial/QMP streams did not reach EOF")
            self.pump(min(0.1, remaining))
        if self.child.poll() != 0:
            raise RuntimeError("guest did not shut down cleanly")
        if not any(e.get("event") == "SHUTDOWN" and e.get("data", {}).get("guest") is True for e in self.qmp_events):
            raise RuntimeError("missing QMP guest SHUTDOWN event")
        self.close()

    def close(self):
        if self.closed:
            return
        self.closed = True
        child = getattr(self, "child", None)
        forced = child is not None and child.poll() is None
        if forced:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        if child is not None:
            self.identity.update({"exit_code": child.returncode, "forced_termination": forced,
                                  "elapsed_host_seconds": time.monotonic() - self.started,
                                  "qmp": self.qmp_events})
            (self.output / "result.json").write_text(json.dumps(self.identity, indent=2) + "\n")
            child.stdin.close()
            child.stdout.close()
        self.stack.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path, help="New external run directory; image and logs retained")
    p.add_argument("--qemu", default="qemu-system-riscv64")
    p.add_argument("--firmware", default="build/fw_dynamic.bin", type=Path)
    p.add_argument("--kernel", default="target/riscv64imac-unknown-none-elf/release/kernel", type=Path)
    p.add_argument("--program-dir", default="target/riscv64imac-unknown-none-elf/release", type=Path)
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.is_relative_to(root):
        p.error("smoke evidence must be outside the candidate tree")
    report = {"schema": 1, "status": "INCOMPLETE", "scope": "Real release shell, worker, pipe and reboot smoke only",
              "limitations": ["No exhaustive syscall/adversarial acceptance", "No power-loss sector injection", "No mandatory scheduler measurements"]}
    guest = None
    created = False
    try:
        output.mkdir(parents=True, exist_ok=False)
        created = True
        qemu = probe("qemu-system-riscv64", args.qemu)
        report["qemu"] = qemu
        if qemu["status"] != "MATCH":
            raise RuntimeError("QEMU 11.1.3 required")
        kernel, firmware, programs = args.kernel.resolve(strict=True), args.firmware.resolve(strict=True), args.program_dir.resolve(strict=True)
        names = ["compute", "writer", "fault", "demo3", "producer", "consumer"]
        report["programs"] = {n: sha256(programs / n) for n in names}
        image = output / "smoke.img"
        mkfs.create(image, uuid.UUID("4b465300-0001-4000-8000-000000000001").bytes, [("/" + n, programs / n) for n in names])
        marker = b"persistent-smoke-23a7d0"
        guest = Guest(qemu["path"], kernel, firmware, image, output / "boot-1")
        guest.boot()
        guest.issue("help", b"write /name text")
        guest.issue("ps", b"PID PARENT STATE PAGES")
        guest.issue("run /demo3", b"demo3 verified peer progress and fault containment")
        pipe_result = guest.issue("run /producer | /consumer", b"consumer verified 8192 bytes")
        if len(re.findall(rb"child \d+ ended kind=0 code=0", pipe_result)) != 2:
            raise AssertionError("both pipeline programs must exit normally")
        guest.issue("write /persistent " + marker.decode())
        guest.issue("cat /persistent", marker)
        guest.shutdown()
        guest = None
        first = fsck.inspect(image)
        if first["needs_replay"]:
            raise AssertionError("clean shutdown left an active journal")
        expected_hash = hashlib.sha256(marker).hexdigest()
        if not any(f["name"] == "/persistent" and f["sha256"] == expected_hash for f in first["files"]):
            raise AssertionError("independent disk oracle did not find acknowledged bytes")
        (output / "fsck-1.json").write_text(json.dumps(first, indent=2) + "\n")
        guest = Guest(qemu["path"], kernel, firmware, image, output / "boot-2")
        guest.boot()
        guest.issue("cat /persistent", marker)
        guest.shutdown()
        guest = None
        second = fsck.inspect(image)
        if first != second:
            raise AssertionError("read-only reboot journey changed logical filesystem state")
        (output / "fsck-2.json").write_text(json.dumps(second, indent=2) + "\n")
        report.update(status="PASS", image_sha256=sha256(image), observations=["immutable init shell", "three worker processes with fault containment", "8192 ordered pipe bytes and EOF", "independent on-disk file digest", "file read after clean shutdown and reboot"])
    except Exception as error:
        report.update(status="INCOMPLETE" if isinstance(error, TimeoutError) else "FAIL", reason=str(error))
    finally:
        if guest:
            guest.close()
        if created:
            (output / "smoke.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
