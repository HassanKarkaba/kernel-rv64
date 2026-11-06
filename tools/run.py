#!/usr/bin/env python3
"""Boot one explicitly named image; retain image and launch evidence on every exit."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from doctor import sha256, probe

IMAGE_SIZE = 64 * 1024 * 1024


@contextmanager
def locked_image(path, run_root=None, read_only=False):
    """Reject symlinks and nonregular files, then lock the same inode being checked."""
    supplied = Path(os.path.abspath(path))
    canonical = supplied.resolve(strict=True)
    if supplied != canonical:
        raise ValueError("image path must not contain symlinks")
    if run_root and not canonical.is_relative_to(Path(run_root).resolve(strict=True)):
        raise ValueError("test image is outside its isolated run directory")
    fd = os.open(canonical, (os.O_RDONLY if read_only else os.O_RDWR) | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != IMAGE_SIZE:
            raise ValueError("image must be a regular file of exactly 64 MiB")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if canonical.stat().st_ino != info.st_ino:
            raise ValueError("image changed while acquiring its lock")
        yield canonical, fd
    finally:
        os.close(fd)


def image_digest(fd):
    """Hash the locked open inode without changing its shared file position."""
    result=hashlib.sha256();offset=0
    while True:
        chunk=os.pread(fd,1024*1024,offset)
        if not chunk:break
        result.update(chunk);offset+=len(chunk)
    return result.hexdigest()


def command(qemu, kernel, firmware, image, qmp, icount=False, paused=False, image_fd=None):
    args = [str(qemu), "-machine", "virt,aia=none", "-cpu", "rv64",
            "-accel", "tcg,thread=single", "-smp", "1", "-m", "256M",
            "-bios", str(firmware), "-kernel", str(kernel), "-display", "none",
            "-monitor", "none", "-serial", "stdio", "-nic", "none", "-no-reboot",
            "-qmp", "unix:" + str(qmp) + ",server=on,wait=off",
            "-global", "virtio-mmio.force-legacy=false",
            # The inherited fdset pins the same validated inode even if its
            # pathname is replaced. Launcher and QEMU share its flock lifetime.
            # QEMU's byte-range lock aliases flock on Darwin, so a second lock would
            # reject our own child. All project mutation/inspection tools use flock.
            "-blockdev", json.dumps({"driver": "file", "filename": "/dev/fdset/1" if image_fd is not None else str(image), "node-name": "diskfile", "locking": "off",
                                     "cache": {"direct": False, "no-flush": False}}, separators=(",", ":")),
            "-blockdev", '{"driver":"raw","file":"diskfile","node-name":"disk"}',
            "-device", "virtio-blk-device,drive=disk"]
    if image_fd is not None:
        # QEMU retains this inherited open-file description independently of
        # the launcher. Even SIGKILL cannot release the image flock while the
        # guest is still alive; only child exit closes its final reference.
        args += ["-add-fd", f"fd={image_fd},set=1,opaque=kernel-image-lock"]
    if icount:
        args += ["-icount", "shift=0,align=off,sleep=off"]
    if paused:
        args += ["-S", "-gdb", "unix:" + str(qmp.with_name("gdb.sock")) + ",server=on,wait=off"]
    return args


def run(args):
    interrupted = []
    def request_stop(signum, _frame):
        interrupted.append(signum)
    previous = signal.signal(signal.SIGTERM, request_stop)
    try:
        return _run(args, interrupted)
    finally:
        signal.signal(signal.SIGTERM, previous)


def _run(args, interrupted):
    q = probe("qemu-system-riscv64", args.qemu)
    if q["status"] != "MATCH":
        raise ValueError("the runner requires QEMU 11.1.3: " + json.dumps(q))
    kernel = Path(args.kernel).resolve(strict=True)
    firmware = Path(args.firmware).resolve(strict=True)
    for path in (kernel, firmware):
        if not path.is_file():
            raise ValueError(f"not a regular input: {path}")
    output = Path(args.output).absolute() if args.output else Path(tempfile.mkdtemp(prefix="kernel-run-"))
    if output.resolve().is_relative_to(Path(__file__).resolve().parents[1]):
        raise ValueError("run evidence must be outside the candidate tree")
    if args.output:
        output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="krv-control-") as control, locked_image(args.image, args.run_root) as (image, image_fd):
        control = Path(control)
        cmd = command(q["path"], kernel, firmware, image, control / "qmp.sock", args.icount, args.paused, image_fd=image_fd)
        dtb_cmd = cmd.copy()
        dtb_cmd[dtb_cmd.index("virt,aia=none")] += ",dumpdtb=" + str(control / "machine.dtb")
        dtb = subprocess.run(dtb_cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=15, pass_fds=(image_fd,))
        if dtb.returncode != 0 or not (control / "machine.dtb").is_file():
            (output / "dtb-error.log").write_bytes(dtb.stdout + dtb.stderr)
            raise ValueError("QEMU DTB preflight failed; see dtb-error.log")
        shutil.copyfile(control / "machine.dtb", output / "machine.dtb")
        cmd += ["-dtb", str(output / "machine.dtb")]
        os.lseek(image_fd, 24, os.SEEK_SET)
        record = {"schema": 1, "command": cmd, "qemu": q, "kernel_sha256": sha256(kernel),
                  "firmware_sha256": sha256(firmware), "dtb_input_sha256": sha256(output / "machine.dtb"),
                  "dtb_scope": "Exact QEMU input blob; identified OpenSBI may apply its normal fixups",
                  "image": str(image), "image_sha256_before": image_digest(image_fd), "image_uuid": os.read(image_fd, 16).hex(),
                  "image_lock": "Inherited flock retained by QEMU until child exit",
                  "readiness": "NOT OBSERVED", "status": "INCOMPLETE", "profile": "virtual-time" if args.icount else "wall-clock",
                  "limitations": ["Boot observation alone is not acceptance", "Process termination is not the sector persistence fault model"]}
        (output / "launch.json").write_text(json.dumps(record, indent=2) + "\n")
        child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, pass_fds=(image_fd,))
        record["qemu_pid"] = child.pid
        (output / "launch.json").write_text(json.dumps(record, indent=2) + "\n")
        start = time.monotonic()
        ready_at = None
        pending = bytearray()
        forced = False
        try:
            with (output / "serial.log").open("wb") as log, selectors.DefaultSelector() as sel:
                sel.register(child.stdout, selectors.EVENT_READ, "output")
                if stat.S_ISFIFO(os.fstat(sys.stdin.fileno()).st_mode) or sys.stdin.isatty():
                    sel.register(sys.stdin, selectors.EVENT_READ, "input")
                while child.poll() is None:
                    if interrupted:
                        record["reason"] = f"operator signal {interrupted[0]}"
                        forced = True
                        break
                    elapsed = time.monotonic() - start
                    if not args.paused and ready_at is None and elapsed > args.timeout:
                        record["reason"] = "readiness timeout"
                        forced = True
                        break
                    if ready_at is not None and args.run_seconds and time.monotonic() - ready_at >= args.run_seconds:
                        record["reason"] = "explicit observation window ended"
                        forced = True
                        break
                    for key, _ in sel.select(0.1):
                        if key.data == "input":
                            data = os.read(sys.stdin.fileno(), 4096)
                            if data:
                                child.stdin.write(data)
                                child.stdin.flush()
                            else:
                                sel.unregister(sys.stdin)
                        else:
                            data = os.read(child.stdout.fileno(), 4096)
                            if not data:
                                sel.unregister(child.stdout)
                                continue
                            log.write(data)
                            log.flush()
                            sys.stdout.buffer.write(data)
                            sys.stdout.buffer.flush()
                            pending.extend(data)
                            while b"\n" in pending:
                                line, _, pending = pending.partition(b"\n")
                                if line.strip() == b"READY":
                                    ready_at = time.monotonic()
                                    record["readiness"] = "OBSERVED"
                                if line.startswith(b"BOOT_FAILED"):
                                    record["reason"] = line.decode("ascii", "replace")
                            if len(pending) > 65536:
                                pending = pending[-65536:]
        except KeyboardInterrupt:
            record["reason"] = "operator interrupt"
            forced = True
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                forced = True
            tail = child.stdout.read()
            if tail:
                with (output / "serial.log").open("ab") as log:
                    log.write(tail)
            record.update({"exit_code": child.returncode, "forced_termination": forced,
                           "elapsed_host_seconds": time.monotonic() - start, "image_sha256_after": image_digest(image_fd)})
            record["status"] = "PASS" if ready_at is not None and child.returncode == 0 and not forced else "INCOMPLETE"
            if str(record.get("reason", "")).startswith("BOOT_FAILED") or child.returncode not in (0, -15, -9):
                record["status"] = "FAIL"
            (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
        print(f"\nRun evidence: {output}", file=sys.stderr)
        return 0 if record["status"] == "PASS" else 2


def main():
    p = argparse.ArgumentParser(description=__doc__, epilog="Exit 0: READY then clean QEMU exit. Exit 2: failure, interruption, or incomplete observation.")
    p.add_argument("--image", required=True)
    p.add_argument("--kernel", default="target/riscv64imac-unknown-none-elf/release/kernel")
    p.add_argument("--firmware", default="build/fw_dynamic.bin", help="Built OpenSBI fw_dynamic.bin (default: build/fw_dynamic.bin)")
    p.add_argument("--qemu", default="qemu-system-riscv64")
    p.add_argument("--output", help="New external evidence directory")
    p.add_argument("--run-root", help="Confine a test image to this isolated directory")
    p.add_argument("--timeout", type=float, default=60, help="Host seconds allowed before READY")
    p.add_argument("--run-seconds", type=float, help="Stop after this many post-READY seconds; records forced termination")
    p.add_argument("--icount", action="store_true")
    p.add_argument("--paused", action="store_true", help="Start paused; local Unix GDB socket; readiness clock disabled")
    args = p.parse_args()
    if args.timeout <= 0 or args.run_seconds is not None and args.run_seconds <= 0:
        p.error("timeouts must be positive")
    try:
        return run(args)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        p.exit(2, f"run: {error}\n")


if __name__ == "__main__":
    sys.exit(main())
