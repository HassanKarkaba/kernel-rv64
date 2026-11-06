#!/usr/bin/env python3
"""Exercise trusted UART framing, real host backpressure and RX overflow in QEMU.

Negative cases persist a result through the independently checked filesystem,
so a broken/suppressed serial channel cannot manufacture their success.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

import fsck
import mkfs
from accept import source_identity
from check_elf import check as check_elf
from doctor import probe, sha256
from guest_test import build
from protocol import trusted_records
from smoke import Guest

EXPECTED = {"short": b"SHORT_OK", "timeout": b"TIMEOUT_STICKY",
            "oversize": b"OVERSIZE_STICKY", "pointer": b"POINTER_STICKY",
            "overflow": b"OVERFLOW_4096"}


def observed_records(serial, mode):
    if mode != "timeout":
        return trusted_records(serial), 0
    # The timeout deliberately aborts one record. Preserve that raw evidence;
    # no malformed line or fragment can become an affirmative trusted record.
    records, rejected = [], 0
    for line in serial.splitlines(keepends=True):
        if not line.startswith(b"KTEST "):
            continue
        try:
            records.extend(trusted_records(line))
        except (ValueError, UnicodeError):
            rejected += 1
    if rejected > 1:
        raise ValueError("timeout corrupted more than its single interrupted record")
    return records, rejected


def run_case(args, root, output, mode, qemu, firmware):
    output.mkdir()
    run_id, boot_id = uuid.uuid4().hex, uuid.uuid4().hex
    report = {"schema": 1, "case": mode, "status": "INCOMPLETE", "run_id": run_id,
              "boot_id": boot_id, "source_identity": source_identity(root)}
    guest = None
    try:
        env = os.environ.copy()
        env.update(KERNEL_UART_CASE=mode, KERNEL_TEST_RUN_ID=run_id,
                   KERNEL_TEST_BOOT_ID=boot_id, CARGO_HOME=str(output / "cargo-home"),
                   CARGO_TARGET_DIR=str(output / "user-target"), SOURCE_DATE_EPOCH="1793923200")
        user_command = [args.cargo, "build", "--locked", "--release", "-p", "user-programs",
                        "--bin", "uart-test-init", "--target", "riscv64imac-unknown-none-elf"]
        build("build-user", user_command, root, output, env)
        init = output / "user-target/riscv64imac-unknown-none-elf/release/uart-test-init"
        env.update(CARGO_TARGET_DIR=str(output / "kernel-target"), KERNEL_INIT_ELF=str(init))
        kernel_command = [args.cargo, "build", "--locked", "--release", "-p", "kernel", "--features",
                          "instrumented", "--target", "riscv64imac-unknown-none-elf"]
        build("build-kernel", kernel_command, root, output, env)
        kernel = output / "kernel-target/riscv64imac-unknown-none-elf/release/kernel"
        report["static_elf"] = {"kernel": check_elf(kernel, kernel=True), "init": check_elf(init)}
        report["build"] = {"commands": [user_command, kernel_command], "kernel_sha256": sha256(kernel),
                           "init_sha256": sha256(init), "firmware_sha256": sha256(firmware)}
        image = output / "uart-test.img"
        mkfs.create(image, uuid.UUID(run_id).bytes, [])
        report["image_sha256_before"] = sha256(image)
        guest = Guest(qemu["path"], kernel, firmware, image, output / "boot", start_paused=True)
        guest.expect(rb"(?:^|\n)READY\r?\n")
        guest.expect(rb"UART_PROBE_READY")
        guest.child.stdin.write(b"s")
        guest.child.stdin.flush()
        pause = {"short": 0.25, "timeout": 3.0}.get(mode, 0)
        if pause:
            started = time.monotonic()
            # Deliberately do not pump either endpoint while the immutable guest
            # emits ~900 KiB into its actual bounded host serial pipe.
            time.sleep(pause)
            report["reader_paused_seconds"] = time.monotonic() - started
        if mode == "overflow":
            guest.expect(rb"UART_INPUT_READY")
            guest.child.stdin.write(b"X" * 8192)
            guest.child.stdin.flush()
            report["input_bytes"] = 8192
            report["expected_rx_capacity"] = 4096
            report["expected_rx_lost"] = 4096
        guest.wait_for_shutdown(60)
        serial = bytes(guest.data)
        report["qmp"] = guest.qmp_events
        guest = None
        records, rejected = observed_records(serial, mode)
        report.update(records=records, rejected_interrupted_records=rejected,
                      serial_bytes=len(serial), serial_sha256=hashlib.sha256(serial).hexdigest())
        for sequence, record in enumerate(records, 1):
            identity = {"schema": 1, "run_id": run_id, "boot_id": boot_id,
                        "case_id": "uart-" + mode, "sequence": sequence}
            if any(record.get(k) != v for k, v in identity.items()):
                raise AssertionError("trusted identity or sequence mismatch")
        if not records or records[0].get("event") != "start":
            raise AssertionError("missing trusted start")
        if mode in ("short", "overflow"):
            count = 2002 if mode == "short" else 2
            if len(records) != count or records[-1].get("event") != "result" or records[-1].get("result") != "PASS":
                raise AssertionError("missing complete positive result or bounded record count")
            if mode == "short" and any(r.get("event") != "data" for r in records[1:-1]):
                raise AssertionError("unexpected data record phase")
        elif any(r.get("event") == "result" or r.get("result") == "PASS" for r in records):
            raise AssertionError("sticky failure allowed a later trusted terminal result")
        checked = fsck.inspect(image)
        (output / "fsck.json").write_text(json.dumps(checked, indent=2) + "\n")
        files = checked["files"]
        expected = EXPECTED[mode]
        if (checked["needs_replay"] or len(files) != 1 or files[0]["name"] != "/uart-result"
                or files[0]["size"] != len(expected) or files[0]["sha256"] != hashlib.sha256(expected).hexdigest()):
            raise AssertionError("independent disk result does not confirm the private syscall assertions")
        report.update(status="PASS", durable_expected=expected.decode(), image_sha256_after=sha256(image),
                      source_unchanged=source_identity(root) == report["source_identity"])
    except Exception as error:
        report.update(status="INCOMPLETE" if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else "FAIL", reason=str(error))
    finally:
        if guest:
            guest.close()
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--qemu", default="qemu-system-riscv64")
    p.add_argument("--firmware", default="build/fw_dynamic.bin", type=Path)
    p.add_argument("--cargo", default="cargo")
    p.add_argument("--case", action="append", choices=tuple(EXPECTED))
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.is_relative_to(root):
        p.error("evidence must be outside the source tree")
    output.mkdir(parents=True, exist_ok=False)
    qemu = probe("qemu-system-riscv64", args.qemu)
    if qemu["status"] != "MATCH":
        raise RuntimeError("QEMU 11.1.3 is required")
    firmware = args.firmware.resolve(strict=True)
    report = {"schema": 1, "status": "INCOMPLETE", "qemu": qemu,
              "scope": "Actual trusted UART transport and RX overflow under specified guest workloads",
              "source_identity": source_identity(root), "cases": []}
    for mode in args.case or EXPECTED:
        result = run_case(args, root, output / mode, mode, qemu, firmware)
        report["cases"].append({"case": mode, "status": result["status"], "report": str(output / mode / "result.json")})
        (output / "uart-report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(mode + ": " + result["status"], flush=True)
    report["source_unchanged"] = source_identity(root) == report["source_identity"]
    report["status"] = "PASS" if all(c["status"] == "PASS" for c in report["cases"]) else "FAIL"
    report["applicability"] = "whole candidate" if report["source_unchanged"] else "identified binaries only; candidate changed during run"
    (output / "uart-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
