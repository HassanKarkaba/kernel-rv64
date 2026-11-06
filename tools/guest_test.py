#!/usr/bin/env python3
"""Build and run the immutable instrumented syscall-test supervisor."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid
import fsck
import mkfs
from accept import source_identity
from check_elf import check as check_elf
from doctor import probe, sha256
from protocol import trusted_records
from smoke import Guest


def validate_records(serial, run_id, boot_id):
    records = trusted_records(serial)
    if len(records) != 2:
        raise ValueError(f"expected two trusted KTEST records, received {len(records)}")
    for sequence, record in enumerate(records, 1):
        expected = {"schema": 1, "run_id": run_id, "boot_id": boot_id,
                    "case_id": "guest-selftest", "sequence": sequence}
        if any(record.get(key) != value for key, value in expected.items()):
            raise ValueError("KTEST identity, schema or sequence mismatch")
    if records[0].get("event") != "start" or "result" in records[0]:
        raise ValueError("invalid start phase")
    terminal = records[1]
    if terminal.get("event") != "result" or terminal.get("result") != "PASS":
        raise ValueError("guest selftest did not report terminal PASS")
    if terminal.get("child_kind") != 0 or terminal.get("child_code") != 0:
        raise ValueError("trusted supervisor did not observe successful child exit")
    return records


def build(label, command, root, output, env):
    with (output / (label + ".log")).open("xb") as log:
        result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed with exit {result.returncode}; see its log")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--qemu", default="qemu-system-riscv64")
    p.add_argument("--firmware", default="build/fw_dynamic.bin", type=Path)
    p.add_argument("--cargo", default="cargo")
    p.add_argument("--run-id", default=uuid.uuid4().hex)
    p.add_argument("--boot-id", default=uuid.uuid4().hex)
    args = p.parse_args()
    if not all(re.fullmatch(r"[0-9a-f]{32}", x) for x in [args.run_id, args.boot_id]):
        p.error("run-id and boot-id must each be 32 lowercase hexadecimal characters")
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.is_relative_to(root):
        p.error("guest-test evidence must be outside the source tree")
    report = {"schema": 1, "run_id": args.run_id, "boot_id": args.boot_id,
              "created_utc": datetime.now(timezone.utc).isoformat(), "status": "INCOMPLETE",
              "scope": "Instrumented guest syscall boundary and immutable supervisor case",
              "instrumentation": "Private init-only KTEST call and escaped user console output",
              "limitations": ["Two supervised programs cover syscall and protection/resource boundaries; see selftest and boundaries sources", "Not all AC-02 through AC-22 families", "No scheduler measurement acceptance"]}
    created = False
    guest = None
    try:
        output.mkdir(parents=True, exist_ok=False)
        created = True
        report["source_identity"] = source_identity(root)
        qemu = probe("qemu-system-riscv64", args.qemu)
        report["qemu"] = qemu
        if qemu["status"] != "MATCH":
            raise RuntimeError("QEMU 11.1.3 required")
        firmware = args.firmware.resolve(strict=True)
        env = os.environ.copy()
        env.update(KERNEL_TEST_RUN_ID=args.run_id, KERNEL_TEST_BOOT_ID=args.boot_id,
                   CARGO_HOME=str(output / "cargo-home"), CARGO_TARGET_DIR=str(output / "user-target"),
                   SOURCE_DATE_EPOCH="1793923200")
        user_command = [args.cargo, "build", "--locked", "--release", "-p", "user-programs", "--target", "riscv64imac-unknown-none-elf"]
        build("build-user", user_command, root, output, env)
        programs = output / "user-target/riscv64imac-unknown-none-elf/release"
        env.update(CARGO_TARGET_DIR=str(output / "kernel-target"), KERNEL_INIT_ELF=str(programs / "test-init"))
        kernel_command = [args.cargo, "build", "--locked", "--release", "-p", "kernel", "--features", "instrumented", "--target", "riscv64imac-unknown-none-elf"]
        build("build-kernel", kernel_command, root, output, env)
        kernel = output / "kernel-target/riscv64imac-unknown-none-elf/release/kernel"
        report["static_elf"] = {"kernel": check_elf(kernel, kernel=True),
                                **{name: check_elf(programs / name) for name in ("test-init", "selftest", "fault", "boundaries", "fault-probe")}}
        report["build"] = {"commands": [user_command, kernel_command], "kernel_sha256": sha256(kernel),
                           "init_sha256": sha256(programs / "test-init"), "selftest_sha256": sha256(programs / "selftest"),
                           "fault_sha256": sha256(programs / "fault"), "boundaries_sha256": sha256(programs / "boundaries"), "fault_probe_sha256": sha256(programs / "fault-probe"), "firmware_sha256": sha256(firmware)}
        image = output / "guest-test.img"
        mkfs.create(image, uuid.UUID(args.run_id).bytes, [("/"+name, programs/name) for name in ("selftest","fault","boundaries","fault-probe")])
        report["image_sha256_before"] = sha256(image)
        guest = Guest(qemu["path"], kernel, firmware, image, output / "boot", start_paused=True)
        guest.expect(rb"(?:^|\n)READY\r?\n")
        guest.wait_for_shutdown(60)
        serial = bytes(guest.data)
        guest = None
        report["records"] = validate_records(serial, args.run_id, args.boot_id)
        checked = fsck.inspect(image)
        if checked["needs_replay"]:
            raise AssertionError("clean shutdown left an active journal")
        if {f["name"] for f in checked["files"]} != {"/selftest", "/fault", "/boundaries", "/fault-probe"}:
            raise AssertionError("selftest did not restore its temporary namespace")
        (output / "fsck.json").write_text(json.dumps(checked, indent=2) + "\n")
        report.update(image_sha256_after=sha256(image), source_unchanged=source_identity(root) == report["source_identity"])
        if not report["source_unchanged"]:
            raise RuntimeError("source changed during the case; whole-candidate evidence is stale")
        report["status"] = "PASS"
    except Exception as error:
        report.update(status="INCOMPLETE" if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else "FAIL", reason=str(error))
    finally:
        if guest:
            guest.close()
        if created:
            (output / "guest-test.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
