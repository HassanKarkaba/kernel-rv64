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
from crash_test import logical


def validate_records(serial,run_id,boot_id):
    records=trusted_records(serial)
    if len(records)<150:raise ValueError("missing mandatory assertion inventory")
    for seq,row in enumerate(records,1):
        expected=dict(schema=1,run_id=run_id,boot_id=boot_id,case_id="abi-matrix",sequence=seq)
        if any(row.get(k)!=v for k,v in expected.items()):raise ValueError("record identity/order")
    if records[0].get("event")!="start" or records[-1].get("event")!="result" or records[-1].get("result")!="PASS" or records[-1].get("error")!=0:raise ValueError("unsuccessful terminal result")
    for row in records[1:-1]:
        if row.get("event")!="assertion" or row.get("result")!="PASS" or row.get("observed")!=row.get("expected"):raise ValueError("failed assertion")
    counts={name:sum(row.get("assertion")==name for row in records) for name in {row.get("assertion") for row in records[1:-1]}}
    for name,n in {"unused-register":24,"pointer-complete-range":60,"pipe-read-no-consume":4,"pipe-write-copy-before-effect":4,"invalid-descriptor-precedence":12,"wrong-rights":4,"wait-full-output":4,"all-owners-restored":1,"pipe-data-authoritative":1,"file-bytes-preserved":1,"file-offset-preserved":1,"rejections-owner-census":1}.items():
        if counts.get(name)!=n:raise ValueError("missing boundary "+name)
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
              "scope": "Detailed actual ecall scalar, pointer, rights and no-effect matrix",
              "instrumentation": "Private init-only KTEST call and escaped user console output",
              "limitations": ["Complements separate resource, ELF, storage-state and concurrency families; does not replace them."]}
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
        env.update(CARGO_TARGET_DIR=str(output / "kernel-target"), KERNEL_INIT_ELF=str(programs / "abi-matrix-init"))
        kernel_command = [args.cargo, "build", "--locked", "--release", "-p", "kernel", "--features", "instrumented", "--target", "riscv64imac-unknown-none-elf"]
        build("build-kernel", kernel_command, root, output, env)
        kernel = output / "kernel-target/riscv64imac-unknown-none-elf/release/kernel"
        report["static_elf"] = {"kernel": check_elf(kernel, kernel=True),
                                **{name: check_elf(programs / name) for name in ("abi-matrix-init", "abi-matrix-worker")}}
        report["build"] = {"commands": [user_command, kernel_command], "kernel_sha256": sha256(kernel),
                           "init_sha256": sha256(programs / "abi-matrix-init"), "selftest_sha256": sha256(programs / "selftest"),
                           "fault_sha256": sha256(programs / "fault"), "boundaries_sha256": sha256(programs / "boundaries"), "fault_probe_sha256": sha256(programs / "fault-probe"), "firmware_sha256": sha256(firmware)}
        image = output / "guest-test.img"
        mkfs.create(image, uuid.UUID(args.run_id).bytes, [("/"+name, programs/name) for name in ("abi-matrix-worker",)])
        report["image_sha256_before"] = sha256(image)
        initial_logical=logical(fsck.inspect(image))
        guest = Guest(qemu["path"], kernel, firmware, image, output / "boot", start_paused=True, icount=True)
        guest.expect(rb"(?:^|\n)READY\r?\n")
        guest.wait_for_shutdown(60)
        serial = bytes(guest.data)
        guest = None
        report["records"] = validate_records(serial, args.run_id, args.boot_id)
        checked = fsck.inspect(image)
        if logical(checked)[1]!=() or checked["sequence"]!=initial_logical[0]+8:
            raise AssertionError("expected seven temporary transactions plus final fixture unlink and empty namespace")
        if checked["needs_replay"]:
            raise AssertionError("clean shutdown left an active journal")
        if {f["name"] for f in checked["files"]} != set():
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
            (output / "abi-matrix-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k:v for k,v in report.items() if k!="records"}, indent=2))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
