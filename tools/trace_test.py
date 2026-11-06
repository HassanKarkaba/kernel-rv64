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
from doctor import probe, sha256
from check_elf import check as check_elf
from protocol import trusted_records
from smoke import Guest


def validate_records(serial, run_id, boot_id):
    records=trusted_records(serial)
    if len(records)<4:raise ValueError("missing trace protocol")
    for seq,record in enumerate(records,1):
        expected=dict(schema=1,run_id=run_id,boot_id=boot_id,case_id="boundary-trace",sequence=seq)
        if any(record.get(k)!=v for k,v in expected.items()):raise ValueError("trace identity/schema/sequence")
    if records[0].get("event")!="start" or records[-1].get("event")!="result" or records[-1].get("result")!="PASS":raise ValueError("missing successful terminal result")
    summary=records[1]
    rows=records[2:-1]
    if summary.get("event")!="summary" or summary.get("trace_schema")!=1 or summary.get("lost")!=0 or summary.get("count")!=len(rows):raise ValueError("trace loss/count/schema")
    analyze(rows)
    return records


def analyze(rows):
    ready=set();blocked={};outstanding=None;phases={};seen=set();previous=0;reasons=set()
    for ordinal,row in enumerate(rows,1):
        if row.get("event")!="trace" or row.get("ordinal")!=ordinal or row.get("ticks",-1)<previous:raise ValueError("trace order")
        previous=row["ticks"];kind=row["kind"];obj=row["object"];detail=row["detail"];seen.add(kind)
        if kind==1:
            if obj in ready:raise ValueError("duplicate READY entry")
            ready.add(obj)
        elif kind==2:
            if obj not in ready:raise ValueError("dispatch without READY")
            ready.remove(obj)
        elif kind==3:
            if obj in blocked:raise ValueError("duplicate block")
            blocked[obj]=detail;reasons.add(detail)
        elif kind==4:
            if blocked.pop(obj,None)!=detail:raise ValueError("wake without matching registered waiter")
        elif kind==7:
            if outstanding is not None:raise ValueError("overlapping queue ownership")
            outstanding=obj
        elif kind==8:
            if outstanding!=obj:raise ValueError("completion without matching submission")
            outstanding=None
        elif 100<=kind<=109:phases.setdefault(obj,[]).append(kind)
    if not set(range(1,10)).issubset(seen):raise ValueError("missing event family")
    if outstanding is not None or blocked or ready:raise ValueError("leaked terminal ownership")
    if not phases or any(v!=list(range(100,110)) for v in phases.values()):raise ValueError("incomplete journal phase sequence")
    if 6 not in reasons or not any(0x100<=r<0x140 for r in reasons) or 4 not in reasons:raise ValueError("missing child/pipe/I/O blocking journey")


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
              "scope": "Bounded scheduler, pipe/child/I/O and journal trace with independent state validation",
              "instrumentation": "Private init-only KTEST call and escaped user console output",
              "limitations": ["This journey observes real blocking/wakeup; it does not force every possible interleaving.", "Replay traces require a separate interrupted recovery run."]}
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
        env.update(CARGO_TARGET_DIR=str(output / "kernel-target"), KERNEL_INIT_ELF=str(programs / "trace-init"))
        kernel_command = [args.cargo, "build", "--locked", "--release", "-p", "kernel", "--features", "instrumented", "--target", "riscv64imac-unknown-none-elf"]
        build("build-kernel", kernel_command, root, output, env)
        kernel = output / "kernel-target/riscv64imac-unknown-none-elf/release/kernel"
        report["static_elf"] = {"kernel": check_elf(kernel, kernel=True), "init": check_elf(programs / "trace-init"), "fault-probe": check_elf(programs / "fault-probe")}
        report["build"] = {"commands": [user_command, kernel_command], "kernel_sha256": sha256(kernel),
                           "init_sha256": sha256(programs / "trace-init"), "selftest_sha256": sha256(programs / "selftest"),
                           "fault_sha256": sha256(programs / "fault"), "firmware_sha256": sha256(firmware)}
        image = output / "guest-test.img"
        mkfs.create(image, uuid.UUID(args.run_id).bytes, [("/"+name, programs/name) for name in ("fault-probe",)])
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
        if {f["name"] for f in checked["files"]} != {"/fault-probe"}:
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
            (output / "trace-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key:value for key,value in report.items() if key != "records"}, indent=2))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
