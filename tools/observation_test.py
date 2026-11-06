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


def validate_records(serial,run_id,boot_id):
    records=trusted_records(serial)
    if len(records)<5:raise ValueError("missing observer protocol")
    for seq,row in enumerate(records,1):
        expected=dict(schema=1,run_id=run_id,boot_id=boot_id,case_id="observation-boundaries",sequence=seq)
        if any(row.get(k)!=v for k,v in expected.items()):raise ValueError("identity/order mismatch")
    if records[0].get("event")!="start" or records[-1].get("event")!="result" or records[-1].get("result")!="PASS":raise ValueError("missing terminalPASS")
    summary=records[1];rows=records[2:-2];overflow=records[-2]
    if summary.get("lost")!=0 or summary.get("count")!=len(rows):raise ValueError("ordinary trace missing/lost")
    if overflow.get("event")!="overflow" or overflow.get("retained")!=8192 or overflow.get("lost",0)<1809 or overflow.get("first")!=overflow['lost']+1 or overflow.get("last")!=overflow['lost']+8192:raise ValueError("trace overflow accounting mismatch")
    analyze(rows)
    return records


def analyze(rows):
    ready=set();blocked={};active=False;ended=False;timers=0;start=None;stop=None;dispatch_after=None;peer=None
    for ordinal,row in enumerate(rows,1):
        if row.get("ordinal")!=ordinal:raise ValueError("trace ordinal mismatch")
        k=row['kind'];obj=row['object'];detail=row['detail']
        if k==30 and detail==40:
            if active or start is not None:raise ValueError("duplicate S-mode window")
            peers=ready-{257}
            if len(peers)!=1:raise ValueError("required peer not runnable at supervisor window")
            peer=next(iter(peers));active=True;start=row['ticks']
        elif k==37:
            if not active:raise ValueError("end without supervisor window")
            active=False;ended=True;stop=row['ticks']
        elif active:
            if k!=36 or detail!=0:raise ValueError("S-mode timer scheduled or lost supervisor origin")
            timers+=1
        if k==1:
            if obj in ready:raise ValueError("duplicate ready")
            ready.add(obj)
        elif k==2:
            if obj not in ready:raise ValueError("dispatch without queue entry")
            ready.remove(obj)
            if ended and dispatch_after is None:dispatch_after=obj
        elif k==3:
            if obj in blocked:raise ValueError("double block")
            blocked[obj]=detail
        elif k==4:
            if blocked.pop(obj,None)!=detail:raise ValueError("unregistered wake")
    if timers<8 or active or start is None or stop<=start or dispatch_after!=peer:raise ValueError("timer/deferred dispatch not observed")
    if ready or blocked:raise ValueError("process ownership leaked")
    return dict(supervisor_timer_interrupts=timers,window_ticks=stop-start,first_deferred_dispatch=peer)


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
              "limitations": ["Private init-only 12ms S-mode observer changes workload duration; release has no test control.", "Overflow test deliberately fills the trace ring; ordinary journey independently requires no lost records."]}
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
        env.update(CARGO_TARGET_DIR=str(output / "kernel-target"), KERNEL_INIT_ELF=str(programs / "observer-init"))
        kernel_command = [args.cargo, "build", "--locked", "--release", "-p", "kernel", "--features", "instrumented", "--target", "riscv64imac-unknown-none-elf"]
        build("build-kernel", kernel_command, root, output, env)
        kernel = output / "kernel-target/riscv64imac-unknown-none-elf/release/kernel"
        report["static_elf"] = {"kernel": check_elf(kernel, kernel=True), "init": check_elf(programs / "observer-init"), "observer-worker": check_elf(programs / "observer-worker")}
        report["build"] = {"commands": [user_command, kernel_command], "kernel_sha256": sha256(kernel),
                           "init_sha256": sha256(programs / "observer-init"), "selftest_sha256": sha256(programs / "selftest"),
                           "fault_sha256": sha256(programs / "fault"), "firmware_sha256": sha256(firmware)}
        image = output / "guest-test.img"
        mkfs.create(image, uuid.UUID(args.run_id).bytes, [("/"+name, programs/name) for name in ("observer-worker",)])
        report["image_sha256_before"] = sha256(image)
        guest = Guest(qemu["path"], kernel, firmware, image, output / "boot", start_paused=True, icount=True)
        guest.expect(rb"(?:^|\n)READY\r?\n")
        guest.wait_for_shutdown(60)
        serial = bytes(guest.data)
        guest = None
        report["records"] = validate_records(serial, args.run_id, args.boot_id)
        report["supervisor_timer"] = analyze(report["records"][2:-2])
        report["overflow"] = report["records"][-2]
        checked = fsck.inspect(image)
        if checked["needs_replay"]:
            raise AssertionError("clean shutdown left an active journal")
        if {f["name"] for f in checked["files"]} != {"/observer-worker"}:
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
            (output / "observation-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key:value for key,value in report.items() if key != "records"}, indent=2))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
