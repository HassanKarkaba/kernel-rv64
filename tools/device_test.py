#!/usr/bin/env python3
"""Test instrumented completion observations over real VirtIO requests.

Substitution happens after real DMA completion for malformed/status cases.
Delay/reset cases change observations, not DMA. Release builds omit the hook.
"""
import argparse
import json
import os
from pathlib import Path
import uuid
from doctor import probe, sha256
from check_elf import check as check_elf
from guest_test import build
from accept import source_identity
from protocol import trusted_records
from smoke import Guest
import mkfs


class ExpectedFatalGuest(Guest):
    def pump(self, timeout):
        try:
            super().pump(timeout)
        except RuntimeError:
            marker=self.data.find(b"BOOT_FAILED")
            if marker<0 or b"KERNEL_PANIC" in self.data:raise
            line=self.data[marker:].split(b"\n",1)
            if len(line)==1:return  # serial reads may split the fatal line
            if b"BOOT_FAILED phase=kernel reason=DMA_RESET_TIMEOUT" not in line[0]:raise


def one(args, root, output, mode):
    output.mkdir()
    run, boot = uuid.uuid4().hex, uuid.uuid4().hex
    env = os.environ.copy()
    env.update(KERNEL_TEST_RUN_ID=run, KERNEL_TEST_BOOT_ID=boot, KERNEL_DEVICE_FAULT=str(mode),
               CARGO_HOME=str(output / "cargo-home"), CARGO_TARGET_DIR=str(output / "target"),
               SOURCE_DATE_EPOCH="1793923200")
    common = [args.cargo, "build", "--locked", "--release", "--target", "riscv64imac-unknown-none-elf"]
    build("build-user", common + ["-p", "user-programs"], root, output, env)
    programs = output / "target/riscv64imac-unknown-none-elf/release"
    env["KERNEL_INIT_ELF"] = str(programs / "device-test-init")
    build("build-kernel", common + ["-p", "kernel", "--features", "instrumented"], root, output, env)
    payload = output / "payload"
    payload.write_bytes(b"P" * 4096)
    image = output / "disk.img"
    mkfs.create(image, uuid.UUID(run).bytes, [("/payload", payload), ("/fault-probe", programs / "fault-probe")])
    before = sha256(image)
    kernel = programs / "kernel"
    checked = {"kernel": check_elf(kernel, kernel=True), "init": check_elf(programs / "device-test-init")}
    guest = (ExpectedFatalGuest if mode == 7 else Guest)(args.qemu, kernel, args.firmware, image, output / "guest", start_paused=True)
    try:
        guest.expect(rb"(?:^|\n)READY\r?\n")
        guest.wait_for_shutdown(30)
        serial = bytes(guest.data)
        records = trusted_records(serial)
        if len(records) != (1 if mode == 7 else 2):
            raise AssertionError("unexpected trusted record count")
        for sequence, record in enumerate(records, 1):
            expected = dict(schema=1, run_id=run, boot_id=boot, case_id="device-fault", sequence=sequence)
            if any(record.get(key) != value for key, value in expected.items()):
                raise AssertionError("record identity/schema mismatch")
        if records[0].get("event") != "start":
            raise AssertionError("missing trusted start")
        if mode == 7:
            if b'DMA_BUFFERS_RETAINED' not in serial or b'DMA_RESET_TIMEOUT' not in serial:
                raise AssertionError("failed reset did not retain DMA buffers and stop")
        else:
            if records[1].get("event") != "result" or records[1].get("result") != "PASS":
                raise AssertionError("failure containment assertions failed")
            if b'RESET_CONFIRMED' not in serial or b'SHUTDOWN_UNCERTAIN' not in serial:
                raise AssertionError("reset/shutdown state missing")
        if b'DEVICE_FAILED' not in serial or b'SHUTDOWN_CLEAN' in serial or sha256(image) != before:
            raise AssertionError("storage failure or persistence contract failed")
        return dict(mode=mode,status="PASS",static_elf=checked,kernel_sha256=sha256(kernel),init_sha256=sha256(programs / "device-test-init"),records=records)
    finally:
        guest.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--qemu",default="qemu-system-riscv64")
    p.add_argument("--firmware",type=Path,default=Path("build/fw_dynamic.bin"))
    p.add_argument("--cargo",default="cargo")
    args=p.parse_args();root=Path(__file__).resolve().parents[1];output=args.output.resolve()
    if output.is_relative_to(root):p.error("evidence must be outside source")
    report=dict(schema=1,status="INCOMPLETE",cases=[],scope="Instrumented completion-observer substitution over real VirtIO requests",limitations=["No physically malicious device or late-DMA overwrite is simulated.","This instrumented candidate is distinct from the release candidate."])
    made=False
    try:
        output.mkdir(parents=True,exist_ok=False);made=True
        report["source_identity"]=source_identity(root)
        report["qemu"]=probe("qemu-system-riscv64",args.qemu)
        if report["qemu"]["status"]!="MATCH":raise RuntimeError("QEMU 11.1.3 required")
        args.qemu=report["qemu"]["path"];args.firmware=args.firmware.resolve(strict=True)
        report["firmware_sha256"]=sha256(args.firmware)
        for mode in range(1,8):
            report["cases"].append(one(args,root,output / f"mode-{mode}",mode))
            print(json.dumps(report["cases"][-1]),flush=True)
        report["source_unchanged"]=source_identity(root)==report["source_identity"]
        report["status"]="PASS" if report["source_unchanged"] else "INCOMPLETE"
    except Exception as error:
        report.update(status="INCOMPLETE" if isinstance(error,TimeoutError) else "FAIL",reason=str(error))
    finally:
        if made:(output / "device-report.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2));return 0 if report["status"]=="PASS" else 2


if __name__=="__main__":raise SystemExit(main())
