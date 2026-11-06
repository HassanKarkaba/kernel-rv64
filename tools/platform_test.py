#!/usr/bin/env python3
"""Boot unsupported QEMU machine/device variants and require explicit refusal."""
import argparse
import json
from pathlib import Path
import shutil
import uuid
import mkfs
import smoke
from doctor import probe,sha256


class Refusal(smoke.Guest):
    def pump(self,timeout):
        try:super().pump(timeout)
        except RuntimeError:
            if b"BOOT_FAILED" not in self.data or b"KERNEL_PANIC" in self.data:raise


def variant(command,name,directory):
    command=command.copy()
    if name=="two-harts":command[command.index("-smp")+1]="2"
    elif name=="small-ram":command[command.index("-m")+1]="128M"
    elif name=="large-ram":command[command.index("-m")+1]="512M"
    elif name=="legacy-virtio":command[command.index("virtio-mmio.force-legacy=false")]="virtio-mmio.force-legacy=true"
    elif name=="missing-block":
        i=command.index("-device");del command[i:i+2]
    elif name=="readonly-block":
        for i,token in enumerate(command):
            if token=="-blockdev":
                value=json.loads(command[i+1]);value["read-only"]=True;command[i+1]=json.dumps(value,separators=(",",":"))
    elif name=="two-blocks":
        command += ["-blockdev",json.dumps(dict(driver="file",filename=str(directory/"second.img"),**{"node-name":"otherfile","locking":"off"})),"-blockdev",'{"driver":"raw","file":"otherfile","node-name":"other"}',"-device","virtio-blk-device,drive=other"]
    else:raise ValueError("unknown platform variant")
    return command


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--qemu",default="qemu-system-riscv64")
    p.add_argument("--kernel",type=Path,default=Path("target/riscv64imac-unknown-none-elf/release/kernel"))
    p.add_argument("--firmware",type=Path,default=Path("build/fw_dynamic.bin"))
    args=p.parse_args();root=Path(__file__).resolve().parents[1];output=args.output.resolve()
    if output.is_relative_to(root):p.error("evidence must be external")
    report=dict(schema=1,status="INCOMPLETE",cases=[]);made=False
    try:
        output.mkdir(parents=True,exist_ok=False);made=True
        qemu=probe("qemu-system-riscv64",args.qemu);report["qemu"]=qemu
        if qemu["status"]!="MATCH":raise ValueError("QEMU 11.1.3 required")
        inputs=output/"inputs";inputs.mkdir();kernel=inputs/"kernel";firmware=inputs/"firmware.bin"
        shutil.copyfile(args.kernel.resolve(strict=True),kernel);shutil.copyfile(args.firmware.resolve(strict=True),firmware)
        report.update(kernel_sha256=sha256(kernel),firmware_sha256=sha256(firmware))
        for name in ["two-harts","small-ram","large-ram","legacy-virtio","missing-block","readonly-block","two-blocks"]:
            directory=output/name;directory.mkdir();image=directory/"disk.img"
            mkfs.create(image,uuid.uuid4().bytes,[]);before=sha256(image)
            if name=="two-blocks":mkfs.create(directory/"second.img",uuid.uuid4().bytes,[])
            original=smoke.command
            try:
                smoke.command=lambda *a,**k:variant(original(*a,**k),name,directory)
                guest=Refusal(qemu["path"],kernel,firmware,image,directory/"guest",start_paused=True,read_only=name=="readonly-block")
            finally:smoke.command=original
            try:
                guest.expect(rb"BOOT_FAILED phase=(kernel|mount) reason=[A-Z_]+\r?\n")
                expected=b"BOOT_ARGUMENTS" if name=="large-ram" else (b"DTB_PLATFORM" if name in ["two-harts","small-ram"] else b"VIRTIO_NEGOTIATION")
                if expected not in guest.data or b"\nREADY" in guest.data:raise AssertionError("wrong refusal phase or READY admitted")
                if expected==b"VIRTIO_NEGOTIATION":
                    guest.expect(rb"Recovery console: status help shutdown\r?\n")
                    guest.shutdown()
                else:guest.wait_for_shutdown(15)
                if sha256(image)!=before:raise AssertionError("unsupported platform modified disk")
                report["cases"].append(dict(name=name,status="PASS",reason=expected.decode(),image_unchanged=True))
                print(json.dumps(report["cases"][-1]),flush=True)
            finally:guest.close()
        report["status"]="PASS"
    except Exception as error:report.update(status="INCOMPLETE" if isinstance(error,TimeoutError) else "FAIL",reason=str(error))
    finally:
        if made:(output/"platform-report.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2));return 0 if report["status"]=="PASS" else 2


if __name__=="__main__":raise SystemExit(main())
