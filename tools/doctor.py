#!/usr/bin/env python3
"""Record actual tool identities; a version selection is not qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

PINNED = {"rustc": "1.99.1", "cargo": "1.99.1", "qemu-system-riscv64": "11.1.3"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def probe(name, executable=None):
    path = shutil.which(executable or name)
    if not path:
        return {"status": "MISSING", "expected": PINNED.get(name)}
    args = [path, "--version"]
    if name == "rustc":
        args.append("--verbose")
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        version = result.stdout.strip()
        good = result.returncode == 0 and PINNED.get(name, "") in version.splitlines()[0]
        return {"path": str(Path(path).resolve()), "sha256": sha256(path),
                "version": version, "status": "MATCH" if good else "MISMATCH",
                "expected": PINNED.get(name), "exit_code": result.returncode}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"status": "ERROR", "error": str(error)}


def inspect(qemu=None, firmware=None):
    report = {"schema": 1, "host": {"system": platform.system(),
              "release": platform.release(), "machine": platform.machine()},
              "python": sys.version, "tools": {name: probe(name, qemu if name.startswith("qemu") else None)
              for name in PINNED}, "device_qualification": "NOT RUN", "firmware_probe": "NOT RUN",
              "reference_container": "NOT QUALIFIED"}
    if firmware:
        path = Path(firmware).resolve(strict=True)
        report["firmware"] = {"path": str(path), "sha256": sha256(path), "size": path.stat().st_size}
    if report["tools"]["qemu-system-riscv64"]["status"] == "MATCH":
        executable = report["tools"]["qemu-system-riscv64"]["path"]
        options = subprocess.run([executable, "-machine", "virt,help"], capture_output=True, text=True, timeout=15)
        device = subprocess.run([executable, "-device", "virtio-blk-device,help"], capture_output=True, text=True, timeout=15)
        report["qemu_options"] = {"machine": options.stdout + options.stderr,
                                  "device": device.stdout + device.stderr,
                                  "status": "MATCH" if options.returncode == device.returncode == 0
                                  and "aia" in options.stdout + options.stderr else "MISMATCH"}
    report["prerequisites"] = "AVAILABLE" if all(t["status"] == "MATCH" for t in report["tools"].values()) else "MISSING"
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--qemu", help="Explicit QEMU executable")
    p.add_argument("--firmware", help="Explicit OpenSBI fw_dynamic.bin to identify")
    p.add_argument("--output", type=Path, help="Exclusively create a JSON identity report")
    args = p.parse_args()
    try:
        report = inspect(args.qemu, args.firmware)
        text = json.dumps(report, indent=2) + "\n"
        if args.output:
            with args.output.open("x") as f:
                f.write(text)
        print(text, end="")
        return 0 if report["prerequisites"] == "AVAILABLE" else 2
    except (OSError, subprocess.TimeoutExpired) as error:
        p.exit(2, f"doctor: {error}\n")


if __name__ == "__main__":
    sys.exit(main())
