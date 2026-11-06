#!/usr/bin/env python3
"""Install hash-locked Rust/QEMU/OpenSBI inputs inside the build container."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import urllib.request

lock = json.loads(Path("/tmp/toolchain.lock").read_text())
prefix = Path("/opt/kernel-tools")
sources = Path("/opt/tool-sources")
prefix.mkdir(parents=True, exist_ok=True)
sources.mkdir(parents=True, exist_ok=True)


def fetch(url, digest, filename):
    path = sources / filename
    with urllib.request.urlopen(url, timeout=120) as response, path.open("xb") as stream:
        while chunk := response.read(1024 * 1024):
            stream.write(chunk)
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise RuntimeError(f"source checksum mismatch: {filename}")
    return path


def unpack(path):
    with tarfile.open(path) as archive:
        top = archive.getmembers()[0].name.split("/")[0]
        for member in archive:
            # This upstream edk2 X11 convenience link is unrelated to RISC-V QEMU.
            if member.name.endswith("EmulatorPkg/Unix/Host/X11IncludeHack") and member.issym() and member.linkname == "/opt/X11/include":
                continue
            archive.extract(member, sources, filter="data")
    return sources / top


def execute(args, cwd=None):
    subprocess.run([str(a) for a in args], cwd=cwd, check=True)


host = {"aarch64": "aarch64-unknown-linux-gnu", "x86_64": "x86_64-unknown-linux-gnu"}.get(platform.machine())
if host is None:
    raise RuntimeError("reference container supports only Linux amd64 or arm64")
for name in ("rustc", "cargo", "rust-std", "rustfmt-preview", "clippy-preview"):
    component = lock["rust"]["components"][name][host]
    source = unpack(fetch(component["url"], component["sha256"], name + ".tar.xz"))
    execute(["sh", source / "install.sh", "--prefix=" + str(prefix / "rust"), "--disable-ldconfig"])
component = lock["rust"]["components"]["rust-std"]["riscv64imac-unknown-none-elf"]
source = unpack(fetch(component["url"], component["sha256"], "riscv-std.tar.xz"))
execute(["sh", source / "install.sh", "--prefix=" + str(prefix / "rust"), "--disable-ldconfig"])
qemu = unpack(fetch(lock["qemu"]["source_url"], lock["qemu"]["source_sha256"], "qemu.tar.xz"))
execute([qemu / "configure", "--prefix=" + str(prefix / "qemu"), "--target-list=riscv64-softmmu",
         "--disable-docs", "--disable-gtk", "--disable-sdl", "--disable-vnc", "--disable-spice",
         "--disable-slirp", "--disable-tools", "--disable-user", "--disable-capstone", "--disable-werror",
         "--python=/opt/python/bin/python"], qemu)
execute(["ninja", "-C", qemu / "build", "-j4", "install"])
unpack(fetch(lock["opensbi"]["source_url"], lock["opensbi"]["source_sha256"], "opensbi.tar.gz"))
execute(["sh", "-c", "dpkg-query -W -f='${binary:Package}\t${Version}\n' > /opt/kernel-tools/debian-packages.lock"])
