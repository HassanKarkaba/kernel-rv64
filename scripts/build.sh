#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
case "${1:-}" in
  --help|-h) printf '%s\n' 'Usage: scripts/build.sh [--kernel-only]' 'Full build requires OPENSBI_SOURCE and CROSS_COMPILE; optional FW_CC and FW_LD override firmware compiler/linker.' 'The explicit --kernel-only mode builds user programs and kernel without claiming firmware reconstruction.'; exit 0;;
  --kernel-only) KERNEL_ONLY=1;;
  '') KERNEL_ONLY=0;;
  *) printf '%s\n' 'Unknown build argument' >&2; exit 2;;
esac
case "$(rustc --version)" in 'rustc 1.99.1 '*) ;; *) printf '%s\n' 'Rust 1.99.1 is required' >&2; exit 2;; esac
export CARGO_HOME="${CARGO_HOME:-$ROOT/build/cargo-home}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1793923200}"
if [[ -z "${CARGO_ENCODED_RUSTFLAGS+x}" && -z "${RUSTFLAGS+x}" ]]; then
  export CARGO_ENCODED_RUSTFLAGS=$'-C\x1frelocation-model=static\x1f-C\x1fforce-frame-pointers=yes\x1f--remap-path-prefix='"$ROOT=/kernel-rv64"
else
  printf '%s\n' 'Using caller-supplied Rust flags; record them with the build identity.'
fi
mkdir -p build
if [[ "$KERNEL_ONLY" == 0 ]]; then
  : "${OPENSBI_SOURCE:?Set OPENSBI_SOURCE to the retained OpenSBI v1.7 source tree}"
  : "${CROSS_COMPILE:?Set CROSS_COMPILE to the GNU RISC-V executable prefix}"
  mkdir -p build/opensbi
  FW_ARGS=(PLATFORM=generic PLATFORM_RISCV_XLEN=64 PLATFORM_RISCV_ISA=rv64imafdc_zicsr_zifencei PLATFORM_RISCV_ABI=lp64d REPRODUCIBLE=y FW_PAYLOAD=n FW_JUMP=n "CROSS_COMPILE=$CROSS_COMPILE" "O=$ROOT/build/opensbi")
  if [[ -n "${FW_CC:-}" ]]; then FW_ARGS+=("CC=$FW_CC"); fi
  if [[ -n "${FW_LD:-}" ]]; then FW_ARGS+=("LD=$FW_LD"); fi
  if [[ "$(uname -s)" == Darwin ]]; then FW_ARGS+=(READLINK=/usr/bin/readlink); fi
  make -C "$OPENSBI_SOURCE" -j"${BUILD_JOBS:-4}" "${FW_ARGS[@]}"
  cp build/opensbi/platform/generic/firmware/fw_dynamic.bin build/fw_dynamic.bin
fi
cargo build --locked --release -p user-programs --target riscv64imac-unknown-none-elf
export KERNEL_INIT_ELF="$(python3 -c 'import os,pathlib; print((pathlib.Path(os.environ.get("CARGO_TARGET_DIR", "target"))/"riscv64imac-unknown-none-elf/release/init").resolve())')"
cargo build --locked --release -p kernel --target riscv64imac-unknown-none-elf
python3 tools/check_elf.py --kernel "${CARGO_TARGET_DIR:-target}/riscv64imac-unknown-none-elf/release/kernel"
for SOURCE in user/programs/src/bin/*.rs; do
  NAME="$(basename "$SOURCE" .rs)"
  python3 tools/check_elf.py "${CARGO_TARGET_DIR:-target}/riscv64imac-unknown-none-elf/release/$NAME"
done
printf '%s\n' 'Kernel and user program build completed. This command does not establish acceptance.'
