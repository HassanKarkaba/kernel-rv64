#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
IMAGE=''
DESTROY=0
EMPTY=0
while (($#)); do
  case "$1" in
    --image) IMAGE="${2:?--image requires a path}"; shift 2;;
    --destroy-existing) DESTROY=1; shift;;
    --empty) EMPTY=1; shift;;
    --help|-h) printf '%s\n' 'Usage: scripts/reset.sh --image EXISTING.img --destroy-existing [--empty]'; exit 0;;
    *) printf '%s\n' "Unknown argument: $1" >&2; exit 2;;
  esac
done
[[ -n "$IMAGE" && "$DESTROY" == 1 ]] || { printf '%s\n' 'An explicit --image and --destroy-existing are required' >&2; exit 2; }
EXTRA=()
if [[ "$EMPTY" == 0 ]]; then
  for program in demo3 compute writer fault producer consumer; do
    source="${CARGO_TARGET_DIR:-target}/riscv64imac-unknown-none-elf/release/$program"
    [[ -f "$source" ]] || { printf '%s\n' "Missing $source; build before reset" >&2; exit 2; }
    EXTRA+=(--import "/$program=$source")
  done
fi
exec python3 tools/image_ops.py reset --image "$IMAGE" --destroy-existing "${EXTRA[@]}"
