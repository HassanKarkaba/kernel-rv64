#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
IMAGE=''
EMPTY=0
EXTRA=()
while (($#)); do
  case "$1" in
    --image) IMAGE="${2:?--image requires a path}"; shift 2;;
    --empty) EMPTY=1; shift;;
    --uuid) EXTRA+=(--uuid "${2:?--uuid requires a UUID}"); shift 2;;
    --help|-h) printf '%s\n' 'Usage: scripts/mkfs.sh --image NEW.img [--empty] [--uuid UUID]'; exit 0;;
    *) printf '%s\n' "Unknown argument: $1" >&2; exit 2;;
  esac
done
[[ -n "$IMAGE" ]] || { printf '%s\n' '--image is required' >&2; exit 2; }
if [[ "$EMPTY" == 0 ]]; then
  for program in demo3 compute writer fault producer consumer; do
    source="${CARGO_TARGET_DIR:-target}/riscv64imac-unknown-none-elf/release/$program"
    [[ -f "$source" ]] || { printf '%s\n' "Missing $source; run scripts/build.sh first" >&2; exit 2; }
    EXTRA+=(--import "/$program=$source")
  done
fi
exec python3 tools/mkfs.py "$IMAGE" "${EXTRA[@]}"
