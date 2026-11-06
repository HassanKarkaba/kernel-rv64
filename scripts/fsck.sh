#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [[ "${1:-}" == --help ]]; then printf '%s\n' 'Usage: scripts/fsck.sh --image PATH'; exit 0; fi
[[ "$#" == 2 && "$1" == --image ]] || { printf '%s\n' 'Usage: scripts/fsck.sh --image PATH' >&2; exit 2; }
exec python3 tools/fsck.py "$2"
