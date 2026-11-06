#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
for argument in "$@"; do
  if [[ "$argument" == seeded-history ]]; then
    exec python3 tools/history_test.py "$@"
  fi
  if [[ "$argument" == repeated-recovery ]]; then
    exec python3 tools/recovery_test.py "$@"
  fi
done
exec python3 tools/crash_test.py "$@"
