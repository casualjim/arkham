#!/usr/bin/env bash
# Confirm test:ssh ran a capture backend and recorded every named scheme.
# Usage: covered.sh LOG SCHEME [SCHEME...]
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: covered.sh LOG SCHEME [SCHEME...]" >&2
  exit 2
fi

log=$1
shift

if [ ! -f "$log" ]; then
  echo "no log at $log" >&2
  exit 1
fi

if grep -q 'skip: test:ssh' "$log"; then
  echo "test:ssh skipped; a missing docker daemon is not a pass" >&2
  exit 1
fi

if ! grep -Eq '=== backend .+ passed ===' "$log"; then
  echo "test:ssh log has no passing backend" >&2
  exit 1
fi

root=$(git rev-parse --show-toplevel)
covered="$root/integration/out/covered.json"
if [ ! -f "$covered" ]; then
  echo "missing $covered" >&2
  exit 1
fi

for scheme in "$@"; do
  if ! grep -Fq "\"${scheme}\"" "$covered"; then
    echo "scheme ${scheme} is not in $covered" >&2
    exit 1
  fi
done

echo "backend ran; schemes present in $covered"
