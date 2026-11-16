#!/bin/sh
# Run golang_loader_assist.py headlessly in IDA against a binary and print a summary.
#
# usage: tests/run_ida.sh [binary] [path/to/idat64]
#   binary   defaults to hello-go/1.8.1/hello-normal
#   idat64   defaults to $IDAT, then idat64 on PATH
#
# Compare the "Found and ..." summary lines before/after a change to catch regressions.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${1:-$ROOT/hello-go/1.8.1/hello-normal}
IDAT=${2:-${IDAT:-idat64}}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp "$BIN" "$WORK/target"

# -B: batch mode; the script quits IDA itself when finished
(cd "$WORK" && timeout "${TIMEOUT:-300}" "$IDAT" -B -c -L"$WORK/ida.log" -S"$ROOT/golang_loader_assist.py" target >/dev/null 2>&1) || true

grep -E "Found and|Traceback|Error:" "$WORK/ida.log" | grep -v "FAILED-RETRY\|error attempting"
echo "pointer-rename errors: $(grep -c 'error attempting to name' "$WORK/ida.log" || true)"
echo "string-create errors:  $(grep -c 'FAILED-RETRY' "$WORK/ida.log" || true)"
