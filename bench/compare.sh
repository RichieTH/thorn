#!/usr/bin/env bash
# Compares thorn-rs and thorn-go performance against fixtures/
set -euo pipefail

FIXTURES="../fixtures"
RUNS="${RUNS:-10}"

EXT=""
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) EXT=".exe" ;;
esac
RS_BIN="../thorn-rs/target/release/thorn${EXT}"
GO_BIN="../thorn-go/bin/thorn${EXT}"

PYTHON="python3"
if ! command -v python3 >/dev/null 2>&1 || ! python3 -c "" >/dev/null 2>&1; then
  PYTHON="python"
fi

check_binary() {
  if [[ ! -f "$1" ]]; then
    echo "ERROR: Binary not found: $1"
    echo "Build first: cd thorn-rs && cargo build --release"
    exit 1
  fi
}

median_time() {
  local bin="$1"
  local times=()
  for _ in $(seq 1 $RUNS); do
    t=$( { time "$bin" --json "$FIXTURES" > /dev/null; } 2>&1 | grep real | awk '{print $2}')
    times+=("$t")
  done
  printf '%s\n' "${times[@]}" | sort | awk 'NR==int((NR+1)/2)'
}

check_binary "$RS_BIN"
check_binary "$GO_BIN"

echo "=== Thorn Benchmark ($RUNS runs each) ==="
echo ""

RS_SIZE=$(du -sh "$RS_BIN" | cut -f1)
GO_SIZE=$(du -sh "$GO_BIN" | cut -f1)
echo "Binary sizes:"
echo "  thorn-rs: $RS_SIZE"
echo "  thorn-go: $GO_SIZE"
echo ""

echo "Median scan time:"
echo -n "  thorn-rs: "
median_time "$RS_BIN"
echo -n "  thorn-go: "
median_time "$GO_BIN"
echo ""

echo "Finding counts (must match):"
RS_COUNT=$("$RS_BIN" --json "$FIXTURES" | "$PYTHON" -c "import sys,json; d=json.load(sys.stdin); print(d['summary']['total'])")
GO_COUNT=$("$GO_BIN" --json "$FIXTURES" | "$PYTHON" -c "import sys,json; d=json.load(sys.stdin); print(d['summary']['total'])")
echo "  thorn-rs: $RS_COUNT"
echo "  thorn-go: $GO_COUNT"

if [[ "$RS_COUNT" != "$GO_COUNT" ]]; then
  echo ""
  echo "FAIL: Finding counts differ between implementations"
  exit 1
fi

echo ""
echo "PASS: Both implementations agree on $RS_COUNT findings"
