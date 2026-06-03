#!/usr/bin/env bash
set -euo pipefail

BENCH_NAME="vaultwarden_cli_bench"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
DHAT_DIR="$TARGET_DIR/dhat"
DHAT_OUT="$DHAT_DIR/${BENCH_NAME}.dhat"

if ! command -v valgrind >/dev/null 2>&1; then
  echo "DHAT allocation profile skipped: valgrind is not installed or not on PATH." >&2
  echo "Install Valgrind with DHAT support, then rerun: just benchmark" >&2
  exit 1
fi

if ! valgrind --tool=dhat --help >/dev/null 2>&1; then
  echo "DHAT allocation profile skipped: this valgrind build does not support --tool=dhat." >&2
  echo "Install a Valgrind build with DHAT support, then rerun: just benchmark" >&2
  exit 1
fi

mkdir -p "$DHAT_DIR"

cargo bench --bench "$BENCH_NAME" --no-run

bench_bin="$(
  find "$TARGET_DIR/release/deps" \
    -maxdepth 1 \
    -type f \
    -executable \
    -name "${BENCH_NAME}-*" \
    ! -name "*.d" \
    -printf '%T@ %p\n' |
  sort -nr |
  awk 'NR == 1 { print $2 }'
)"

if [[ -z "$bench_bin" ]]; then
  echo "DHAT allocation profile failed: benchmark binary for ${BENCH_NAME} was not found under ${TARGET_DIR}/release/deps." >&2
  exit 1
fi

rm -f "$DHAT_OUT"

echo "DHAT benchmark binary: $bench_bin"
echo "DHAT output path: $DHAT_OUT"

valgrind \
  --tool=dhat \
  --dhat-out-file="$DHAT_OUT" \
  "$bench_bin" --bench --profile-time 1

test -s "$DHAT_OUT"
echo "DHAT output written: $DHAT_OUT"
