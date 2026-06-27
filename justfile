check:
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery
    cargo audit
    cargo deny check all
    cargo test

test:
    cargo test

coverage:
    #!/usr/bin/env bash
    set -euo pipefail
    RUN_ROOT="${RUN_ROOT:-$(mktemp -d /tmp/vaultwarden-cli-tarpaulin.XXXXXX)}"
    mkdir -p "$RUN_ROOT/tmp" "$RUN_ROOT/target" "$RUN_ROOT/out"
    echo "coverage run root: $RUN_ROOT"
    TMPDIR="$RUN_ROOT/tmp" cargo tarpaulin --all-targets --no-fail-fast --target-dir "$RUN_ROOT/target" --output-dir "$RUN_ROOT/out" --out Json Stdout --timeout 120
    test -s "$RUN_ROOT/out/tarpaulin-report.json"
    echo "coverage report: $RUN_ROOT/out/tarpaulin-report.json"

benchmark:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo bench
    ./scripts/benchmark-dhat.sh

pre-commit:
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/scan-staged-secrets.sh
    before_fmt_diff="$(mktemp)"
    after_fmt_diff="$(mktemp)"
    trap 'rm -f "$before_fmt_diff" "$after_fmt_diff"' EXIT
    git diff --name-only -- . >"$before_fmt_diff"
    cargo fmt --all
    git diff --name-only -- . >"$after_fmt_diff"
    if ! cmp -s "$before_fmt_diff" "$after_fmt_diff"; then
      echo "cargo fmt updated files. Review and stage the formatting changes, then commit again." >&2
      exit 1
    fi
    cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery
    cargo audit
    cargo deny check all
    cargo test

release *args:
    git pull --rebase
    just check
    cargo release {{args}}

bump version:
    cargo release version {{version}} --execute --no-confirm

install:
    cargo install --path .

run *args:
    cargo run --bin vaultwarden-cli -- {{args}}
