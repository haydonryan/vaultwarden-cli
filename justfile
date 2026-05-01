check:
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery
    cargo audit
    cargo deny check all
    cargo test

test:
    cargo test

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
    cargo release {{args}}

bump version:
    cargo release version {{version}} --execute --no-confirm

install:
    cargo install --path .

run *args:
    cargo run --bin vaultwarden-cli -- {{args}}
