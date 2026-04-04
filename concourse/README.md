# Concourse CI for vaultwarden-cli

This folder contains a Concourse pipeline that mirrors the Rust build/test/release behavior from
`github.com/haydonryan/vaultwarden-cli`.

## What this pipeline does

- Builds a pinned Rust build image (`concourse/Dockerfile`) and publishes it to `ci_image_repository`.
- Runs:
  - `cargo check`
  - `cargo test --workspace` in Stable and Beta modes
  - `coverage` via `cargo tarpaulin` (best-effort, non-blocking)
  - `rustfmt` + `clippy`
  - `cargo audit` + `cargo deny`
  - Release artifact + SBOM generation for release tags matching `vX.Y.Z`

## Setup

1. Edit `/concourse/vars.example.yml` values and save as `/concourse/vars.yml`.
2. Target your Concourse and create/set the pipeline:

```bash
fly -t <target> set-pipeline \
  -p vaultwarden-cli-ci \
  -c concourse/pipeline.yml \
  -l concourse/vars.example.yml
```

3. Unpause and trigger:

```bash
fly -t <target> unpause-pipeline -p vaultwarden-cli-ci
fly -t <target> trigger-job -j vaultwarden-cli-ci/check
```

## Note on parity with GitHub Actions

- `macos` and `windows` release targets from the GitHub Actions workflow are not built in this
  Concourse baseline because those platforms require dedicated platform workers (or a custom setup).
- `PR-only` coverage gating is represented as an always-available best-effort coverage job here.
  If you want strict PR-only behavior, you can wire in a `pull-request` resource.
