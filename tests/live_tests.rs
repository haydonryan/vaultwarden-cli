//! Live integration test binary.
//!
//! Gated by environment variables — see `live/env.rs` for details.
//! Run via: `./scripts/test-live.sh`
#![allow(clippy::pedantic, clippy::nursery, unused_imports)]

// Shared live test environment (LiveTestEnv + fixture constants).
#[path = "live/env.rs"]
mod live_env;

// Test modules — one file per command group.
#[path = "live/session.rs"]
mod session;

#[path = "live/list.rs"]
mod list;

#[path = "live/get.rs"]
mod get;

#[path = "live/run.rs"]
mod run;

#[path = "live/interpolate.rs"]
mod interpolate;
