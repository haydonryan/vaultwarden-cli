//! vaultwarden-cli library
//!
//! This library provides the core functionality for the vaultwarden-cli tool.
#![allow(
    clippy::pedantic,
    clippy::nursery,
    clippy::assigning_clones,
    clippy::cast_possible_wrap,
    clippy::missing_errors_doc,
    clippy::unreadable_literal
)]

pub mod api;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod models;
