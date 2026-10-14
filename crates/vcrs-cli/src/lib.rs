//! The parts of `vcrs` that another crate can call.
//!
//! The binary is a thin front end over these modules. Everything that turns a
//! container into a drive letter on Windows lives here — the iSCSI attach and
//! detach, the background server, the cached elevated agent and the raw Win32
//! calls behind them — so a GUI inside this workspace can drive a volume without
//! spawning `vcrs.exe` and scraping its output.
//!
//! What is exposed is the *implementation* of the CLI: the `pub(crate)` items
//! were promoted to `pub` so the binary and any other crate share one copy, and
//! they are not a frozen API yet. Anything that wants a stable surface should
//! call [`attach`]/[`detach`] (the orchestration) or the `vcrs-core` /
//! `vcrs-mount` crates directly (the crypto and block-device layers).

pub mod agent;
pub mod attach;
pub mod detach;
pub mod prompt;
pub mod serve;
pub mod status;
pub mod win32;
