//! The front door of `vcrs` for other crates.
//!
//! The Windows half — attaching a served volume to a drive letter, taking it off
//! again, and the background server and cached elevated agent behind both — lives
//! in the `vcrs-host` crate now. This module keeps the old paths working (the
//! binary and anything else that already depends on `vcrs_cli::attach`-style
//! names) and holds the one piece that is about the command line rather than about
//! Windows: the password prompt.

pub use vcrs_host::{agent, attach, detach, serve, status, win32};

pub mod prompt;
