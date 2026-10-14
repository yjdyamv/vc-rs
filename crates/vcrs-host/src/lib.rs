//! Windows-side hosting: putting a served volume on a drive letter, and taking it
//! off again.
//!
//! `vcrs-mount` serves a container over iSCSI in-process. This crate is the half
//! that makes Windows see it as a disk: the initiator login, the wait for the disk
//! to arrive, the drive letter, the flush and the logout — plus the background
//! server and the cached elevated agent those steps need, because `iscsicli`
//! carries a `requireAdministrator` manifest and can only be run elevated.
//!
//! The binary is a thin front end over this crate, and so is anything else in the
//! workspace that wants to drive a volume without spawning `vcrs.exe`: everything
//! here is callable in-process (`attach::attach`, `detach::detach`,
//! `serve::spawn`, `status::snapshot`). It is the implementation of the CLI rather
//! than a frozen API yet; the crypto and block-device layers underneath are
//! `vcrs-core` and `vcrs-mount`.

pub mod agent;
pub mod attach;
pub mod detach;
pub mod serve;
pub mod status;
pub mod win32;
