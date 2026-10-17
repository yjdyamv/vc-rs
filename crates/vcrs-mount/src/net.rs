//! Portal arithmetic that both halves of a mount need.
//!
//! "Portal" is iSCSI's name for `host:port`. Picking a free one, splitting one,
//! and deciding whether one is reachable only from this machine are the same
//! questions on every platform, so they live here rather than in the Windows
//! half that happens to be the first caller.

use crate::{Error, Result};

/// The iSCSI well-known port, used when an address carries no port.
const DEFAULT_PORT: u16 = 3260;

/// How many ports above the preferred one are tried before giving up.
const PORT_SEARCH: u16 = 32;

/// Split `host:port` (the form `IscsiMount::addr` uses) into a host and a port.
///
/// A bare IPv6 address is nothing but colons, so `rsplit_once(':')` would read
/// its last group as the port: `--address ::1` would come out as the host `::`
/// (every interface) and the port `1`. A string that parses as an address in
/// full is therefore an address without a port, in the bare form and in the
/// bracketed form with the port left out. An address *with* a port stays
/// unambiguous only when the brackets are there (`[::1]:3260`), which is what
/// the RFCs require.
pub fn split_address(address: &str) -> (String, u16) {
    let bare = address.trim();
    let unbracketed = bare
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(bare);
    if let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() {
        return (ip.to_string(), DEFAULT_PORT);
    }
    match address.rsplit_once(':') {
        Some((host, port)) => match port.parse() {
            Ok(port) => (host.trim_matches(['[', ']']).to_string(), port),
            Err(_) => (address.to_string(), DEFAULT_PORT),
        },
        None => (address.to_string(), DEFAULT_PORT),
    }
}

/// Whether an iSCSI portal is one only this machine can reach.
///
/// The threat this guards is `--bind 0.0.0.0:3260`: the disk the target serves
/// is the *decrypted* volume, and its sessions are plaintext, so a loopback bind
/// is the only one that is safe by default and anything else has to be asked for
/// explicitly.
pub fn is_loopback_addr(address: &str) -> bool {
    let address = address.trim();
    // A bare IPv6 address is all colons, and `split_address` would read its last
    // group as a port, so try the whole string first.
    if let Ok(ip) = address.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    let (host, port) = split_address(address);
    if port == 0 {
        return false;
    }
    let host = host.trim();
    if host.is_empty() {
        // `:3260` listens on every interface.
        return false;
    }
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        // A name this cannot resolve is assumed to be reachable.
        Err(_) => false,
    }
}

/// The first free port at or above the one `preferred` asks for.
///
/// Two volumes cannot share a portal, and the default portal is
/// `127.0.0.1:3260`: without this a second `vcrs mount` would fail with
/// `EADDRINUSE` although nothing is wrong with it. The initiator is told the
/// portal explicitly, so a different port costs nothing.
pub fn free_bind_addr(preferred: &str) -> Result<String> {
    let (host, port) = split_address(preferred);
    let last_port = port.saturating_add(PORT_SEARCH - 1);
    let mut last = None;
    for candidate in port..=last_port {
        let address = format!("{host}:{candidate}");
        match std::net::TcpListener::bind(&address) {
            Ok(listener) => {
                // Free right now: the server that is about to start binds it for
                // real. Nothing else can take it in between but this program.
                drop(listener);
                return Ok(address);
            }
            Err(err) => last = Some(err),
        }
    }
    let reason = last
        .map(|err| err.to_string())
        .unwrap_or_else(|| "no candidate port".to_string());
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        format!("no free port between {port} and {last_port} for the iSCSI target on {host}: {reason}"),
    )))
}
