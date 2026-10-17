//! What is mounted right now, in one object.
//!
//! `vcrs list` prints this; `vcrs list --json` hands it to a program. Anything
//! else in this workspace (a GUI) should call [`snapshot`] rather than run
//! `vcrs.exe` and scrape its lines.

use serde::Serialize;

use crate::{agent, attach, detach, serve};

/// Everything `vcrs list` looks at, at the moment it looks.
#[derive(Debug, Serialize)]
pub struct Snapshot {
    /// True when this process has administrator rights, without which the
    /// session list cannot be read.
    pub elevated: bool,
    /// The pid of the cached elevated agent, when one is up.
    pub agent: Option<u32>,
    /// The logged-in iSCSI sessions that have a vc-rs target (`all` widens this
    /// to every session on the machine).
    pub sessions: Vec<Session>,
    /// The serving processes `vcrs mount --letter` left in the background.
    pub servers: Vec<Server>,
    /// The disks Windows has under the vc-rs disk name.
    pub disks: Vec<Disk>,
    /// Whatever could not be read, in the words `vcrs list` prints for it.
    pub notes: Vec<String>,
}

/// One logged-in iSCSI session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Session {
    pub id: String,
    /// The target's name, e.g. `iqn.2025-12.io.vcrs:secret`.
    pub iqn: String,
    /// The initiator node name of the machine, usually empty when `iscsicli`
    /// would not say.
    pub initiator: String,
    /// `iscsicli`'s "Number Connections", when it printed one.
    pub connections: Option<u32>,
}

/// One background server, i.e. one `%TEMP%\vcrs-<name>.server` file.
#[derive(Debug, Serialize)]
pub struct Server {
    pub iqn: String,
    pub pid: u32,
    /// The drive letter it was mounted on, when it was mounted on one.
    pub letter: Option<char>,
    /// The container it is serving, as recorded when it was started (a state
    /// file written by an older version does not have it).
    pub container: Option<std::path::PathBuf>,
}

/// One disk Windows shows under the vc-rs disk name.
#[derive(Debug, Serialize)]
pub struct Disk {
    pub number: u32,
    pub size: u64,
    /// The drive letter the volume wears, wherever Windows kept it.
    pub letter: Option<char>,
    pub file_system: Option<String>,
    pub partition: Option<u32>,
}

/// Look at everything. This never fails: a part that cannot be read is reported
/// in [`Snapshot::notes`], so a caller always gets an answer (an unelevated
/// process cannot read the session list, and that is normal).
pub fn snapshot(all: bool) -> Snapshot {
    let mut notes = Vec::new();

    let sessions = match attach::iscsicli(&["SessionList", "1"]) {
        Ok(text) => parse_sessions(&text)
            .into_iter()
            .filter(|session| all || session.iqn.starts_with(detach::VCRS_IQN_PREFIX))
            .collect(),
        Err(err) => {
            // `iscsicli` needs elevation, and the message it produces says so;
            // an unelevated `vcrs list` still shows the disks.
            notes.push(format!("({err:#})"));
            Vec::new()
        }
    };

    let servers = serve::states()
        .into_iter()
        .map(|server| Server {
            iqn: server.iqn,
            pid: server.pid,
            letter: server.letter,
            container: server.container,
        })
        .collect();

    let disks = match attach::vcrs_disks() {
        Ok(disks) => disks
            .into_iter()
            .map(|disk| Disk {
                number: disk.number,
                size: disk.size,
                letter: disk
                    .letter
                    .or_else(|| disk.partition.as_ref().and_then(|part| part.letter)),
                file_system: disk
                    .partition
                    .as_ref()
                    .and_then(|part| part.file_system.clone()),
                partition: disk.partition.as_ref().map(|part| part.number),
            })
            .collect(),
        Err(err) => {
            notes.push(format!("(the disks could not be read: {err:#})"));
            Vec::new()
        }
    };

    Snapshot {
        elevated: attach::elevated(),
        agent: agent::status(),
        sessions,
        servers,
        disks,
        notes,
    }
}

/// Parse `iscsicli SessionList 1` output into one entry per session.
pub fn parse_sessions(list: &str) -> Vec<Session> {
    let mut sessions: Vec<Session> = Vec::new();
    let mut current: Option<Session> = None;
    for line in list.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case("Session Id") && !value.is_empty() {
            if let Some(session) = current.take() {
                sessions.push(session);
            }
            current = Some(Session {
                id: value.to_string(),
                iqn: String::new(),
                initiator: String::new(),
                connections: None,
            });
            continue;
        }
        if let Some(session) = current.as_mut() {
            if key.eq_ignore_ascii_case("Initiator Node Name") {
                session.initiator = value.to_string();
            } else if (key.eq_ignore_ascii_case("Target Name")
                || key.eq_ignore_ascii_case("Target Node Name"))
                && session.iqn.is_empty()
                && value != "(null)"
            {
                session.iqn = value.to_string();
            } else if key.eq_ignore_ascii_case("Number Connections") {
                session.connections = value.parse().ok();
            }
        }
    }
    if let Some(session) = current.take() {
        sessions.push(session);
    }
    sessions
}

#[cfg(test)]
mod tests {
    use super::Session;

    #[test]
    fn every_session_in_the_list_is_read() {
        // Trimmed-down `iscsicli SessionList 1` output from a real run with one
        // vc-rs target and one unrelated session.
        let list = "Microsoft iSCSI Initiator Version 10.0 Build 26300\n\
                    Total of 2 sessions\n\
                    Session Id             : ffffe68332afe010-4000013700000006\n\
                    Initiator Node Name    : iqn.1991-05.com.microsoft:desktop-985akhr\n\
                    Target Node Name       : (null)\n\
                    Target Name            : iqn.2025-12.io.vcrs:probe\n\
                    ISID                   : 40 00 01 37 00 00\n\
                    Session Id             : ffffe68332afe010-4000013700000009\n\
                    Initiator Node Name    : iqn.1991-05.com.microsoft:desktop-985akhr\n\
                    Target Node Name       : iqn.other:storage\n\
                    ISID                   : 40 00 01 37 00 00\n";
        assert_eq!(
            super::parse_sessions(list),
            vec![
                Session {
                    id: "ffffe68332afe010-4000013700000006".to_string(),
                    iqn: "iqn.2025-12.io.vcrs:probe".to_string(),
                    initiator: "iqn.1991-05.com.microsoft:desktop-985akhr".to_string(),
                    connections: None,
                },
                Session {
                    id: "ffffe68332afe010-4000013700000009".to_string(),
                    iqn: "iqn.other:storage".to_string(),
                    initiator: "iqn.1991-05.com.microsoft:desktop-985akhr".to_string(),
                    connections: None,
                },
            ]
        );
        assert!(super::parse_sessions("").is_empty());
        assert!(super::parse_sessions("Total of 0 sessions\n").is_empty());
    }

    #[test]
    fn the_number_of_connections_is_read_when_it_is_there() {
        let list = "Session Id             : abc-123\n\
                    Target Name            : iqn.2025-12.io.vcrs:two\n\
                    Number Connections     : 2\n";
        let sessions = super::parse_sessions(list);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].connections, Some(2));
    }
}
