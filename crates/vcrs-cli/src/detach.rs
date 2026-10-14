//! Detaching a volume: the mirror image of [`crate::attach`].
//!
//! `vcrs mount --letter Y` puts a volume on a drive letter; `vcrs dismount`
//! takes it off again. Both need the one UAC prompt the Microsoft iSCSI
//! Initiator requires (`iscsicli` carries a `requireAdministrator` manifest),
//! both take the drive letter, the container path, the target name or "all of
//! them", and both re-run themselves elevated so the user only ever answers a
//! Windows prompt.
//!
//! The order of the steps is not free: the initiator refuses to log a session
//! out while Windows is still using its disk ("the session cannot be logged out
//! since a device on that session is currently being used"), so the drive
//! letters come off and the disk goes offline *before* the logout.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::attach::{self, DiskInfo, Report};
use crate::serve;

/// The IQN prefix every target `vcrs mount` serves shares.
pub(crate) const VCRS_IQN_PREFIX: &str = "iqn.2025-12.io.vcrs:";

/// How long to wait for Windows to let go of a disk ("<letter>: is in use").
const RELEASE_WAIT: Duration = Duration::from_secs(4);

/// What to detach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Every target vc-rs serves (VeraCrypt's `/dismount` without a volume).
    All,
    /// One target, by the IQN `vcrs mount` prints.
    Iqn(String),
    /// The volume Windows currently has on this drive letter.
    Letter(char),
}

impl Target {
    fn describe(&self) -> String {
        match self {
            Target::All => "every volume vc-rs serves".to_string(),
            Target::Iqn(iqn) => iqn.clone(),
            Target::Letter(letter) => format!("the volume on {}:", letter.to_ascii_uppercase()),
        }
    }
}

/// What to detach and where the elevated child writes its output.
#[derive(Debug, Clone)]
pub struct DetachOptions {
    pub target: Target,
    /// Write the output to this file as well (used by `vcrs dismount`, whose
    /// elevated child has a console window of its own).
    pub log: Option<PathBuf>,
}

/// What actually went away.
#[derive(Debug, Default, Clone)]
pub struct Detached {
    /// The IQNs whose sessions were logged out.
    pub targets: Vec<String>,
    /// The drive letters that were released.
    pub letters: Vec<char>,
    /// Things the user has to know about (a disk Windows still lists, a
    /// session that was already gone, …).
    pub notes: Vec<String>,
}

/// One iSCSI session, as `Get-IscsiSession` reports it.
///
/// `Get-IscsiSession` is the only way to get from a disk number to the target
/// (its IQN) it came from, which is what `vcrs dismount --letter S` needs; the
/// session *id* is the handle `iscsicli LogoutTarget` wants, and it is the same
/// string in both worlds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub iqn: String,
    pub disk: Option<u32>,
    pub connected: bool,
}

/// Detach the target from the Microsoft iSCSI Initiator (needs an elevated
/// prompt: `iscsicli` cannot run without one).
pub fn detach(options: &DetachOptions, report: &mut Report) -> Result<Detached> {
    if !attach::elevated() {
        bail!(
            "detaching a volume needs elevation: iscsicli carries a requireAdministrator \
             manifest, so Windows refuses to run it from a normal prompt. Re-run this in an \
             elevated prompt, or run `vcrs dismount` — like `vcrs mount --letter`, it asks for \
             the one prompt itself"
        );
    }

    let (sessions, disks) = snapshot();
    let vcrs: Vec<Session> = sessions
        .iter()
        .filter(|session| session.iqn.starts_with(VCRS_IQN_PREFIX))
        .cloned()
        .collect();

    let mut out = Detached::default();
    report.line(&format!("detaching {} …", options.target.describe()));

    // Which sessions, and which disks to let go of first.
    let wanted: Vec<Session> = match &options.target {
        Target::All => {
            if vcrs.is_empty() && disks.is_empty() {
                report.line("no vc-rs volume is attached");
                return Ok(out);
            }
            vcrs.clone()
        }
        Target::Iqn(iqn) => {
            let wanted: Vec<Session> = vcrs.iter().filter(|s| &s.iqn == iqn).cloned().collect();
            if wanted.is_empty() {
                out.notes
                    .push(format!("no session for {iqn} (already logged out?)"));
            }
            wanted
        }
        Target::Letter(letter) => {
            // A dismount has to accept the letter its volume is *on*: this is
            // not the attach side, where a taken letter is an error.
            let want = attach::letter_argument(*letter)?;
            // The state file `vcrs mount --letter` wrote names the target that
            // letter was given to. It is the only record that survives Windows
            // forgetting the volume (a letter left behind with no disk under it, a
            // session the initiator refuses to log out) — and the disk is the
            // fallback for a mount made by hand, which leaves no state file.
            let recorded = serve::states()
                .into_iter()
                .find(|server| server.letter == Some(want))
                .map(|server| server.iqn);
            let iqn = match recorded {
                Some(iqn) => Some(iqn),
                None => disks
                    .iter()
                    .find(|disk| disk.letter == Some(want))
                    .and_then(|disk| {
                        vcrs.iter()
                            .find(|session| session.disk == Some(disk.number))
                            .or_else(|| vcrs.first())
                            .map(|session| session.iqn.clone())
                    }),
            };
            let Some(iqn) = iqn else {
                bail!("no vc-rs volume is on {want}: (see `vcrs list`)");
            };
            let candidates: Vec<Session> = vcrs
                .iter()
                .filter(|session| session.iqn == iqn)
                .cloned()
                .collect();
            if candidates.is_empty() {
                out.notes.push(format!(
                    "{iqn} has no session any more (Windows may have logged it out already)"
                ));
            }
            candidates
        }
    };

    // 1. Stop the serving processes **before** the logout. The initiator refuses to
    //    log out a session while its target is alive and Windows has the volume in
    //    use ("a device on that session is currently being used"), and waiting for
    //    Windows to change its mind is what made a dismount take a minute. Once the
    //    target is gone the session is stale, and a stale session *can* be logged
    //    out — which is what the earlier probe on this machine showed.
    let mut iqns: Vec<String> = wanted.iter().map(|session| session.iqn.clone()).collect();
    let servers: Vec<serve::Server> = match &options.target {
        Target::All => serve::states(),
        Target::Iqn(_) => iqns.iter().filter_map(|iqn| serve::state(iqn)).collect(),
        Target::Letter(letter) => {
            let by_iqn: Vec<serve::Server> =
                iqns.iter().filter_map(|iqn| serve::state(iqn)).collect();
            if by_iqn.is_empty() {
                // No session was left to name it, so the recorded letter is what
                // identifies the server (`vcrs mount --letter` writes it down).
                let want = (*letter).to_ascii_uppercase();
                serve::states()
                    .into_iter()
                    .filter(|server| server.letter == Some(want))
                    .collect()
            } else {
                by_iqn
            }
        }
    };
    let mut stopped_any = false;
    for server in &servers {
        stopped_any |= serve::stop(server, report);
        if !iqns.contains(&server.iqn) {
            iqns.push(server.iqn.clone());
        }
    }

    // The target that just died may still hold a session, and a stale session logs
    // out more reliably than a live one: look again before logging out.
    // Only when the session list came out empty (a target that outlived its
    // sessions): every `Get-IscsiSession` costs seconds while an older stale session
    // is making the initiator retry, so it is not done for nothing.
    let (after_stop, after_stop_disks) = if wanted.is_empty() {
        snapshot()
    } else {
        (Vec::new(), Vec::new())
    };
    let mut to_logout: Vec<Session> = wanted.clone();
    for session in &after_stop {
        if iqns.contains(&session.iqn) && !to_logout.iter().any(|known| known.id == session.id) {
            to_logout.push(session.clone());
        }
    }
    let known_disks: Vec<DiskInfo> = if disks.is_empty() {
        after_stop_disks
    } else {
        disks
    };

    // 2. Release the volumes: drop the drive letters, then take the disk offline —
    //    a disk Windows is still using is one more thing holding the session open.
    //
    //    The disks come from the request, not from the sessions: Windows often
    //    gives a session no disk number at all, and releasing every vc-rs disk
    //    because of that would take a second volume down with the one asked for.
    let numbers: Vec<u32> = if to_logout.iter().any(|session| session.disk.is_none()) {
        target_disks(&options.target, &known_disks)?
    } else {
        to_logout
            .iter()
            .filter_map(|session| session.disk)
            .collect()
    };
    let letters = release(&numbers, report)?;
    out.letters.extend(letters);

    // 2. Log the session out, 3. forget the static target.
    let mut refused: Vec<Session> = Vec::new();
    for session in &to_logout {
        if logout(session, report) {
            out.targets.push(session.iqn.clone());
        } else {
            refused.push(session.clone());
        }
        if let Err(err) = attach::iscsicli(&["RemoveTarget", session.iqn.as_str()]) {
            report.line(&format!("could not forget {}: {err:#}", session.iqn));
        }
    }
    if let Target::Iqn(iqn) = &options.target {
        if !wanted.iter().any(|session| &session.iqn == iqn) {
            // The target may be registered without a session (a login that never
            // completed): `RemoveTarget` is still what the user asked for.
            let _ = attach::iscsicli(&["RemoveTarget", iqn.as_str()]);
        }
    }

    // 3b. (The serving processes were stopped at the top of this function, before
    //     the letters were released: a session can only be logged out once the
    //     target is gone — while it is alive the initiator answers "a device on that
    //     session is currently being used".)

    // 3c. Ask again about the sessions Windows would not let go of. The initiator
    //     said "a device on that session is currently being used" — and the device
    //     is the serving process, which is gone now. Only a session that outlived
    //     its own target survives this, and clearing that takes a service restart
    //     (see `drop_stale_sessions`, which refuses to touch sessions that are not
    //     ours).
    let mut still_refused: Vec<Session> = Vec::new();
    for session in &refused {
        if logout(session, report) {
            if !out.targets.contains(&session.iqn) {
                out.targets.push(session.iqn.clone());
            }
        } else {
            still_refused.push(session.clone());
        }
    }
    if !still_refused.is_empty() {
        clear_leftover_sessions(&mut out, &still_refused, report);
    }

    // 4. Say what is left, if anything. A disk whose server was stopped above is
    //    on its way out with it; one that is still listed with no server behind it
    //    (a mount made by hand, or by a build that wrote no state file) is worth
    //    saying out loud — and finding out costs a PowerShell call, so it is
    //    skipped when the servers were already stopped.
    if !stopped_any {
        for disk in attach::vcrs_disks().unwrap_or_default() {
            out.notes.push(format!(
                "Windows still lists disk {} ({} bytes): its serving process is still running \
                 (`vcrs list` shows the targets; stopping the process in Task Manager clears it)",
                disk.number, disk.size
            ));
        }
    }

    match (&out.targets, &out.letters) {
        (targets, letters) if targets.is_empty() && letters.is_empty() && !stopped_any => {
            report.line("nothing was attached")
        }
        (targets, letters) => {
            let mut summary = Vec::new();
            if !targets.is_empty() {
                summary.push(format!("logged out {}", targets.join(", ")));
            }
            if !letters.is_empty() {
                let letters: String = letters
                    .iter()
                    .map(|letter| format!("{letter}:"))
                    .collect::<Vec<_>>()
                    .join(", ");
                summary.push(format!("released {letters}"));
            }
            if summary.is_empty() {
                // The letter and the disk were already gone (Windows had taken the
                // volume away); the serving process was all that was left.
                summary.push("the serving process was stopped".to_string());
            }
            report.line(&summary.join("; "));
        }
    }
    for note in &out.notes {
        report.line(&format!("note: {note}"));
    }
    Ok(out)
}

/// Detach, asking Windows for elevation when this process has none.
///
/// This is what `vcrs dismount` calls: from a normal prompt it produces one UAC
/// prompt and nothing else to do; from an elevated prompt it detaches straight
/// away.
pub fn detach_with_elevation(options: &DetachOptions) -> Result<()> {
    let exe = std::env::current_exe().context("finding this program's own path")?;
    if attach::elevated() {
        let mut report = Report::new(options.log.as_deref());
        detach(options, &mut report)?;
        return Ok(());
    }

    let log = attach::temp_log_path();
    let args = detach_arguments(options, Some(&log));
    println!(
        "detaching {} needs an elevated prompt (iscsicli carries a requireAdministrator manifest):",
        options.target.describe()
    );
    println!(
        "  approving the Windows prompt that is about to appear …  (or run `vcrs dismount {}` \
         yourself from an elevated prompt)",
        target_argument(&options.target)
    );
    let code = attach::start_elevated(&exe, &args, &log)?;
    attach::replay_elevated(code, &log, "dismount")
}

/// Everything needed to re-run this program as `vcrs detach …`.
fn detach_arguments(options: &DetachOptions, log: Option<&Path>) -> Vec<String> {
    let mut args = vec!["detach".to_string()];
    match &options.target {
        Target::All => args.push("--all".to_string()),
        Target::Iqn(iqn) => {
            args.push("--iqn".to_string());
            args.push(iqn.clone());
        }
        Target::Letter(letter) => {
            args.push("--letter".to_string());
            args.push(letter.to_ascii_uppercase().to_string());
        }
    }
    if let Some(log) = log {
        args.push("--log".to_string());
        args.push(log.display().to_string());
    }
    args
}

/// How the same request would be typed by hand, for the message that tells the
/// user what to run instead.
fn target_argument(target: &Target) -> String {
    match target {
        Target::All => "--all".to_string(),
        Target::Iqn(iqn) => format!("--iqn {iqn}"),
        Target::Letter(letter) => format!("--letter {}", letter.to_ascii_uppercase()),
    }
}

/// Drop the drive letters of these disks and take them offline.
///
/// Returns the letters that were taken away. A letter goes away with the
/// offline flag, but removing the access path first is what makes Windows
/// release the volume handle immediately.
fn release(numbers: &[u32], report: &mut Report) -> Result<Vec<char>> {
    if numbers.is_empty() {
        return Ok(Vec::new());
    }
    let before = letters_of(numbers);
    let list = numbers
        .iter()
        .map(|number| number.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$deadline = (Get-Date).AddSeconds(6); \
         foreach ($n in @({list})) {{ \
           while ($true) {{ \
           Get-Partition -DiskNumber $n -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.DriveLetter }} | ForEach-Object {{ \
               Remove-PartitionAccessPath -DiskNumber $n -PartitionNumber $_.PartitionNumber \
                 -AccessPath ($_.DriveLetter + ':\\') -ErrorAction SilentlyContinue }}; \
             Set-Disk -Number $n -IsOffline $true -ErrorAction SilentlyContinue; \
             $d = Get-Disk -Number $n -ErrorAction SilentlyContinue; \
             if ((-not $d) -or $d.IsOffline -or ((Get-Date) -gt $deadline)) {{ break }}; \
             Start-Sleep -Milliseconds 250 }}; \
           $d = Get-Disk -Number $n -ErrorAction SilentlyContinue; \
           if ($d -and -not $d.IsOffline) {{ 'still-online=' + $n }} }}; exit 0"
    );
    // The offline step is **verified inside the same PowerShell** (and retried in
    // it): the initiator will not log out a session whose disk is still online and
    // in use, which is exactly the refusal this path runs into. A disk that will
    // not go offline is the reason a logout would fail, so it is said out loud.
    match attach::powershell(&script) {
        Ok(text) => {
            for (i, _) in text
                .lines()
                .filter(|line| line.trim().starts_with("still-online="))
                .enumerate()
            {
                let _ = i;
                report.line(
                    "  a disk would not go offline: Windows may refuse to log its session out",
                );
            }
        }
        Err(err) => report.line(&format!("  could not offline the disk(s): {err:#}")),
    }

    // Windows gives the letter back a moment later ("<letter>: is in use"
    // otherwise), so ask it inside one PowerShell rather than starting a whole
    // process per attempt (about a second each).
    let left = letters_still_used(&list);
    let gone: Vec<char> = before
        .iter()
        .filter(|letter| !left.contains(letter))
        .copied()
        .collect();
    if !left.is_empty() {
        let letters: String = left
            .iter()
            .map(|letter| format!("{letter}:"))
            .collect::<Vec<_>>()
            .join(", ");
        report.line(&format!(
            "  {letters} is still in use: Windows has not let go of it yet"
        ));
    }
    Ok(gone)
}

/// The letters these disks still have.  Polled inside **one** PowerShell: a
/// letter does not go away the instant its access path does, and asking from
/// here would cost a whole process per attempt.
fn letters_still_used(list: &str) -> Vec<char> {
    let script = format!(
        r#"$numbers = @({list})
$deadline = (Get-Date).AddSeconds({wait})
$left = @()
do {{
  Update-HostStorageCache -ErrorAction SilentlyContinue
  $left = @()
  foreach ($n in $numbers) {{
    foreach ($p in @(Get-Partition -DiskNumber $n -ErrorAction SilentlyContinue)) {{
      if ($p.DriveLetter) {{ $left += $p.DriveLetter }}
    }}
  }}
  if ($left.Count -eq 0) {{ break }}
  Start-Sleep -Milliseconds 300
}} while ((Get-Date) -lt $deadline)
'left=' + ($left -join ',')"#,
        list = list,
        wait = RELEASE_WAIT.as_secs()
    );
    attach::powershell(&script)
        .map(|text| letters_after(&text, "left="))
        .unwrap_or_default()
}

/// The disks a request is about, for the case where Windows will not name them.
fn target_disks(target: &Target, disks: &[DiskInfo]) -> Result<Vec<u32>> {
    Ok(match target {
        Target::All => disks.iter().map(|disk| disk.number).collect(),
        Target::Letter(letter) => {
            let want = attach::letter_argument(*letter)?;
            disks
                .iter()
                .filter(|disk| disk.letter == Some(want))
                .map(|disk| disk.number)
                .collect()
        }
        // An IQN names a target, not a disk, and with no session to ask there is
        // nothing to narrow it down with.
        Target::Iqn(_) => disks.iter().map(|disk| disk.number).collect(),
    })
}

/// Log one session out, retrying while Windows still calls its device busy.
///
/// The initiator refuses to log out a session whose disk it is still using
/// (`the session cannot be logged out since a device on that session is currently
/// being used`), and that state clears a moment after the access paths are gone —
/// so a refusal is about timing, not about the request. A session whose target is
/// already gone comes back as "already logged out", which is the outcome wanted.
fn logout(session: &Session, report: &mut Report) -> bool {
    for attempt in 0..3 {
        match attach::iscsicli(&["LogoutTarget", session.id.as_str()]) {
            Ok(_) => {
                report.line(&format!("logged out {} ({})", session.iqn, session.id));
                return true;
            }
            Err(err) => {
                let text = format!("{err:#}");
                if text.contains("already") {
                    report.line(&format!("{} was already logged out", session.iqn));
                    return true;
                }
                let busy = text.contains("currently being used");
                if !busy || attempt == 2 {
                    report.line(&format!("could not log out {}: {text}", session.iqn));
                    return false;
                }
                std::thread::sleep(Duration::from_millis(700));
            }
        }
    }
    false
}

/// Free the sessions Windows would not log out: one more logout for each, and an
/// honest report for the ones that survive.
///
/// The initiator refuses to log out a session while Windows still has its device in
/// use, and on this machine that can outlast the serving process (the disk device
/// outlives the target). Removing the device node (`pnputil`, the same cleanup an
/// attach does) was tried here and did not help, at the price of a minute of extra
/// PowerShell per dismount — so a survivor is reported instead, and the next
/// `vcrs mount` of that volume clears it, because attaching prunes stale sessions.
fn clear_leftover_sessions(out: &mut Detached, refused: &[Session], report: &mut Report) {
    for session in refused {
        if logout(session, report) {
            if !out.targets.contains(&session.iqn) {
                out.targets.push(session.iqn.clone());
            }
        }
    }
    let (after, _) = snapshot();
    let left = after
        .iter()
        .filter(|session| session.iqn.starts_with(VCRS_IQN_PREFIX))
        .count();
    if left > 0 {
        out.notes.push(format!(
            "{left} vc-rs session(s) are still logged in: Windows would not let them go while the \
             volume was in use; mounting that volume again clears the leftover"
        ));
    }
}

/// The letters on the `key=…` line PowerShell printed, e.g. `left=C,D`.
fn letters_after(text: &str, key: &str) -> Vec<char> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix(key))
        .map(|value| {
            value
                .split(',')
                .filter_map(|letter| letter.trim().chars().next())
                .filter(|letter| letter.is_ascii_alphabetic())
                .map(|letter| letter.to_ascii_uppercase())
                .collect()
        })
        .unwrap_or_default()
}

/// The drive letters Windows currently has on these disks.
fn letters_of(numbers: &[u32]) -> Vec<char> {
    let disks: Vec<DiskInfo> = attach::vcrs_disks().unwrap_or_default();
    let mut letters: Vec<char> = disks
        .iter()
        .filter(|disk| numbers.contains(&disk.number))
        .filter_map(|disk| disk.letter)
        .collect();
    letters.sort_unstable();
    letters.dedup();
    letters
}

/// Every iSCSI session in the machine, with the disk each one carries.
fn sessions_script() -> String {
    format!(
        "Get-IscsiSession -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.TargetNodeAddress -like '*{VCRS_IQN_PREFIX}*' }} | ForEach-Object {{ \
           'sess={{0}};iqn={{1}};disk={{2}};conn={{3}}' -f \
             $_.SessionIdentifier, $_.TargetNodeAddress, \
             $(if ($_.DiskNumber) {{ $_.DiskNumber }} else {{ 0 }}), \
             $(if ($_.IsConnected) {{ 'True' }} else {{ 'False' }}) }}"
    )
}

/// The iSCSI sessions and the vc-rs disks in **one** PowerShell pass: they are
/// two CIM queries and each process costs about a second.
fn snapshot() -> (Vec<Session>, Vec<DiskInfo>) {
    let script = format!(
        "{sessions}\n{disks}",
        sessions = sessions_script(),
        disks = attach::disks_script(None, None, true)
    );
    let text = attach::powershell(&script).unwrap_or_default();
    (parse_sessions(&text), attach::parse_disks(&text))
}

/// Read the `sess=…;iqn=…;disk=…;conn=…` lines [`sessions`] prints.
fn parse_sessions(text: &str) -> Vec<Session> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with("sess=") {
                return None;
            }
            let mut session = Session {
                id: String::new(),
                iqn: String::new(),
                disk: None,
                connected: false,
            };
            for field in line.split(';') {
                let (key, value) = field.split_once('=')?;
                match key {
                    "sess" if !value.is_empty() => session.id = value.to_string(),
                    "iqn" if !value.is_empty() => session.iqn = value.to_string(),
                    "disk" => session.disk = value.parse::<u32>().ok().filter(|n| *n != 0),
                    "conn" => session.connected = value.eq_ignore_ascii_case("true"),
                    _ => {}
                }
            }
            (!session.id.is_empty() && !session.iqn.is_empty()).then_some(session)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_child_gets_the_same_target_plus_a_log() {
        let log = PathBuf::from(r"C:\Temp\vcrs-detach-1.log");
        let all = DetachOptions {
            target: Target::All,
            log: None,
        };
        assert_eq!(detach_arguments(&all, None), vec!["detach", "--all"]);
        assert_eq!(
            detach_arguments(&all, Some(&log)),
            vec!["detach", "--all", "--log", r"C:\Temp\vcrs-detach-1.log"]
        );

        let by_iqn = DetachOptions {
            target: Target::Iqn("iqn.2025-12.io.vcrs:secret".to_string()),
            log: None,
        };
        assert_eq!(
            detach_arguments(&by_iqn, None),
            vec!["detach", "--iqn", "iqn.2025-12.io.vcrs:secret"]
        );

        let by_letter = DetachOptions {
            target: Target::Letter('y'),
            log: None,
        };
        assert_eq!(
            detach_arguments(&by_letter, None),
            vec!["detach", "--letter", "Y"]
        );
        assert_eq!(target_argument(&by_letter.target), "--letter Y");
    }

    #[test]
    fn the_session_lines_powershell_prints_are_read_back() {
        let text = "\
Session Id                       Initiator Node Name
sess=ffff9c8e78edf010-4000013700000012;iqn=iqn.2025-12.io.vcrs:smoke;disk=1;conn=True
sess=ffff9c8e78edf010-4000013700000009;iqn=iqn.2025-12.io.vcrs:letter-test;disk=0;conn=False
";
        let sessions = parse_sessions(text);
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].id, "ffff9c8e78edf010-4000013700000012");
        assert_eq!(sessions[0].iqn, "iqn.2025-12.io.vcrs:smoke");
        assert_eq!(sessions[0].disk, Some(1));
        assert!(sessions[0].connected);
        // A session Windows has no disk for reports 0, which means "unknown".
        assert_eq!(sessions[1].disk, None);
        assert!(!sessions[1].connected);
    }

    #[test]
    fn a_warning_banner_is_not_mistaken_for_a_session() {
        let text = "\
Get-IscsiSession : No MSFT_iSCSISession objects found
sess=;iqn=;disk=0;conn=False
";
        assert!(parse_sessions(text).is_empty());
    }

    #[test]
    fn only_the_targets_vcrs_serves_are_counted() {
        let sessions = parse_sessions(&format!(
            "sess=abc;iqn={VCRS_IQN_PREFIX}secret;disk=1;conn=True\n\
             sess=def;iqn=iqn.1991-05.com.microsoft:some-other-array;disk=2;conn=True\n"
        ));
        let vcrs: Vec<&Session> = sessions
            .iter()
            .filter(|session| session.iqn.starts_with(VCRS_IQN_PREFIX))
            .collect();
        assert_eq!(vcrs.len(), 1);
        assert_eq!(vcrs[0].iqn, "iqn.2025-12.io.vcrs:secret");
    }
}
