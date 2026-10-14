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
use crate::serve::{self, STOP_WAIT};
use crate::win32;

/// The IQN prefix every target `vcrs mount` serves shares.
pub(crate) const VCRS_IQN_PREFIX: &str = "iqn.2025-12.io.vcrs:";

/// How long to wait for Windows to let go of a disk ("<letter>: is in use").
const RELEASE_WAIT: Duration = Duration::from_secs(2);

/// How long to wait for the disk devices to disappear once they have been removed, so
/// that the logout that follows sees a storage stack Windows is done with. The removal
/// is asynchronous: `pnputil` returns, the device goes off the list, and only then can
/// the session go.
const DEVICE_WAIT: Duration = Duration::from_secs(4);

/// How long to wait for whatever has the volume open to close it, so that the
/// filesystem can be taken off and the session logged out. The lock succeeds at
/// once on a volume nobody is using, so this only costs time when it really is in
/// use — and a volume in use is exactly the case Windows refuses to log out.
const LOCK_WAIT: Duration = Duration::from_secs(10);

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

    let stage = std::time::Instant::now();
    let (sessions, disks) = snapshot();
    trace(report, "listing the sessions and the disks", stage);
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

    // 1. Let go of the volumes **while the target is still serving them**. Dropping the
    //    access path and taking a disk offline is instant while the volume is healthy,
    //    and a dead iSCSI target leaves every later storage call waiting on command
    //    time-outs: measured on this machine, this step took **72.6 s** with the server
    //    stopped first and 0.2 s with it still alive.
    //
    //    The disks come from the request rather than from the sessions: Windows often
    //    gives a session no disk number at all, and letting go of every vc-rs disk
    //    because of that would take a second volume down with the one asked for.
    let numbers: Vec<u32> = if wanted.iter().any(|session| session.disk.is_none()) {
        target_disks(&options.target, &disks)?
    } else {
        wanted.iter().filter_map(|session| session.disk).collect()
    };
    // The serving processes are found before the release, because this step also stops
    // them (see `release`): the volumes have to be Windows' again before the target
    // dies, or every later storage call waits on command time-outs.
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
    let pids: Vec<u32> = servers.iter().map(|server| server.pid).collect();
    // A server we asked `release` to stop is on its way out with the volumes it served.
    let stopped_any = !pids.is_empty();
    let stage = std::time::Instant::now();
    // The letters come from the disk listing, which knows them, and from the request when
    // Windows would not name a disk: a session with no disk number still has a letter
    // when the user asked for one.
    let mut letters: Vec<char> = disks
        .iter()
        .filter(|disk| numbers.contains(&disk.number))
        .filter_map(|disk| disk.letter)
        .collect();
    if let Target::Letter(letter) = &options.target {
        let want = letter.to_ascii_uppercase();
        if !letters.contains(&want) {
            letters.push(want);
        }
    }
    let released = release(&numbers, &letters, &pids, report)?;
    trace(report, "letting go, stopping and forgetting", stage);
    out.letters.extend(released.letters);

    // 2. The serving processes were stopped by `release` above. The initiator refuses
    //    to log out a session while its target is alive and Windows has the volume in
    //    use ("a device on that session is currently being used"), and waiting for
    //    Windows to change its mind is what made a dismount take a minute. Once the
    //    target is gone the session is stale, and a stale session *can* be logged
    //    out — which is what the earlier probe on this machine showed.
    for server in &servers {
        if !iqns.contains(&server.iqn) {
            iqns.push(server.iqn.clone());
        }
        if released.stopped.contains(&server.pid) {
            serve::forget(&server.iqn);
            report.line(&format!(
                "  stopped the serving process (pid {})",
                server.pid
            ));
        } else {
            // Already gone, or it would not die: let `serve::stop` report it.
            let _ = serve::stop(server, report);
        }
    }

    // The target that just died may still hold a session, and a stale session logs
    // out more reliably than a live one: look again before logging out.
    // Only when the session list came out empty (a target that outlived its
    // sessions): every `Get-IscsiSession` costs seconds while an older stale session
    // is making the initiator retry, so it is not done for nothing.
    let stage = std::time::Instant::now();
    let (after_stop, _) = if wanted.is_empty() {
        snapshot()
    } else {
        (Vec::new(), Vec::new())
    };
    trace(report, "looking again after the stop", stage);
    let mut to_logout: Vec<Session> = wanted.clone();
    for session in &after_stop {
        if iqns.contains(&session.iqn) && !to_logout.iter().any(|known| known.id == session.id) {
            to_logout.push(session.clone());
        }
    }
    // 3. Log the session out, and forget the static target.
    let mut refused: Vec<Session> = Vec::new();
    let stage = std::time::Instant::now();
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
    trace(
        report,
        "logging the sessions out and forgetting the targets",
        stage,
    );
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
/// Report how long a stage of the detach took, when `VCRS_TRACE` is set.
///
/// A dismount is a chain of Windows calls (a PowerShell here, an `iscsicli` there, the
/// storage stack in between) and guessing which one is slow costs more time than
/// measuring it.
fn trace(report: &mut Report, what: &str, since: std::time::Instant) {
    if std::env::var_os("VCRS_TRACE").is_some() {
        report.line(&format!(
            "  [{:>6.1}s] {what}",
            since.elapsed().as_secs_f64()
        ));
    }
}

pub fn detach_with_elevation(options: &DetachOptions) -> Result<()> {
    let exe = std::env::current_exe().context("finding this program's own path")?;
    if attach::elevated() {
        let mut report = Report::new(options.log.as_deref());
        detach(options, &mut report)?;
        return Ok(());
    }

    // An agent an earlier prompt left behind does the work with no prompt at all.
    if let Some((_, text)) = crate::agent::try_run(&detach_arguments(options, None)) {
        return attach::judge(&text, "dismount");
    }

    let log = attach::temp_log_path();
    // A log left behind by an earlier run is not this run's answer, and reading it
    // as it grows is how the run's verdict comes back (see `attach::wait_for_log`).
    let _ = std::fs::remove_file(&log);
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
    attach::start_elevated(&exe, &args, &log)?;
    let text = attach::wait_for_log(&log);
    let _ = std::fs::remove_file(&log);
    attach::judge(&text, "dismount")
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
/// What the storage half of a dismount produced.
#[derive(Default)]
pub struct Released {
    /// The letters Windows actually gave up.
    pub letters: Vec<char>,
    /// The serving processes this step found alive and stopped.
    pub stopped: Vec<u32>,
}

/// Let go of the volumes, take the disks offline, stop the serving processes and get the
/// orphaned disk devices out of the way.
///
/// This is the heart of a dismount and it runs on every one, so it is Win32 throughout:
/// the earlier version asked a PowerShell for the letters, the offline step, the
/// processes and the devices, and the process start-up alone cost seconds per call.
///
/// The order is what makes it work at all:
///
/// 1. the letters go first, while the target is **still serving** the volume — a dead
///    target leaves every later storage call waiting on SCSI command time-outs
///    (measured at 72.6 s on this machine against 0.2 s with it alive);
/// 2. then the disks go offline: the initiator refuses to log a session out while a
///    device on that session is in use, and an offline disk is not in use;
/// 3. then the serving processes stop, which is what makes the session stale — a stale
///    session logs out, a live one answers "a device on that session is currently
///    being used";
/// 4. and finally the disk devices Windows still has are taken away, because the
///    storage stack holds a session open for those as well.
fn release(
    numbers: &[u32],
    letters: &[char],
    pids: &[u32],
    report: &mut Report,
) -> Result<Released> {
    if numbers.is_empty() && letters.is_empty() && pids.is_empty() {
        return Ok(Released::default());
    }

    // 1. The filesystem off the volume first, then its letters. A mounted filesystem is
    //    a device "currently being used", and Windows will not log the session behind
    //    it out until it is taken off ("The session cannot be logged out since a device
    //    on that session is currently being used."); this is why a dismount used to
    //    leave its session behind. It is instant while the volume is healthy, and it
    //    has to happen while the target is still serving it: a dead target turns every
    //    step afterwards into a SCSI command time-out (measured: 72.6 s against 0.2 s).
    for letter in letters {
        if let Err(err) = win32::dismount_volume(*letter, LOCK_WAIT) {
            report.line(&format!(
                "  could not take the filesystem off {letter}: {err:#}"
            ));
        }
    }
    let mut gone: Vec<char> = Vec::new();
    for letter in letters {
        match win32::release_letter(*letter) {
            Ok(()) => {
                if !gone.contains(letter) {
                    gone.push(*letter);
                }
            }
            Err(err) => report.line(&format!(
                "  could not take {letter}: off the volume: {err:#}"
            )),
        }
    }

    // 2. Offline. A disk that is offline is not in use, and only a disk that is not in
    //    use lets its session go. Nothing is done to a disk Windows already took
    //    offline, so a second dismount of the same volume is quiet.
    for number in numbers {
        if let Err(err) = win32::set_disk_offline(*number, true) {
            report.line(&format!("  could not take disk {number} offline: {err:#}"));
        }
        // Eject the medium the way VeraCrypt's unmount does: the disk is presented as
        // removable, so this makes the storage stack drop the disk and its volumes —
        // and it must happen while the target is still serving them.
        if let Err(err) = win32::eject_media(*number) {
            report.line(&format!("  could not eject disk {number}: {err:#}"));
        }
    }

    // Windows acts on that a moment later, so the letters are asked for again until
    // they are gone. A disk that goes offline takes its letters with it, which is why
    // the wait is usually over on the first look.
    let deadline = std::time::Instant::now() + RELEASE_WAIT;
    let mut left: Vec<char> = gone
        .iter()
        .copied()
        .filter(|letter| win32::volume_of_letter(*letter).is_ok())
        .collect();
    while !left.is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        left.retain(|letter| win32::volume_of_letter(*letter).is_ok());
    }
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

    // 3. The serving processes. One that is already gone needs no report — the caller
    //    says "the target keeps serving" for that case.
    let mut stopped: Vec<u32> = Vec::new();
    for pid in pids {
        if serve::wait_and_kill(*pid, STOP_WAIT) != "gone" {
            stopped.push(*pid);
        }
    }

    // 4. The disk devices the storage stack still holds. `pnputil` is a plain program
    //    (the earlier version called it from inside a PowerShell, which cost a whole
    //    shell every time).
    match win32::disk_devices(attach::DISK_NAME) {
        Ok(devices) => {
            for device in devices {
                match remove_device(&device.instance_id) {
                    Ok(()) => report.line(&format!(
                        "  took the disk device {} away",
                        device.instance_id
                    )),
                    Err(err) => report.line(&format!(
                        "  could not take the disk device {} away: {err:#}",
                        device.instance_id
                    )),
                }
            }
            // Windows removes the device a moment after `pnputil` returns. Waiting for
            // the list to come back empty is what the logout needs: while Windows still
            // holds a device of this session, the session is "currently being used".
            let deadline = std::time::Instant::now() + DEVICE_WAIT;
            loop {
                match win32::disk_devices(attach::DISK_NAME) {
                    Ok(devices) if devices.is_empty() => break,
                    Ok(devices) => {
                        if std::time::Instant::now() >= deadline {
                            report.line(&format!(
                                "  {} vc-rs disk device(s) are still listed",
                                devices.len()
                            ));
                            break;
                        }
                    }
                    Err(_) => {
                        if std::time::Instant::now() >= deadline {
                            break;
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        Err(err) => report.line(&format!("  could not list the disk devices: {err:#}")),
    }

    Ok(Released {
        letters: gone,
        stopped,
    })
}

/// `pnputil /remove-device`: what takes a phantom disk device (a vc-rs volume whose
/// serving process is gone) out of the device tree.
fn remove_device(instance_id: &str) -> Result<()> {
    // `pnputil` answers 3010 (`ERROR_SUCCESS_REBOOT_REQUIRED`) when the device is gone
    // but Windows wants a restart to settle the rest; that is still a removal.
    const REBOOT_REQUIRED: i32 = 3010;
    let out = attach::quiet_command("pnputil.exe")
        .args(["/remove-device", instance_id])
        .output()
        .context("taking the disk device away")?;
    if !out.status.success() && out.status.code() != Some(REBOOT_REQUIRED) {
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        // `pnputil` prints a banner first and its verdict last, so the verdict is the
        // line worth repeating (and the exit code, for when it says nothing at all).
        let last = text
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .map(|line| line.trim().to_string())
            .unwrap_or_else(|| "no output".to_string());
        anyhow::bail!(
            "pnputil /remove-device {instance_id}: exit {:?}: {last}",
            out.status.code()
        );
    }
    Ok(())
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
    // Six tries with 800 ms between them: Windows finishes dropping the device a moment
    // after `pnputil` returns, and until it has, the session answers "currently being
    // used" — which is a state that passes, not a failure to report.
    for attempt in 0..6 {
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
                if !busy || attempt == 5 {
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
             volume was in use (something inside it was still open); mounting that volume again \
             clears the leftover"
        ));
    }
}

/// Every vc-rs iSCSI session in the machine, in the `sess=…` form [`parse_sessions`]
/// reads.
///
/// This used to be a `Get-IscsiSession` one-liner, which cost a cmdlet import in a
/// PowerShell process of its own.  The initiator's own `iscsicli SessionList` prints the
/// same two facts that matter — the session id and its target — in one native process.
/// The disk number is not in its output, and nothing here needs it: a session is named
/// by its id and by its target.
fn sessions_text() -> String {
    let Ok(list) = attach::iscsicli(&["SessionList", "1"]) else {
        return String::new();
    };
    let mut text = String::new();
    let mut current: Option<String> = None;
    for line in list.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "Session Id" => current = Some(value.trim().to_string()),
            "Target Name" => {
                let iqn = value.trim();
                if iqn.starts_with(VCRS_IQN_PREFIX) {
                    if let Some(id) = current.take() {
                        text.push_str(&format!("sess={id};iqn={iqn};disk=0;conn=True\n"));
                    }
                }
            }
            _ => {}
        }
    }
    text
}

/// The iSCSI sessions and the vc-rs disks Windows has.
///
/// Both come from the machine itself now: the disks from Win32 (a few ioctls, which also
/// does away with the `Update-HostStorageCache` a cmdlet-based listing needed before a
/// freshly attached disk showed up), and the sessions from `iscsicli SessionList`.
fn snapshot() -> (Vec<Session>, Vec<DiskInfo>) {
    let text = sessions_text();
    (
        parse_sessions(&text),
        attach::vcrs_disks().unwrap_or_default(),
    )
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
