//! Logging in to a served volume and mounting it, through the system's iSCSI
//! initiator and `mount(8)`.
//!
//! On Windows the platform's own initiator is driven by [`crate`]-external code
//! (`vcrs-host`), which needs elevation and a drive letter. On Linux the same
//! job is done here with two ordinary tools: `iscsiadm` (open-iscsi) logs in to
//! the loopback target that the background server is offering, the kernel's
//! iSCSI driver creates a SCSI disk, and `mount` puts its filesystem on a
//! directory. The result is one mount point per container, and `vcrs dismount`
//! undoes all of it.
//!
//! Everything here needs root: login creates a block device and `mount` needs
//! `CAP_SYS_ADMIN`. The command reports that instead of failing obscurely.
//!
//! What is remembered between the two commands is a small text file per mount in
//! [`state_dir`] (no password, no key material: the container path, the IQN, the
//! portal, the device, the mount point and the server's pid).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use vcrs_core::error::{Error, Result};

/// How long the parent waits for the detached server's handshake.
pub const READY_WAIT: Duration = Duration::from_secs(60);
/// How long the kernel gets to produce `/dev/disk/by-path/...` after a login.
const DISK_WAIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(200);
/// How many times `umount` is retried before giving up (a process still holding
/// a file open is the usual reason for the first refusal).
const UMOUNT_TRIES: u32 = 5;

/// One container that is currently served and mounted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Target name the background server answers to.
    pub iqn: String,
    /// Portal the server listens on, as `host:port`.
    pub portal: String,
    /// Process id of the background server.
    pub pid: u32,
    /// The container file the volume lives in.
    pub container: PathBuf,
    /// Block device the kernel created, e.g. `/dev/sdb1`.
    pub device: PathBuf,
    /// Where the filesystem is mounted.
    pub mount_point: PathBuf,
    /// The server's log file.
    pub log: PathBuf,
}

impl Session {
    /// The state file that records this mount.
    pub fn state_path(&self) -> PathBuf {
        state_dir().join(format!("vcrs-{}.session", slug(&self.iqn)))
    }

    fn to_text(&self) -> String {
        format!(
            "iqn={}\nportal={}\npid={}\ncontainer={}\ndevice={}\nmount_point={}\nlog={}\n",
            self.iqn,
            self.portal,
            self.pid,
            self.container.display(),
            self.device.display(),
            self.mount_point.display(),
            self.log.display()
        )
    }

    fn from_text(text: &str) -> Option<Session> {
        let mut iqn = None;
        let mut portal = None;
        let mut pid = None;
        let mut container = None;
        let mut device = None;
        let mut mount_point = None;
        let mut log = None;
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "iqn" => iqn = Some(value.trim().to_string()),
                "portal" => portal = Some(value.trim().to_string()),
                "pid" => pid = value.trim().parse().ok(),
                "container" => container = Some(PathBuf::from(value.trim())),
                "device" => device = Some(PathBuf::from(value.trim())),
                "mount_point" => mount_point = Some(PathBuf::from(value.trim())),
                "log" => log = Some(PathBuf::from(value.trim())),
                _ => {}
            }
        }
        Some(Session {
            iqn: iqn?,
            portal: portal?,
            pid: pid?,
            container: container?,
            device: device?,
            mount_point: mount_point?,
            log: log?,
        })
    }

    /// Write the state file, so a later `vcrs dismount` can find this mount.
    pub fn save(&self) -> Result<()> {
        let dir = state_dir();
        std::fs::create_dir_all(&dir).map_err(Error::Io)?;
        adopt(&dir);
        let path = self.state_path();
        std::fs::write(&path, self.to_text()).map_err(Error::Io)?;
        adopt(&path);
        Ok(())
    }

    /// Forget this mount (the state file and the log both go).
    pub fn forget(&self) {
        let _ = std::fs::remove_file(self.state_path());
        let _ = std::fs::remove_file(&self.log);
    }
}

/// Map anything that is not safe in a file name to `_`.
fn slug(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect()
}

/// Where the mount records live.
///
/// The user's own cache directory, not a shared temp directory, and not root's
/// home when the command ran through `sudo` — the record has to be readable by
/// the unprivileged `vcrs list` that follows.
pub fn state_dir() -> PathBuf {
    let base = match sudo_uid() {
        Some(_) => sudo_home(),
        None => None,
    };
    if let Some(home) = base {
        return home.join(".cache").join("vcrs");
    }
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|dir| !dir.is_empty()) {
        return PathBuf::from(dir).join("vcrs");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|dir| !dir.is_empty()) {
        return PathBuf::from(home).join(".cache").join("vcrs");
    }
    std::env::temp_dir().join("vcrs")
}

/// The log file the detached server will write.
pub fn log_path(iqn: &str) -> PathBuf {
    state_dir().join(format!("vcrs-{}.log", slug(iqn)))
}

fn sudo_uid() -> Option<u32> {
    std::env::var("SUDO_UID").ok()?.parse().ok()
}

fn sudo_gid() -> Option<u32> {
    std::env::var("SUDO_GID").ok()?.parse().ok()
}

/// The home directory of the user who ran `sudo`.
fn sudo_home() -> Option<PathBuf> {
    let user = std::env::var("SUDO_USER").ok()?;
    let uid = sudo_uid()?;
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 6 && fields[0] == user && fields[2] == uid.to_string() {
            return Some(PathBuf::from(fields[5]));
        }
    }
    None
}

/// Hand a file or directory this process created as root back to the user who
/// asked for the mount, so they can read it (and remove it) without `sudo`.
fn adopt(path: &Path) {
    if let (Some(uid), Some(gid)) = (sudo_uid(), sudo_gid()) {
        let Ok(text) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
            return;
        };
        unsafe {
            libc::chown(text.as_ptr(), uid, gid);
        }
    }
}

/// Whether this process is root (mounting needs it).
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Every mount that has a state file, newest name first.
pub fn sessions() -> Vec<Session> {
    let dir = state_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut found: Vec<Session> = entries
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".session"))
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .filter_map(|text| Session::from_text(&text))
        .collect();
    found.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));
    found
}

/// Run a program and return its trimmed stdout.
fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output().map_err(|err| {
        Error::Unsupported(format!(
            "could not run {program} ({err}); mounting a volume on this system needs the \
             iSCSI tools and mount(8) — install the open-iscsi package"
        ))
    })?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() { stdout } else { stderr };
        return Err(Error::Io(std::io::Error::other(format!(
            "{program} {} failed: {detail}",
            args.join(" ")
        ))));
    }
    Ok(stdout)
}

/// Make sure the iSCSI driver and the open-iscsi daemon are available.
///
/// Both are one-time system setup, so doing it here means the user does not have
/// to run them by hand before every mount. A failure is reported with the package
/// that provides them.
fn ensure_initiator() -> Result<()> {
    // `iscsi_tcp` is a module on most kernels and built in on some; only a
    // failure of `iscsiadm` below is interesting.
    let _ = Command::new("modprobe").arg("iscsi_tcp").output();
    if Path::new("/run/iscsid.pid").exists() {
        return Ok(());
    }
    // A system with systemd starts it through the unit; one without (a
    // container, WSL) needs the daemon started directly.
    let _ = Command::new("systemctl").args(["start", "iscsid"]).output();
    let _ = Command::new("iscsid").output();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if Path::new("/run/iscsid.pid").exists() {
            return Ok(());
        }
        std::thread::sleep(POLL);
    }
    run("iscsiadm", &["--version"]).map_err(|_| {
        Error::Unsupported(
            "this system has no iSCSI initiator; mounting a volume on Linux needs the \
             open-iscsi package (`apt install open-iscsi`) and the `iscsi_tcp` kernel module"
                .to_string(),
        )
    })?;
    Err(Error::Unsupported(
        "the open-iscsi daemon (iscsid) is not running and could not be started; start it \
         with `sudo systemctl start iscsid` (or `sudo iscsid`)"
            .to_string(),
    ))
}

/// The `by-path` link the kernel publishes for an iSCSI lun.
fn by_path(portal: &str, iqn: &str, suffix: &str) -> PathBuf {
    PathBuf::from(format!(
        "/dev/disk/by-path/ip-{portal}-iscsi-{iqn}-lun-0{suffix}"
    ))
}

/// Wait for the kernel to publish the disk, and return the device to mount.
///
/// `--disk-mode partition` (the default) puts a partition table inside the
/// volume, so the filesystem is on the first partition and the whole disk is not
/// mountable; raw mode has no partition.
fn wait_for_device(portal: &str, iqn: &str) -> Result<PathBuf> {
    let start = Instant::now();
    loop {
        let disk = by_path(portal, iqn, "");
        let part = by_path(portal, iqn, "-part1");
        if disk.exists() || part.exists() {
            // Give udev a moment to finish the partition scan before deciding.
            std::thread::sleep(Duration::from_millis(500));
            if part.exists() {
                return Ok(std::fs::canonicalize(&part).unwrap_or(part));
            }
            if disk.exists() {
                return Ok(std::fs::canonicalize(&disk).unwrap_or(disk));
            }
        }
        if start.elapsed() >= DISK_WAIT {
            return Err(Error::Unsupported(format!(
                "the kernel did not publish a disk for {iqn} within {} s; the background server \
                 may have stopped, see {}",
                DISK_WAIT.as_secs(),
                log_path(iqn).display()
            )));
        }
        std::thread::sleep(POLL);
    }
}

/// The filesystem type `mount` will find, if it can be asked.
fn filesystem_type(device: &Path) -> Option<String> {
    let device = device.to_string_lossy().to_string();
    let output = Command::new("blkid")
        .args(["-o", "value", "-s", "TYPE", &device])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// The volume label, for the default mount point.
fn filesystem_label(device: &Path) -> Option<String> {
    let device = device.to_string_lossy().to_string();
    let output = Command::new("lsblk")
        .args(["-n", "-o", "LABEL", &device])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Mount options that make the files usable by the person who asked for the
/// mount, for the filesystems that need to be told (Windows' drive letters are
/// owned by their user too, and a root-owned FAT volume would be a regression).
fn mount_options(filesystem: Option<&str>) -> Option<String> {
    let (uid, gid) = (sudo_uid()?, sudo_gid()?);
    match filesystem {
        Some("vfat") | Some("exfat") | Some("ntfs") | Some("ntfs3") | Some("fuseblk") => {
            Some(format!("uid={uid},gid={gid},umask=0022"))
        }
        _ => None,
    }
}

/// Where a volume should be mounted when the user did not say.
///
/// `/media/vcrs/<label>`, falling back to the target's suffix, and `-2`, `-3`, …
/// when that name is taken (`/media/vcrs` is the same tree udisks uses, so it is
/// already browsable and already cleaned up by the desktop's file manager).
fn default_mount_point(device: &Path, iqn: &str) -> PathBuf {
    let base = filesystem_label(device)
        .map(|label| slug(&label.to_ascii_lowercase()))
        .filter(|label| !label.is_empty() && label != "_")
        .unwrap_or_else(|| {
            iqn.rsplit(':')
                .next()
                .map(slug)
                .unwrap_or_else(|| "volume".to_string())
        });
    // A leftover *empty* directory from a previous mount is reused (it is in
    // vcrs's own tree, and after an unclean shutdown it is exactly where the
    // volume used to be); only a directory that currently holds another mount is
    // stepped over.
    let mut path = Path::new("/media/vcrs").join(&base);
    let mut count = 2;
    while is_mounted(&path) {
        path = Path::new("/media/vcrs").join(format!("{base}-{count}"));
        count += 1;
    }
    path
}

/// Whether a directory is a mount point right now.
fn is_mounted(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let want = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    text.lines().any(|line| {
        line.split(' ')
            .nth(4)
            .map(|field| field.replace("\\040", " "))
            .is_some_and(|field| Path::new(&field) == want)
    })
}

/// Log in to a target the background server is offering and mount its filesystem.
///
/// Returns the record that `vcrs dismount` needs. On failure everything this call
/// did is undone, so a failed mount does not leave a logged-in session behind.
pub fn mount_served(
    iqn: &str,
    portal: &str,
    container: &Path,
    mount_point: Option<&Path>,
    pid: u32,
    log: PathBuf,
) -> Result<Session> {
    ensure_initiator()?;
    // Discovery is what makes `iscsiadm -m node` know the target; it is
    // idempotent, so running it for every mount is fine.
    run("iscsiadm", &["-m", "discovery", "-t", "sendtargets", "-p", portal])?;
    run(
        "iscsiadm",
        &["-m", "node", "-T", iqn, "-p", portal, "--login"],
    )?;

    let device = match wait_for_device(portal, iqn) {
        Ok(device) => device,
        Err(err) => {
            logout(iqn, portal);
            return Err(err);
        }
    };
    let mount_point = match mount_point {
        Some(path) => path.to_path_buf(),
        None => default_mount_point(&device, iqn),
    };
    let filesystem = filesystem_type(&device);
    let mut command = Command::new("mount");
    if let Some(options) = mount_options(filesystem.as_deref()) {
        command.arg("-o").arg(options);
    }
    let created = std::fs::create_dir_all(&mount_point).is_ok();
    let mounted = command
        .arg(&device)
        .arg(&mount_point)
        .output()
        .map_err(Error::Io);
    let mounted = match mounted {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let reason = String::from_utf8_lossy(&output.stderr).trim().to_string();
            // The one mistake this flow invites is mounting a volume that has no
            // filesystem yet (a container that was created but not formatted).
            let hint = if reason.contains("wrong fs type")
                || reason.contains("can't read superblock")
                || reason.contains("bad option")
            {
                "; the volume has no filesystem this system can read — `vcrs format <volume>`                  puts a FAT32 one inside it"
            } else {
                ""
            };
            Err(Error::Io(std::io::Error::other(format!(
                "mount {} {} failed: {reason}{hint}",
                device.display(),
                mount_point.display()
            ))))
        }
        Err(err) => Err(err),
    };
    if let Err(err) = mounted {
        if created {
            let _ = std::fs::remove_dir(&mount_point);
        }
        logout(iqn, portal);
        return Err(err);
    }

    let session = Session {
        iqn: iqn.to_string(),
        portal: portal.to_string(),
        pid,
        container: container.to_path_buf(),
        device,
        mount_point,
        log,
    };
    session.save()?;
    Ok(session)
}

/// Log out and delete the node record, ignoring failures.
fn logout(iqn: &str, portal: &str) {
    let _ = Command::new("iscsiadm")
        .args(["-m", "node", "-T", iqn, "-p", portal, "--logout"])
        .output();
    let _ = Command::new("iscsiadm")
        .args(["-m", "node", "-T", iqn, "-p", portal, "-o", "delete"])
        .output();
}

/// Unmount, log out, stop the server and forget the mount.
///
/// Every step is attempted even if an earlier one failed: the point of a dismount
/// is to get everything back, and a busy filesystem should still log out and stop
/// the server so a retry starts from a clean slate.
pub fn unmount(session: &Session) -> Result<()> {
    let mut problems: Vec<String> = Vec::new();
    if is_mounted(&session.mount_point) {
        let mut last = String::new();
        for attempt in 0..UMOUNT_TRIES {
            let output = Command::new("umount").arg(&session.mount_point).output();
            match output {
                Ok(output) if output.status.success() => {
                    last.clear();
                    break;
                }
                Ok(output) => {
                    last = String::from_utf8_lossy(&output.stderr).trim().to_string();
                }
                Err(err) => {
                    last = err.to_string();
                }
            }
            if attempt + 1 < UMOUNT_TRIES {
                std::thread::sleep(Duration::from_millis(400));
            }
        }
        if !last.is_empty() {
            problems.push(format!(
                "could not unmount {}: {last}",
                session.mount_point.display()
            ));
        }
    }
    // The directory the default mount point created goes too, when it is empty;
    // a directory the user named is left alone.
    let _ = std::fs::remove_dir(&session.mount_point);
    logout(&session.iqn, &session.portal);
    if !stop(session.pid) {
        problems.push(format!(
            "the background server (pid {}) did not stop",
            session.pid
        ));
    }
    session.forget();
    if problems.is_empty() {
        Ok(())
    } else {
        Err(Error::Unsupported(problems.join("; ")))
    }
}

/// Ask the server to stop, and make sure it did.
pub fn stop(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    if pid <= 1 {
        return false;
    }
    unsafe {
        if libc::kill(pid, libc::SIGTERM) == -1 {
            return true; // already gone
        }
    }
    for _ in 0..25 {
        std::thread::sleep(Duration::from_millis(100));
        if unsafe { libc::kill(pid, 0) } == -1 {
            return true;
        }
    }
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session {
            iqn: "iqn.2025-12.io.vcrs:65ac470871d3".to_string(),
            portal: "127.0.0.1:3260".to_string(),
            pid: 4242,
            container: PathBuf::from("/home/u/secret.vc"),
            device: PathBuf::from("/dev/sdb1"),
            mount_point: PathBuf::from("/media/vcrs/private"),
            log: PathBuf::from("/home/u/.cache/vcrs/vcrs-x.log"),
        }
    }

    #[test]
    fn a_state_file_round_trips() {
        let original = session();
        let text = original.to_text();
        assert_eq!(Session::from_text(&text), Some(original));
    }

    #[test]
    fn a_state_file_needs_every_field() {
        let text = "iqn=x\nportal=127.0.0.1:3260\npid=1\ncontainer=/c\ndevice=/dev/sdb1\n";
        assert_eq!(Session::from_text(text), None);
    }

    #[test]
    fn the_slug_is_safe_in_a_file_name() {
        assert_eq!(slug("iqn.2025-12.io.vcrs:a/b"), "iqn.2025-12.io.vcrs_a_b");
        assert_eq!(slug("PRIVATE"), "PRIVATE");
    }

    #[test]
    fn windows_filesystems_get_the_users_ids() {
        // Without sudo there is no id to hand over; with it, vfat-like filesystems
        // get the three options that make the mount usable by that user.
        std::env::set_var("SUDO_UID", "1000");
        std::env::set_var("SUDO_GID", "1000");
        assert_eq!(
            mount_options(Some("vfat")).as_deref(),
            Some("uid=1000,gid=1000,umask=0022")
        );
        assert_eq!(mount_options(Some("ext4")), None);
        assert_eq!(mount_options(None), None);
        std::env::remove_var("SUDO_UID");
        std::env::remove_var("SUDO_GID");
        assert_eq!(mount_options(Some("vfat")), None);
    }
}
