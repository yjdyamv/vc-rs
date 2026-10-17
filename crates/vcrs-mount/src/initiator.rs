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
/// How long a partitioned volume's disk may exist without a partition node
/// before the disk itself is taken to be what the initiator published. The
/// kernel creates the disk node first and scans it for partitions afterwards, so
/// the partition node can lag by a few hundred milliseconds — mounting the disk
/// in that window reads the partition table as if it were the filesystem.
const PARTITION_GRACE: Duration = Duration::from_secs(5);
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

/// What is left of a mount that a state file still records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// The device is there and the filesystem is mounted.
    Live,
    /// The session is gone (the server stopped, or the login was dropped), so
    /// the block device the mount point was mounted from no longer exists.
    DeviceGone,
    /// The device and the mount are still there, but the background server is
    /// gone: the mount looks fine and every read fails.
    ServerGone,
    /// The session is there but nothing is mounted: someone ran `umount` by hand.
    NotMounted,
}

impl std::fmt::Display for Health {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Health::Live => write!(f, "mounted"),
            Health::DeviceGone => write!(f, "stale: the session is gone"),
            Health::ServerGone => write!(f, "stale: the server behind it is gone"),
            Health::NotMounted => write!(f, "stale: nothing is mounted there"),
        }
    }
}

/// The program a pid is running, without the kernel's ` (deleted)` suffix.
fn process_name(pid: i32) -> Option<PathBuf> {
    if pid <= 1 {
        return None;
    }
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let text = exe.to_string_lossy().into_owned();
    let text = text.strip_suffix(" (deleted)").unwrap_or(&text).to_string();
    Some(PathBuf::from(text))
}

/// Whether a recorded pid still runs this program.
///
/// A pid is reused: after a reboot, or once the server is gone, the number in a
/// state file can belong to anything at all. Signalling a stranger would be a
/// hostile act, so the check compares the binary name and fails closed.
pub fn is_our_process(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    let Some(theirs) = process_name(pid) else {
        return false;
    };
    let Ok(ours) = std::env::current_exe() else {
        return false;
    };
    ours.file_name().is_some() && ours.file_name() == theirs.file_name()
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

    /// Whether the device is gone, nothing is mounted, or both are fine.
    pub fn health(&self) -> Health {
        if !self.device.exists() {
            Health::DeviceGone
        } else if !self.server_alive() {
            // The kernel keeps the device node while the session is logged in, so
            // a dead server shows up as a mount whose reads fail.
            Health::ServerGone
        } else if !is_mounted(&self.mount_point) {
            Health::NotMounted
        } else {
            Health::Live
        }
    }

    /// Whether this mount is a leftover: the state file outlived the session.
    pub fn is_stale(&self) -> bool {
        self.health() != Health::Live
    }

    /// Whether the background server is still running *and is this program*.
    pub fn server_alive(&self) -> bool {
        is_our_process(self.pid)
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
    // The privileged command writes these records and the unprivileged one reads
    // them, so both have to land in the same directory. `sudo` resets HOME and
    // XDG_RUNTIME_DIR to root's, which is why the invoking user's candidates are
    // built from their uid (and their /etc/passwd home) instead of the
    // environment.
    let sudo = sudo_uid();
    let mut bases: Vec<PathBuf> = Vec::new();
    if sudo.is_none() {
        if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|dir| !dir.is_empty()) {
            bases.push(PathBuf::from(dir));
        }
    }
    let uid = sudo.unwrap_or_else(|| unsafe { libc::geteuid() });
    bases.push(PathBuf::from(format!("/run/user/{uid}")));
    let home = sudo_home().or_else(|| {
        std::env::var_os("HOME")
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from)
    });
    if let Some(home) = home {
        bases.push(home.join(".cache"));
    }
    bases.push(std::env::temp_dir());
    let first = bases.first().cloned().unwrap_or_default();
    for base in &bases {
        if base.is_dir() {
            return base.join("vcrs");
        }
    }
    first.join("vcrs")
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

/// Which node under `/dev/disk/by-path` carries the filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceChoice {
    /// The whole disk: raw mode, no partition table.
    Disk,
    /// The first partition: the partitioned presentation.
    Partition,
}

/// Decide between the disk and its first partition.
///
/// `--disk-mode partition` (the default) presents a synthetic MBR, so the kernel
/// creates a partition node and that is where the filesystem is; raw mode has no
/// partition table, so the disk itself is the filesystem.  Raw mode ignores a
/// partition node on purpose: a stale one would be the wrong device.
/// Which node to mount.
///
/// `settled` says the disk has been there for [`PARTITION_GRACE`] with no
/// partition node next to it, so the volume really is laid out as a bare disk.
fn pick_device(raw: bool, disk: bool, part: bool, settled: bool) -> Option<DeviceChoice> {
    if raw {
        disk.then_some(DeviceChoice::Disk)
    } else if part {
        Some(DeviceChoice::Partition)
    } else if settled {
        // No partition: either the volume is not partitioned at all (a raw image,
        // `--disk-mode raw`), or its partition table has no entry the kernel
        // knows. The disk is still worth a try, and `mount` will say no.
        disk.then_some(DeviceChoice::Disk)
    } else {
        None
    }
}

/// Wait for the kernel to publish the disk, and return the device to mount.
fn wait_for_device(portal: &str, iqn: &str, raw: bool) -> Result<PathBuf> {
    let start = Instant::now();
    let mut disk_seen: Option<Instant> = None;
    loop {
        let disk = by_path(portal, iqn, "");
        let part = by_path(portal, iqn, "-part1");
        let disk_exists = disk.exists();
        if disk_exists && disk_seen.is_none() {
            disk_seen = Some(Instant::now());
        }
        let settled = disk_seen
            .map(|seen| seen.elapsed() >= PARTITION_GRACE)
            .unwrap_or(false);
        if let Some(choice) = pick_device(raw, disk_exists, part.exists(), settled) {
            // Give udev a moment to finish the partition scan before deciding,
            // except in raw mode, where there is no partition to wait for.
            if !raw {
                std::thread::sleep(Duration::from_millis(500));
            }
            let path = match choice {
                DeviceChoice::Partition => part,
                DeviceChoice::Disk => disk,
            };
            return Ok(std::fs::canonicalize(&path).unwrap_or(path));
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
fn mount_options(filesystem: Option<&str>, read_only: bool) -> Option<String> {
    let mut options: Vec<String> = Vec::new();
    if read_only {
        options.push("ro".to_string());
    }
    if matches!(
        filesystem,
        Some("vfat" | "exfat" | "ntfs" | "ntfs3" | "fuseblk")
    ) {
        // FAT and NTFS cannot carry unix ownership, so the mount has to be told
        // whose files these are; otherwise everything is root's and the caller
        // cannot write to a volume they just unlocked.
        if let (Some(uid), Some(gid)) = (sudo_uid(), sudo_gid()) {
            options.push(format!("uid={uid}"));
            options.push(format!("gid={gid}"));
            options.push("umask=0022".to_string());
        }
    }
    if options.is_empty() {
        None
    } else {
        Some(options.join(","))
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
/// How the served target should be mounted.
#[derive(Clone, Copy, Default)]
pub struct MountKnobs<'a> {
    /// Mount the filesystem read-only (the volume itself may also be read-only).
    pub read_only: bool,
    /// CHAP credentials `(user, secret)` the login has to present, when the
    /// target asks for CHAP.
    pub auth: Option<(&'a str, &'a str)>,
    /// The target presents no partition table, so the disk itself is mounted.
    pub raw: bool,
}

/// Configure `iscsiadm`'s persistent node record with the CHAP credentials.
fn set_auth(iqn: &str, portal: &str, user: &str, secret: &str) -> Result<()> {
    run(
        "iscsiadm",
        &[
            "-m",
            "node",
            "-T",
            iqn,
            "-p",
            portal,
            "-o",
            "update",
            "-n",
            "node.session.auth.authmethod",
            "-v",
            "CHAP",
            "-n",
            "node.session.auth.username",
            "-v",
            user,
            "-n",
            "node.session.auth.password",
            "-v",
            secret,
        ],
    )?;
    Ok(())
}

/// Discovery is its own iSCSI session and is authenticated separately, so the
/// same credentials have to go into the discovery database as well.
fn set_discovery_auth(portal: &str, user: &str, secret: &str) -> Result<()> {
    let _ = Command::new("iscsiadm")
        .args(["-m", "discoverydb", "-t", "sendtargets", "-p", portal, "--op=new"])
        .output();
    run(
        "iscsiadm",
        &[
            "-m",
            "discoverydb",
            "-t",
            "sendtargets",
            "-p",
            portal,
            "--op=update",
            "-n",
            "discovery.sendtargets.auth.authmethod",
            "-v",
            "CHAP",
            "-n",
            "discovery.sendtargets.auth.username",
            "-v",
            user,
            "-n",
            "discovery.sendtargets.auth.password",
            "-v",
            secret,
        ],
    )?;
    Ok(())
}

pub fn mount_served(
    iqn: &str,
    portal: &str,
    container: &Path,
    mount_point: Option<&Path>,
    pid: u32,
    log: PathBuf,
    knobs: MountKnobs<'_>,
) -> Result<Session> {
    ensure_initiator()?;
    // Discovery is what makes `iscsiadm -m node` know the target; it is
    // idempotent, so running it for every mount is fine.
    // A record left behind by an earlier run of this IQN would point at the
    // portal of that run, and `--login` would go there instead of here.
    let _ = Command::new("iscsiadm")
        .args(["-m", "node", "-T", iqn, "-o", "delete"])
        .output();
    if let Some((user, secret)) = knobs.auth {
        set_discovery_auth(portal, user, secret)?;
    }
    run("iscsiadm", &["-m", "discovery", "-t", "sendtargets", "-p", portal])?;
    if let Some((user, secret)) = knobs.auth {
        set_auth(iqn, portal, user, secret)?;
    }
    run(
        "iscsiadm",
        &["-m", "node", "-T", iqn, "-p", portal, "--login"],
    )?;

    let device = match wait_for_device(portal, iqn, knobs.raw) {
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
    if let Some(options) = mount_options(filesystem.as_deref(), knobs.read_only) {
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
                "; the volume has no filesystem this system can read — `vcrs format <volume>` puts a FAT32 one inside it; if it is NTFS, `apt install ntfs-3g` (or use a kernel with ntfs3); if it was written with the other disk mode, pass `--disk-mode raw` (or drop it)"
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

/// Appended to a busy-mount complaint: what to do about it.
const MOVE_AWAY: &str = "; leave the directory (or close the program) and run the same command again — `umount -l` detaches it anyway, and `vcrs dismount` falls back to it when the device is already gone";

/// The process ids `fuser -m` printed, from either stream.
///
/// `fuser` writes `"/mnt/x:  1234 5678"` and exits non-zero whenever it found
/// something, so the status says nothing useful and only the numbers matter.  A
/// bare run tags each pid with what it does there: `1234c` is a process whose
/// current directory is the mount point.
fn pids_in_fuser_output(text: &str) -> Vec<u32> {
    let mut pids: Vec<u32> = text
        .split_whitespace()
        .filter_map(|word| {
            let digits: String = word
                .trim_end_matches(':')
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse().ok()
        })
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids
}

/// Who is keeping a mount point busy, as `"name (pid N)"`.
///
/// A busy mount is the one failure a user cannot diagnose from `umount`'s
/// "target is busy": the shell they are standing in is enough to cause it.
fn mount_users(mount_point: &Path) -> Vec<String> {
    let Ok(output) = Command::new("fuser").arg("-m").arg(mount_point).output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    pids_in_fuser_output(&text)
        .into_iter()
        .map(|pid| {
            let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|line| line.trim().to_string())
                .unwrap_or_else(|_| "?".to_string());
            format!("{name} (pid {pid})")
        })
        .collect()
}

/// Unmount, log out, stop the server and forget the mount.
///
/// Every step is attempted even if an earlier one failed: the point of a dismount
/// is to get everything back, and a busy filesystem should still log out and stop
/// the server so a retry starts from a clean slate.
pub fn unmount(session: &Session) -> Result<()> {
    let mut problems: Vec<String> = Vec::new();
    let mut still_mounted = false;
    // A mount whose device vanished is a leftover: `umount` can still be refused
    // ("device is busy"), and `umount -l` detaches it either way.
    let device_gone = !session.device.exists();
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
        if !last.is_empty() && device_gone {
            let lazy = Command::new("umount").arg("-l").arg(&session.mount_point).output();
            match lazy {
                Ok(output) if output.status.success() => last.clear(),
                Ok(output) => {
                    last = String::from_utf8_lossy(&output.stderr).trim().to_string();
                }
                Err(err) => last = err.to_string(),
            }
        }
        if !last.is_empty() {
            // "target is busy" alone leaves the user with nothing to act on, and
            // the usual culprit is a shell whose working directory is inside.
            let users = mount_users(&session.mount_point);
            let busy = if users.is_empty() {
                String::new()
            } else {
                format!(" — in use by {}", users.join(", "))
            };
            still_mounted = true;
            problems.push(format!(
                "could not unmount {}: {last}{busy}{MOVE_AWAY}",
                session.mount_point.display()
            ));
        }
    }
    // The directory the default mount point created goes too, when it is empty;
    // a directory the user named is left alone.
    let _ = std::fs::remove_dir(&session.mount_point);
    logout(&session.iqn, &session.portal);
    // Only a pid that still runs this program is signalled: a reused number may
    // belong to anything, and a server that is already gone needs nothing.
    if session.server_alive() && !stop(session.pid) {
        problems.push(format!(
            "the background server (pid {}) did not stop",
            session.pid
        ));
    }
    if still_mounted {
        // The mount point is still there, so the record stays too: otherwise
        // `vcrs list` would lose a volume that is still mounted, and the retry
        // after the user leaves the directory would have nothing to find.
        problems.push(format!(
            "{} is still mounted, and it is still recorded (`vcrs dismount {}` retries it)",
            session.mount_point.display(),
            session.container.display()
        ));
    } else {
        session.forget();
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(Error::Unsupported(problems.join("; ")))
    }
}

/// Ask the server to stop, and make sure it did.
pub fn stop(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        // Not a number this kernel could have handed out, so nothing is running
        // behind it.
        return true;
    };
    if pid <= 1 || !is_our_process(pid as u32) {
        // Already gone, or a stranger that ended up with a recorded number.
        return true;
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
    fn a_mount_whose_device_is_gone_is_stale() {
        let mut gone = session();
        gone.device = PathBuf::from("/dev/vcrs-definitely-not-here");
        assert_eq!(gone.health(), Health::DeviceGone);
        assert!(gone.is_stale());
        assert_eq!(gone.health().to_string(), "stale: the session is gone");

        let mut unmounted = session();
        unmounted.pid = std::process::id();
        unmounted.device = std::env::current_exe().expect("this test has a binary");
        // A plain directory: not a mount point of its own, however the temporary
        // directory happens to be mounted.
        unmounted.mount_point = std::env::temp_dir().join("vcrs-not-a-mount-point");
        let _ = std::fs::create_dir_all(&unmounted.mount_point);
        // A temp dir is not a mount point of its own, so nothing is mounted there.
        assert_eq!(unmounted.health(), Health::NotMounted);
        assert!(unmounted.is_stale());
    }

    #[test]
    fn a_mount_whose_server_is_gone_is_stale() {
        let mut orphan = session();
        // The device and the mount point are still there, but the pid is not this
        // program any more.
        orphan.device = std::env::current_exe().expect("this test has a binary");
        orphan.pid = 1;
        assert_eq!(orphan.health(), Health::ServerGone);
        assert!(orphan.is_stale());
        assert!(!orphan.server_alive());
    }

    #[test]
    fn a_fuser_line_gives_up_its_pids() {
        assert_eq!(pids_in_fuser_output("/media/vcrs/x:  1234 5678"), vec![1234, 5678]);
        assert_eq!(pids_in_fuser_output("/media/vcrs/x:"), Vec::<u32>::new());
        assert_eq!(pids_in_fuser_output(""), Vec::<u32>::new());
        assert_eq!(pids_in_fuser_output("  42   42  "), vec![42]);
        // A bare run tags the pid with the access it found.
        assert_eq!(pids_in_fuser_output("/media/vcrs/x: 13895c"), vec![13895]);
    }

    #[test]
    fn the_disk_mode_decides_which_node_is_mounted() {
        use DeviceChoice::{Disk, Partition};
        // Raw mode: the disk itself, even if a partition node is lying around.
        assert_eq!(pick_device(true, true, true, false), Some(Disk));
        assert_eq!(pick_device(true, true, false, false), Some(Disk));
        assert_eq!(pick_device(true, false, true, true), None);
        // Partitioned mode prefers the partition, whenever it turns up.
        assert_eq!(pick_device(false, true, true, false), Some(Partition));
        assert_eq!(pick_device(false, true, true, true), Some(Partition));
        // A disk whose partition node has not appeared yet is not mounted: the
        // kernel publishes the disk before it scans the partition table, and
        // mounting the disk in that window fails on the partition table.
        assert_eq!(pick_device(false, true, false, false), None);
        // Once the grace period is over, a disk with no partition is what the
        // volume is: an unpartitioned image.
        assert_eq!(pick_device(false, true, false, true), Some(Disk));
        assert_eq!(pick_device(false, false, false, true), None);
    }

    #[test]
    fn only_this_program_counts_as_ours() {
        assert!(is_our_process(std::process::id()));
        // pid 1 is init/systemd and never this binary, and pid 0 is not a process.
        assert!(!is_our_process(1));
        assert!(!is_our_process(0));
        // A pid that cannot be read (or does not exist) is not ours either.
        assert!(!is_our_process(u32::MAX));
        // ... and stopping one is a no-op that reports success.
        assert!(stop(u32::MAX));
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
            mount_options(Some("vfat"), false).as_deref(),
            Some("uid=1000,gid=1000,umask=0022")
        );
        assert_eq!(mount_options(Some("ext4"), false), None);
        assert_eq!(mount_options(None, false), None);
        // A read-only volume must be mounted read-only, and a filesystem that
        // needs no id options still needs `ro`.
        assert_eq!(
            mount_options(Some("vfat"), true).as_deref(),
            Some("ro,uid=1000,gid=1000,umask=0022")
        );
        assert_eq!(mount_options(Some("ext4"), true).as_deref(), Some("ro"));
        std::env::remove_var("SUDO_UID");
        std::env::remove_var("SUDO_GID");
        assert_eq!(mount_options(Some("vfat"), false), None);
    }
}
