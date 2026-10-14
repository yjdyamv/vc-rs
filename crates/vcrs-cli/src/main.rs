//! `vcrs` — command line front end for the vc-rs VeraCrypt implementation.
//!
//! The commands mirror what is needed to check the on-disk format against real
//! VeraCrypt: create volumes, inspect headers, and read/write raw volume data.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use vcrs_core::header::{
    VolumeHeader, HEADER_ENCRYPTED_DATA_OFFSET, MASTER_KEY_AREA_OFFSET, VOLUME_HEADER_SIZE,
    VOLUME_HEADER_SIZE_LEGACY,
};
use vcrs_core::volume::{CreateOptions, OpenOptions, ProtectedRange, RestoreHeaderOptions, Volume};
use vcrs_core::{EncryptionAlgorithm, Prf, VolumeLayout, VolumeType};

use vcrs_cli::{agent, attach, detach, prompt, serve, status};

#[derive(Parser)]
#[command(name = "vcrs", version, about = "VeraCrypt-compatible volume tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Print a machine-readable JSON document instead of the usual lines, for the
    /// commands that have one (`vcrs list --json`).
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new VeraCrypt-format volume (V2 normal volume).
    Create(CreateArgs),
    /// Create a hidden volume inside an existing volume file.
    CreateHidden(CreateHiddenArgs),
    /// Open a volume and print its header fields.
    Info(InfoArgs),
    /// Print the raw (still encrypted) header bytes of a volume file.
    Header(HeaderArgs),
    /// Read decrypted data from a volume.
    Read(ReadArgs),
    /// Write data into a volume.
    Write(WriteArgs),
    /// Create a FAT32 filesystem inside an existing volume's data area.
    Format(FormatArgs),
    /// Mount a volume: expose its data area as a raw block device over iSCSI,
    /// so the initiator's own drivers mount (and can format) the filesystem
    /// inside it. Needs an elevated prompt to log the target in.
    Mount(MountArgs),
    /// Detach a volume mounted with `vcrs mount` from the iSCSI initiator: it
    /// releases the drive letter, takes the disk offline, logs the session out
    /// and forgets the target. A bare `vcrs dismount` does that for every volume
    /// vc-rs serves (VeraCrypt's `/dismount` without a volume); `--letter S`,
    /// `--iscsi <IQN>` and a container path pick one. Needs the same one UAC
    /// prompt `vcrs mount --letter` asks for, and asks for it itself.
    Dismount(DismountArgs),
    /// Attach a volume `vcrs mount` is serving to the Microsoft iSCSI Initiator,
    /// and put it on the drive letter you want. `vcrs mount --letter Y` does
    /// this for you, in one command; this is the same step on its own.
    /// Needs an elevated prompt (iscsicli refuses to run without one).
    Attach(AttachArgs),
    /// Detach without asking for elevation: what `vcrs dismount` runs as, once it
    /// has the prompt it needs. Not meant to be typed by hand.
    #[command(hide = true)]
    Detach(DetachArgs),
    /// The cached elevated helper: the first prompt leaves it running, and the
    /// commands after that need no prompt at all. `--status` and `--stop` look
    /// after it; `--serve` is what that first prompt starts.
    Agent(AgentArgs),
    /// Grow an existing container (VeraCrypt's Volume Expander). The data area
    /// gets bigger and the existing data is kept; the filesystem inside keeps
    /// its old size and has to be extended from the operating system once the
    /// volume is mounted.
    Expand(ExpandArgs),
    /// Encrypt a plaintext partition/device image in place (VeraCrypt's "Encrypt
    /// a non-system partition in place"), or resume an interrupted run: the image
    /// becomes a normal container without needing a second copy of the data.
    EncryptInPlace(EncryptInPlaceArgs),
    /// Permanently decrypt a container that was encrypted in place (VeraCrypt's
    /// "Permanently decrypt a non-system partition/volume"): the data is moved
    /// back down and the file becomes the plaintext image it was made from.
    DecryptInPlace(DecryptInPlaceArgs),
    /// Save a copy of a volume's header area (VeraCrypt's "Backup Volume
    /// Header"), so a damaged header can be restored later without the data
    /// area being needed.
    BackupHeaders(BackupHeadersArgs),
    /// Restore a volume's header (VeraCrypt's "Restore Volume Header"): from a
    /// header backup file, from the copy embedded in the container itself, or
    /// rebuilt from a master key when every header copy is gone.
    RestoreHeaders(RestoreHeadersArgs),
    /// Change a volume's password, keyfiles, PIM and/or header hash (VeraCrypt's
    /// "Change Volume Password"). Only the header is rewritten -- the data area
    /// is not re-encrypted, so it is instant.
    Change(ChangeArgs),
    /// Write a new keyfile (VeraCrypt's "Create Keyfile"): a file of random
    /// bytes that has to be given with `--keyfile` on top of the password, so
    /// the password alone is not enough to open the volume.
    CreateKeyfile(CreateKeyfileArgs),
    /// List the volumes this machine has attached over iSCSI (`vcrs mount`),
    /// together with the disk Windows sees for each of them.
    List(ListArgs),
    /// Run the built-in crypto self-test: the format's checksums, every header
    /// hash, every encryption algorithm and a header round trip. Useful to
    /// confirm a fresh build (and Botan) works before creating a volume.
    Test(TestArgs),
    /// Describe a partition or volume and whether it can be encrypted in place
    /// (VeraCrypt's non-system in-place encryption needs a mounted NTFS volume
    /// whose filesystem can give up its last 128 KiB). Read-only: nothing is
    /// written, not even with --probe-shrink.
    DeviceInfo(DeviceInfoArgs),
}

#[derive(Args)]
struct CreateArgs {
    /// Volume file to create (must not exist).
    path: PathBuf,
    /// Volume size, e.g. `100M`, `4G`, or a byte count.
    #[arg(short, long, value_parser = parse_size)]
    size: u64,
    /// Encryption algorithm, e.g. `AES`, `Serpent-AES`, `AES-Twofish-Serpent`.
    #[arg(short, long, visible_alias = "encryption", default_value = "AES")]
    ea: String,
    /// Header key derivation function, e.g. `SHA-512`, `Blake2s`, `Argon2`.
    #[arg(long, visible_alias = "hash", default_value = "SHA-512")]
    prf: String,
    /// Quick format: leave the data area as the host filesystem reports it
    /// instead of writing random-looking data over it. Faster, but the
    /// untouched part of the volume then stays zero bytes on disk, which gives
    /// the container away as a container (VeraCrypt uses a full format by
    /// default for exactly this reason, and refuses a quick format for an outer
    /// volume that is meant to host a hidden volume).
    #[arg(long)]
    quick: bool,
    /// Create the container even when it is larger than the free space on the
    /// filesystem (VeraCrypt refuses that too).
    #[arg(long)]
    no_size_check: bool,
    /// Create a sparse (VeraCrypt's "dynamic") container: it is created at its
    /// full size but only the parts that are written use disk space. Implies a
    /// quick format (a full format would write every byte) and skips the
    /// free-space check, like VeraCrypt.
    #[arg(long)]
    sparse: bool,
    /// Read the volume's random bytes from this file instead of the operating
    /// system's generator, so the same file always builds the same container
    /// byte for byte (VeraCrypt's `--random-source` switch, but reproducible
    /// rather than extra entropy). Meant for tests and audits: the container's
    /// keys are then reproducible from that file, so never use it for a volume
    /// that is supposed to keep a secret.
    #[arg(long, value_name = "FILE")]
    random_source: Option<PathBuf>,
    /// Volume sector size (512, 1024, 2048 or 4096). VeraCrypt defaults to 512
    /// and uses 4096 for very large volumes; the header records it and the
    /// filesystem inside should match it. XTS data-unit numbering is 512-based
    /// regardless, so this changes no ciphertext.
    #[arg(long, default_value_t = 512, value_parser = parse_sector_size)]
    sector_size: u32,
    /// Print the master key of the new volume (it is masked otherwise).
    #[arg(long)]
    show_master_key: bool,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args)]
struct CreateHiddenArgs {
    /// Existing volume file to add a hidden volume to.
    path: PathBuf,
    /// Size of the hidden volume.
    #[arg(short, long, value_parser = parse_size)]
    size: u64,
    #[arg(short, long, default_value = "AES")]
    ea: String,
    #[arg(long, default_value = "SHA-512")]
    prf: String,
    /// Volume sector size, as for `create`.
    #[arg(long, default_value_t = 512, value_parser = parse_sector_size)]
    sector_size: u32,
    /// Read the volume's random bytes from this file, as for `create`.
    #[arg(long, value_name = "FILE")]
    random_source: Option<PathBuf>,
    /// Print the master key of the new hidden volume (it is masked otherwise).
    #[arg(long)]
    show_master_key: bool,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args, Clone)]
struct PasswordArgs {
    /// Volume password.
    #[arg(short, long, env = "VCRS_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    /// Read the password from stdin (raw bytes, one trailing newline trimmed).
    #[arg(long, conflicts_with = "password")]
    password_stdin: bool,
    /// Personal iterations multiplier (0 = VeraCrypt default).
    #[arg(long, default_value_t = 0)]
    pim: i32,
    /// Keyfile, or a directory whose files are used as keyfiles.  Repeatable;
    /// the keyfile pool is mixed into the password exactly like VeraCrypt does.
    #[arg(short = 'k', long = "keyfile", value_name = "PATH", action = clap::ArgAction::Append)]
    keyfiles: Vec<PathBuf>,
}

impl PasswordArgs {
    fn read(&self) -> Result<Vec<u8>> {
        read_password(
            self.password.as_deref(),
            self.password_stdin,
            "no password given (use --password, $VCRS_PASSWORD or --password-stdin)",
            false,
        )
    }

    /// True when a credential was supplied, so a volume can be opened without
    /// having to ask.
    fn is_given(&self) -> bool {
        self.password.is_some() || self.password_stdin || !self.keyfiles.is_empty()
    }
    fn open_options(
        &self,
        volume_type: Option<VolumeType>,
        use_backup_header: bool,
    ) -> Result<OpenOptions> {
        Ok(OpenOptions {
            password: self.read()?,
            keyfiles: self.keyfiles.clone(),
            pim: self.pim,
            volume_type,
            use_backup_header,
            // VeraCrypt's tools do not leave a trace in the container's
            // timestamps, whether they mount it, change its password or just
            // check that the password is right.
            preserve_timestamps: true,
            ..Default::default()
        })
    }
}

/// Read a password the way every command does: raw bytes from stdin (with one
/// trailing newline trimmed), the UTF-8 bytes of the string that was given, or —
/// when there is neither and a person is at the terminal — a prompt with the echo
/// switched off. `fresh` marks a password that is being *set* rather than checked;
/// those are asked for twice, so one typo cannot lock the volume away for good.
fn read_password(
    value: Option<&str>,
    from_stdin: bool,
    missing: &str,
    fresh: bool,
) -> Result<Vec<u8>> {
    if from_stdin {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        if buf.last() == Some(&b'\n') {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
        }
        return Ok(buf);
    }
    match value {
        Some(password) => Ok(password.as_bytes().to_vec()),
        None if fresh => prompt::new_password(missing),
        None => prompt::password(missing),
    }
}

/// The credentials to put into a header, for `vcrs change`. VeraCrypt's
/// change-password dialog asks for the same fields.
#[derive(Args, Clone)]
struct NewPasswordArgs {
    /// New password.
    #[arg(
        long = "new-password",
        env = "VCRS_NEW_PASSWORD",
        hide_env_values = true
    )]
    new_password: Option<String>,
    /// Read the new password from stdin (raw bytes, one trailing newline trimmed).
    #[arg(long = "new-password-stdin", conflicts_with = "new_password")]
    new_password_stdin: bool,
    /// New keyfile (repeatable); replaces the volume's current keyfiles.
    #[arg(long = "new-keyfile", value_name = "PATH", action = clap::ArgAction::Append)]
    new_keyfiles: Vec<PathBuf>,
    /// New PIM. Defaults to the PIM the volume is opened with, so that changing
    /// only the password cannot silently weaken the key derivation.
    #[arg(long = "new-pim", value_name = "N")]
    new_pim: Option<i32>,
    /// New header hash algorithm; defaults to the one the volume already uses.
    #[arg(long = "new-hash", value_name = "PRF")]
    new_prf: Option<String>,
}

impl NewPasswordArgs {
    fn read(&self) -> Result<Vec<u8>> {
        read_password(
            self.new_password.as_deref(),
            self.new_password_stdin,
            "no new password given (use --new-password, $VCRS_NEW_PASSWORD or \
             --new-password-stdin)",
            true,
        )
    }

    /// The password bytes the KDF sees, i.e. with the keyfile pool mixed in.
    fn effective_password(&self, volume: &Path) -> Result<Vec<u8>> {
        Ok(vcrs_core::apply_keyfiles(
            &self.read()?,
            &self.new_keyfiles,
            Some(volume),
        )?)
    }
}

#[derive(Args)]
struct FormatArgs {
    /// Volume file holding the filesystem.
    path: PathBuf,
    /// Volume label (max 11 characters).
    #[arg(long, default_value = "")]
    label: String,
    #[command(flatten)]
    kind: VolumeKindArgs,
    #[command(flatten)]
    password: PasswordArgs,
    #[command(flatten)]
    protect: HiddenProtectionArgs,
}

#[derive(Args)]
struct MountArgs {
    /// Volume file to mount.
    path: PathBuf,
    /// How the disk is presented to the initiator: `partition` (default; the
    /// data area is exposed as one partition behind a synthetic in-memory MBR,
    /// which is what Windows needs to format it) or `raw` (the data area starts
    /// at LBA 0, i.e. a partitionless "super floppy").
    #[arg(
        long,
        aliases = ["iscsi", "raw"],
        value_name = "MODE",
        num_args = 0..=1,
        default_missing_value = "partition"
    )]
    disk_mode: Option<String>,
    /// Report the disk as removable media (the INQUIRY RMB bit).
    ///
    /// Windows only offers exFAT in its format dialogs for removable media, so
    /// this is how to get exFAT into that list.
    #[arg(long)]
    removable: bool,
    /// Address the iSCSI target listens on (default `127.0.0.1:3260`).
    #[arg(long, value_name = "ADDR")]
    bind: Option<String>,
    /// IQN the iSCSI target is published under.
    #[arg(long, value_name = "IQN")]
    target_name: Option<String>,
    /// Refuse all writes.
    #[arg(long)]
    read_only: bool,
    /// Keep the iSCSI target running this many seconds after the last initiator
    /// logs out (default 5, `0` = keep serving until Ctrl-C).
    #[arg(long, value_name = "SECONDS")]
    idle_timeout: Option<u64>,
    /// Do not preserve the container's modification timestamp. VeraCrypt keeps
    /// it unchanged by default (its "Preserve modification timestamp of file
    /// containers" option), so that using a volume does not reveal when it was
    /// used; pass this to let the container's timestamp change normally.
    #[arg(long)]
    no_preserve_timestamp: bool,
    /// Open the volume through its backup header instead of the primary one
    /// (VeraCrypt's "Use backup header embedded in volume if available",
    /// `/mountoption headerbak`). Useful when the primary header is damaged.
    #[arg(long)]
    backup: bool,
    /// Put the mounted volume on this drive letter, e.g. `--letter Y`.
    ///
    /// The attach needs an elevated prompt, so this asks Windows for one (a
    /// single UAC prompt) and waits for it; from an already elevated prompt
    /// there is no prompt at all. Once the letter is there the mount has done
    /// its job, so the target is handed to a detached copy of this program and
    /// the prompt comes back — the volume stays mounted until `vcrs dismount`
    /// (or until the initiator logs out and the idle timeout runs out).
    /// `--foreground` keeps serving in this terminal instead, which is what
    /// `vcrs mount` does without `--letter`.
    #[arg(long, value_name = "LETTER")]
    letter: Option<char>,
    /// Serve the volume in this terminal even when `--letter` is given (Ctrl-C
    /// then stops the target).
    #[arg(long)]
    foreground: bool,
    #[command(flatten)]
    kind: VolumeKindArgs,
    #[command(flatten)]
    password: PasswordArgs,
    #[command(flatten)]
    protect: HiddenProtectionArgs,
}

/// What `vcrs agent` was asked to do.
#[derive(Args)]
struct AgentArgs {
    /// Run the helper: listen for requests until the idle timeout, then end.
    /// Normally started by the first prompt, not by hand.
    #[arg(long)]
    serve: bool,
    /// End the helper that is running.
    #[arg(long, conflicts_with = "serve")]
    stop: bool,
    /// Say whether a helper is running, and its pid.
    #[arg(long, conflicts_with_all = ["serve", "stop"])]
    status: bool,
    /// Minutes with no requests after which the helper ends itself.
    #[arg(long, value_name = "MINUTES", default_value_t = agent::DEFAULT_IDLE.as_secs_f64() / 60.0)]
    idle: f64,
}

#[derive(Args)]
struct AttachArgs {
    /// IQN of the target `vcrs mount` is serving (printed by `vcrs mount`).
    #[arg(long, value_name = "IQN")]
    iqn: String,
    /// `host:port` the target listens on.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:3260")]
    address: String,
    /// Drive letter to put the volume on, e.g. `Y` (Windows picks one itself
    /// when this is not given).
    #[arg(long, value_name = "LETTER")]
    letter: Option<char>,
    /// Size in bytes of the disk the target presents. Used to tell this
    /// volume's disk apart from another one when several are served at once.
    #[arg(long, value_name = "BYTES")]
    disk_size: Option<u64>,
    /// How long to wait for Windows to show the disk.
    #[arg(long, value_name = "SECONDS", default_value_t = 30)]
    wait: u64,
    /// Write the output to this file as well (used by `vcrs mount --letter`,
    /// whose elevated child has a console window of its own).
    #[arg(long, value_name = "FILE")]
    log: Option<PathBuf>,
}

#[derive(Args)]
struct DetachArgs {
    /// Target to detach, by the IQN `vcrs mount` printed.
    #[arg(long, value_name = "IQN", conflicts_with_all = ["letter", "all"])]
    iqn: Option<String>,
    /// The volume Windows has on this drive letter.
    #[arg(long, value_name = "LETTER", conflicts_with = "all")]
    letter: Option<char>,
    /// Detach every target vc-rs serves.
    #[arg(long)]
    all: bool,
    /// Write the output to this file as well (used by the `vcrs dismount` that
    /// started this process, which reads the file back).
    #[arg(long, value_name = "FILE")]
    log: Option<PathBuf>,
}

#[derive(Args)]
struct DismountArgs {
    /// The container `vcrs mount` is serving (`vcrs dismount secret.vc`). The
    /// target name is derived from the file name exactly as the mount does it,
    /// so the extension does not matter.
    #[arg(value_name = "CONTAINER", conflicts_with_all = ["iscsi", "letter", "all"])]
    path: Option<PathBuf>,
    /// The volume Windows has on this drive letter (`vcrs dismount --letter S`).
    #[arg(long, value_name = "LETTER", conflicts_with_all = ["iscsi", "all"])]
    letter: Option<char>,
    /// The target by name, exactly as `vcrs mount` printed it.
    #[arg(long, value_name = "IQN", conflicts_with = "all")]
    iscsi: Option<String>,
    /// Every target vc-rs serves — what a bare `vcrs dismount` does, like
    /// VeraCrypt's `/dismount` without a volume.
    #[arg(long)]
    all: bool,
    /// Write the output to this file as well (used by the elevated child this
    /// command starts; not meant to be typed by hand).
    #[arg(long, value_name = "FILE", hide = true)]
    log: Option<PathBuf>,
}

#[derive(Args)]
struct ExpandArgs {
    /// Container to grow.
    path: PathBuf,
    /// New size of the container, e.g. `200M`, `2G` (must be larger than the
    /// current size).
    #[arg(short, long, value_parser = parse_size)]
    size: u64,
    /// Confirm the expansion even though any hidden volume inside the container
    /// is destroyed by it (VeraCrypt asks the same question interactively).
    #[arg(long)]
    force: bool,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args)]
struct EncryptInPlaceArgs {
    /// Image file to encrypt in place: a plain (unencrypted) file/partition image
    /// whose last 128 KiB are free (VeraCrypt shrinks the filesystem by that much
    /// first; a partition image usually needs `truncate -s -128K` or zeroed
    /// trailing bytes). If the file already contains a container whose in-place
    /// encryption was interrupted, the run resumes instead.
    ///
    /// A partition or volume (`E:`, `\\.\HarddiskVolume22`) is encrypted the way
    /// VeraCrypt's non-system in-place encryption works: the NTFS filesystem is
    /// shrunk to make room for the header areas and then moved towards the end of
    /// the device while it is encrypted. This needs an elevated prompt, a mounted
    /// NTFS volume, and `--yes`; the volume cannot be mounted again until the run
    /// finishes (an interrupted run is resumed with `--resume`).
    path: PathBuf,
    /// Encryption algorithm for the new volume.
    #[arg(long, default_value = "AES")]
    ea: String,
    /// Header key derivation function for the new volume.
    #[arg(long, default_value = "SHA-512")]
    prf: String,
    /// Read the random bytes that build the volume from this file instead of the
    /// operating system's generator (VeraCrypt's `--random-source`).
    #[arg(long)]
    random_source: Option<PathBuf>,
    /// Confirm that a partition may be transformed in place. Without it a device
    /// path is only described, never written to; container files ignore this.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args)]
struct DecryptInPlaceArgs {
    /// Container made by `vcrs encrypt-in-place` (or by VeraCrypt's in-place
    /// encryption). It must hold a *completed* in-place volume; the run moves the
    /// data back down and truncates the file to the plaintext image it was made
    /// from.
    path: PathBuf,
    /// Continue an interrupted in-place *decryption*. Without it a run only starts
    /// from a completed in-place volume, because a half decrypted and a half
    /// encrypted container look identical in the header (VeraCrypt tells them apart
    /// by the switch too: `/resumeinplacedec` vs `/zinplace`).
    #[arg(long)]
    resume: bool,
    /// Confirm that a partition may be transformed in place (a device path is only
    /// described without it). Container files ignore this.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    password: PasswordArgs,
}

/// Saves a header backup.
#[derive(Args)]
struct BackupHeadersArgs {
    /// Volume file whose header area is saved.
    path: PathBuf,
    /// Where to write the backup (default: `<volume>.hc`).
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

/// Restores a header from one of the three sources.
#[derive(Args)]
#[command(group = clap::ArgGroup::new("source").required(true).args(["from", "embedded", "master_key"]))]
struct RestoreHeadersArgs {
    /// Volume file whose header is restored.
    path: PathBuf,
    /// Restore from a header backup written by `vcrs backup-headers`.
    #[arg(long, value_name = "FILE")]
    from: Option<PathBuf>,
    /// Restore from the backup header embedded in the container itself (the
    /// copy at the end of the file), without needing a backup file.
    #[arg(long)]
    embedded: bool,
    /// Rebuild the header from the volume's master key, in hex, for when every
    /// header copy is lost. The data area itself is untouched.
    #[arg(long, value_name = "HEX")]
    master_key: Option<String>,
    /// Size of the volume's data area when rebuilding from a master key. An
    /// ordinary volume's data area is `container size - 262144` and is computed
    /// automatically; a hidden volume's has to be given here.
    #[arg(long, value_name = "SIZE", value_parser = parse_size, requires = "master_key")]
    data_size: Option<u64>,
    /// Encryption algorithm the master key belongs to.
    #[arg(long, default_value = "AES")]
    ea: String,
    /// Header hash algorithm for the rebuilt header.
    #[arg(long, default_value = "SHA-512")]
    prf: String,
    /// Sector size the volume was created with.
    #[arg(long, default_value_t = 512)]
    sector_size: u32,
    /// Which header to restore: the hidden volume's instead of the outer one.
    #[command(flatten)]
    kind: VolumeKindArgs,
    /// The volume's password (or, when rebuilding from a master key, the
    /// password the rebuilt header should use). Without one the restored header
    /// is written but not verified.
    #[command(flatten)]
    password: PasswordArgs,
}

/// `vcrs change` arguments.
#[derive(Args)]
struct ChangeArgs {
    /// Volume whose header is rewritten.
    path: PathBuf,
    /// Open the volume's *backup* header first (for a volume whose primary
    /// header is damaged).
    #[arg(long)]
    backup: bool,
    /// Which volume to change: the hidden volume's header instead of the outer
    /// one.
    #[command(flatten)]
    kind: VolumeKindArgs,
    /// The volume's current credentials.
    #[command(flatten)]
    password: PasswordArgs,
    /// The credentials to put into the header.
    #[command(flatten)]
    new: NewPasswordArgs,
}

/// Create a keyfile: a file of random bytes that has to be given with
/// `--keyfile` in addition to the password.
#[derive(Args)]
struct CreateKeyfileArgs {
    /// File to create (it must not exist unless --force is given).
    path: PathBuf,
    /// Take the bytes from this file instead of the system random generator
    /// (the file is read from its start and repeated until the keyfile is full).
    #[arg(long)]
    random_source: Option<PathBuf>,
    /// Overwrite the file if it already exists.
    #[arg(long)]
    force: bool,
}

/// List the volumes attached over iSCSI.
#[derive(Args)]
struct ListArgs {
    /// Show every iSCSI session, not just the ones vc-rs serves.
    #[arg(long)]
    all: bool,
}

/// Run the built-in crypto self-test.
#[derive(Args)]
struct TestArgs {}

/// Arguments of `vcrs device-info`.
#[derive(Args)]
struct DeviceInfoArgs {
    /// Partition or volume to describe: a drive letter (`E:`) or a device like
    /// `\\.\PhysicalDrive1\Partition2`. Reading a device needs an elevated
    /// prompt.
    device: PathBuf,
    /// Also ask NTFS whether it could give up its tail right now (VeraCrypt's
    /// `FSCTL_SHRINK_VOLUME` in `ShrinkPrepare` mode, immediately undone with
    /// `ShrinkAbort`). Nothing is written and the filesystem is not resized; it
    /// answers the question that otherwise only shows up half way through the
    /// encryption. Leave it off if the volume is in use.
    #[arg(long)]
    probe_shrink: bool,
}

/// Selects which volume of a container to address.
#[derive(Args, Clone, Copy, Default)]
struct VolumeKindArgs {
    /// Address the hidden volume instead of the outer one.
    #[arg(long)]
    hidden: bool,
}

impl VolumeKindArgs {
    fn volume_type(&self) -> Option<VolumeType> {
        if self.hidden {
            Some(VolumeType::Hidden)
        } else {
            None
        }
    }
}

/// VeraCrypt's *protect hidden volume* option: while the outer volume is in use,
/// any write that would land inside the hidden volume fails instead of
/// destroying it. Needs the hidden volume's own credentials.
#[derive(Args, Clone)]
struct HiddenProtectionArgs {
    /// Protect the hidden volume inside this outer volume from being written to.
    #[arg(long)]
    protect_hidden: bool,
    /// Password of the hidden volume.
    #[arg(
        long = "hidden-password",
        visible_alias = "protection-password",
        env = "VCRS_HIDDEN_PASSWORD",
        hide_env_values = true
    )]
    hidden_password: Option<String>,
    /// Read the hidden volume's password from stdin (raw bytes).
    #[arg(long = "hidden-password-stdin", conflicts_with = "hidden_password")]
    hidden_password_stdin: bool,
    /// PIM of the hidden volume.
    #[arg(
        long = "hidden-pim",
        visible_alias = "protection-pim",
        default_value_t = 0
    )]
    hidden_pim: i32,
    /// Keyfile of the hidden volume (repeatable).
    #[arg(
        long = "hidden-keyfile",
        visible_alias = "protection-keyfile",
        value_name = "PATH",
        action = clap::ArgAction::Append
    )]
    hidden_keyfiles: Vec<PathBuf>,
}

impl HiddenProtectionArgs {
    /// How to open the hidden volume, or `None` when protection is off.
    fn hidden_open_options(&self) -> Result<Option<OpenOptions>> {
        if !self.protect_hidden {
            if self.hidden_password.is_some()
                || self.hidden_password_stdin
                || !self.hidden_keyfiles.is_empty()
            {
                bail!("--hidden-password/--hidden-pim/--hidden-keyfile need --protect-hidden");
            }
            return Ok(None);
        }
        let creds = PasswordArgs {
            password: self.hidden_password.clone(),
            password_stdin: self.hidden_password_stdin,
            pim: self.hidden_pim,
            keyfiles: self.hidden_keyfiles.clone(),
        };
        let options = creds
            .open_options(Some(VolumeType::Hidden), false)
            .context(
                "--protect-hidden needs the hidden volume's password \
             (--hidden-password, $VCRS_HIDDEN_PASSWORD or --hidden-password-stdin)",
            )?;
        Ok(Some(options))
    }
}

/// Turn on hidden-volume protection for an already opened outer volume.
fn apply_hidden_protection(
    volume: &Volume,
    protect: &HiddenProtectionArgs,
    path: &Path,
) -> Result<()> {
    let Some(hidden_options) = protect.hidden_open_options()? else {
        return Ok(());
    };
    let hidden = Volume::open(path, &hidden_options).with_context(|| {
        format!(
            "opening the hidden volume of {} (needed by --protect-hidden)",
            path.display()
        )
    })?;
    let range = ProtectedRange::new(hidden.data_offset, hidden.data_size);
    println!(
        "protecting the hidden volume: host range {}..{} ({} bytes) is now write-protected",
        range.start,
        range.end(),
        range.length
    );
    volume.protect_hidden_volume(range);
    Ok(())
}

#[derive(Args)]
struct InfoArgs {
    path: PathBuf,
    /// Open the backup header (at the end of the file) instead of the primary one.
    #[arg(long)]
    backup: bool,
    /// Print the master key (masked by default: it decrypts the data area without
    /// the password).
    #[arg(long)]
    show_master_key: bool,
    #[command(flatten)]
    kind: VolumeKindArgs,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args)]
struct HeaderArgs {
    path: PathBuf,
    /// Dump the backup header region instead of the primary one.
    #[arg(long)]
    backup: bool,
    /// Only print the 512-byte effective header.
    #[arg(long)]
    short: bool,
}

#[derive(Args)]
struct ReadArgs {
    path: PathBuf,
    /// Offset inside the encrypted data area.
    #[arg(short, long, default_value_t = 0)]
    offset: u64,
    /// Number of bytes to read.
    #[arg(short, long, default_value_t = 512, value_parser = parse_size)]
    length: u64,
    /// Write the bytes to this file instead of dumping them.
    #[arg(long)]
    out: Option<PathBuf>,
    #[command(flatten)]
    kind: VolumeKindArgs,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args)]
struct WriteArgs {
    path: PathBuf,
    /// Offset inside the encrypted data area.
    #[arg(short, long, default_value_t = 0)]
    offset: u64,
    /// Bytes to write, as hex (leading 0x optional).
    #[arg(long)]
    hex: Option<String>,
    /// Read the bytes to write from this file.
    #[arg(long, conflicts_with = "hex")]
    from: Option<PathBuf>,
    #[command(flatten)]
    kind: VolumeKindArgs,
    #[command(flatten)]
    password: PasswordArgs,
    #[command(flatten)]
    protect: HiddenProtectionArgs,
}

/// The exit codes are VeraCrypt's own where they exist: 0 for "it worked", 1 for
/// "it did not", 2 for a usage mistake (clap), and Windows' 1223 when the
/// elevation prompt was declined — so a script can tell the user's "no" from a
/// real failure.
fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vcrs: error: {e:#}");
            if e.downcast_ref::<attach::Cancelled>().is_some() {
                // `std::process::exit` keeps the whole 32-bit code; an `ExitCode`
                // built from a `u8` would truncate 1223 to 199.
                std::process::exit(attach::ELEVATION_CANCELLED);
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let json = cli.json;
    match cli.command {
        Command::Create(a) => {
            let ea = parse_ea(&a.ea)?;
            let prf = parse_prf(&a.prf)?;
            // A sparse (dynamic) container only uses the space that is actually
            // written, so the free-space check does not apply to it -- and
            // VeraCrypt only sets the sparse flag for a quick format.
            let quick = a.quick || a.sparse;
            if a.sparse && !a.quick {
                println!(
                    "note: a sparse (dynamic) container is quick-formatted; --sparse implies --quick"
                );
            }
            if a.sparse {
                println!(
                    "note: {} is created at its full size but only uses the space that is written\n  \
                     (Windows Explorer and `vcrs info` still show the maximum size; look at the file's\n  \
                     \"Size on disk\" instead). Moving the file to another volume can expand it.",
                    a.path.display()
                );
            } else if !a.no_size_check {
                check_free_space(&a.path, a.size)?;
            }
            if quick && !a.sparse {
                eprintln!(
                    "warning: --quick leaves the unused part of the data area empty on disk (zero \
                     bytes on\n  NTFS/ext4), so it is recognisable as a region nobody wrote to. \
                     VeraCrypt uses a\n  full format by default for that reason, and refuses quick \
                     formats for an outer volume\n  that is meant to host a hidden volume."
                );
            }
            if let Some(source) = &a.random_source {
                eprintln!(
                    "warning: --random-source makes {} reproducible from {}: anyone who has that \
                     file can\n  rebuild the container's keys. Use it for tests and audits, not for \
                     a real volume.",
                    a.path.display(),
                    source.display()
                );
            }
            let options = CreateOptions {
                ea,
                prf,
                password: a.password.read()?,
                keyfiles: a.password.keyfiles.clone(),
                pim: a.password.pim,
                sector_size: a.sector_size,
                full_format: !quick,
                sparse: a.sparse,
                random_source: a.random_source.clone(),
            };
            let started = std::time::Instant::now();
            let volume = Volume::create(&a.path, a.size, &options)?;
            println!(
                "created {} ({}, {:.2} MiB) in {:.2}s",
                a.path.display(),
                ea.name(),
                a.size as f64 / (1024.0 * 1024.0),
                started.elapsed().as_secs_f64()
            );
            print_header(&volume, a.show_master_key);
            Ok(())
        }
        Command::CreateHidden(a) => {
            if vcrs_core::looks_quick_formatted(&a.path)? {
                eprintln!(
                    "warning: {} looks like it was created with a quick format (its unused space is\n  \
                     still zero bytes on disk), so a hidden volume inside it can be detected. \
                     VeraCrypt\n  refuses to put a hidden volume into a quickly formatted outer \
                     volume.",
                    a.path.display()
                );
            }
            let options = CreateOptions {
                ea: parse_ea(&a.ea)?,
                prf: parse_prf(&a.prf)?,
                password: a.password.read()?,
                keyfiles: a.password.keyfiles.clone(),
                pim: a.password.pim,
                sector_size: a.sector_size,
                full_format: false,
                sparse: false,
                random_source: a.random_source.clone(),
            };
            let started = std::time::Instant::now();
            let volume = Volume::create_hidden(&a.path, a.size, &options)
                .context("creating a hidden volume inside the existing container")?;
            println!(
                "created a {} hidden volume in {} in {:.2}s",
                volume.header.ea.name(),
                a.path.display(),
                started.elapsed().as_secs_f64()
            );
            print_header(&volume, a.show_master_key);
            Ok(())
        }
        Command::Info(a) => {
            let options = a.password.open_options(a.kind.volume_type(), a.backup)?;
            let volume = Volume::open(&a.path, &options)?;
            print_header(&volume, a.show_master_key);
            Ok(())
        }
        Command::Header(a) => dump_header_region(&a),
        Command::Read(a) => {
            let volume = open_ro(&a.path, &a.password, a.kind.volume_type())?;
            let mut buf = vec![0u8; a.length as usize];
            volume.read_data(a.offset, &mut buf)?;
            if let Some(out) = a.out {
                std::fs::write(&out, &buf)?;
                println!("wrote {} bytes to {}", buf.len(), out.display());
            } else {
                print_hex_dump(a.offset, &buf);
            }
            Ok(())
        }
        Command::Write(a) => {
            let data = match (&a.hex, &a.from) {
                (Some(h), _) => parse_hex(h)?,
                (None, Some(p)) => std::fs::read(p)?,
                (None, None) => bail!("pass --hex or --from"),
            };
            let volume = open_rw(&a.path, &a.password, a.kind.volume_type())?;
            apply_hidden_protection(&volume, &a.protect, &a.path)?;
            volume.write_data(a.offset, &data)?;
            volume.flush()?;
            println!("wrote {} bytes at data offset {}", data.len(), a.offset);
            Ok(())
        }
        Command::Format(a) => {
            let mut volume = open_rw(&a.path, &a.password, a.kind.volume_type())?;
            apply_hidden_protection(&volume, &a.protect, &a.path)?;
            vcrs_mount::format_volume(&mut volume, &a.label)?;
            volume.flush()?;
            println!(
                "created a FAT32 filesystem (label {:?}) in {}",
                a.label,
                a.path.display()
            );
            println!("expose it to Windows with: vcrs mount {}", a.path.display());
            Ok(())
        }
        Command::Expand(a) => {
            if !a.force {
                bail!(
                    "expanding a container destroys any hidden volume inside it (VeraCrypt asks \
                     the same question interactively); pass --force if you are sure that {} has \
                     no hidden volume",
                    a.path.display()
                );
            }
            // Build the options once: `--password-stdin` can only be read once.
            let options = a.password.open_options(None, false)?;
            let password = options.effective_password(Some(&a.path))?;
            let mut volume = Volume::open(&a.path, &options)?;
            let old_host_size = volume.host_size;
            let old_data_size = volume.data_size;
            let started = std::time::Instant::now();
            volume.expand(a.size, &password, a.password.pim)?;
            volume.flush()?;
            println!(
                "expanded {} from {old_host_size} to {} bytes in {:.2}s",
                a.path.display(),
                volume.host_size,
                started.elapsed().as_secs_f64()
            );
            println!(
                "  data area: {} -> {} bytes (the master key and the existing data are unchanged)",
                old_data_size, volume.data_size
            );
            println!(
                "  the filesystem inside still has its old size: mount the volume and extend it \
                 there (Windows: Disk Management -> Extend Volume, or `Resize-Partition`)"
            );
            Ok(())
        }
        Command::EncryptInPlace(a) => {
            let ea = EncryptionAlgorithm::from_name(&a.ea)
                .with_context(|| format!("unknown encryption algorithm {:?}", a.ea))?;
            let prf = Prf::from_name(&a.prf).with_context(|| format!("unknown PRF {:?}", a.prf))?;
            if vcrs_core::looks_like_device(&a.path) {
                return encrypt_device(&a, ea, prf);
            }
            // Build the options once: `--password-stdin` can only be read once.
            let options = a.password.open_options(None, false)?;
            let password = options.effective_password(Some(&a.path))?;
            let host_size = std::fs::metadata(&a.path)
                .with_context(|| format!("reading {}", a.path.display()))?
                .len();
            let started = std::time::Instant::now();
            let mut reporter = watch_progress();
            let watch = vcrs_core::Watch::new(&mut reporter);
            let volume = vcrs_core::encrypt_in_place(
                &a.path,
                &password,
                a.password.pim,
                ea,
                prf,
                Some(watch),
            )?;
            let elapsed = started.elapsed();
            match volume.in_place() {
                Some(state) => {
                    println!(
                        "paused: {} of {} bytes encrypted ({:.1}%) in {:.1}s",
                        state.encrypted_length,
                        state.total(),
                        state.progress() * 100.0,
                        elapsed.as_secs_f64()
                    );
                    println!(
                        "  run the same command again to continue (it resumes from the backup \
                         header)"
                    );
                }
                None => {
                    println!(
                        "encrypted {} in place in {:.1}s (was {host_size} bytes)",
                        a.path.display(),
                        elapsed.as_secs_f64()
                    );
                    println!(
                        "  {}: {} byte data area, mountable like any other container",
                        volume.header.ea, volume.data_size
                    );
                }
            }
            Ok(())
        }
        Command::DecryptInPlace(a) => {
            if vcrs_core::looks_like_device(&a.path) {
                return decrypt_device(&a);
            }
            // Build the options once: `--password-stdin` can only be read once.
            let options = a.password.open_options(None, false)?;
            let password = options.effective_password(Some(&a.path))?;
            let started = std::time::Instant::now();
            let mut reporter = watch_progress();
            let watch = vcrs_core::Watch::new(&mut reporter);
            let outcome = vcrs_core::decrypt_in_place_stopping_after(
                &a.path,
                &password,
                a.password.pim,
                a.resume,
                None,
                Some(watch),
            )?;
            let elapsed = started.elapsed();
            if outcome.finished {
                println!(
                    "decrypted {} in place in {:.1}s",
                    a.path.display(),
                    elapsed.as_secs_f64()
                );
                println!(
                    "  the file is a {} byte plaintext image again (the filesystem followed by \
                     {} zero bytes)",
                    outcome.data_size + 131072,
                    131072
                );
            } else {
                let left = outcome.data_size - outcome.decrypted;
                println!(
                    "paused: {} of {} bytes decrypted ({:.1}%) in {:.1}s",
                    outcome.decrypted,
                    outcome.data_size,
                    outcome.decrypted as f64 * 100.0 / outcome.data_size.max(1) as f64,
                    elapsed.as_secs_f64()
                );
                println!(
                    "  {left} bytes are still encrypted; continue with \
                     `vcrs decrypt-in-place --resume`"
                );
            }
            Ok(())
        }
        Command::BackupHeaders(a) => {
            let out = a
                .out
                .clone()
                .unwrap_or_else(|| default_header_backup_path(&a.path));
            let written = vcrs_core::backup_headers(&a.path, &out)?;
            println!("wrote a {written} byte header backup to {}", out.display());
            println!(
                "  keep it away from the container: with this file and the password, a container \
                 whose\n  headers were destroyed can be restored without touching the data area"
            );
            Ok(())
        }
        Command::RestoreHeaders(a) => restore_headers(&a),
        Command::Change(a) => {
            let options = a.password.open_options(a.kind.volume_type(), a.backup)?;
            let mut volume = Volume::open(&a.path, &options)?;
            let new_password = a.new.effective_password(&a.path)?;
            // A PIM is not stored in the header, so "no --new-pim" means "keep
            // using the PIM this volume was opened with" rather than silently
            // dropping back to the default iteration count.
            let new_pim = a.new.new_pim.unwrap_or(a.password.pim);
            let new_prf = match &a.new.new_prf {
                Some(name) => Some(parse_prf(name)?),
                None => None,
            };
            let old_prf = volume.header.prf;
            volume.change_credentials(&new_password, new_pim, new_prf)?;
            println!(
                "changed the {} header of {}: hash {} -> {}, PIM {} -> {}",
                if a.kind.hidden { "hidden" } else { "ordinary" },
                a.path.display(),
                old_prf,
                volume.header.prf,
                a.password.pim,
                new_pim
            );
            println!("  the data area was not touched (the master key is unchanged)");
            print_header(&volume, false);
            Ok(())
        }
        Command::CreateKeyfile(a) => create_keyfile(&a),
        Command::List(a) => list_mounts(&a, json),
        Command::Test(_) => self_test(),
        Command::DeviceInfo(a) => device_info(&a),
        Command::Mount(a) => {
            let options = a.password.open_options(a.kind.volume_type(), a.backup)?;

            let disk_mode = match a.disk_mode.as_deref() {
                None => vcrs_mount::DiskMode::default(),
                Some(mode) => vcrs_mount::DiskMode::from_name(mode).with_context(|| {
                    format!("unknown disk mode {mode:?}; expected `partition` or `raw`")
                })?,
            };
            let mut iscsi = vcrs_mount::IscsiMountOptions::for_volume(&a.path);
            iscsi.disk_mode = disk_mode;
            iscsi.read_only = a.read_only;
            iscsi.removable = a.removable;
            iscsi.preserve_timestamp = !a.no_preserve_timestamp;
            if let Some(seconds) = a.idle_timeout {
                iscsi.idle_timeout = std::time::Duration::from_secs(seconds);
            }
            iscsi.protect_hidden = a.protect.hidden_open_options()?;
            if let Some(bind) = &a.bind {
                iscsi.bind_addr = bind.clone();
            } else {
                // Two volumes cannot share a portal, and the default portal is
                // `127.0.0.1:3260`: without this a second `vcrs mount` would fail
                // with `os error 10048` although nothing is wrong with it. The
                // initiator is told the portal in `AddTarget`, so a different port
                // costs nothing.
                iscsi.bind_addr = attach::free_bind_addr(&iscsi.bind_addr)?;
            }
            if let Some(name) = &a.target_name {
                iscsi.target_name = name.clone();
            } else if a.kind.hidden {
                // The hidden volume of a container needs its own target name: both
                // halves of one file would otherwise be served (and logged into)
                // under one IQN, so the second mount would land on the first one's
                // session and pull in the wrong disk — or be refused outright.
                iscsi.target_name = format!("{}-hidden", iscsi.target_name);
            }
            match a.letter {
                None => vcrs_mount::mount_iscsi(&a.path, &options, &iscsi)?,
                Some(letter) => {
                    // Refuse a letter that cannot work before a target is left
                    // running behind it.
                    let letter = attach::check_letter(letter)?;
                    if !a.foreground {
                        // With `--letter` the mount is finished by the time this
                        // command returns, so holding the terminal open for as
                        // long as the volume stays mounted buys nothing. The
                        // target moves to a detached copy of this program, which
                        // `vcrs dismount` stops again.
                        let mut report = attach::Report::new(None);
                        let server = serve::spawn(
                            &iscsi.target_name,
                            &options.password,
                            Some(letter),
                            &iscsi.bind_addr,
                            &mut report,
                        )?;
                        let request = attach::AttachOptions {
                            iqn: iscsi.target_name.clone(),
                            address: iscsi.bind_addr.clone(),
                            letter: Some(letter),
                            disk_size: serve::disk_size(&server),
                            wait: attach::DISK_WAIT,
                            log: None,
                        };
                        match attach::attach_with_elevation(&request) {
                            Ok(()) => {
                                serve::remember(&server)?;
                                println!(
                                    "{letter}: is mounted. `vcrs dismount --letter {letter}` (or \
                                     `vcrs dismount`) takes it off again."
                                );
                                return Ok(());
                            }
                            Err(err) => {
                                // Nothing was attached, so nothing should keep
                                // serving either.
                                let _ = serve::stop(&server, &mut report);
                                return Err(err).context(
                                    "attaching the volume; nothing is mounted (the background \
                                     server was stopped again)",
                                );
                            }
                        }
                    }
                    // Attaching is what produces the drive letter, and it needs
                    // elevation (iscsicli), so it happens once the target is up
                    // and before this process blocks on serving it. A failed
                    // attach must not kill the mount: the target is running, so
                    // report it and keep serving.
                    let hook = |mount: &vcrs_mount::IscsiMount, disk_size: u64| {
                        let request = attach::AttachOptions {
                            iqn: mount.target_name().to_string(),
                            address: mount.addr().to_string(),
                            letter: Some(letter),
                            disk_size: Some(disk_size),
                            wait: attach::DISK_WAIT,
                            log: None,
                        };
                        if let Err(err) = attach::attach_with_elevation(&request) {
                            println!("\ncould not attach the volume: {err:#}");
                            println!("the target keeps serving it; attach it by hand with");
                            println!(
                                "    vcrs attach --iqn {} --address {} --letter {}",
                                request.iqn, request.address, letter
                            );
                        }
                    };
                    vcrs_mount::mount_iscsi_with(&a.path, &options, &iscsi, Some(&hook))?;
                }
            }
            println!("iSCSI target stopped");
            Ok(())
        }
        Command::Attach(a) => {
            // The elevated half of a mount has to run to the end; a console control
            // event (a Ctrl-C in some arrangements, or a closing console) killed it
            // with STATUS_CONTROL_C_EXIT in the middle of the work.
            attach::ignore_console_control_events();
            if !attach::is_detached_worker() {
                return attach::wait_for_detached_worker();
            }
            // This is the run that had a prompt approved, so it is the run that can
            // leave an agent behind: the commands after it need no prompt at all.
            agent::start_if_absent();
            let log = a.log.clone();
            let request = attach::AttachOptions {
                iqn: a.iqn,
                address: a.address,
                letter: a.letter,
                disk_size: a.disk_size,
                wait: std::time::Duration::from_secs(a.wait),
                log: a.log,
            };
            if let Err(err) = attach::attach(&request) {
                // The elevated child gets a console of its own, so the process
                // that asked for it reads this file back: a failure has to be
                // in it, or all the parent sees is a bare exit code.
                if let Some(path) = &log {
                    use std::io::Write as _;
                    if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(path) {
                        let _ = writeln!(file, "vcrs: error: {err:#}");
                        let _ = writeln!(file, "{}", attach::FAILED);
                    }
                }
                return Err(err);
            }
            attach::mark_done(log.as_deref());
            Ok(())
        }
        Command::Dismount(a) => {
            let target = match (&a.path, a.letter, &a.iscsi, a.all) {
                (Some(path), _, _, _) => {
                    // The same derivation `vcrs mount` uses for the target name:
                    // the file stem, so `secret.vc` and `secret.hc` are one name.
                    if path.file_stem().and_then(|stem| stem.to_str()).is_none() {
                        bail!(
                            "cannot tell which target {} is: pass a container path, \
                             `--letter <LETTER>` or `--iscsi <IQN>`",
                            path.display()
                        );
                    }
                    detach::Target::Iqn(vcrs_mount::IscsiMountOptions::for_volume(path).target_name)
                }
                (None, Some(letter), _, _) => detach::Target::Letter(letter),
                (None, None, Some(iqn), _) => detach::Target::Iqn(iqn.clone()),
                (None, None, None, true) => detach::Target::All,
                // A bare `vcrs dismount` detaches everything vc-rs serves, the
                // way VeraCrypt's `/dismount` without a volume dismounts all —
                // but say so first, so nobody loses two volumes to a missing
                // argument.
                (None, None, None, false) => {
                    println!(
                        "no volume named: detaching every volume vc-rs serves (name one with a \
                         container path, `--letter <LETTER>` or `--iqn <IQN>`)"
                    );
                    detach::Target::All
                }
            };
            let options = detach::DetachOptions { target, log: a.log };
            detach::detach_with_elevation(&options)?;
            Ok(())
        }
        Command::Agent(a) => {
            if a.status {
                match agent::status() {
                    Some(pid) => println!("the agent (pid {pid}) is running"),
                    None => println!(
                        "no agent is running; the next `vcrs mount --letter` or `vcrs dismount` \
                         asks for a prompt once and leaves one behind"
                    ),
                }
                return Ok(());
            }
            if a.stop {
                if agent::stop() {
                    println!("the agent was asked to stop");
                } else {
                    println!("no agent is running");
                }
                return Ok(());
            }
            if !a.serve {
                bail!(
                    "say what to do: `vcrs agent --serve` starts one, `--status` asks after it, \
                     `--stop` ends it"
                );
            }
            // The launcher's console is a window somebody can close, and a console
            // app is killed with it (`0xC000013A`). The agent has to outlive its
            // launcher, so it hands the job to a console-less child of its own and
            // returns; that child is the agent.
            attach::ignore_console_control_events();
            if !attach::is_detached_worker() {
                attach::spawn_detached_worker()?;
                return Ok(());
            }
            agent::serve(std::time::Duration::from_secs_f64(a.idle.max(0.0) * 60.0))?;
            Ok(())
        }
        Command::Detach(a) => {
            attach::ignore_console_control_events();
            if !attach::is_detached_worker() {
                return attach::wait_for_detached_worker();
            }
            // The elevated run leaves an agent behind (see the `Attach` arm above).
            agent::start_if_absent();
            let log = a.log.clone();
            let target = match (&a.iqn, a.letter, a.all) {
                (Some(iqn), _, _) => detach::Target::Iqn(iqn.clone()),
                (None, Some(letter), _) => detach::Target::Letter(letter),
                (None, None, _) => detach::Target::All,
            };
            let options = detach::DetachOptions { target, log: a.log };
            let mut report = attach::Report::new(log.as_deref());
            if let Err(err) = detach::detach(&options, &mut report) {
                // The elevated child gets a console of its own, so the process
                // that asked for it reads this file back: a failure has to be
                // in it, or all the parent sees is a bare exit code.
                if let Some(path) = &log {
                    use std::io::Write as _;
                    if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(path) {
                        let _ = writeln!(file, "vcrs: error: {err:#}");
                        let _ = writeln!(file, "{}", attach::FAILED);
                    }
                }
                return Err(err);
            }
            attach::mark_done(log.as_deref());
            Ok(())
        }
    }
}

/// Detach a target from the Microsoft iSCSI Initiator (needs an elevated prompt).
///
/// The keyfiles VeraCrypt writes are `VolumePassword::MaxSize` = 128 bytes of
/// random data (see `CoreBase::CreateKeyfile` in src/Core/CoreBase.cpp).
const KEYFILE_SIZE: usize = 128;

/// Prints what an in-place transformation of a partition is about to do (and,
/// without `--yes`, is all that happens).
fn describe_device(device: &vcrs_core::Device, action: &str) -> Result<()> {
    let info = device.info();
    println!("{action} {}", info.path.display());
    println!(
        "  size            {} ({} bytes)",
        human_size(info.size),
        info.size
    );
    println!("  sector size     {}", info.sector_size);
    match (info.partition_style.as_deref(), info.partition_number) {
        (Some(style), Some(number)) => println!("  partition       {style} partition {number}"),
        _ => println!("  partition       (no partition table found)"),
    }
    println!(
        "  filesystem      {}",
        info.boot_sector_fs
            .as_deref()
            .unwrap_or("nothing recognisable")
    );
    if let Some(ntfs) = &info.ntfs {
        println!(
            "  filesystem size {} ({} bytes), {} free",
            human_size(ntfs.filesystem_size()),
            ntfs.filesystem_size(),
            human_size(ntfs.free_bytes())
        );
    }
    println!(
        "  data area       {} ({} bytes), from offset {} to {}",
        human_size(info.data_area_size()),
        info.data_area_size(),
        vcrs_core::header::VOLUME_HEADER_GROUP_SIZE,
        info.data_area_size() + vcrs_core::header::VOLUME_HEADER_GROUP_SIZE
    );
    println!(
        "  backup header   at offset {} ({})",
        info.backup_header_offset(),
        human_size(info.backup_header_offset())
    );
    Ok(())
}

/// `vcrs encrypt-in-place <partition>`: VeraCrypt's non-system in-place
/// encryption, driven against a real partition instead of a container file.
/// A watcher for a long in-place run: a line every five percent, on stderr so a
/// pipeline's stdout stays what the command meant to say.
fn watch_progress() -> impl FnMut(u64, u64) {
    let mut said = 0u64;
    let started = std::time::Instant::now();
    move |done: u64, total: u64| {
        if total == 0 {
            return;
        }
        let percent = done.saturating_mul(100) / total;
        if percent >= said + 5 || done == total {
            said = percent;
            eprintln!(
                "  {done} of {total} bytes ({percent}%), {:.0}s",
                started.elapsed().as_secs_f64()
            );
        }
    }
}

fn encrypt_device(a: &EncryptInPlaceArgs, ea: EncryptionAlgorithm, prf: Prf) -> Result<()> {
    let device = vcrs_core::Device::open(&a.path, true).with_context(|| {
        format!(
            "opening {} (a partition needs an elevated prompt)",
            a.path.display()
        )
    })?;
    describe_device(&device, "will encrypt")?;
    let info = device.info().clone();
    if let Some(reason) = info.blocker() {
        bail!("cannot encrypt {} in place: {reason}", info.path.display());
    }
    if !a.yes {
        bail!(
            "pass --yes to encrypt {} in place: this rewrites the partition's filesystem, and the \
             volume cannot be mounted again until the run finishes (an interrupted run is resumed \
             by running the same command again)",
            info.path.display()
        );
    }
    let options = vcrs_core::DeviceInPlaceOptions {
        password: a.password.read()?,
        keyfiles: a.password.keyfiles.clone(),
        pim: a.password.pim,
        ea,
        prf,
        random_source: a.random_source.clone(),
    };
    println!(
        "encrypting {} in place ({} byte data area): the run can be interrupted and resumed",
        info.path.display(),
        info.data_area_size()
    );
    let started = std::time::Instant::now();
    let mut reporter = watch_progress();
    let watch = vcrs_core::Watch::new(&mut reporter);
    let outcome = vcrs_core::encrypt_device_in_place(&device, &options, None, Some(watch))?;
    let elapsed = started.elapsed();
    if outcome.finished {
        println!(
            "encrypted {} in place in {:.1}s",
            info.path.display(),
            elapsed.as_secs_f64()
        );
        println!(
            "  {}: {} byte data area, a VeraCrypt volume on a partition",
            ea, outcome.data_size
        );
        println!(
            "  mount it with VeraCrypt: `vcrs mount` serves *containers* over iSCSI, a bare \
             partition needs a filesystem driver"
        );
    } else {
        println!(
            "paused: {} of {} bytes encrypted ({:.1}%) in {:.1}s",
            outcome.transformed,
            outcome.total,
            outcome.progress() * 100.0,
            elapsed.as_secs_f64()
        );
        println!(
            "  {} bytes are still plaintext; continue by running the same command again",
            outcome.total - outcome.transformed
        );
    }
    Ok(())
}

/// `vcrs decrypt-in-place <partition>`: the mirror of [`encrypt_device`].
fn decrypt_device(a: &DecryptInPlaceArgs) -> Result<()> {
    let device = vcrs_core::Device::open(&a.path, true).with_context(|| {
        format!(
            "opening {} (a partition needs an elevated prompt)",
            a.path.display()
        )
    })?;
    describe_device(&device, "will decrypt")?;
    let info = device.info().clone();
    if !a.yes {
        bail!(
            "pass --yes to decrypt {} in place: this rewrites the partition",
            info.path.display()
        );
    }
    let options = vcrs_core::DeviceInPlaceOptions {
        password: a.password.read()?,
        keyfiles: a.password.keyfiles.clone(),
        pim: a.password.pim,
        // Discovered from the volume's own header while it opens.
        ea: EncryptionAlgorithm::Aes,
        prf: Prf::Sha512,
        random_source: None,
    };
    let started = std::time::Instant::now();
    let mut reporter = watch_progress();
    let watch = vcrs_core::Watch::new(&mut reporter);
    let outcome =
        vcrs_core::decrypt_device_in_place(&device, &options, a.resume, None, Some(watch))?;
    let elapsed = started.elapsed();
    if outcome.finished {
        println!(
            "decrypted {} in place in {:.1}s",
            info.path.display(),
            elapsed.as_secs_f64()
        );
        println!(
            "  the partition holds a plain {} byte filesystem again (Windows mounts it directly; \
             the device kept its {} bytes)",
            outcome.data_size, outcome.device_size
        );
    } else {
        println!(
            "paused: {} of {} bytes decrypted ({:.1}%) in {:.1}s",
            outcome.transformed,
            outcome.total,
            outcome.progress() * 100.0,
            elapsed.as_secs_f64()
        );
        println!(
            "  continue with `vcrs decrypt-in-place {} --resume --yes`",
            info.path.display()
        );
    }
    Ok(())
}

/// Write a keyfile. The bytes are random (or taken from `--random-source`,
/// which is what makes keyfile creation reproducible in tests).
fn create_keyfile(a: &CreateKeyfileArgs) -> Result<()> {
    if a.path.exists() && !a.force {
        bail!(
            "{} already exists; pass --force to overwrite it (the old keyfile would be lost)",
            a.path.display()
        );
    }
    let bytes = match &a.random_source {
        Some(source) => {
            let data = std::fs::read(source)
                .with_context(|| format!("reading the random source {}", source.display()))?;
            if data.is_empty() {
                bail!("the random source {} is empty", source.display());
            }
            data.iter().copied().cycle().take(KEYFILE_SIZE).collect()
        }
        None => vcrs_core::random_bytes(KEYFILE_SIZE)?,
    };
    std::fs::write(&a.path, &bytes)
        .with_context(|| format!("writing the keyfile {}", a.path.display()))?;
    println!(
        "wrote a {KEYFILE_SIZE} byte keyfile to {}",
        a.path.display()
    );
    println!(
        "  pass it with `--keyfile {}` in addition to the password; losing it makes the volume unopenable",
        a.path.display()
    );
    Ok(())
}

/// List the iSCSI sessions (ours, or all of them), the serving processes and the
/// disks Windows has.
fn list_mounts(a: &ListArgs, json: bool) -> Result<()> {
    #[cfg(not(windows))]
    {
        let _ = (a, json);
        bail!("listing iSCSI sessions needs the Microsoft iSCSI Initiator (Windows only)");
    }
    #[cfg(windows)]
    {
        let state = status::snapshot(a.all);
        if json {
            println!("{}", serde_json::to_string_pretty(&state)?);
            return Ok(());
        }
        if state.sessions.is_empty() {
            if a.all {
                println!("no iSCSI session is logged in");
            } else {
                println!("no vc-rs volume is attached (pass --all to list every iSCSI session)");
            }
        } else {
            for session in &state.sessions {
                println!("{}  (session {})", session.iqn, session.id);
                if !session.initiator.is_empty() {
                    println!("  initiator {}", session.initiator);
                }
            }
        }
        if !state.servers.is_empty() {
            println!("serving in the background:");
            for server in &state.servers {
                match server.letter {
                    Some(letter) => {
                        println!("  {}  (pid {}, on {letter}:)", server.iqn, server.pid)
                    }
                    None => println!("  {}  (pid {})", server.iqn, server.pid),
                }
            }
        }
        if state.disks.is_empty() {
            println!("no disk with the vc-rs disk name is present");
        } else {
            println!("disks:");
            for disk in &state.disks {
                let letter = match disk.letter {
                    Some(letter) => format!("{letter}:"),
                    None => "no drive letter".to_string(),
                };
                let mut what = format!("{} bytes", disk.size);
                if let Some(file_system) = &disk.file_system {
                    what.push_str(", ");
                    what.push_str(file_system);
                }
                if let Some(partition) = disk.partition {
                    what.push_str(&format!(", partition {partition}"));
                }
                println!("  disk {}: {what}, {letter}", disk.number);
            }
        }
        for note in &state.notes {
            println!("  {note}");
        }
        Ok(())
    }
}

/// Exercise everything the crypto backend has to get right, without touching a
/// volume. The CRC-32 value is VeraCrypt's own self-test value, so a mismatch
/// means the format's checksums would not be accepted by VeraCrypt either.
/// `vcrs device-info`: describe a partition or volume and whether VeraCrypt-style
/// in-place encryption could run on it. Read-only (the optional shrink probe
/// only asks the filesystem a question and immediately withdraws it).
fn device_info(a: &DeviceInfoArgs) -> Result<()> {
    // The shrink probe is a filesystem control code, which needs a handle with
    // write access; without the probe a read-only handle is enough.
    let device = vcrs_core::Device::open(&a.device, a.probe_shrink)?;
    let info = device.info().clone();

    println!("device            {}", info.path.display());
    if let Some(path) = &info.volume_path {
        println!("volume path       {}", path.display());
    }
    println!(
        "size              {} ({} bytes)",
        human_size(info.size),
        info.size
    );
    println!("sector size       {}", info.sector_size);
    match (info.partition_style.as_deref(), info.partition_number) {
        (Some(style), Some(number)) => println!("partition         {style} partition {number}"),
        _ => println!("partition         (no partition table found)"),
    }
    println!(
        "service partition {}",
        if info.is_service_partition {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "system volume     {}",
        if info.is_system_volume { "yes" } else { "no" }
    );
    println!(
        "filesystem        {}",
        info.boot_sector_fs
            .as_deref()
            .unwrap_or("nothing recognisable")
    );
    if let Some(ntfs) = &info.ntfs {
        println!("ntfs serial       0x{:08x}", ntfs.serial);
        println!(
            "filesystem size   {} ({} bytes)",
            human_size(ntfs.filesystem_size()),
            ntfs.filesystem_size()
        );
        println!(
            "cluster size      {} bytes ({} clusters, {} free)",
            ntfs.bytes_per_cluster, ntfs.total_clusters, ntfs.free_clusters
        );
        println!(
            "free space        {} ({} bytes)",
            human_size(ntfs.free_bytes()),
            ntfs.free_bytes()
        );
    }

    println!();
    println!("a VeraCrypt volume covering this device would have");
    println!(
        "  data area       {} ({} bytes), from offset {} to {}",
        human_size(info.data_area_size()),
        info.data_area_size(),
        vcrs_core::header::VOLUME_HEADER_GROUP_SIZE,
        info.data_area_size() + vcrs_core::header::VOLUME_HEADER_GROUP_SIZE
    );
    println!(
        "  primary header  offset 0, backup header group at {} ({})",
        info.backup_header_offset(),
        human_size(info.backup_header_offset())
    );
    println!(
        "  minimum size    {} ({} bytes)",
        human_size(vcrs_core::device::MIN_DEVICE_SIZE),
        vcrs_core::device::MIN_DEVICE_SIZE
    );

    println!();
    match info.blocker() {
        None => {
            println!("in-place encryption: possible");
            let shrink = info.shrink_bytes();
            if shrink > 0 {
                println!(
                    "  the filesystem has to give up its last {} bytes ({}) first",
                    shrink,
                    human_size(shrink)
                );
            } else {
                println!("  the filesystem already ends before the header area");
            }
        }
        Some(reason) => {
            println!("in-place encryption: not possible");
            println!("  {reason}");
        }
    }

    if a.probe_shrink {
        println!();
        if info.ntfs.is_none() {
            println!("shrink probe: skipped (the filesystem is not NTFS)");
            return Ok(());
        }
        match device.probe_shrink(info.data_area_size()) {
            Ok(vcrs_core::ShrinkProbe::Ready) => println!(
                "shrink probe: NTFS can give up its tail right now (no clusters would have to move)"
            ),
            Ok(vcrs_core::ShrinkProbe::NeedsClusterMove) => println!(
                "shrink probe: clusters are allocated in the tail; they would have to be moved \
                 (VeraCrypt does that, or `defrag <drive> /X` before the run)"
            ),
            Err(e) => println!("shrink probe: could not be run ({e})"),
        }
    }

    Ok(())
}

fn self_test() -> Result<()> {
    use vcrs_core::prf::{argon2_params, HEADER_KEY_SIZE, SALT_SIZE};

    println!("vcrs self-test");
    let mut checks = 0usize;

    let crc_data: Vec<u8> = (0u8..32).collect();
    let crc = vcrs_core::crc32(&crc_data);
    anyhow::ensure!(
        crc == 0x9126_7E8A && vcrs_core::crc32(b"123456789") == 0xCBF4_3926,
        "crc32 self-test failed: {crc:#010x} where VeraCrypt's own test wants 0x91267e8a"
    );
    println!("  crc32                      ok (VeraCrypt's own check value)");
    checks += 1;

    let salt = [0x42u8; SALT_SIZE];
    for prf in Prf::ALL {
        let mut key = vec![0u8; HEADER_KEY_SIZE];
        let mut again = vec![0u8; HEADER_KEY_SIZE];
        let mut other = vec![0u8; HEADER_KEY_SIZE];
        prf.derive(b"vcrs self-test", &salt, 1, &mut key)?;
        prf.derive(b"vcrs self-test", &salt, 1, &mut again)?;
        prf.derive(b"vcrs self-test!", &salt, 1, &mut other)?;
        anyhow::ensure!(key == again, "{prf}: the derivation is not deterministic");
        anyhow::ensure!(
            key != other,
            "{prf}: a different password gave the same key"
        );
        anyhow::ensure!(
            key.iter().any(|byte| *byte != 0),
            "{prf}: the key is all zero"
        );
        let label = prf.to_string();
        if prf == Prf::Argon2 {
            let (memory_kib, iterations, parallelism) = argon2_params(1);
            println!(
                "  {label:<26} ok (PIM 1: {memory_kib} KiB, {iterations} passes, parallelism {parallelism})"
            );
        } else {
            println!(
                "  {label:<26} ok ({} iterations at PIM 1, {} at PIM 0)",
                prf.iterations(1),
                prf.iterations(0)
            );
        }
        checks += 1;
    }

    let mut plain = vec![0u8; 3 * vcrs_core::xts::DATA_UNIT_SIZE];
    for (index, byte) in plain.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    for ea in EncryptionAlgorithm::ALL {
        let key = vec![0x11u8; ea.key_size() * 2];
        let xts = vcrs_core::Xts::new(ea, &key)?;
        let mut buffer = plain.clone();
        xts.encrypt(&mut buffer, 7)?;
        anyhow::ensure!(buffer != plain, "{ea}: XTS left the data unchanged");
        let mut twice = plain.clone();
        xts.encrypt(&mut twice, 7)?;
        anyhow::ensure!(twice == buffer, "{ea}: XTS is not deterministic");
        xts.decrypt(&mut buffer, 7)?;
        anyhow::ensure!(buffer == plain, "{ea}: the XTS round trip changed the data");
        println!(
            "  {:<26} ok (XTS, {} byte key)",
            ea.to_string(),
            ea.key_size() * 2
        );
        checks += 1;
    }

    for (ea, prf) in [
        (EncryptionAlgorithm::Aes, Prf::Sha512),
        (EncryptionAlgorithm::SerpentTwofishAes, Prf::Argon2),
    ] {
        let header = VolumeHeader {
            version: vcrs_core::VOLUME_HEADER_VERSION,
            required_min_version: 0x010b,
            volume_type: VolumeType::Normal,
            creation_time: 0,
            modification_time: 0,
            hidden_volume_data_size: 0,
            volume_data_size: 4 * 1024 * 1024,
            encrypted_area_start: 131072,
            encrypted_area_length: 4 * 1024 * 1024,
            flags: 0,
            sector_size: 512,
            ea,
            prf,
            salt: vec![0x5au8; SALT_SIZE],
            master_key: vec![0x7eu8; ea.key_size() * 2],
        };
        let mut header_key = vec![0u8; HEADER_KEY_SIZE];
        prf.derive(b"vcrs self-test", &header.salt, 1, &mut header_key)?;
        let region =
            header.encrypt_with_salt(VOLUME_HEADER_SIZE as usize, &header_key, &header.salt)?;
        anyhow::ensure!(
            &region[HEADER_ENCRYPTED_DATA_OFFSET..HEADER_ENCRYPTED_DATA_OFFSET + 4] != b"VERA",
            "{ea} + {prf}: the header body is not encrypted"
        );
        anyhow::ensure!(
            VolumeHeader::region_has_magic(&region, &header_key, ea)?,
            "{ea} + {prf}: the magic is not detectable"
        );
        let back = VolumeHeader::decrypt(&region, &header_key, ea, prf)?;
        anyhow::ensure!(
            back.master_key == header.master_key,
            "{ea} + {prf}: the master key was lost"
        );
        anyhow::ensure!(
            back.volume_data_size == header.volume_data_size
                && back.encrypted_area_start == header.encrypted_area_start
                && back.sector_size == header.sector_size,
            "{ea} + {prf}: the header fields were lost"
        );
        println!("  header round trip          ok ({ea} + {prf})");
        checks += 1;
    }

    println!("all {checks} checks passed");
    Ok(())
}

fn open_ro(path: &Path, creds: &PasswordArgs, volume_type: Option<VolumeType>) -> Result<Volume> {
    Volume::open(path, &creds.open_options(volume_type, false)?).map_err(Into::into)
}

fn open_rw(path: &Path, creds: &PasswordArgs, volume_type: Option<VolumeType>) -> Result<Volume> {
    open_ro(path, creds, volume_type)
}

fn parse_ea(s: &str) -> Result<EncryptionAlgorithm> {
    EncryptionAlgorithm::from_name(s).with_context(|| {
        let names: Vec<&str> = EncryptionAlgorithm::ALL.iter().map(|e| e.name()).collect();
        format!(
            "unknown encryption algorithm {s:?}; known: {}",
            names.join(", ")
        )
    })
}

fn parse_prf(s: &str) -> Result<Prf> {
    Prf::from_name(s).with_context(|| {
        let names: Vec<&str> = Prf::ALL.iter().map(|p| p.name()).collect();
        format!("unknown hash algorithm {s:?}; known: {}", names.join(", "))
    })
}

/// Parse a volume sector size: VeraCrypt allows 512..4096 in 512-byte steps
/// (`TC_MIN_VOLUME_SECTOR_SIZE`..`TC_MAX_VOLUME_SECTOR_SIZE`).
fn parse_sector_size(s: &str) -> Result<u32, String> {
    let value: u32 = s
        .trim()
        .parse()
        .map_err(|_| format!("{s:?} is not a sector size"))?;
    if !(512..=4096).contains(&value) || value % 512 != 0 {
        return Err(format!(
            "sector size must be 512..4096 and a multiple of 512, got {value}"
        ));
    }
    Ok(value)
}

/// Parse `123`, `123K`, `64M`, `4G` (binary suffixes).
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (digits, mult) = match s.chars().last() {
        Some('k' | 'K') => (&s[..s.len() - 1], 1024u64),
        Some('m' | 'M') => (&s[..s.len() - 1], 1024 * 1024),
        Some('g' | 'G') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        Some('t' | 'T') => (&s[..s.len() - 1], 1024u64.pow(4)),
        _ => (s, 1),
    };
    let n: u64 = digits
        .trim()
        .parse()
        .map_err(|e| format!("invalid size {s:?}: {e}"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("size {s:?} is too large"))
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() % 2 != 0 {
        bail!("hex string must have an even number of digits");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow::anyhow!("{e}")))
        .collect()
}

fn print_header(volume: &Volume, show_master_key: bool) {
    let h = &volume.header;
    println!("header:");
    println!("  magic             VERA");
    println!("  version           {}", h.version);
    println!("  required min      0x{:04x}", h.required_min_version);
    println!("  volume type       {:?}", h.volume_type);
    println!(
        "  encryption        {} ({} bytes of key)",
        h.ea.name(),
        h.ea.key_size()
    );
    println!("  hash (PRF)        {}", h.prf.name());
    println!("  sector size       {}", h.sector_size);
    println!("  volume data size  {} bytes", h.volume_data_size);
    println!("  enc. area start   {}", h.encrypted_area_start);
    println!("  enc. area length  {}", h.encrypted_area_length);
    println!("  hidden data size  {}", h.hidden_volume_data_size);
    println!("  flags             0x{:08x}", h.flags);
    println!("  creation time     {}", h.creation_time);
    println!("  modification time {}", h.modification_time);
    println!("  salt              {}", hex(&h.salt));
    println!(
        "  master key        {}",
        format_master_key(show_master_key, &h.master_key)
    );
    println!("layout:");
    println!("  host size         {} bytes", volume.host_size);
    println!("  data offset       {}", volume.data_offset);
    println!("  data size         {} bytes", volume.data_size);
}

/// The master key is the one secret that decrypts the data area without the
/// password (that is why VeraCrypt's rescue disk stores it), so it stays hidden
/// unless the caller explicitly asks for it. VeraCrypt's format wizard does the
/// same thing: the fields show stars until "Display keys" is ticked.
fn format_master_key(show: bool, master_key: &[u8]) -> String {
    if show {
        hex(master_key)
    } else {
        format!(
            "<{} bytes, pass --show-master-key to print>",
            master_key.len()
        )
    }
}

fn dump_header_region(args: &HeaderArgs) -> Result<()> {
    let len = std::fs::metadata(&args.path)?.len();
    let layout = VolumeLayout::V2Normal;
    let base = match args.backup {
        true => layout
            .backup_header_offset()
            .map(|o| len.wrapping_add(o as u64))
            .context("layout has no backup header")?,
        false => 0,
    };
    let size = if args.short {
        VOLUME_HEADER_SIZE_LEGACY
    } else {
        VOLUME_HEADER_SIZE
    };
    let bytes = vcrs_core::volume::read_region(&args.path, base, size as usize)?;
    println!("# {} bytes at offset {base}", bytes.len());
    print_hex_dump(0, &bytes[..VOLUME_HEADER_SIZE_LEGACY as usize]);
    if !args.short {
        println!("--- salt (offset 0, 64 bytes) vs key area (offset {MASTER_KEY_AREA_OFFSET}) ---");
        println!(
            "  encrypted data starts at offset {HEADER_ENCRYPTED_DATA_OFFSET}, {} bytes follow",
            size.saturating_sub(HEADER_ENCRYPTED_DATA_OFFSET as u64)
        );
    }
    Ok(())
}

fn print_hex_dump(base: u64, data: &[u8]) {
    for (row, chunk) in data.chunks(16).enumerate() {
        let addr = base + (row * 16) as u64;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let mut ascii = String::new();
        for b in chunk {
            ascii.push(if (0x20..0x7f).contains(b) {
                *b as char
            } else {
                '.'
            });
        }
        println!("{addr:08x}  {:<47}  {ascii}", hex.join(" "));
    }
}

fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Default name for a header backup: `<volume>.hc`.
fn default_header_backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".hc");
    PathBuf::from(name)
}

/// `vcrs restore-headers`: put a header back from a backup file, from the
/// container's own embedded copy, or -- when every copy is gone -- from a
/// master key.
fn restore_headers(a: &RestoreHeadersArgs) -> Result<()> {
    let volume_type = a.kind.volume_type().unwrap_or(VolumeType::Normal);

    if let Some(key) = &a.master_key {
        let master_key = parse_hex(key)?;
        let host_size = std::fs::metadata(&a.path)
            .with_context(|| format!("reading {}", a.path.display()))?
            .len();
        let data_size = match (a.data_size, volume_type) {
            (Some(size), _) => size,
            (None, VolumeType::Normal) => VolumeLayout::V2Normal
                .max_data_size(host_size)
                .with_context(|| format!("{} is too small to hold a volume", a.path.display()))?,
            (None, VolumeType::Hidden) => bail!(
                "rebuilding a hidden volume's header needs --data-size: its data area does not sit \
                 where an ordinary volume's would"
            ),
        };
        let options = RestoreHeaderOptions {
            password: a.password.read()?,
            keyfiles: a.password.keyfiles.clone(),
            pim: a.password.pim,
            ea: parse_ea(&a.ea)?,
            prf: parse_prf(&a.prf)?,
            sector_size: a.sector_size,
            volume_type,
            data_size,
        };
        let volume = vcrs_core::restore_headers_from_master_key(&a.path, &master_key, &options)?;
        println!(
            "rebuilt the {} header of {} from its master key",
            volume_name(volume_type),
            a.path.display()
        );
        print_header(&volume, false);
        return Ok(());
    }

    // Writing a header does not need a password, but without one the result
    // cannot be checked -- and a backup taken from another volume would leave
    // this container unopenable.
    let verify = if a.password.is_given() {
        Some(a.password.open_options(a.kind.volume_type(), false)?)
    } else {
        None
    };
    let volume = if let Some(from) = &a.from {
        vcrs_core::restore_headers(&a.path, from, volume_type, verify.as_ref())?
    } else if a.embedded {
        vcrs_core::restore_headers_from_embedded(&a.path, volume_type, verify.as_ref())?
    } else {
        bail!("pass --from <FILE>, --embedded or --master-key <HEX>")
    };

    match volume {
        Some(volume) => {
            println!(
                "restored the {} header of {} and opened it with the password given",
                volume_name(volume_type),
                a.path.display()
            );
            print_header(&volume, false);
        }
        None => {
            println!(
                "restored the {} header of {}",
                volume_name(volume_type),
                a.path.display()
            );
            eprintln!(
                "warning: no password was given, so the restored header was not checked; if it came\n  \
                 from another volume, this container can no longer be opened"
            );
        }
    }
    Ok(())
}

fn volume_name(volume_type: VolumeType) -> &'static str {
    match volume_type {
        VolumeType::Normal => "ordinary",
        VolumeType::Hidden => "hidden",
    }
}

/// Refuse to create a container larger than the free space on the filesystem it
/// is created on (VeraCrypt's "not enough free space" check), unless
/// `--no-size-check` was passed.
fn check_free_space(path: &Path, host_size: u64) -> Result<()> {
    let Some(free) = available_space(path) else {
        return Ok(());
    };
    if host_size > free {
        bail!(
            "the container ({}) does not fit in the {} free on {}: pass --no-size-check to create \
             it anyway (the format would then fail part-way through)",
            human_size(host_size),
            human_size(free),
            existing_dir(path).display()
        );
    }
    Ok(())
}

/// The closest existing directory, i.e. the filesystem the container will live
/// on.
fn existing_dir(path: &Path) -> PathBuf {
    let mut candidate = path.parent().map(Path::to_path_buf);
    while let Some(dir) = candidate {
        if dir.as_os_str().is_empty() {
            break;
        }
        if dir.is_dir() {
            return dir;
        }
        candidate = dir.parent().map(Path::to_path_buf);
    }
    PathBuf::from(".")
}

/// Bytes available to the user on the filesystem that holds `path`.
#[cfg(windows)]
fn available_space(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::fileapi::GetDiskFreeSpaceExW;
    use winapi::um::winnt::ULARGE_INTEGER;

    let dir = existing_dir(path);
    let mut wide: Vec<u16> = dir.as_os_str().encode_wide().collect();
    wide.push(0);
    let mut free: ULARGE_INTEGER = unsafe { std::mem::zeroed() };
    // SAFETY: `wide` is a NUL-terminated UTF-16 path and `free` is a valid,
    // initialised ULARGE_INTEGER of ours.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        None
    } else {
        // SAFETY: the call succeeded, so the union holds the free byte count.
        Some(unsafe { *free.QuadPart() })
    }
}

/// Bytes available to the user on the filesystem that holds `path`.
#[cfg(unix)]
fn available_space(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;

    let dir = existing_dir(path);
    let c_path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is a valid NUL-terminated C string and `stat` is ours.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    Some(stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(not(any(windows, unix)))]
fn available_space(_path: &Path) -> Option<u64> {
    None
}

/// A byte count as `12.34 MiB`, for messages a person reads.
fn human_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("TiB", 1 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
    ];
    for (unit, factor) in UNITS {
        if bytes >= factor {
            return format!("{:.2} {unit}", bytes as f64 / factor as f64);
        }
    }
    format!("{bytes} B")
}

#[cfg(test)]
mod tests {
    use super::{format_master_key, human_size, parse_sector_size, Cli, Command};
    use clap::Parser;

    #[test]
    fn mount_can_open_the_backup_header() {
        // VeraCrypt's "Use backup header embedded in volume if available"
        // (`/mountoption headerbak`), for a container whose primary header is
        // damaged.
        let cmd = Cli::parse_from(["vcrs", "mount", "vol.hc", "--backup"]);
        let Command::Mount(args) = cmd.command else {
            panic!("expected the mount subcommand")
        };
        assert!(args.backup);
        assert!(!args.read_only);

        let cmd = Cli::parse_from(["vcrs", "mount", "vol.hc"]);
        let Command::Mount(args) = cmd.command else {
            panic!("expected the mount subcommand")
        };
        assert!(!args.backup, "the primary header is the default");
    }

    #[test]
    fn dismount_takes_one_iqn_or_all_of_them() {
        // `/dismount <letter>` vs `/dismount` in VeraCrypt, plus the container
        // path `vcrs mount` was started with.
        let cmd = Cli::parse_from(["vcrs", "dismount", "--iscsi", "iqn.x:y"]);
        let Command::Dismount(args) = cmd.command else {
            panic!("expected the dismount subcommand")
        };
        assert_eq!(args.iscsi.as_deref(), Some("iqn.x:y"));
        assert!(args.path.is_none() && args.letter.is_none());
        assert!(!args.all);

        let cmd = Cli::parse_from(["vcrs", "dismount", "--letter", "Y"]);
        let Command::Dismount(args) = cmd.command else {
            panic!("expected the dismount subcommand")
        };
        assert_eq!(args.letter, Some('Y'));

        let cmd = Cli::parse_from(["vcrs", "dismount", "secret.vc"]);
        let Command::Dismount(args) = cmd.command else {
            panic!("expected the dismount subcommand")
        };
        assert_eq!(
            args.path.as_deref(),
            Some(std::path::Path::new("secret.vc"))
        );

        // a bare `vcrs dismount` is the `--all` case
        let cmd = Cli::parse_from(["vcrs", "dismount"]);
        let Command::Dismount(args) = cmd.command else {
            panic!("expected the dismount subcommand")
        };
        assert!(!args.all && args.iscsi.is_none() && args.path.is_none() && args.letter.is_none());

        let cmd = Cli::parse_from(["vcrs", "dismount", "--all"]);
        let Command::Dismount(args) = cmd.command else {
            panic!("expected the dismount subcommand")
        };
        assert!(args.all);
        assert!(args.iscsi.is_none());

        // the ways of naming targets cannot be combined
        assert!(Cli::try_parse_from(["vcrs", "dismount", "--all", "--iscsi", "iqn.x:y"]).is_err());
        assert!(Cli::try_parse_from(["vcrs", "dismount", "--letter", "Y", "--all"]).is_err());
        assert!(Cli::try_parse_from(["vcrs", "dismount", "secret.vc", "--letter", "Y"]).is_err());
        assert!(
            Cli::try_parse_from(["vcrs", "dismount", "secret.vc", "--iscsi", "iqn.x:y"]).is_err()
        );
    }

    #[test]
    fn sizes_are_readable() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.00 KiB");
        assert_eq!(human_size(20 * 1024 * 1024), "20.00 MiB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.00 GiB");
    }

    #[test]
    fn the_master_key_is_masked_unless_requested() {
        let key = [0xab, 0xcd];
        assert_eq!(format_master_key(true, &key), "abcd");
        let hidden = format_master_key(false, &key);
        assert!(
            !hidden.contains("abcd"),
            "the key must not appear: {hidden}"
        );
        assert!(hidden.contains("2 bytes") && hidden.contains("--show-master-key"));
    }

    #[test]
    fn sector_sizes_are_validated_like_veracrypt_does() {
        for good in ["512", "1024", "2048", "4096", " 4096 "] {
            assert!(parse_sector_size(good).is_ok(), "{good} should be accepted");
        }
        for bad in ["0", "256", "600", "4097", "8192", "abc", ""] {
            let err = parse_sector_size(bad).expect_err("{bad} should be refused");
            assert!(!err.is_empty());
        }
    }
}
