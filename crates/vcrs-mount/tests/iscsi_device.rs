//! Tests for the iSCSI block device.
//!
//! These drive [`ScsiVolume`]'s [`ScsiBlockDevice`] implementation directly, so
//! they need neither administrator rights nor the Microsoft iSCSI Initiator, and
//! they exercise exactly the part we wrote: the synthetic MBR, the data-area
//! mapping, XTS decryption/encryption in both directions, the read-only guard
//! and the absorption of writes into the synthetic region.
//!
//! The full transport handshake is *not* exercised here on purpose. The
//! initiator shipping with `iscsi-target` offers `HeaderDigest=CRC32C` and the
//! crate's multi-target server negotiates it, but then writes its PDUs without
//! the digest (it calls `write_pdu` instead of `write_pdu_digest`), so those two
//! halves of the crate cannot talk to each other. Real initiators offer `None`
//! by default -- which is what `scripts/vc-iscsi-e2e.ps1` proves end to end
//! against the Microsoft initiator -- so this is an upstream bug we avoid rather
//! than paper over. See the module docs of `vcrs_mount::iscsi`.
//!
//! One test does start the real server and check that the socket comes up.

use std::path::PathBuf;

use iscsi_target::ScsiBlockDevice;
use vcrs_core::volume::{CreateOptions, OpenOptions, Volume};
use vcrs_mount::iscsi::{free_loopback_port, DiskMode, IscsiMount, IscsiMountOptions, ScsiVolume};
use vcrs_mount::{format_volume, FatKind};

/// Container size used by every test (VeraCrypt's own minimum is 299008 bytes).
const VOLUME_SIZE: u64 = 10 * 1024 * 1024;
/// Two header groups: the data area is the rest of the container.
const HEADER_SIZE: u64 = 262_144;
const PASSWORD: &[u8] = b"iscsi-test-password";
const LABEL: &str = "ISCSITEST";
const DATA_SECTORS: u64 = (VOLUME_SIZE - HEADER_SIZE) / 512;
/// 1 MiB alignment of the synthetic partition.
const PARTITION_START: u64 = 2048;

/// A container that has been FAT16-formatted, plus the options needed to reopen
/// it and (optionally) a device or a running server built from it.
struct Fixture {
    path: PathBuf,
    open: OpenOptions,
    opts: IscsiMountOptions,
    device: Option<ScsiVolume>,
    mount: Option<IscsiMount>,
}

impl Fixture {
    /// Create the container and open it as a block device.
    fn new(name: &str, mode: DiskMode, read_only: bool) -> Fixture {
        let path =
            std::env::temp_dir().join(format!("vcrs-iscsi-{name}-{}.vc", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let mut create = CreateOptions::default();
        create.password = PASSWORD.to_vec();
        // PIM 1 keeps the (500k-iteration default) PBKDF2 cost out of the test.
        create.pim = 1;
        let mut volume = Volume::create(&path, VOLUME_SIZE, &create).expect("create volume");
        format_volume(&mut volume, FatKind::Fat16, LABEL).expect("format the FAT16 filesystem");
        volume.flush().expect("flush the container");
        drop(volume);

        let mut open = OpenOptions::default();
        open.password = PASSWORD.to_vec();
        open.pim = 1;

        let mut opts = IscsiMountOptions::for_volume(&path);
        opts.disk_mode = mode;
        opts.read_only = read_only;
        // `IscsiServer` binds the socket itself, so pick a free port first.
        opts.bind_addr = format!("127.0.0.1:{}", free_loopback_port().expect("free port"));

        let device = ScsiVolume::open(&path, &open, &opts).expect("open the device");
        Fixture {
            path,
            open,
            opts,
            device: Some(device),
            mount: None,
        }
    }

    fn device(&self) -> &ScsiVolume {
        self.device.as_ref().expect("the device is open")
    }

    fn device_mut(&mut self) -> &mut ScsiVolume {
        self.device.as_mut().expect("the device is open")
    }

    /// Hand the device to a real iSCSI server.
    fn serve(&mut self) {
        let device = self.device.take().expect("the device is open");
        let mount = IscsiMount::start(device, &self.opts).expect("start the iSCSI server");
        self.mount = Some(mount);
    }

    /// Re-open the container with `vcrs-core`, i.e. the plaintext the mount
    /// layer must have written.
    fn reopen(&self) -> Volume {
        Volume::open(&self.path, &self.open).expect("re-open the container")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Stop serving (which closes the container file) before deleting it.
        self.mount.take();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A single-sector READ(10) through our device.
fn read_sector(device: &ScsiVolume, lba: u64) -> Vec<u8> {
    let data = device.read(lba, 1, 512).expect("read a sector");
    assert_eq!(data.len(), 512);
    data
}

fn read_signature(device: &ScsiVolume) -> u32 {
    u32::from_le_bytes(read_sector(device, 0)[0x1B8..0x1BC].try_into().unwrap())
}

fn pattern() -> Vec<u8> {
    let mut bytes = vec![0u8; 512];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    bytes
}

#[test]
fn partitioned_disk_exposes_the_filesystem_inside_a_synthetic_mbr() {
    let mut target = Fixture::new("partitioned", DiskMode::Partitioned, false);

    // 1 MiB of synthetic space in front of the data area.
    assert_eq!(target.device().block_size(), 512);
    assert_eq!(target.device().capacity(), PARTITION_START + DATA_SECTORS);
    assert_eq!(target.device().data_start_lba(), PARTITION_START);

    // LBA 0 is an MBR that describes the data area as one FAT16 partition.
    let mbr = read_sector(target.device(), 0);
    assert_eq!(&mbr[510..512], &[0x55, 0xAA], "the MBR must be signed");
    let entry = 0x1BE;
    assert_eq!(mbr[entry + 4], 0x0E, "the partition type should be FAT16 LBA");
    let start = u32::from_le_bytes(mbr[entry + 8..entry + 12].try_into().unwrap()) as u64;
    let sectors = u32::from_le_bytes(mbr[entry + 12..entry + 16].try_into().unwrap()) as u64;
    assert_eq!(start, PARTITION_START);
    assert_eq!(sectors, DATA_SECTORS);
    assert_ne!(
        read_signature(target.device()),
        0,
        "the disk needs a non-zero signature, or Windows offers to initialise it"
    );

    // Inside the partition sits the FAT16 filesystem, exactly as VeraCrypt's own
    // driver would present it (the data area starts with the boot sector).
    let vbr = read_sector(target.device(), start);
    assert_eq!(&vbr[0..3], &[0xEB, 0x3C, 0x90], "no FAT boot sector");
    assert_eq!(&vbr[0x36..0x3E], b"FAT16   ");
    assert_eq!(&vbr[0x2B..0x36], b"ISCSITEST  ", "volume label");
    assert_eq!(&vbr[510..512], &[0x55, 0xAA]);

    // A write through the device lands in the container as plaintext.
    let pattern = pattern();
    target
        .device_mut()
        .write(start + 37, &pattern, 512)
        .expect("write a sector");
    assert_eq!(read_sector(target.device(), start + 37), pattern);

    let volume = target.reopen();
    let mut direct = vec![0u8; 512];
    volume
        .read_data(37 * 512, &mut direct)
        .expect("read the container directly");
    assert_eq!(
        direct, pattern,
        "the container must hold the plaintext at data offset 37*512"
    );
}

#[test]
fn raw_mode_exposes_the_bare_data_area() {
    let target = Fixture::new("raw", DiskMode::Raw, false);

    // No synthetic MiB: the disk *is* the data area.
    assert_eq!(target.device().block_size(), 512);
    assert_eq!(target.device().capacity(), DATA_SECTORS);
    assert_eq!(target.device().data_start_lba(), 0);

    // ...so LBA 0 is the filesystem itself.
    let vbr = read_sector(target.device(), 0);
    assert_eq!(&vbr[3..11], b"MSWIN4.1");
    assert_eq!(&vbr[0x36..0x3E], b"FAT16   ");
    assert_eq!(&vbr[0x2B..0x36], b"ISCSITEST  ");
}

#[test]
fn read_only_refuses_writes_and_leaves_the_container_alone() {
    let mut target = Fixture::new("readonly", DiskMode::Partitioned, true);
    let lba = PARTITION_START + 5;
    let before = read_sector(target.device(), lba);
    let pattern = vec![0xEEu8; 512];

    let err = target
        .device_mut()
        .write(lba, &pattern, 512)
        .expect_err("a read-only target must reject writes");
    assert!(
        err.to_string().contains("read-only"),
        "unexpected error: {err}"
    );
    assert_eq!(
        read_sector(target.device(), lba),
        before,
        "the sector must be unchanged"
    );

    let volume = target.reopen();
    let mut direct = vec![0u8; 512];
    volume.read_data(5 * 512, &mut direct).expect("read the container");
    assert_eq!(direct, before, "the container must be unchanged");
}

#[test]
fn writes_into_the_synthetic_region_never_reach_the_container() {
    let mut target = Fixture::new("synthetic", DiskMode::Partitioned, false);

    // Windows is free to rewrite the MBR (disk signature, partition table) and
    // "initialize" the disk at any time; none of that may touch the container.
    let mut rewritten = read_sector(target.device(), 0);
    rewritten[0x1B8..0x1BC].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    target
        .device_mut()
        .write(0, &rewritten, 512)
        .expect("a write into the synthetic region is absorbed, not refused");
    assert_eq!(
        read_sector(target.device(), 0),
        rewritten,
        "the session should see the MBR it wrote (it lives in memory)"
    );

    let volume = target.reopen();
    let mut first = vec![0u8; 512];
    volume.read_data(0, &mut first).expect("read the container");
    assert_eq!(
        &first[3..11], b"MSWIN4.1",
        "the data area must still start with the FAT boot sector"
    );
}

#[test]
fn the_disk_signature_is_stable_across_sessions() {
    let target = Fixture::new("signature", DiskMode::Partitioned, false);
    let signature = read_signature(target.device());
    assert_ne!(signature, 0);

    // A second session (a new process, or a re-login) must present the same
    // disk, otherwise Windows forgets the drive letter and re-runs the
    // "initialize this disk?" dialog.
    let again = ScsiVolume::open(&target.path, &target.open, &target.opts).expect("re-open");
    assert_eq!(read_signature(&again), signature);
}

#[test]
fn the_removable_bit_is_configurable() {
    let mut target = Fixture::new("removable", DiskMode::Partitioned, false);
    assert!(
        !target.device().removable(),
        "disks default to fixed media (VeraCrypt's own driver does the same)"
    );

    // Windows only offers exFAT in its format dialogs for removable media, so
    // the flag is the way to get exFAT into that list. It has to reach the
    // device, whose `removable()` the patched INQUIRY turns into the RMB bit of
    // response byte 1.
    target.device = None;
    target.opts.removable = true;
    target.device = Some(
        ScsiVolume::open(&target.path, &target.open, &target.opts).expect("re-open as removable"),
    );
    assert!(target.device().removable());
}

#[test]
fn the_server_starts_and_answers_tcp() {
    let mut target = Fixture::new("listening", DiskMode::Partitioned, false);
    target.serve();
    let mount = target.mount.as_ref().expect("the server is running");
    assert!(mount.is_running());
    assert!(mount.target_name().starts_with("iqn."));
    // The listener really is up (the probe is not an iSCSI session, so the
    // server just drops it).
    std::net::TcpStream::connect(mount.addr()).expect("the listener must answer");
}
