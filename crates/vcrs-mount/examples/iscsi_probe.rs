//! Diagnostic probe for the iSCSI device: prints each step so a hang can be
//! located. Run with `cargo run -p vcrs-mount --example iscsi_probe`.

use std::io::Write;

use iscsi_target::IscsiClient;
use vcrs_core::volume::{CreateOptions, OpenOptions, Volume};
use vcrs_mount::iscsi::{free_loopback_port, DiskMode, IscsiMount, IscsiMountOptions, ScsiVolume};
use vcrs_mount::{format_volume, FatKind};

macro_rules! step {
    ($($arg:tt)*) => {{
        println!($($arg)*);
        let _ = std::io::stdout().flush();
    }};
}

fn main() {
    let path = std::env::temp_dir().join("vcrs-iscsi-probe.vc");
    let _ = std::fs::remove_file(&path);
    let size = 10 * 1024 * 1024u64;
    let password = b"probe-password".to_vec();

    step!("1. create");
    let mut create = CreateOptions::default();
    create.password = password.clone();
    create.pim = 1;
    let mut volume = Volume::create(&path, size, &create).expect("create");
    step!("2. format");
    format_volume(&mut volume, FatKind::Fat16, "PROBE").expect("format");
    volume.flush().expect("flush");
    drop(volume);

    let mut open = OpenOptions::default();
    open.password = password;
    open.pim = 1;

    let mut opts = IscsiMountOptions::for_volume(&path);
    opts.disk_mode = DiskMode::Partitioned;
    opts.bind_addr = format!("127.0.0.1:{}", free_loopback_port().expect("port"));
    step!("3. ScsiVolume::open (bind {})", opts.bind_addr);
    let device = ScsiVolume::open(&path, &open, &opts).expect("scsi volume");
    step!("4. IscsiMount::start");
    let mount = IscsiMount::start(device, &opts).expect("start");
    step!("5. connect to {}", mount.addr());
    let mut client = IscsiClient::connect(mount.addr()).expect("connect");
    step!("6. login");
    client
        .login("iqn.1991-05.com.microsoft:vcrs-probe", mount.target_name())
        .expect("login");
    step!("7. INQUIRY");
    let inquiry = client
        .send_scsi_command(&[0x12, 0, 0, 0, 36, 0], None)
        .expect("inquiry");
    step!("   -> {:?}", String::from_utf8_lossy(&inquiry.data));
    step!("8. READ CAPACITY(10)");
    let cap = client
        .send_scsi_command(&[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], None)
        .expect("capacity");
    step!("   -> data {:?}", cap.data);
    step!("9. READ(10) LBA 0");
    let (_pdu, mbr) = client.send_read(0, 1).expect("read 0");
    step!("   -> {:02x?}", &mbr[..16]);
    step!("10. READ(10) LBA 2048");
    let (_pdu, vbr) = client.send_read(2048, 1).expect("read 2048");
    step!("   -> {:02x?}", &vbr[..16]);
    step!("11. WRITE(10) LBA 2053");
    client.send_write(2053, &[0xABu8; 512]).expect("write");
    step!("12. READ back");
    let (_pdu, back) = client.send_read(2053, 1).expect("read back");
    step!("   -> {} bytes, first {:02x?}", back.len(), &back[..8]);
    step!("13. read-only write");
    step!("14. logout");
    let _ = client.logout();
    drop(client);
    let t = std::time::Instant::now();
    step!("15. drop the mount (stops the target)");
    drop(mount);
    step!("    dropped in {:?}", t.elapsed());
    step!("16. done");
    let _ = std::fs::remove_file(&path);
}
