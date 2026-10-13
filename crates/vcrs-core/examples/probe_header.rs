//! Probe a volume's primary and backup header regions with every PRF x EA combination.
//!
//! Usage: cargo run --example probe_header -- <volume> <password> [pim]
//!
//! Prints, for each combination, the first plaintext bytes of the decrypted header
//! data area, and a full field dump for the combination whose plaintext starts with
//! the "VERA" magic. Useful for diagnosing "the header does not decrypt" cases
//! (corruption vs. a KDF/algorithm mismatch).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use vcrs_core::cipher::EncryptionAlgorithm;
use vcrs_core::header::{
    VolumeHeader, HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, HEADER_SALT_SIZE,
};
use vcrs_core::prf::{Prf, HEADER_KEY_SIZE};
use vcrs_core::xts::Xts;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("usage: probe_header <volume> <password> [pim]")?;
    let password = args.next().unwrap_or_default();
    let pim: i32 = args.next().map(|s| s.parse()).transpose()?.unwrap_or(0);

    let mut file = File::open(&path)?;
    let host_size = file.metadata()?.len();
    println!("file {path}: {host_size} bytes, pim={pim}");

    let regions = [
        ("primary", 0u64),
        ("backup", host_size.saturating_sub(vcrs_core::header::VOLUME_HEADER_GROUP_SIZE)),
        ("hidden-primary", vcrs_core::layout::HIDDEN_VOLUME_HEADER_OFFSET),
    ];

    for (label, offset) in regions {
        if offset >= host_size {
            continue;
        }
        println!("--- {label} header region at {offset} ---");
        let mut region = vec![0u8; vcrs_core::header::VOLUME_HEADER_SIZE as usize];
        file.seek(SeekFrom::Start(offset))?;
        if file.read(&mut region)? != region.len() {
            println!("  (short read)");
        }
        let salt = &region[..HEADER_SALT_SIZE];
        println!("  salt {}", hex(salt));

        for prf in Prf::ALL {
            let mut header_key = vec![0u8; HEADER_KEY_SIZE];
            if let Err(e) = prf.derive(password.as_bytes(), salt, pim, &mut header_key) {
                println!("  {prf:?}: derive failed: {e}");
                continue;
            }
            for ea in EncryptionAlgorithm::ALL {
                let mut block =
                    region[HEADER_ENCRYPTED_DATA_OFFSET..HEADER_ENCRYPTED_DATA_OFFSET + HEADER_ENCRYPTED_DATA_SIZE]
                        .to_vec();
                let xts = match Xts::new(ea, &header_key) {
                    Ok(x) => x,
                    Err(e) => {
                        println!("  {prf:?}/{ea:?}: {e}");
                        continue;
                    }
                };
                if let Err(e) = xts.decrypt(&mut block, 0) {
                    println!("  {prf:?}/{ea:?}: decrypt failed: {e}");
                    continue;
                }
                let magic_ok = &block[..4] == b"VERA";
                match VolumeHeader::decrypt(&region, &header_key, ea, prf) {
                    Ok(h) => println!(
                        "  *** {prf:?}/{ea:?}: opens (version {}, EA key {} bytes, volume_data_size {}, enc_area {}+{}, sector {}, hidden_size {})\n      plaintext[0..32] {}",
                        h.version,
                        h.ea.key_size(),
                        h.volume_data_size,
                        h.encrypted_area_start,
                        h.encrypted_area_length,
                        h.sector_size,
                        h.hidden_volume_data_size,
                        hex(&block[..32.min(block.len())]),
                    ),
                    Err(e) => {
                        if magic_ok || block[..4] != [0, 0, 0, 0] {
                            println!(
                                "  {prf:?}/{ea:?}: magic_ok={magic_ok} plaintext[0..16] {} -> {e}",
                                hex(&block[..16.min(block.len())])
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
