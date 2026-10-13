# Local patches to `iscsi-target` 1.0.0

`crates/vcrs-mount` serves the decrypted VeraCrypt data area as an iSCSI LUN, and
the Windows client is the in-box Microsoft Initiator (`msiscsi`).  Version 1.0.0
of the crate is not usable with that initiator as published, so the crate is
vendored here and wired in with

```toml
# Cargo.toml (workspace root)
[patch.crates-io]
iscsi-target = { path = "vendor/iscsi-target" }
```

Upstream: <https://github.com/lawless-m/iscsi-crate> (MIT OR Apache-2.0).
The vendored tree is the registry copy minus `.cargo-ok`/`Cargo.lock`; only
`src/pdu.rs` and `src/target.rs` differ (see `git diff` against
`~/.cargo/registry/src/*/iscsi-target-1.0.0/src`).

Delete this fork as soon as upstream fixes (1) and (2) below.

## (1) `src/target.rs` — signal residual overflow/underflow on the final Data-In

**Symptom.** The Microsoft Initiator logs in fine, issues `REPORT LUNS`,
`INQUIRY` and `READ CAPACITY`, and then resets the connection and retries
forever; no disk ever appears.  A packet capture shows every command answered
with a Data-In PDU whose DataSegmentLength is smaller than the initiator's
Expected Data Transfer Length (INQUIRY VPD with allocation length 255 is
answered with 8 bytes), yet with **no** residual flags and no residual count.

**Cause.** `build_scsi_response` completed commands inline in the Data-In PDU
(legal, RFC 7143 section 11.7.3) but never set the iSCSI `O`/`U` bits nor the
`Residual Count`, so the initiator could not tell a genuine short read from a
truncated transfer and dropped the session.

**Fix.** On the final Data-In chunk compare `cmd.expected_data_length` with
`response.data.len()`: set `0x04` (overflow) or `0x02` (underflow) in byte 1 and
write the difference into `specific[24..28]` (bytes 44..48, the residual count
field).  RFC 7143 section 11.4.5.2: "If SPDTL < EDTL for a task, iSCSI Underflow
MUST be signaled".

## (2) `src/pdu.rs` — move the SCSI response code and status out of `specific`

**Cause.** Bytes 2-3 of the basic header segment are not part of the
opcode-specific area, but the crate smuggled them through `specific[0]`,
`specific[1]` and (for Data-In) `specific[27]` — and `specific[27]` is the last
byte of the residual count that fix (1) needs.  `scsi_response` also wrote the
residual count at `specific[20..24]` (bytes 40..43) instead of the last field of
the response body, bytes 44..47.

**Fix.** `IscsiPdu` gains explicit `pub response: u8` and `pub status: u8`
fields (defaulted in `new()`, filled by `from_bytes`, emitted by `to_bytes`);
`scsi_response`/`scsi_data_in` fill them (keeping the legacy `specific` slots in
sync) and the residual count moved to `specific[24..28]`.  `from_bytes` already
read bytes 2-3 into `version_or_reserved`, so receiving code should read
`pdu.status` (or `pdu.version_or_reserved as u8`) rather than `specific[1]`.

## Still broken upstream (worked around, not patched)

* **Discovery sessions.** `QAddTargetPortal` (portal scan) opens a *discovery*
  session whose login needs the same multi-PDU handshake as a normal login, but
  `handle_discovery_session` only processes the first login PDU and then expects
  a `SendTargets` text request, so the scan always fails with "Target Error".
  Workaround (verified against Windows 10/11 build 26300): register the target
  statically and log in from there, both from an elevated prompt --

  ```
  iscsicli AddTarget <iqn> vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 "" "" 0 0
  iscsicli QLoginTarget <iqn>
  ```

  This uses the normal login path, which does handle the multi-PDU handshake.
  The two empty strings must reach `iscsicli` as genuinely empty arguments,
  which in PowerShell only happens through a `cmd /c` hop (see
  `scripts/vc-iscsi-e2e.ps1`).
* **CRC32C digests.** `negotiate_digest` accepts CRC32C when the initiator
  offers it, but multi-target responses are written with `write_pdu`
  (digest-less), so any client that offers CRC32C first (including the crate's
  own `IscsiClient::login`) sees a header digest mismatch.  The Microsoft
  Initiator offers `None` by default, so this does not affect us.
