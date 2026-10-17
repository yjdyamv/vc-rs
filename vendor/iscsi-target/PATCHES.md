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
The vendored tree is the registry copy minus `.cargo-ok`/`Cargo.lock`;
`src/pdu.rs`, `src/target.rs`, `src/session.rs` and `src/typestate_session.rs`
differ (see `git diff` against
`~/.cargo/registry/src/*/iscsi-target-1.0.0/src`).

`vendor/iscsi-target` is also listed in the workspace `members` array, so
`cargo test --workspace` runs this crate's own tests (64 of them at the time of
writing).  That is deliberate: the patches below are not otherwise exercised by
anything, and the crate cannot be tested through a path dependency alone.

Delete this fork as soon as upstream fixes (1) to (4) below.

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

## (3) `src/target.rs` — bound what a WRITE command may allocate

**Cause.** `handle_write_command` computed `expected_data_len` straight from the
CDB (`transfer_length as usize * block_size as usize`) and used it for
`vec![0u8; expected_data_len]`.  A `WRITE(32)` CDB carries a 32-bit block count,
so one command could ask for a ~2 TiB allocation; a PDU carrying more immediate
data than the CDB asked for then indexed `buffer[..pdu.data.len()]` and panicked,
and the `expected_data_len as u32 - bytes_received` on the Data-Out path
underflowed.  The capacity checks in `src/scsi.rs` were unreachable because
`handle_write_command` answers the command itself.

**Fix.** `check_write_span(lba, transfer_length, block_size, capacity,
immediate_len)` rejects an out-of-range LBA (`LBA Out Of Range`), a transfer
above `MAX_WRITE_BYTES` (256 MiB) and immediate data longer than the transfer
(`Invalid Command`), and both WRITE handlers answer `CHECK CONDITION` with that
sense data instead of allocating.  The Data-Out handlers use `saturating_mul`
for `total_expected`.

## (4) `src/typestate_session.rs`, `src/session.rs` — a login may not skip CHAP

**Cause.** `TypestateSession<Free>::process_login` forwards a first login with
`CSG=1` straight to `LoginOperationalNegotiation::process_login`, whose
`transit && NSG == 3` branch reached `FullFeaturePhase` without consulting
`auth_config` or the ACL, so an initiator could get a full session on a target
configured for CHAP without ever authenticating.  (vc-rs itself configures
`AuthConfig::None`, so for this project it is defence in depth.)

**Fix.** Both session types gain `login_may_transit()`
(`!auth_config.requires_auth() || chap_completed`); the
`LoginOperationalNegotiation` branch now rejects such a login with `AUTH_FAILURE`
and the other login path ANDs the same predicate into its transit decision.
Covered by `typestate_session::tests::a_login_that_skips_security_negotiation_*`.

## (5) `src/typestate_session.rs` — the CHAP challenge reply must echo `AuthMethod`

**Cause.** In `handle_chap_auth`, the branch that sends the challenge
(`chap_a.is_some() && chap_state.is_none()`) built its response without
`AuthMethod`.  RFC 7143 makes `AuthMethod` mandatory in both the
SecurityNegotiation request and its response; the Microsoft initiator requires
it and does not answer a challenge that omits it.

**Fix.** The challenge reply now carries `AuthMethod=CHAP` in front of
`TargetPortalGroupTag`, `CHAP_A`, `CHAP_I` and `CHAP_C`.

## (6) `src/target.rs` — the connection handler has to use the configured session

**Cause.** `handle_connection_with_first_pdu_boxed` created its session with
`AnySession::new()`, which is `AuthConfig::None`, instead of the target's own
configuration.  A target therefore answered the initiator's very first login
PDU with `AuthMethod=None` no matter what `add_target_with_auth` had been given,
and Windows refused the session with the event `iScsiPrt` 38: "the initiator
requires CHAP for login authentication, but the target did not offer CHAP".
This is why authentication could not be turned on in the first place; the bug in
(4) only mattered after this one was fixed.

**Fix.** The session is built with
`AnySession::new_configured(auth_config.clone(), target_name, target_alias,
allowed_initiators.clone())`.  Covered by
`target::tests::a_configured_connection_answers_the_first_login_with_chap`,
which drives the real handler over a socket pair (and was checked to fail when
this fix is reverted) and by
`typestate_session::tests::a_configured_session_offers_chap_in_the_first_login_reply`.

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

  (with `--chap` the credential arguments and the type change: `... 0 0 vcrs
  <secret> 1 0`, and `vcrs attach --chap-from <volume>` computes the secret
  from the container's header salt for you.)

  This uses the normal login path, which does handle the multi-PDU handshake.
  The two empty strings must reach `iscsicli` as genuinely empty arguments.
  `scripts/vc-iscsi-e2e.ps1` needs a `cmd /c` hop for that because of how
  PowerShell quotes arguments; the Rust side does not, because a Rust
  `Command` passes an empty argument through as an empty argv element (verified
  with a throwaway program), so `vcrs-host` passes all eighteen arguments of
  `AddTarget` directly to `iscsicli` -- see `attach.rs`.
* **CRC32C digests.** `negotiate_digest` accepts CRC32C when the initiator
  offers it, but multi-target responses are written with `write_pdu`
  (digest-less), so any client that offers CRC32C first (including the crate's
  own `IscsiClient::login`) sees a header digest mismatch.  The Microsoft
  Initiator offers `None` by default, so this does not affect us.
