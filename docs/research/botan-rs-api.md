# botan-rs 0.14 API cookbook for vc-rs

Verified against the actual crate sources (every signature copied from source) and the
Botan 3.13.0 build actually produced by the vendored build.

## Versions / wiring

- Workspace dependency (root `Cargo.toml`):
  `botan = { version = "0.14", default-features = false, features = ["std", "vendored"] }`
- `botan 0.14.0` -> `botan-sys 1.20260811.1` (FFI API `20260811`) -> `botan-src 0.31300.1`
  -> builds **Botan 3.13.0** from source.
- `botan` has **no** `send`/module cargo features for individual algorithms; the vendored
  build compiles Botan with its default module set (332 `BOTAN_HAS_*` modules; see item 6).
- Include everything with `use botan::*;` (the crate re-exports all modules, `src/lib.rs:186-221`).

## 1. PBKDF2 (HMAC-based) with a chosen hash

Exact botan-rs entry point (`botan-0.14.0/src/pbkdf.rs:106-117`):

```rust
pub fn pbkdf<A: crate::PasswordHashAlgorithmIdentifier>(
    algo: A,
    out_len: usize,
    passphrase: &str,
    salt: &[u8],
    iterations: usize,
) -> Result<Vec<u8>>;
```

`pbkdf` is a thin wrapper over `derive_key_from_password(algo, out_len, passphrase, salt,
iterations, 0, 0)`. Botan's `PasswordHashFamily::create` parses `PBKDF2(X)` by first trying
`MessageAuthenticationCode::create("HMAC(" + X + ")")` — i.e. `PBKDF2(SHA-256)` **is**
`HMAC(SHA-256)` (verified `Botan-3.13.0/src/lib/pbkdf/pwdhash.cpp:62-69`).

```rust
use botan::*;

// VeraCrypt PRFs -> exact Botan algorithm-name strings:
const PBKDF2_SHA256:    &str = "PBKDF2(SHA-256)";
const PBKDF2_SHA512:    &str = "PBKDF2(SHA-512)";
const PBKDF2_WHIRLPOOL: &str = "PBKDF2(Whirlpool)";
const PBKDF2_BLAKE2S:   &str = "PBKDF2(BLAKE2s(256))";   // BLAKE2s-256
const PBKDF2_STREEBOG:  &str = "PBKDF2(Streebog-512)";   // GOST R 34.11-2012

fn derive_prf(name: &str, password: &str, salt: &[u8], iterations: usize, out_len: usize)
    -> Result<Vec<u8>>
{
    botan::pbkdf(name, out_len, password, salt, iterations)
}

// Typical VeraCrypt header-key derivation: 64 bytes, 500_000 iterations.
let dk = botan::pbkdf(PBKDF2_SHA512, 64, password, &salt, 500_000)?;
```

Typed alternative (no stringly API): `PasswordHashAlgorithm::Pbkdf2(HashAlgorithm)`, e.g.
`PasswordHashAlgorithm::Pbkdf2(HashAlgorithm::Sha512)` -> `"PBKDF2(SHA-512)"`
(`botan-0.14.0/src/algo.rs:632-659`). `HashAlgorithm` models `Sha256`, `Sha512`,
`Whirlpool`, `Blake2s(u32)`; `Streebog-512` is **not** modeled — use a string or
`PasswordHashAlgorithm::Arbitrary("PBKDF2(Streebog-512)")`.

Caveats (important for VeraCrypt compatibility):
- `passphrase: &str`, so it must be valid UTF-8, and Botan passes `passphrase_len = 0` so
  it calls `strlen`: **the password may not contain an interior NUL byte**. VeraCrypt
  passwords are stored as UTF-8 byte strings, so `std::str::from_utf8` is the right bridge.
- `iterations: usize`; no upper bound enforced by the wrapper.

## 2. Argon2id

`pbkdf()` only supports PBKDF2; use the general form (`botan-0.14.0/src/pbkdf.rs:26-46`):

```rust
pub fn derive_key_from_password<A: crate::PasswordHashAlgorithmIdentifier>(
    algo: A,
    out_len: usize,
    passphrase: &str,
    salt: &[u8],
    param1: usize,   // Argon2: M = memory in KiB
    param2: usize,   // Argon2: t = iterations (time cost)
    param3: usize,   // Argon2: p = parallelism
) -> Result<Vec<u8>>;
```

Botan parameter order is `(M, t, p)` — **not** `(t, M, p)`. Confirmed end to end:
`botan_pwdhash` calls `pwdhash_fam->from_params(param1, param2, param3)`
(`.../src/lib/ffi/ffi_kdf.cpp:80-81`) and `Argon2_Family::from_params(size_t M, size_t t,
size_t p)` (`.../src/lib/pbkdf/argon2/argon2pwhash.cpp:149-151`). The Python binding agrees
(`botan3.py:1581`: `botan_pwdhash(variant, m, t, p, ...)`).

```rust
use botan::*;

// VeraCrypt Argon2id: 192-byte output, 64-byte salt, explicit memory/time, p = 1.
fn argon2id_derive(password: &str, salt: &[u8; 64],
                   m_cost_kib: usize, t_cost: usize, out_len: usize)
    -> Result<Vec<u8>>
{
    botan::derive_key_from_password(
        "Argon2id",        // PasswordHashAlgorithm::Argon2id
        out_len,           // 192 for VeraCrypt
        password,
        salt,
        m_cost_kib,        // param1 = M  (KiB)
        t_cost,            // param2 = t  (iterations)
        1,                 // param3 = p  (parallelism = 1)
    )
}

let key = argon2id_derive(password, &salt, 65536, 3, 192)?;
```

- Algorithm names: `"Argon2id"`, `"Argon2i"`, `"Argon2d"`
  (`botan-0.14.0/src/algo.rs:648-650`).
- `output_len` is arbitrary (Argon2's H' XOF expansion); `derive_key(out, out_len, …)` has
  no fixed-size restriction, so 192 bytes is fine.
- Constraints enforced by Botan (`argon2pwhash.cpp:37-42`):
  `p` in `1..=128`; `M >= 8 * p`; `M <= 8 * 1024 * 1024` KiB on 64-bit
  (`2 * 1024 * 1024` on 32-bit); `t >= 1`.
- **Default parallelism is 1**: `Argon2_Family::default_params()` is
  `from_params(128*1024, 1, 1)` and `tune_params` also uses `p = 1`
  (`argon2pwhash.cpp:77, 133-135`).

## 3. Raw 16-byte block encryption (AES/Serpent/Twofish/Camellia/Kuznyechik)

The raw block cipher type is `botan::BlockCipher` (single-block / ECB-style only). There is
**no `CipherDirection` parameter** on `BlockCipher::new` — direction only exists on
`Cipher` (modes/AEAD). Signatures (`botan-0.14.0/src/block.rs`):

```rust
impl BlockCipher {
    pub fn new<A: crate::BlockCipherAlgorithmIdentifier>(name: A) -> Result<BlockCipher>; // :34
    pub fn block_size(&self) -> Result<usize>;                                            // :66
    pub fn key_spec(&self) -> Result<KeySpec>;                                            // :95
    pub fn set_key(&mut self, key: &[u8]) -> Result<()>;                                  // :117
    pub fn encrypt_in_place(&self, buf: &mut [u8]) -> Result<()>;                         // :160
    pub fn decrypt_in_place(&self, buf: &mut [u8]) -> Result<()>;                          // :203
    pub fn encrypt_blocks(&self, input: &[u8]) -> Result<Vec<u8>>;                         // :152
    pub fn decrypt_blocks(&self, input: &[u8]) -> Result<Vec<u8>>;                         // :187
    pub fn clear(&mut self) -> Result<()>;                                                 // :219
}
```

`encrypt_in_place` / `decrypt_in_place` require `buf.len() % block_size == 0`; a single
16-byte block works. Use 32-byte keys for all VeraCrypt 256-bit ciphers.

```rust
use botan::*;

fn encipher(cipher_name: &str, key: &[u8; 32], block: [u8; 16]) -> Result<[u8; 16]> {
    let mut c = BlockCipher::new(cipher_name)?;
    c.set_key(key)?;                       // &mut self
    let mut buf = block;
    c.encrypt_in_place(&mut buf)?;         // &self
    Ok(buf)
}

// Exact Botan names + typed enum variants (botan-0.14.0/src/algo.rs:176-255):
//   "AES-256"       BlockCipherAlgorithm::Aes256       key = 32 (fixed)
//   "Serpent"       BlockCipherAlgorithm::Serpent      key = 16/24/32 (mod 8) -> use 32
//   "Twofish"       BlockCipherAlgorithm::Twofish      key = 16/24/32 (mod 8) -> use 32
//   "Camellia-256"  BlockCipherAlgorithm::Camellia256  key = 32 (fixed)
//   "Kuznyechik"    BlockCipherAlgorithm::Kuznyechik   key = 32 (fixed)
// NOTE: there is NO bare "Camellia" name; Botan only registers
// "Camellia-128" / "Camellia-192" / "Camellia-256" (block/block_cipher.cpp:180-196).
```

Key-length rules come from `Block_Cipher_Fixed_Params<block, kmin, kmax, kmod>`
(`Botan-3.13.0/src/lib/base/sym_algo.h:36`: `max = (max_k > 0 ? max_k : min_k)`):
`AES_256`/`Camellia_256`/`Kuznyechik` are `<16,32>` -> exactly 32; `Serpent`/`Twofish` are
`<16,16,32,8>` -> 16, 24 or 32. All five accept 32-byte keys.

XTS: implement it yourself. Botan *does* ship an `"AES-256/XTS"` etc. via
`CipherAlgorithm::Xts`, but its data-unit/tweak convention is not VeraCrypt's, so do not use
it; drive `BlockCipher` with your own tweak and per-cipher cascade.

## 4. Cryptographically secure random bytes

`botan::RandomNumberGenerator` (`botan-0.14.0/src/rng.rs`):

```rust
pub fn new_system() -> Result<RandomNumberGenerator>;   // "system" RNG :56
pub fn new() -> Result<RandomNumberGenerator>;          // userspace "user" :116
pub fn read(&mut self, len: usize) -> Result<Vec<u8>>;  // :128
pub fn fill(&mut self, out: &mut [u8]) -> Result<()>;   // :140
pub fn reseed(&mut self, bits: usize) -> Result<()>;    // :148
```

```rust
use botan::*;

let mut rng = RandomNumberGenerator::new_system()?;     // OS CSPRNG ("system")
let salt = rng.read(64)?;                               // 64-byte salt
let master_key = rng.read(64)?;                         // e.g. 512-bit master key
// or fill a fixed buffer:
let mut iv = [0u8; 16];
rng.fill(&mut iv)?;
```

`RngType::System` -> `"system"`, `RngType::User` -> `"user"`
(`botan-0.14.0/src/algo.rs:1306-1326`). Prefer `new_system()` for key/salt material.

## 5. Runtime algorithm availability

botan-rs 0.14 exposes **no** `have_block_cipher` / `have_hash` / `have_kdf` / `have_mac`
(those are C++ `Botan::` helpers; the C FFI set has no equivalent either). The supported
idiom is *trial construction*: the init calls return
`BOTAN_FFI_ERROR_NOT_IMPLEMENTED` when the algorithm was compiled out
(`ffi_block.cpp:26-28` for block ciphers; `botan_hash_init` and `botan_mac_init` behave the
same). Map that to `ErrorType::NotImplemented`.

```rust
use botan::*;

#[derive(Debug, PartialEq, Eq)]
enum Avail { Yes, No }

fn block_cipher_available(name: &str) -> Result<Avail> {
    match BlockCipher::new(name) {
        Ok(_) => Ok(Avail::Yes),
        Err(e) if e.error_type() == ErrorType::NotImplemented => Ok(Avail::No),
        Err(e) => Err(e),
    }
}

fn hash_available(name: &str) -> Result<Avail> {
    match HashFunction::new(name) {
        Ok(_) => Ok(Avail::Yes),
        Err(e) if e.error_type() == ErrorType::NotImplemented => Ok(Avail::No),
        Err(e) => Err(e),
    }
}
// KDF: `kdf::kdf(name, 1, &[], &[], &[])`; MAC: `MsgAuthCode::new(name)`.

// Library-level checks:
let v = Version::current()?;              // major/minor/patch/string (version.rs:29)
assert!(v.at_least(3, 13));
assert!(Version::supports_version(20191214));   // FFI API version
```

Note the two distinct meanings of `ErrorType::NotImplemented`:
`err.is_function_unavailable() == true` means the *FFI symbol* is missing from the linked
Botan; `false` means Botan itself has no such algorithm. For the vendored 3.13 build both
are effectively "not compiled in".

## 6. Cargo features and vendored module coverage

Required: `std` (for `Vec`/`String`/`Error: std::error::Error`) + `vendored` (build Botan
from source). That is exactly the workspace setting. You do **not** need the `rand` feature
(it only adds `rand_core::TryRng` impls, `rng.rs:176-192`); use `read`/`fill` instead.

All algorithms vc-rs needs are present in the vendored **Botan 3.13.0** static library.
Verified from the generated config at
`C:/Users/yuan/Desktop/vc-rs/target/debug/build/botan-sys-25a2c8b26b66ef5f/out/botan-build/build/build.h`
(332 modules), including:

```
BOTAN_HAS_AES         BOTAN_HAS_SERPENT      BOTAN_HAS_TWOFISH
BOTAN_HAS_CAMELLIA    BOTAN_HAS_KUZNYECHIK   BOTAN_HAS_CASCADE
BOTAN_HAS_PBKDF2      BOTAN_HAS_HMAC         BOTAN_HAS_ARGON2
BOTAN_HAS_SHA2_64     BOTAN_HAS_BLAKE2S      BOTAN_HAS_STREEBOG
BOTAN_HAS_WHIRLPOOL   BOTAN_HAS_SYSTEM_RNG
```

(There is no `BOTAN_HAS_DEV_RANDOM`; the OS entropy path is `BOTAN_HAS_SYSTEM_RNG`.)
No per-algorithm Cargo flag is needed. If a future build ever dropped a module,
`Version`/trial-construction (item 5) is the guard.

FFI bindings are **not** bindgen-generated into `.../out`; `botan-sys` hand-declares them in
`botan-sys-1.20260811.1/src/*.rs` (e.g. `botan_pwdhash` at `src/kdf.rs:26`, RNG at
`src/rng.rs:8-50`, block ciphers at `src/block.rs`).

## 7. Error handling

```rust
// botan-0.14.0/src/utils.rs:22
pub type Result<T> = core::result::Result<T, Error>;

// botan-0.14.0/src/utils.rs:247-282
pub struct Error { /* err_type, message, fn_unavailable */ }
impl Error {
    pub fn error_type(&self) -> ErrorType;
    pub fn error_message(&self) -> Option<&str>;
    pub fn is_function_unavailable(&self) -> bool;
}
#[non_exhaustive]                                  // utils.rs:380
pub enum ErrorType { BadAuthCode, BadFlag, BadParameter, NoValueAvailable,
    ExceptionThrown, InsufficientBufferSpace, StringConversionError, InternalError,
    InvalidInput, InvalidObject, InvalidObjectState, InvalidVerifier, InvalidKeyLength,
    KeyNotSet, NotImplemented, NullPointer, OutOfMemory, SystemError, UnknownError,
    ConversionError, TlsError, HttpError, LibraryNotLoaded }
```

`Error` is `Clone + Debug + PartialEq + Eq`, implements `Display`, and (with `std`)
`std::error::Error`, so it drops straight into `thiserror`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum VcError {
    #[error("botan: {0}")]
    Botan(#[from] botan::Error),
    #[error("bad key length")]
    BadKey,
}
```

Notable variants for vc-rs: `InvalidKeyLength` (wrong key size to `set_key`), `KeyNotSet`
(encrypt/decrypt before `set_key`), `InvalidInput` (buffer not a multiple of the 16-byte
block size), `NotImplemented` (algorithm/FFI unavailable).

## 8. Thread safety and object reuse

Every handle type is explicitly `Send + Sync` via `unsafe impl`:

- `unsafe impl Sync for BlockCipher {}` / `unsafe impl Send for BlockCipher {}`
  (`botan-0.14.0/src/block.rs:16-17`)
- `RandomNumberGenerator` (`src/rng.rs:10-11`), `HashFunction` (`src/hash.rs:17-18`),
  `MsgAuthCode` (`src/mac.rs:14-15`), and `Cipher` (`src/cipher.rs:18-19`) likewise.

Recommended reuse pattern: build one `BlockCipher` per cipher, call `set_key` (takes
`&mut self`), then share `&BlockCipher` — `encrypt_in_place`/`decrypt_in_place` take
`&self`, so they can be called concurrently (Botan 3.x block ciphers are const-correct).
Rekeying requires `&mut self`, so serialize it (own the object per thread, or guard with
`Mutex`/`RwLock`). Keep separate objects when two different keys are live at once.

```rust
use std::sync::{Arc, Mutex};
use botan::*;

struct XtsCipher { enc: BlockCipher, dec: BlockCipher }

impl XtsCipher {
    fn new(name: &str, key: &[u8]) -> Result<Self> {
        let mut enc = BlockCipher::new(name)?;
        let mut dec = BlockCipher::new(name)?;
        enc.set_key(key)?;
        dec.set_key(key)?;
        Ok(Self { enc, dec })
    }
}

// Arc<XtsCipher> can be shared across threads; `enc`/`dec` are used via &self.
// `BlockCipher::clear(&mut self)` wipes the key when done.
```

The per-key serialization lock in `botan-0.14.0/src/pubkey.rs:36-45` applies only to
certain post-quantum private-key algorithms on Botan < 3.11 and does not affect symmetric
block ciphers or the RNG.

