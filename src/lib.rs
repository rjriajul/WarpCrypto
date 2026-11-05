//! Fast AES-256-IGE, AES-256-CTR and MTProto 2.0 message packing for Telegram clients.
//!
//! The same code also builds the `warpcrypto` Python extension (behind the `python` feature).

use aes::{Aes256, Aes256Enc};
use aes::cipher::typenum::U16;
use aes::cipher::typenum::Unsigned;
use aes::cipher::{
    Array, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, KeyInit, ParBlocks,
};
use sha2::{Digest, Sha256};
use std::mem::ManuallyDrop;
use std::ops::Deref;
use std::sync::atomic::{Ordering, compiler_fence};

type AesBlock = Array<u8, U16>;

/// A cipher whose key schedule is overwritten with zeros when it is dropped.
///
/// `aes` is built without its `zeroize` feature: from 0.9 that feature wipes the whole cipher
/// (about 1 KB, sized for the software fallback) one byte at a time on every drop, which costs
/// more than encrypting a short message. This wipes the same bytes a machine word at a time.
struct Wiped<C>(ManuallyDrop<C>);

impl<C: KeyInit> Wiped<C> {
    /// Panics unless `key` has the cipher's key length.
    fn new(key: &[u8]) -> Self {
        Self(ManuallyDrop::new(C::new_from_slice(key).unwrap()))
    }
}

impl<C> Deref for Wiped<C> {
    type Target = C;

    fn deref(&self) -> &C {
        &self.0
    }
}

impl<C> Drop for Wiped<C> {
    fn drop(&mut self) {
        const { assert!(align_of::<C>() >= align_of::<usize>()) };
        let words = size_of::<C>() / size_of::<usize>();
        let tail = size_of::<C>() % size_of::<usize>();
        let p = (&mut *self.0 as *mut C).cast::<usize>();
        // SAFETY: `p` points to the `size_of::<C>()` bytes of `self.0` and is aligned for `usize`
        // (asserted above); `words` words and then `tail` bytes cover exactly those bytes.
        // `self.0` is never read or dropped after this, so the zeros need not be a valid `C`.
        // Skipping `C`'s destructor is fine because it does nothing here: in aes 0.9.2 the `Drop`
        // of `Aes256`/`Aes256Enc` (src/lib.rs:434-442) has the `zeroize` wipe as its only
        // statement, compiled out since that feature is off, and the ciphers own no heap memory.
        // `needs_drop::<C>()` is still true because the impl exists, so this can't be asserted;
        // it relies on that body staying empty, which the `<0.9.3` cap in Cargo.toml pins.
        unsafe {
            for i in 0..words {
                p.add(i).write_volatile(0);
            }
            let p = p.add(words).cast::<u8>();
            for i in 0..tail {
                p.add(i).write_volatile(0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[inline(always)]
fn block_from_slice(s: &[u8]) -> AesBlock {
    let mut b = [0u8; 16];
    b.copy_from_slice(&s[..16]);
    AesBlock::from(b)
}

#[inline(always)]
fn word_at(s: &[u8], at: usize) -> u128 {
    u128::from_ne_bytes(s[at..at + 16].try_into().unwrap())
}

struct IgeEncrypt<'a> {
    data: &'a mut [u8],
    iv: &'a [u8],
}

impl BlockSizeUser for IgeEncrypt<'_> {
    type BlockSize = U16;
}

impl BlockCipherEncClosure for IgeEncrypt<'_> {
    fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, backend: &B) {
        let mut iv1 = word_at(self.iv, 0);
        let mut iv2 = word_at(self.iv, 16);

        for chunk in self.data.chunks_exact_mut(16) {
            let plain = u128::from_ne_bytes(chunk.try_into().unwrap());
            let mut block = AesBlock::from((plain ^ iv1).to_ne_bytes());
            backend.encrypt_block_inplace(&mut block);
            let out = u128::from_ne_bytes(block.into()) ^ iv2;
            chunk.copy_from_slice(&out.to_ne_bytes());
            iv1 = out;
            iv2 = plain;
        }
    }
}

struct IgeDecrypt<'a> {
    data: &'a mut [u8],
    iv: &'a [u8],
}

impl BlockSizeUser for IgeDecrypt<'_> {
    type BlockSize = U16;
}

impl BlockCipherDecClosure for IgeDecrypt<'_> {
    fn call<B: BlockCipherDecBackend<BlockSize = U16>>(self, backend: &B) {
        let mut iv1 = word_at(self.iv, 16);
        let mut iv2 = word_at(self.iv, 0);

        for chunk in self.data.chunks_exact_mut(16) {
            let ct = u128::from_ne_bytes(chunk.try_into().unwrap());
            let mut block = AesBlock::from((ct ^ iv1).to_ne_bytes());
            backend.decrypt_block_inplace(&mut block);
            let out = u128::from_ne_bytes(block.into()) ^ iv2;
            chunk.copy_from_slice(&out.to_ne_bytes());
            iv1 = out;
            iv2 = ct;
        }
    }
}

fn ige256_encrypt_slice(data: &mut [u8], cipher: &Wiped<Aes256>, iv: &[u8]) {
    cipher.encrypt_with_backend(IgeEncrypt { data, iv });
}

fn ige256_decrypt_slice(data: &mut [u8], cipher: &Wiped<Aes256>, iv: &[u8]) {
    cipher.decrypt_with_backend(IgeDecrypt { data, iv });
}

const KDF_A_LO: usize = 0;
const KDF_A_HI: usize = 36;
const KDF_B_LO: usize = 40;
const KDF_B_HI: usize = 76;
const MSG_KEY_AUTH_LO: usize = 88;
const MSG_KEY_AUTH_HI: usize = 120;

#[inline(always)]
fn kdf_inner(auth_key: &[u8], msg_key: &[u8], x: usize) -> ([u8; 32], [u8; 32]) {
    let sha_a = {
        let mut h = Sha256::new();
        h.update(msg_key);
        h.update(&auth_key[x + KDF_A_LO..x + KDF_A_HI]);
        h.finalize()
    };
    let sha_b = {
        let mut h = Sha256::new();
        h.update(&auth_key[x + KDF_B_LO..x + KDF_B_HI]);
        h.update(msg_key);
        h.finalize()
    };

    let mut aes_key = [0u8; 32];
    aes_key[..8].copy_from_slice(&sha_a[..8]);
    aes_key[8..24].copy_from_slice(&sha_b[8..24]);
    aes_key[24..32].copy_from_slice(&sha_a[24..32]);

    let mut aes_iv = [0u8; 32];
    aes_iv[..8].copy_from_slice(&sha_b[..8]);
    aes_iv[8..24].copy_from_slice(&sha_a[8..24]);
    aes_iv[24..32].copy_from_slice(&sha_b[24..32]);

    (aes_key, aes_iv)
}

#[inline(always)]
fn ctr_next(ctr: &mut [u8; 16]) {
    *ctr = u128::from_be_bytes(*ctr).wrapping_add(1).to_be_bytes();
}

struct CtrProcess<'a> {
    data: &'a mut [u8],
    ctr: &'a mut [u8; 16],
    state: &'a mut usize,
}

impl BlockSizeUser for CtrProcess<'_> {
    type BlockSize = U16;
}

impl BlockCipherEncClosure for CtrProcess<'_> {
    fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, backend: &B) {
        let data = self.data;
        let ctr = self.ctr;
        let state = self.state;

        let len = data.len();
        if len == 0 { return; }

        let mut pos = 0;

        if *state != 0 {
            let mut ks = block_from_slice(ctr);
            backend.encrypt_block_inplace(&mut ks);
            let take = (16 - *state).min(len);
            for i in 0..take {
                data[pos + i] ^= ks[*state + i];
            }
            pos += take;
            *state += take;
            if *state == 16 {
                *state = 0;
                ctr_next(ctr);
            }
            if pos == len { return; }
        }

        let wide_n = B::ParBlocksSize::USIZE;
        let mut wide = data[pos..].chunks_exact_mut(wide_n * 16);
        for group in &mut wide {
            let mut ks: ParBlocks<B> = Default::default();
            for k in ks.iter_mut() {
                *k = block_from_slice(ctr);
                ctr_next(ctr);
            }
            backend.encrypt_par_blocks_inplace(&mut ks);
            for (i, k) in ks.iter().enumerate() {
                let at = i * 16;
                let x = u128::from_ne_bytes(group[at..at + 16].try_into().unwrap())
                    ^ u128::from_ne_bytes((*k).into());
                group[at..at + 16].copy_from_slice(&x.to_ne_bytes());
            }
        }

        let mut chunks = wide.into_remainder().chunks_exact_mut(16);
        for chunk in &mut chunks {
            let mut ks = block_from_slice(ctr);
            backend.encrypt_block_inplace(&mut ks);
            let x = u128::from_ne_bytes(chunk.try_into().unwrap())
                ^ u128::from_ne_bytes(ks.into());
            chunk.copy_from_slice(&x.to_ne_bytes());
            ctr_next(ctr);
        }
        let tail = chunks.into_remainder();

        if !tail.is_empty() {
            let mut ks = block_from_slice(ctr);
            backend.encrypt_block_inplace(&mut ks);
            for i in 0..tail.len() {
                tail[i] ^= ks[i];
            }
            *state = tail.len();
        }
    }
}

fn ctr_process<C: BlockCipherEncrypt<BlockSize = U16>>(data: &mut [u8], cipher: &Wiped<C>, ctr: &mut [u8; 16], state: &mut usize) {
    cipher.encrypt_with_backend(CtrProcess { data, ctr, state });
}

fn packed_len(body_len: usize) -> usize {
    let inner_len = 8 + 8 + 8 + 4 + 4 + body_len;
    24 + ((inner_len + 12 + 15) & !15)
}

/// Writes salt, session_id, msg_id, seq_no, length, body and random padding after the 24-byte outer header.
fn pack_plain(out: &mut [u8], msg_id: i64, seq_no: i32, body: &[u8], salt: i64, session_id: &[u8]) {
    let plain = &mut out[24..];
    let (salt_slice, rest) = plain.split_at_mut(8);
    salt_slice.copy_from_slice(&(salt as u64).to_le_bytes());
    let (sid, rest) = rest.split_at_mut(8);
    sid.copy_from_slice(session_id);
    let (mid, rest) = rest.split_at_mut(8);
    mid.copy_from_slice(&(msg_id as u64).to_le_bytes());
    let (sn, rest) = rest.split_at_mut(4);
    sn.copy_from_slice(&(seq_no as u32).to_le_bytes());
    let (lenb, rest) = rest.split_at_mut(4);
    lenb.copy_from_slice(&(body.len() as u32).to_le_bytes());
    let (data_slice, padding) = rest.split_at_mut(body.len());
    data_slice.copy_from_slice(body);
    let _ = getrandom::getrandom(padding);
}

/// Encrypts the plaintext written by `pack_plain` in place and fills in auth_key_id and msg_key.
fn pack_seal(out: &mut [u8], auth_key: &[u8; 256], auth_key_id: &[u8; 8]) {
    // https://core.telegram.org/mtproto/description
    // msg_key = SHA256(auth_key[88+x:88+x+32] + plaintext)[8:24]
    // x=0 for outgoing (client→server), so auth_key[88:120]
    let msg_key_large = {
        let mut h = Sha256::new();
        h.update(&auth_key[MSG_KEY_AUTH_LO..MSG_KEY_AUTH_HI]);
        h.update(&out[24..]);
        h.finalize()
    };
    let msg_key: [u8; 16] = msg_key_large[8..24].try_into().unwrap();

    let (aes_key, aes_iv) = kdf_inner(auth_key, &msg_key, 0);
    let cipher = Wiped::<Aes256>::new(&aes_key);
    ige256_encrypt_slice(&mut out[24..], &cipher, &aes_iv);

    out[..8].copy_from_slice(auth_key_id);
    out[8..24].copy_from_slice(&msg_key);
}

/// Checks the outer header and returns the msg_key.
fn unpack_header(packed: &[u8], auth_key_id: &[u8]) -> Result<[u8; 16], Error> {
    if packed.len() < 24 {
        return Err(Error::TooShort);
    }
    if packed[..8] != *auth_key_id {
        return Err(Error::AuthKeyIdMismatch);
    }
    Ok(packed[8..24].try_into().unwrap())
}

/// Decrypts `dec` (everything after the outer header) in place and runs the MTProto checks.
/// Returns msg_id, seq_no and the body length; the body is `dec[32..32 + length]`.
fn unpack_open(dec: &mut [u8], msg_key: &[u8; 16], auth_key: &[u8; 256], session_id: &[u8], incoming: bool) -> Result<(i64, i32, usize), Error> {
    let x: usize = if incoming { 8 } else { 0 };
    let (aes_key, aes_iv) = kdf_inner(auth_key, msg_key, x);
    let cipher = Wiped::<Aes256>::new(&aes_key);
    ige256_decrypt_slice(dec, &cipher, &aes_iv);

    if dec.len() < 32 {
        return Err(Error::MsgKeyMismatch);
    }

    // https://core.telegram.org/mtproto/description
    // msg_key = SHA256(auth_key[88+x:88+x+32] + plaintext + padding)[8:24]
    // where x=0 for client->server (outgoing), x=8 for server->client (incoming)
    // https://core.telegram.org/mtproto/security_guidelines#checking-sha256-hash-value-of-msg-key
    // Note: the security guidelines page incorrectly omits the x offset (always shows 88:120)
    let (msg_key_lo, msg_key_hi) = if incoming {
        (96usize, 128usize)
    } else {
        (88usize, 120usize)
    };
    let msg_key_check = {
        let mut h = Sha256::new();
        h.update(&auth_key[msg_key_lo..msg_key_hi]);
        h.update(&*dec);
        h.finalize()
    };
    if msg_key_check[8..24] != *msg_key {
        return Err(Error::MsgKeyMismatch);
    }

    // https://core.telegram.org/mtproto/security_guidelines#checking-session-id
    if dec[8..16] != *session_id {
        return Err(Error::SessionIdMismatch);
    }
    let msg_id = i64::from_le_bytes(dec[16..24].try_into().unwrap());
    let seq_no = i32::from_le_bytes(dec[24..28].try_into().unwrap());
    let length_i32 = i32::from_le_bytes(dec[28..32].try_into().unwrap());
    if length_i32 < 0 {
        return Err(Error::NegativeLength);
    }
    let length = length_i32 as usize;
    if 32 + length > dec.len() {
        return Err(Error::LengthExceedsData);
    }
    // https://core.telegram.org/mtproto/security_guidelines#checking-message-length
    if length % 4 != 0 {
        return Err(Error::LengthNotAligned);
    }
    if !(12..=1024).contains(&(dec.len() - 32 - length)) {
        return Err(Error::PaddingOutOfRange);
    }
    Ok((msg_id, seq_no, length))
}

/// Why an operation was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// IGE input length is not a multiple of 16 bytes.
    NotBlockAligned,
    /// Packed message is shorter than its 24-byte outer header.
    TooShort,
    AuthKeyIdMismatch,
    /// The message was tampered with, corrupted, or encrypted with another key.
    MsgKeyMismatch,
    SessionIdMismatch,
    NegativeLength,
    LengthExceedsData,
    LengthNotAligned,
    PaddingOutOfRange,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::NotBlockAligned => "data length must be a multiple of 16 bytes",
            Error::TooShort => "packed data too short",
            Error::AuthKeyIdMismatch => "auth_key_id mismatch",
            Error::MsgKeyMismatch => "msg_key mismatch",
            Error::SessionIdMismatch => "session_id mismatch",
            Error::NegativeLength => "negative body length",
            Error::LengthExceedsData => "body length exceeds decrypted data",
            Error::LengthNotAligned => "body length not divisible by 4",
            Error::PaddingOutOfRange => "padding length out of range",
        })
    }
}

impl std::error::Error for Error {}

/// AES-256-IGE encrypts `data` in place. `data.len()` must be a multiple of 16.
pub fn ige256_encrypt(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) -> Result<(), Error> {
    if data.len() % 16 != 0 {
        return Err(Error::NotBlockAligned);
    }
    ige256_encrypt_slice(data, &Wiped::new(key), iv);
    Ok(())
}

/// AES-256-IGE decrypts `data` in place. `data.len()` must be a multiple of 16.
pub fn ige256_decrypt(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) -> Result<(), Error> {
    if data.len() % 16 != 0 {
        return Err(Error::NotBlockAligned);
    }
    ige256_decrypt_slice(data, &Wiped::new(key), iv);
    Ok(())
}

/// AES-256-CTR encrypts or decrypts `data` in place.
///
/// `iv` (the counter) and `state` (bytes already used from the current keystream block)
/// are updated, so a stream can be processed across several calls. Start `state` at 0;
/// a value of 16 or more is treated as 0.
pub fn ctr256(data: &mut [u8], key: &[u8; 32], iv: &mut [u8; 16], state: &mut u8) {
    let mut off = if *state < 16 { *state as usize } else { 0 };
    ctr_process(data, &Wiped::<Aes256>::new(key), iv, &mut off);
    *state = off as u8;
}

/// AES-256-CTR with the key expanded once, for a stream processed piece by piece.
///
/// Gives the same output as [`ctr256`] called with the same key on each piece, without
/// expanding the key again on every call.
///
/// ```
/// let (key, iv) = ([7u8; 32], [9u8; 16]);
/// let mut a = *b"split across calls";
/// let mut b = a;
///
/// let mut ctr = warpcrypto::Ctr256::new(&key, &iv);
/// ctr.apply_keystream(&mut a[..5]);
/// ctr.apply_keystream(&mut a[5..]);
///
/// let (mut iv, mut state) = (iv, 0);
/// warpcrypto::ctr256(&mut b, &key, &mut iv, &mut state);
/// assert_eq!(a, b);
/// assert_eq!((ctr.iv(), ctr.state()), (&iv, state));
/// ```
pub struct Ctr256 {
    cipher: Wiped<Aes256Enc>,
    iv: [u8; 16],
    state: usize,
}

impl Ctr256 {
    /// Starts a stream at counter `iv`.
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self { cipher: Wiped::new(key), iv: *iv, state: 0 }
    }

    /// Encrypts or decrypts `data` in place, continuing where the previous call stopped.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        ctr_process(data, &self.cipher, &mut self.iv, &mut self.state);
    }

    /// The current counter, as [`ctr256`] would have left `iv`.
    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    /// Bytes already used from the current keystream block, as [`ctr256`] would have left `state`.
    pub fn state(&self) -> u8 {
        self.state as u8
    }
}

impl std::fmt::Debug for Ctr256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctr256").finish_non_exhaustive()
    }
}

/// MTProto 2.0 key derivation: returns `(aes_key, aes_iv)` for a message.
/// `outgoing` is true for client→server messages (x=0) and false for server→client (x=8).
pub fn kdf(auth_key: &[u8; 256], msg_key: &[u8; 16], outgoing: bool) -> ([u8; 32], [u8; 32]) {
    kdf_inner(auth_key, msg_key, if outgoing { 0 } else { 8 })
}

/// Encrypts a client→server MTProto 2.0 message, ready to send.
pub fn pack_message(auth_key: &[u8; 256], auth_key_id: &[u8; 8], session_id: &[u8; 8], salt: i64, msg_id: i64, seq_no: i32, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; packed_len(body.len())];
    pack_plain(&mut out, msg_id, seq_no, body, salt, session_id);
    pack_seal(&mut out, auth_key, auth_key_id);
    out
}

/// A decrypted MTProto message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub msg_id: i64,
    pub seq_no: i32,
    pub body: Vec<u8>,
}

/// Decrypts and checks an MTProto 2.0 message.
/// `incoming` is true for server→client messages, the usual case for a client.
pub fn unpack_message(packed: &[u8], auth_key: &[u8; 256], auth_key_id: &[u8; 8], session_id: &[u8; 8], incoming: bool) -> Result<Message, Error> {
    let msg_key = unpack_header(packed, auth_key_id)?;
    let mut dec = packed[24..].to_vec();
    let (msg_id, seq_no, length) = unpack_open(&mut dec, &msg_key, auth_key, session_id, incoming)?;
    dec.truncate(32 + length);
    dec.drain(..32);
    Ok(Message { msg_id, seq_no, body: dec })
}

#[cfg(feature = "python")]
mod python;
