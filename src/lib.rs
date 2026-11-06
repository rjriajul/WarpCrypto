//! Fast AES-256-IGE, AES-256-CTR and MTProto 2.0 message packing for Telegram clients.
//!
//! The same code also builds the `warpcrypto` Python extension (behind the `python` feature).

use aes::{Aes256Dec, Aes256Enc};
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

/// Ciphers a [`Wiped`] may hold: plain bytes with no heap memory or handles.
trait PlainKeySchedule: KeyInit {}
impl PlainKeySchedule for Aes256Enc {}
impl PlainKeySchedule for Aes256Dec {}

/// A cipher whose key schedule is overwritten with zeros when it is dropped.
///
/// This crate doesn't turn on `aes`'s `zeroize` feature: from 0.9 that feature wipes the whole
/// cipher one byte at a time on every drop, which costs more than encrypting a short message.
/// This wipes the same bytes a machine word at a time.
///
/// Best effort: copies Rust leaves when a value is moved aren't wiped. Don't move a `Wiped`;
/// use [`Wiped::boxed`] for one on the heap.
#[repr(transparent)]
struct Wiped<C: PlainKeySchedule>(ManuallyDrop<C>);

impl<C: PlainKeySchedule> Wiped<C> {
    /// Panics unless `key` has the cipher's key length.
    fn new(key: &[u8]) -> Self {
        Self(ManuallyDrop::new(C::new_from_slice(key).unwrap()))
    }

    /// Like [`Wiped::new`], on the heap, with the stack copy wiped.
    fn boxed(key: &[u8]) -> Box<Self> {
        let tmp = Self::new(key);
        let mut b = Box::<Self>::new_uninit();
        // SAFETY: `C` is plain bytes, so a byte copy is a valid `Self` and both copies can be
        // dropped; dropping `tmp` wipes the stack copy.
        unsafe {
            b.as_mut_ptr().copy_from_nonoverlapping(&tmp, 1);
            b.assume_init()
        }
    }
}

impl<C: PlainKeySchedule> Deref for Wiped<C> {
    type Target = C;

    fn deref(&self) -> &C {
        &self.0
    }
}

impl<C: PlainKeySchedule> Drop for Wiped<C> {
    fn drop(&mut self) {
        const { assert!(align_of::<C>() >= align_of::<usize>()) };
        let words = size_of::<C>() / size_of::<usize>();
        let tail = size_of::<C>() % size_of::<usize>();
        let p = (&mut *self.0 as *mut C).cast::<usize>();
        // SAFETY: `p` points to the `size_of::<C>()` bytes of `self.0` and is aligned for `usize`
        // (asserted above); `words` words and then `tail` bytes cover exactly those bytes.
        // `self.0` is never read or dropped after this, so the zeros need not be a valid `C`.
        // Not running `C`'s destructor is allowed in safe Rust (as with `mem::forget`), so it
        // can't make this unsound, and `PlainKeySchedule` limits `C` to types where it loses
        // nothing: their `Drop` only wipes, and only when some crate in the build turns on
        // `aes`'s `zeroize` feature.
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

fn ige256_encrypt_slice(data: &mut [u8], cipher: &Wiped<Aes256Enc>, iv: &[u8]) {
    cipher.encrypt_with_backend(IgeEncrypt { data, iv });
}

fn ige256_decrypt_slice(data: &mut [u8], cipher: &Wiped<Aes256Dec>, iv: &[u8]) {
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
    /// Keystream for `ctr` while `state != 0`; trusted on entry only if `ks_ready`.
    ks: &'a mut AesBlock,
    ks_ready: bool,
}

impl BlockSizeUser for CtrProcess<'_> {
    type BlockSize = U16;
}

impl BlockCipherEncClosure for CtrProcess<'_> {
    fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, backend: &B) {
        let data = self.data;
        let ctr = self.ctr;
        let state = self.state;
        let ks = self.ks;

        let len = data.len();
        if len == 0 { return; }

        let mut pos = 0;

        if *state != 0 {
            if !self.ks_ready {
                *ks = block_from_slice(ctr);
                backend.encrypt_block_inplace(ks);
            }
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

        // The counter stays in a local until the end. Storing it to `ctr` after every block and
        // loading it again for the next made each block wait for that store to land. LLVM keeps
        // it in registers when it fully unrolls the 8-block batches of the AES-NI backend, but
        // not for the 64-block batches of the AVX-512 VAES backend that aes 0.9.4 picks at
        // runtime, where it cost about 60% of the speed.
        let mut c = u128::from_be_bytes(*ctr);

        let mut wide = data[pos..].chunks_exact_mut(B::ParBlocksSize::USIZE * 16);
        let mut par: ParBlocks<B> = Default::default();
        for group in &mut wide {
            for k in par.iter_mut() {
                *k = AesBlock::from(c.to_be_bytes());
                c = c.wrapping_add(1);
            }
            backend.encrypt_par_blocks_inplace(&mut par);
            for (chunk, k) in group.chunks_exact_mut(16).zip(par.iter()) {
                let x = u128::from_ne_bytes(chunk.try_into().unwrap())
                    ^ u128::from_ne_bytes((*k).into());
                chunk.copy_from_slice(&x.to_ne_bytes());
            }
        }

        let mut chunks = wide.into_remainder().chunks_exact_mut(16);
        for chunk in &mut chunks {
            let mut k = AesBlock::from(c.to_be_bytes());
            backend.encrypt_block_inplace(&mut k);
            let x = u128::from_ne_bytes(chunk.try_into().unwrap()) ^ u128::from_ne_bytes(k.into());
            chunk.copy_from_slice(&x.to_ne_bytes());
            c = c.wrapping_add(1);
        }
        *ctr = c.to_be_bytes();
        let tail = chunks.into_remainder();

        if !tail.is_empty() {
            *ks = AesBlock::from(*ctr);
            backend.encrypt_block_inplace(ks);
            for i in 0..tail.len() {
                tail[i] ^= ks[i];
            }
            *state = tail.len();
        }
    }
}

fn ctr_process(data: &mut [u8], cipher: &Wiped<Aes256Enc>, ctr: &mut [u8; 16], state: &mut usize) {
    let mut ks = AesBlock::default();
    cipher.encrypt_with_backend(CtrProcess { data, ctr, state, ks: &mut ks, ks_ready: false });
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
    let cipher = Wiped::<Aes256Enc>::new(&aes_key);
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
    let cipher = Wiped::<Aes256Dec>::new(&aes_key);
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
    ctr_process(data, &Wiped::new(key), iv, &mut off);
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
    cipher: Box<Wiped<Aes256Enc>>,
    iv: [u8; 16],
    state: usize,
    ks: AesBlock,
}

impl Ctr256 {
    /// Starts a stream at counter `iv`.
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self::with_state(key, iv, 0)
    }

    /// Continues a stream that [`ctr256`] left at counter `iv` and `state`.
    /// A `state` of 16 or more is treated as 0, as in [`ctr256`].
    pub fn with_state(key: &[u8; 32], iv: &[u8; 16], state: u8) -> Self {
        let cipher = Wiped::<Aes256Enc>::boxed(key);
        let mut ks = AesBlock::from(*iv);
        cipher.encrypt_block(&mut ks);
        let state = if state < 16 { state as usize } else { 0 };
        Self { cipher, iv: *iv, state, ks }
    }

    /// Encrypts or decrypts `data` in place, continuing where the previous call stopped.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        self.cipher.encrypt_with_backend(CtrProcess {
            data,
            ctr: &mut self.iv,
            state: &mut self.state,
            ks: &mut self.ks,
            ks_ready: true,
        });
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

impl Drop for Ctr256 {
    fn drop(&mut self) {
        // SAFETY: `self.ks` is a valid, aligned place we own.
        unsafe { std::ptr::write_volatile(&mut self.ks, AesBlock::default()) };
        compiler_fence(Ordering::SeqCst);
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
