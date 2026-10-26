use aes::cipher::{BlockBackend, BlockClosure, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, ParBlocks};
use aes::cipher::typenum::Unsigned;
use aes::cipher::inout::InOut;
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U16;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use sha2::{Digest, Sha256};

thread_local! {
    static SCRATCH: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

const SCRATCH_KEEP: usize = 2 * 1024 * 1024;

const GIL_RELEASE_MIN: usize = 2048;

#[inline(always)]
fn maybe_detach<T: Send>(py: Python<'_>, len: usize, f: impl FnOnce() -> T + Send) -> T {
    if len >= GIL_RELEASE_MIN { py.detach(f) } else { f() }
}

fn scratch_take() -> Vec<u8> {
    SCRATCH.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

fn scratch_put(buf: Vec<u8>) {
    if buf.capacity() <= SCRATCH_KEEP {
        SCRATCH.with(|s| *s.borrow_mut() = buf);
    }
}

type AesBlock = GenericArray<u8, U16>;

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

impl BlockClosure for IgeEncrypt<'_> {
    fn call<B: BlockBackend<BlockSize = U16>>(self, backend: &mut B) {
        let mut iv1 = word_at(self.iv, 0);
        let mut iv2 = word_at(self.iv, 16);

        for chunk in self.data.chunks_exact_mut(16) {
            let plain = u128::from_ne_bytes(chunk.try_into().unwrap());
            let mut block = AesBlock::from((plain ^ iv1).to_ne_bytes());
            backend.proc_block(InOut::from(&mut block));
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

impl BlockClosure for IgeDecrypt<'_> {
    fn call<B: BlockBackend<BlockSize = U16>>(self, backend: &mut B) {
        let mut iv1 = word_at(self.iv, 16);
        let mut iv2 = word_at(self.iv, 0);

        for chunk in self.data.chunks_exact_mut(16) {
            let ct = u128::from_ne_bytes(chunk.try_into().unwrap());
            let mut block = AesBlock::from((ct ^ iv1).to_ne_bytes());
            backend.proc_block(InOut::from(&mut block));
            let out = u128::from_ne_bytes(block.into()) ^ iv2;
            chunk.copy_from_slice(&out.to_ne_bytes());
            iv1 = out;
            iv2 = ct;
        }
    }
}

fn ige256_encrypt_slice(data: &mut [u8], cipher: &Aes256, iv: &[u8]) {
    cipher.encrypt_with_backend(IgeEncrypt { data, iv });
}

fn ige256_decrypt_slice(data: &mut [u8], cipher: &Aes256, iv: &[u8]) {
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

impl BlockClosure for CtrProcess<'_> {
    fn call<B: BlockBackend<BlockSize = U16>>(self, backend: &mut B) {
        let data = self.data;
        let ctr = self.ctr;
        let state = self.state;

        let len = data.len();
        if len == 0 { return; }

        let mut pos = 0;

        if *state != 0 {
            let mut ks = block_from_slice(ctr);
            backend.proc_block(InOut::from(&mut ks));
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
            backend.proc_par_blocks(InOut::from(&mut ks));
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
            backend.proc_block(InOut::from(&mut ks));
            let x = u128::from_ne_bytes(chunk.try_into().unwrap())
                ^ u128::from_ne_bytes(ks.into());
            chunk.copy_from_slice(&x.to_ne_bytes());
            ctr_next(ctr);
        }
        let tail = chunks.into_remainder();

        if !tail.is_empty() {
            let mut ks = block_from_slice(ctr);
            backend.proc_block(InOut::from(&mut ks));
            for i in 0..tail.len() {
                tail[i] ^= ks[i];
            }
            *state = tail.len();
        }
    }
}

fn ctr_process(data: &mut [u8], cipher: &Aes256, ctr: &mut [u8; 16], state: &mut usize) {
    cipher.encrypt_with_backend(CtrProcess { data, ctr, state });
}

#[pyfunction]
fn ige256_encrypt<'py>(py: Python<'py>, data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    if key.len() != 32 { return Err(PyValueError::new_err("Key must be 32 bytes")); }
    if iv.len() != 32 { return Err(PyValueError::new_err("IV must be 32 bytes")); }
    let mut buf = scratch_take();
    buf.clear();
    buf.extend_from_slice(data);
    let key: [u8; 32] = key.try_into().unwrap();
    let iv: [u8; 32] = iv.try_into().unwrap();
    let buf = maybe_detach(py, buf.len(), move || {
        let cipher = Aes256::new_from_slice(&key).unwrap();
        let mut buf = buf;
        ige256_encrypt_slice(&mut buf, &cipher, &iv);
        buf
    });
    let out = PyBytes::new(py, &buf);
    scratch_put(buf);
    Ok(out)
}

#[pyfunction]
fn ige256_decrypt<'py>(py: Python<'py>, data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    if key.len() != 32 { return Err(PyValueError::new_err("Key must be 32 bytes")); }
    if iv.len() != 32 { return Err(PyValueError::new_err("IV must be 32 bytes")); }
    let mut buf = scratch_take();
    buf.clear();
    buf.extend_from_slice(data);
    let key: [u8; 32] = key.try_into().unwrap();
    let iv: [u8; 32] = iv.try_into().unwrap();
    let buf = maybe_detach(py, buf.len(), move || {
        let cipher = Aes256::new_from_slice(&key).unwrap();
        let mut buf = buf;
        ige256_decrypt_slice(&mut buf, &cipher, &iv);
        buf
    });
    let out = PyBytes::new(py, &buf);
    scratch_put(buf);
    Ok(out)
}

#[pyfunction]
fn ctr256_encrypt<'py>(
    py: Python<'py>,
    src: &[u8],
    key: &[u8],
    iv: &Bound<'_, PyByteArray>,
    state: &Bound<'_, PyByteArray>,
) -> PyResult<Bound<'py, PyBytes>> {
    if key.len() != 32 { return Err(PyValueError::new_err("Key must be 32 bytes")); }
    if iv.len() != 16 { return Err(PyValueError::new_err("IV must be 16 bytes")); }

    let mut data = scratch_take();
    data.clear();
    data.extend_from_slice(src);
    let key: [u8; 32] = key.try_into().unwrap();
    let mut ctr = [0u8; 16];
    unsafe {
        ctr.copy_from_slice(iv.as_bytes());
    }
    let mut state_off = unsafe { state.as_bytes()[0] } as usize;
    if state_off >= 16 { state_off = 0; }

    let (buf, ctr_out, state_out) = maybe_detach(py, data.len(), move || {
        let cipher = Aes256::new_from_slice(&key).unwrap();
        let mut buf = data;
        ctr_process(&mut buf, &cipher, &mut ctr, &mut state_off);
        (buf, ctr, state_off)
    });

    unsafe {
        iv.as_bytes_mut().copy_from_slice(&ctr_out);
        state.as_bytes_mut()[0] = state_out as u8;
    }
    let out = PyBytes::new(py, &buf);
    scratch_put(buf);
    Ok(out)
}

#[pyfunction]
fn ctr256_decrypt<'py>(
    py: Python<'py>,
    src: &[u8],
    key: &[u8],
    iv: &Bound<'_, PyByteArray>,
    state: &Bound<'_, PyByteArray>,
) -> PyResult<Bound<'py, PyBytes>> {
    ctr256_encrypt(py, src, key, iv, state)
}

/// In-place CTR encrypt: copies data out, processes, writes back.
/// Saves one allocation vs the returning version.
#[pyfunction]
fn ctr256_encrypt_inplace(
    py: Python<'_>,
    data: &Bound<'_, PyByteArray>,
    key: &[u8],
    iv: &Bound<'_, PyByteArray>,
    state: &Bound<'_, PyByteArray>,
) -> PyResult<()> {
    if key.len() != 32 { return Err(PyValueError::new_err("Key must be 32 bytes")); }
    if iv.len() != 16 { return Err(PyValueError::new_err("IV must be 16 bytes")); }

    let mut buf = unsafe { data.as_bytes() }.to_vec();
    let key: [u8; 32] = key.try_into().unwrap();
    let mut ctr = [0u8; 16];
    unsafe { ctr.copy_from_slice(iv.as_bytes()); }
    let mut state_off = unsafe { state.as_bytes()[0] } as usize;
    if state_off >= 16 { state_off = 0; }

    let (buf, ctr_out, state_out) = maybe_detach(py, buf.len(), move || {
        let cipher = Aes256::new_from_slice(&key).unwrap();
        ctr_process(&mut buf, &cipher, &mut ctr, &mut state_off);
        (buf, ctr, state_off)
    });

    unsafe {
        data.as_bytes_mut().copy_from_slice(&buf);
        iv.as_bytes_mut().copy_from_slice(&ctr_out);
        state.as_bytes_mut()[0] = state_out as u8;
    }
    Ok(())
}

#[pyfunction]
fn ctr256_decrypt_inplace(
    py: Python<'_>,
    data: &Bound<'_, PyByteArray>,
    key: &[u8],
    iv: &Bound<'_, PyByteArray>,
    state: &Bound<'_, PyByteArray>,
) -> PyResult<()> {
    ctr256_encrypt_inplace(py, data, key, iv, state)
}

/// Batch CTR encrypt: all data passed as a single flat buffer with sizes list.
/// Eliminates per-item Python list indexing (O(1) Python calls regardless of batch size).
#[pyfunction]
fn ctr256_encrypt_batch(
    _py: Python<'_>,
    data_flat: &[u8],
    sizes: &Bound<'_, PyByteArray>,
    key: &[u8],
    ivs: &Bound<'_, PyByteArray>,
    states: &Bound<'_, PyByteArray>,
) -> PyResult<Vec<u8>> {
    if key.len() != 32 { return Err(PyValueError::new_err("Key must be 32 bytes")); }
    let n = states.len();
    if n == 0 { return Ok(Vec::new()); }
    if ivs.len() != n * 16 { return Err(PyValueError::new_err("ivs must be 16*n bytes")); }
    if sizes.len() != n * 4 { return Err(PyValueError::new_err("sizes must be 4*n bytes")); }

    let mut offsets: Vec<usize> = Vec::with_capacity(n + 1);
    offsets.push(0);
    let mut total = 0usize;
    unsafe {
        let sz_bytes = sizes.as_bytes();
        for i in 0..n {
            let sz = u32::from_le_bytes([
                sz_bytes[i * 4],
                sz_bytes[i * 4 + 1],
                sz_bytes[i * 4 + 2],
                sz_bytes[i * 4 + 3],
            ]) as usize;
            total = total.checked_add(sz).ok_or_else(|| PyValueError::new_err("total data size overflow"))?;
            offsets.push(total);
        }
    }
    if total > data_flat.len() {
        return Err(PyValueError::new_err("data_flat too short for given sizes"));
    }

    let key_vec = key.to_vec();
    let mut data_owned = data_flat.to_vec();

    let mut ctrs: Vec<[u8; 16]> = Vec::with_capacity(n);
    let mut state_offs: Vec<usize> = Vec::with_capacity(n);
    unsafe {
        let iv_bytes = ivs.as_bytes();
        let st_bytes = states.as_bytes();
        for i in 0..n {
            let mut ctr = [0u8; 16];
            ctr.copy_from_slice(&iv_bytes[i * 16..][..16]);
            ctrs.push(ctr);
            let mut s = st_bytes[i] as usize;
            if s >= 16 { s = 0; }
            state_offs.push(s);
        }
    }

    let results = _py.detach(move || {
        let cipher = Aes256::new_from_slice(&key_vec).unwrap();
        for i in 0..n {
            let slice = &mut data_owned[offsets[i]..offsets[i + 1]];
            ctr_process(slice, &cipher, &mut ctrs[i], &mut state_offs[i]);
        }
        (data_owned, ctrs, state_offs)
    });

    let (data_out, ctrs_out, state_offs_out) = results;
    unsafe {
        for i in 0..n {
            ivs.as_bytes_mut()[i * 16..][..16].copy_from_slice(&ctrs_out[i]);
            states.as_bytes_mut()[i] = state_offs_out[i] as u8;
        }
    }
    Ok(data_out)
}

#[pyfunction]
fn ctr256_decrypt_batch(
    py: Python<'_>,
    data_flat: &[u8],
    sizes: &Bound<'_, PyByteArray>,
    key: &[u8],
    ivs: &Bound<'_, PyByteArray>,
    states: &Bound<'_, PyByteArray>,
) -> PyResult<Vec<u8>> {
    ctr256_encrypt_batch(py, data_flat, sizes, key, ivs, states)
}

#[pyfunction]
fn kdf(auth_key: &[u8], msg_key: &[u8], outgoing: bool) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if auth_key.len() != 256 { return Err(PyValueError::new_err("auth_key must be 256 bytes")); }
    let x: usize = if outgoing { 0 } else { 8 };
    let (key_arr, iv_arr) = kdf_inner(auth_key, msg_key, x);
    Ok((key_arr.to_vec(), iv_arr.to_vec()))
}

#[pyfunction]
fn pack_message<'py>(py: Python<'py>, msg_id: i64, seq_no: i32, body: &[u8], salt: i64, session_id: &[u8], auth_key: &[u8], auth_key_id: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    if auth_key.len() != 256 { return Err(PyValueError::new_err("auth_key must be 256 bytes")); }
    if auth_key_id.len() != 8 { return Err(PyValueError::new_err("auth_key_id must be 8 bytes")); }
    if session_id.len() != 8 { return Err(PyValueError::new_err("session_id must be 8 bytes")); }
    let body_len = body.len();
    let inner_len = 8 + 8 + 8 + 4 + 4 + body_len;
    let total_plain = (inner_len + 12 + 15) & !15;
    let total_out = 24 + total_plain;

    let mut out = scratch_take();
    out.clear();
    out.resize(total_out, 0);
    {
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
        lenb.copy_from_slice(&(body_len as u32).to_le_bytes());
        let (data_slice, padding) = rest.split_at_mut(body_len);
        data_slice.copy_from_slice(body);
        let _ = getrandom::getrandom(padding);
    }

    let auth_key: [u8; 256] = auth_key.try_into().unwrap();
    let auth_key_id: [u8; 8] = auth_key_id.try_into().unwrap();

    let out = maybe_detach(py, total_out, move || {
        let mut out = out;

        // https://core.telegram.org/mtproto/description
        // msg_key = SHA256(auth_key[88+x:88+x+32] + plaintext)[8:24]
        // x=0 for outgoing (client→server), so auth_key[88:120]
        let msg_key_large = {
            let mut h = Sha256::new();
            h.update(&auth_key[MSG_KEY_AUTH_LO..MSG_KEY_AUTH_HI]);
            h.update(&out[24..24 + total_plain]);
            h.finalize()
        };
        let msg_key: [u8; 16] = msg_key_large[8..24].try_into().unwrap();

        let (aes_key, aes_iv) = kdf_inner(&auth_key, &msg_key, 0);
        let cipher = Aes256::new_from_slice(&aes_key).unwrap();
        ige256_encrypt_slice(&mut out[24..], &cipher, &aes_iv);

        out[..8].copy_from_slice(&auth_key_id);
        out[8..24].copy_from_slice(&msg_key);
        out
    });

    let packed = PyBytes::new(py, &out);
    scratch_put(out);
    Ok(packed)
}

#[pyfunction]
#[pyo3(signature = (packed, session_id, auth_key, auth_key_id, incoming=true))]
fn unpack_message<'py>(py: Python<'py>, packed: &[u8], session_id: &[u8], auth_key: &[u8], auth_key_id: &[u8], incoming: bool) -> PyResult<(i64, i32, i32, Bound<'py, PyBytes>, i32)> {
    if auth_key.len() != 256 { return Err(PyValueError::new_err("auth_key must be 256 bytes")); }
    if auth_key_id.len() != 8 { return Err(PyValueError::new_err("auth_key_id must be 8 bytes")); }
    if packed.len() < 24 {
        return Err(PyValueError::new_err("packed data too short"));
    }
    if &packed[..8] != auth_key_id {
        return Err(PyValueError::new_err("auth_key_id mismatch"));
    }
    let msg_key: [u8; 16] = packed[8..24].try_into().unwrap();
    let mut dec = scratch_take();
    dec.clear();
    dec.extend_from_slice(&packed[24..]);
    let session_id = session_id.to_vec();
    let auth_key: [u8; 256] = auth_key.try_into().unwrap();
    let x: usize = if incoming { 8 } else { 0 };

    let (msg_id, seq_no, length, total_len, dec) = maybe_detach(py, dec.len(),
        move || -> PyResult<(i64, i32, usize, i32, Vec<u8>)> {
        let (aes_key, aes_iv) = kdf_inner(&auth_key, &msg_key, x);
        let cipher = Aes256::new_from_slice(&aes_key).unwrap();
        ige256_decrypt_slice(&mut dec, &cipher, &aes_iv);

        if dec.len() < 32 {
            return Err(PyValueError::new_err("msg_key mismatch"));
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
            h.update(&dec);
            h.finalize()
        };
        if msg_key_check[8..24] != msg_key {
            return Err(PyValueError::new_err("msg_key mismatch"));
        }

        // https://core.telegram.org/mtproto/security_guidelines#checking-session-id
        if dec[8..16] != session_id[..] {
            return Err(PyValueError::new_err("session_id mismatch"));
        }
        let msg_id = i64::from_le_bytes(dec[16..24].try_into().unwrap());
        let seq_no = i32::from_le_bytes(dec[24..28].try_into().unwrap());
        let length_i32 = i32::from_le_bytes(dec[28..32].try_into().unwrap());
        if length_i32 < 0 {
            return Err(PyValueError::new_err("negative body length"));
        }
        let length = length_i32 as usize;
        if 32 + length > dec.len() {
            return Err(PyValueError::new_err("body length exceeds decrypted data"));
        }
        // https://core.telegram.org/mtproto/security_guidelines#checking-message-length
        if length % 4 != 0 {
            return Err(PyValueError::new_err("body length not divisible by 4"));
        }
        if !(12..=1024).contains(&(dec.len() - 32 - length)) {
            return Err(PyValueError::new_err("padding length out of range"));
        }
        let total_len = dec[16..].len() as i32;
        Ok((msg_id, seq_no, length, total_len, dec))
    })?;

    let body = PyBytes::new(py, &dec[32..32 + length]);
    scratch_put(dec);
    Ok((msg_id, seq_no, length as i32, body, total_len))
}

#[pymodule]
fn warpcrypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(ige256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ige256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt_batch, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt_batch, m)?)?;
    m.add_function(wrap_pyfunction!(kdf, m)?)?;
    m.add_function(wrap_pyfunction!(pack_message, m)?)?;
    m.add_function(wrap_pyfunction!(unpack_message, m)?)?;
    Ok(())
}
