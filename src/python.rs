use aes::Aes256;
use aes::cipher::KeyInit;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};

use crate::{ctr_process, ige256_decrypt_slice, ige256_encrypt_slice, kdf_inner};
use crate::{pack_plain, pack_seal, packed_len, unpack_header, unpack_open, Error};

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
    let total_out = packed_len(body.len());

    let mut out = scratch_take();
    out.clear();
    out.resize(total_out, 0);
    pack_plain(&mut out, msg_id, seq_no, body, salt, session_id);

    let auth_key: [u8; 256] = auth_key.try_into().unwrap();
    let auth_key_id: [u8; 8] = auth_key_id.try_into().unwrap();

    let out = maybe_detach(py, total_out, move || {
        let mut out = out;
        pack_seal(&mut out, &auth_key, &auth_key_id);
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
    let msg_key = unpack_header(packed, auth_key_id).map_err(py_err)?;
    let mut dec = scratch_take();
    dec.clear();
    dec.extend_from_slice(&packed[24..]);
    let session_id = session_id.to_vec();
    let auth_key: [u8; 256] = auth_key.try_into().unwrap();

    let (opened, dec) = maybe_detach(py, dec.len(), move || {
        let mut dec = dec;
        let opened = unpack_open(&mut dec, &msg_key, &auth_key, &session_id, incoming);
        (opened, dec)
    });
    let (msg_id, seq_no, length) = opened.map_err(py_err)?;
    let total_len = dec[16..].len() as i32;

    let body = PyBytes::new(py, &dec[32..32 + length]);
    scratch_put(dec);
    Ok((msg_id, seq_no, length as i32, body, total_len))
}

fn py_err(e: Error) -> PyErr {
    PyValueError::new_err(e.to_string())
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