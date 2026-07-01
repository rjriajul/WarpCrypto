# WarpCrypto

> Fast Cryptography Extension Library — Rust Implementation

WarpCrypto is a high-performance cryptography library written in **Rust** as a Python extension (via [PyO3](https://pyo3.rs) + [maturin](https://maturin.rs)).
It implements the cryptographic algorithms required by Telegram's MTProto protocol:

- **`AES-256-IGE`** — used in [MTProto v2.0](https://core.telegram.org/mtproto)
- **`AES-256-CTR`** — used for [CDN encrypted files](https://core.telegram.org/cdn)
- **`kdf`** — key derivation function per MTProto 2.0 spec
- **`pack_message` / `unpack_message`** — combined KDF+AES-IGE in a single call (1 GIL release vs 3 for tgcrypto)

## Features

- **3–5× faster** than tgcrypto (C extension) in multi-client benchmarks
- **AES-NI hardware acceleration** via the `aes` crate's runtime CPU feature detection (`cpufeatures`)
- **Zero-copy** IGE with block-aligned GenericArray operations
- **Block-based CTR** — processes 16-byte blocks with `chunks_exact_mut`, not byte-by-byte
- **Proper state propagation** — IV and state bytearrays are mutated in-place matching tgcrypto exactly
- **Memory safe** — Rust's type system guarantees no buffer overflows, use-after-free, or data races
- **Zero compiler warnings**

## Requirements

- Python 3.8 or higher
- Rust toolchain (for building from source; pre-built wheels available for most platforms)

## Installation

```bash
pip install WarpCrypto
```

Install from source:

```bash
pip install maturin
maturin build --release
pip install target/wheels/*.whl
```

## API

```python
def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...

def ctr256_encrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray) -> bytes: ...
def ctr256_decrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray) -> bytes: ...

def kdf(auth_key: bytes, msg_key: bytes, outgoing: bool) -> tuple[bytes, bytes]: ...

def pack_message(data: bytes, salt: int, session_id: bytes, auth_key: bytes, auth_key_id: bytes) -> bytes: ...
def unpack_message(packed: bytes, session_id: bytes, auth_key: bytes, auth_key_id: bytes) -> bytes: ...
```

## Usage

### IGE Mode (MTProto 2.0)

```python
import os
import warpcrypto

data = os.urandom(10 * 1024 * 1024)
key = os.urandom(32)
iv = os.urandom(32)

ige_encrypted = warpcrypto.ige256_encrypt(data, key, iv)
ige_decrypted = warpcrypto.ige256_decrypt(ige_encrypted, key, iv)
assert data == ige_decrypted
```

### CTR Mode (CDN)

```python
import os
import warpcrypto

data = os.urandom(10 * 1024 * 1024)
key = os.urandom(32)
enc_iv = bytearray(os.urandom(16))
dec_iv = bytearray(enc_iv)

ctr_encrypted = warpcrypto.ctr256_encrypt(data, key, enc_iv, bytearray(1))
ctr_decrypted = warpcrypto.ctr256_decrypt(ctr_encrypted, key, dec_iv, bytearray(1))
assert data == ctr_decrypted
```

### KDF (MTProto 2.0 key derivation)

```python
import warpcrypto

auth_key = bytes(range(256))
msg_key = os.urandom(16)

aes_key, aes_iv = warpcrypto.kdf(auth_key, msg_key, outgoing=True)   # x=0
aes_key, aes_iv = warpcrypto.kdf(auth_key, msg_key, outgoing=False)  # x=8
```

## Testing

```bash
pip install pytest
pytest
```

## Performance

WarpCrypto outperforms tgcrypto (C extension) by **3–5×** across all client counts (1–128 concurrent clients).
Performance scales with AES-NI availability (most x86_64 and Apple Silicon CPUs).

## License

[LGPLv3+](COPYING.lesser) — Originally by Dan. Rust port maintained by Riajul.
