# WarpCrypto

> Fast and Portable Cryptography Extension Library

WarpCrypto is a Cryptography Library written in C as a Python extension. It is designed to be portable, fast,
easy to install and use. Forked from [TgCrypto](https://github.com/pyrogram/tgcrypto), it implements the
cryptographic algorithms required by Telegram's MTProto protocol:

- **`AES-256-IGE`** - used in [MTProto v2.0](https://core.telegram.org/mtproto).
- **`AES-256-CTR`** - used for [CDN encrypted files](https://core.telegram.org/cdn).
- **`AES-256-CBC`** - used for [encrypted passport credentials](https://core.telegram.org/passport).

## Requirements

- Python 3.9 or higher.

## Installation

``` bash
$ pip install WarpCrypto
```

## API

WarpCrypto API consists of these six methods:

```python
def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...

def ctr256_encrypt(data: bytes, key: bytes, iv: bytes, state: bytes) -> bytes: ...
def ctr256_decrypt(data: bytes, key: bytes, iv: bytes, state: bytes) -> bytes: ...

def cbc256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def cbc256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
```

## Usage

### IGE Mode

``` python
import os
import tgcrypto

data = os.urandom(10 * 1024 * 1024 + 7)
key = os.urandom(32)
iv = os.urandom(32)
data += bytes(-len(data) % 16)

ige_encrypted = tgcrypto.ige256_encrypt(data, key, iv)
ige_decrypted = tgcrypto.ige256_decrypt(ige_encrypted, key, iv)

print(data == ige_decrypted)
```

### CTR Mode

``` python
import os
import tgcrypto

data = os.urandom(10 * 1024 * 1024)
key = os.urandom(32)
enc_iv = bytearray(os.urandom(16))
dec_iv = enc_iv.copy()

ctr_encrypted = tgcrypto.ctr256_encrypt(data, key, enc_iv, bytes(1))
ctr_decrypted = tgcrypto.ctr256_decrypt(ctr_encrypted, key, dec_iv, bytes(1))

print(data == ctr_decrypted)
```

### CBC Mode

``` python
import os
import tgcrypto

data = os.urandom(10 * 1024 * 1024 + 7)
key = os.urandom(32)
enc_iv = bytearray(os.urandom(16))
dec_iv = enc_iv.copy()
data += bytes(-len(data) % 16)

cbc_encrypted = tgcrypto.cbc256_encrypt(data, key, enc_iv)
cbc_decrypted = tgcrypto.cbc256_decrypt(cbc_encrypted, key, dec_iv)

print(data == cbc_decrypted)
```

## Testing

``` bash
pip install tox
tox
```

## License

[LGPLv3+](COPYING.lesser) - Originally by Dan. Fork maintained by Riajul.
