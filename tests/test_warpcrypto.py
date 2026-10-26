import os
import unittest

import warpcrypto


class TestBindings(unittest.TestCase):
    def test_all_functions_present(self):
        required = [
            "ige256_encrypt", "ige256_decrypt",
            "ctr256_encrypt", "ctr256_decrypt",
            "kdf", "pack_message", "unpack_message",
        ]
        for name in required:
            self.assertTrue(hasattr(warpcrypto, name), f"Missing: {name}")


class TestIGE256(unittest.TestCase):
    def test_ige256_roundtrip(self):
        key = os.urandom(32)
        iv = os.urandom(32)
        for size in [16, 32, 48, 64, 128, 1024, 1048576]:
            pt = os.urandom(size)
            ct = warpcrypto.ige256_encrypt(pt, key, iv)
            dec = warpcrypto.ige256_decrypt(ct, key, iv)
            self.assertEqual(dec, pt, f"IGE roundtrip failed at size={size}")

    def test_ige256_encrypt_wrong_key_size(self):
        with self.assertRaises(ValueError):
            warpcrypto.ige256_encrypt(b"\x00" * 16, b"\x00" * 31, b"\x00" * 32)

    def test_ige256_encrypt_wrong_iv_size(self):
        with self.assertRaises(ValueError):
            warpcrypto.ige256_encrypt(b"\x00" * 16, b"\x00" * 32, b"\x00" * 31)

    def test_ige256_decrypt_wrong_key_size(self):
        with self.assertRaises(ValueError):
            warpcrypto.ige256_decrypt(b"\x00" * 16, b"\x00" * 31, b"\x00" * 32)

    def test_ige256_decrypt_wrong_iv_size(self):
        with self.assertRaises(ValueError):
            warpcrypto.ige256_decrypt(b"\x00" * 16, b"\x00" * 32, b"\x00" * 31)


class TestCTR256(unittest.TestCase):
    def test_ctr256_roundtrip(self):
        key = os.urandom(32)
        for size in [1, 15, 16, 17, 31, 32, 100, 1024, 1048576]:
            pt = os.urandom(size)
            orig_iv = bytearray(os.urandom(16))

            iv1 = bytearray(orig_iv)
            enc = warpcrypto.ctr256_encrypt(pt, key, iv1, bytearray(1))

            iv2 = bytearray(orig_iv)
            dec = warpcrypto.ctr256_decrypt(enc, key, iv2, bytearray(1))

            self.assertEqual(dec, pt, f"CTR roundtrip failed at size={size}")

    def test_ctr256_identity(self):
        key = os.urandom(32)
        for size in [1, 15, 16, 31, 100]:
            pt = os.urandom(size)
            orig_iv = bytearray(os.urandom(16))
            iv1 = bytearray(orig_iv)
            double = warpcrypto.ctr256_encrypt(
                warpcrypto.ctr256_encrypt(pt, key, iv1, bytearray(1)),
                key, bytearray(orig_iv), bytearray(1),
            )
            self.assertEqual(double, pt, f"CTR double encrypt != original at size={size}")

    def test_ctr256_state_propagation(self):
        key = os.urandom(32)
        for s1, s2 in [(10, 10), (20, 10), (5, 20), (16, 16), (100, 50)]:
            d1 = os.urandom(s1)
            d2 = os.urandom(s2)
            orig_iv = bytearray(os.urandom(16))

            iv_t = bytearray(orig_iv)
            st_t = bytearray(1)

            iv_w = bytearray(orig_iv)
            st_w = bytearray(1)

            r1_w = warpcrypto.ctr256_encrypt(d1, key, iv_w, st_w)
            r2_w = warpcrypto.ctr256_encrypt(d2, key, iv_w, st_w)

            self.assertIsInstance(r1_w, bytes)
            self.assertIsInstance(r2_w, bytes)
            self.assertEqual(len(r1_w), s1)
            self.assertEqual(len(r2_w), s2)

    def test_ctr256_iv_mutated(self):
        key = os.urandom(32)
        iv = bytearray(os.urandom(16))
        iv_original = list(iv)
        _ = warpcrypto.ctr256_encrypt(b"\x00" * 32, key, iv, bytearray(1))
        self.assertNotEqual(list(iv), iv_original, "IV should be mutated after CTR call")

    def test_ctr256_state_mutated(self):
        key = os.urandom(32)
        state = bytearray(1)
        _ = warpcrypto.ctr256_encrypt(b"\x00" * 10, key, bytearray(os.urandom(16)), state)
        self.assertNotEqual(list(state), [0], "State should be mutated after CTR call")


class TestKDF(unittest.TestCase):
    def test_kdf_returns_key_iv(self):
        auth_key = os.urandom(256)
        msg_key = os.urandom(16)
        for outgoing in [True, False]:
            k, iv = warpcrypto.kdf(auth_key, msg_key, outgoing)
            self.assertEqual(len(k), 32)
            self.assertEqual(len(iv), 32)

    def test_kdf_outgoing_vs_incoming(self):
        auth_key = os.urandom(256)
        msg_key = os.urandom(16)
        k_out, iv_out = warpcrypto.kdf(auth_key, msg_key, True)
        k_in, iv_in = warpcrypto.kdf(auth_key, msg_key, False)
        self.assertNotEqual(k_out, k_in)
        self.assertNotEqual(iv_out, iv_in)


class TestPackMessage(unittest.TestCase):
    AUTH_KEY = bytes(range(256))
    AUTH_KEY_ID = __import__("hashlib").sha256(AUTH_KEY).digest()[-8:]
    SESSION_ID = os.urandom(8)
    SALT = 1234567890

    def pack(self, body: bytes, msg_id: int = 0, seq_no: int = 0):
        return warpcrypto.pack_message(msg_id, seq_no, body, self.SALT, self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID)

    def test_pack_has_auth_key_id(self):
        packed = self.pack(b"test")
        self.assertEqual(packed[:8], self.AUTH_KEY_ID)

    def test_pack_has_msg_key(self):
        packed = self.pack(b"test")
        self.assertEqual(len(packed[8:24]), 16)

    def test_pack_16_byte_aligned(self):
        packed = self.pack(b"test")
        self.assertEqual((len(packed) - 8) % 16, 0)

    def test_pack_unique(self):
        results = set()
        for i in range(10):
            p = bytes(self.pack(b"test", msg_id=i))
            results.add(p)
        self.assertEqual(len(results), 10)

    def test_pack_various_sizes(self):
        for size in [0, 1, 16, 100, 1000]:
            payload = os.urandom(size)
            packed = self.pack(payload)
            self.assertGreater(len(packed), 24)
            self.assertEqual((len(packed) - 8) % 16, 0)


class TestUnpackMessage(unittest.TestCase):
    AUTH_KEY = bytes(range(256))
    AUTH_KEY_ID = __import__("hashlib").sha256(AUTH_KEY).digest()[-8:]
    SESSION_ID = os.urandom(8)
    SALT = 1234567890

    def pack(self, body: bytes, msg_id: int = 0, seq_no: int = 0):
        return warpcrypto.pack_message(msg_id, seq_no, body, self.SALT, self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID)

    def test_unpack_roundtrip(self):
        payload = os.urandom(52)
        packed = self.pack(payload, msg_id=42, seq_no=7)
        # outgoing=False because pack uses x=0 (client→server), so unpack must also use x=0
        msg_id, seq_no, length, body, total_len = warpcrypto.unpack_message(
            packed, self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID, incoming=False
        )
        self.assertEqual(msg_id, 42)
        self.assertEqual(seq_no, 7)
        self.assertEqual(length, 52)
        self.assertEqual(body, payload)
        self.assertGreater(total_len, 0)

    def test_unpack_incoming_realistic(self):
        # Simulate server→client: use incoming=True (x=8) with a self-consistency check
        payload = b"hello from server"
        # Build using outgoing logic, then verify incoming check uses different auth_key range
        packed = self.pack(payload, msg_id=99, seq_no=3)
        # This should NOT match because pack uses auth_key[88:120], unpack(incoming=True) uses [96:128]
        with self.assertRaises(ValueError):
            warpcrypto.unpack_message(
                packed, self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID, incoming=True
            )

    def test_unpack_invalid_auth_key_id(self):
        packed = self.pack(b"test")
        bad_key_id = os.urandom(8)
        with self.assertRaises(ValueError):
            warpcrypto.unpack_message(packed, self.SESSION_ID, self.AUTH_KEY, bad_key_id)

    def test_unpack_invalid_session_id(self):
        packed = self.pack(b"test")
        bad_sid = os.urandom(8)
        with self.assertRaises(ValueError):
            warpcrypto.unpack_message(packed, bad_sid, self.AUTH_KEY, self.AUTH_KEY_ID)

    def test_unpack_too_short(self):
        with self.assertRaises(ValueError):
            warpcrypto.unpack_message(b"", self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID)

    def test_unpack_tampered_body(self):
        payload = b"hello"
        packed = bytearray(self.pack(payload))
        # Flip a bit in the encrypted portion
        packed[30] ^= 0x01
        with self.assertRaises(ValueError):
            warpcrypto.unpack_message(bytes(packed), self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID)

    def test_unpack_wrong_msg_key(self):
        payload = b"test"
        packed = bytearray(self.pack(payload))
        # Flip a bit in the msg_key
        packed[10] ^= 0x01
        with self.assertRaises(ValueError):
            warpcrypto.unpack_message(bytes(packed), self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID)

    def server_packet(self, body: bytes, pad: int, declared_len=None):
        # Build a server→client message by hand (x=8) with a valid msg_key, so only the length checks can reject it
        import hashlib, struct
        plain = struct.pack("<q8sqii", self.SALT, self.SESSION_ID, 99, 3,
                            len(body) if declared_len is None else declared_len) + body + os.urandom(pad)
        assert len(plain) % 16 == 0
        msg_key = hashlib.sha256(self.AUTH_KEY[96:128] + plain).digest()[8:24]
        key, iv = warpcrypto.kdf(self.AUTH_KEY, msg_key, False)
        return self.AUTH_KEY_ID + msg_key + warpcrypto.ige256_encrypt(plain, key, iv)

    def unpack_server(self, packet):
        return warpcrypto.unpack_message(packet, self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID)

    def test_unpack_server_message(self):
        for body, pad in [(b"abcd", 12), (b"", 1024), (os.urandom(100), 12), (os.urandom(1000), 24)]:
            msg_id, seq_no, length, out, _ = self.unpack_server(self.server_packet(body, pad))
            self.assertEqual((msg_id, seq_no, length, out), (99, 3, len(body), body))

    def test_unpack_padding_too_short(self):
        for body, pad in [(b"abcdefgh", 8), (os.urandom(16), 0), (os.urandom(12), 4)]:
            with self.assertRaisesRegex(ValueError, "padding length out of range"):
                self.unpack_server(self.server_packet(body, pad))

    def test_unpack_padding_too_long(self):
        for pad in [1040, 2048]:
            with self.assertRaisesRegex(ValueError, "padding length out of range"):
                self.unpack_server(self.server_packet(b"", pad))

    def test_unpack_padding_hidden_by_declared_length(self):
        # 16 real body bytes + 16 padding, but the header claims 28 bytes of body, leaving 4 bytes of padding
        with self.assertRaisesRegex(ValueError, "padding length out of range"):
            self.unpack_server(self.server_packet(os.urandom(16), 16, declared_len=28))

    def test_unpack_length_not_divisible_by_4(self):
        for body, pad in [(b"ab", 14), (b"abcde", 27)]:
            with self.assertRaisesRegex(ValueError, "not divisible by 4"):
                self.unpack_server(self.server_packet(body, pad))


if __name__ == "__main__":
    unittest.main()
