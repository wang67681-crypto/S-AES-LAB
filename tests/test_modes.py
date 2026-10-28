"""填充、字节串、多重加密与 CBC 模式测试。"""

from __future__ import annotations

import random
import unittest

from s_aes.modes import (
    cbc_decrypt,
    cbc_encrypt,
    decrypt_bytes,
    double_decrypt_block,
    double_encrypt_block,
    double_decrypt_bytes,
    double_encrypt_bytes,
    encrypt_bytes,
    flip_ciphertext_bit,
    pkcs7_pad,
    pkcs7_unpad,
    replace_ciphertext_block,
    triple_decrypt_block,
    triple_encrypt_block,
)


class TestPadding(unittest.TestCase):
    def test_padding_lengths(self) -> None:
        self.assertEqual(pkcs7_pad(b""), b"\x02\x02")
        self.assertEqual(pkcs7_pad(b"A"), b"A\x01")
        self.assertEqual(pkcs7_pad(b"AB"), b"AB\x02\x02")
        self.assertEqual(pkcs7_pad(b"ABC"), b"ABC\x01")

    def test_unpad(self) -> None:
        for data in (b"", b"A", b"AB", b"ABC", b"hello world"):
            self.assertEqual(pkcs7_unpad(pkcs7_pad(data)), data)

    def test_invalid_padding(self) -> None:
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"AB\x03")
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"AB\x01")
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"")


class TestByteString(unittest.TestCase):
    def test_roundtrip_various_lengths(self) -> None:
        key = 0x2D55
        for length in range(0, 40):
            data = bytes(random.randrange(256) for _ in range(length))
            self.assertEqual(decrypt_bytes(encrypt_bytes(data, key), key), data)

    def test_known_prefix(self) -> None:
        # 前三个分组与手动计算一致：He / ll / o+0x01
        ciphertext = encrypt_bytes(b"Hello", 0x2D55)
        self.assertEqual(ciphertext[:6].hex().upper(), "E90156CDF603")
        self.assertEqual(decrypt_bytes(ciphertext, 0x2D55), b"Hello")

    def test_no_padding_requires_even_length(self) -> None:
        with self.assertRaises(ValueError):
            encrypt_bytes(b"A", 0x2D55, add_padding=False)


class TestDoubleTriple(unittest.TestCase):
    def test_double_roundtrip(self) -> None:
        key = 0x1A2B3C4D
        for plaintext in (0x0000, 0x1234, 0xFFFF, 0xABCD):
            ciphertext = double_encrypt_block(plaintext, key)
            self.assertEqual(double_decrypt_block(ciphertext, key), plaintext)

    def test_double_bytes_roundtrip(self) -> None:
        key = 0x1A2B3C4D
        data = b"double encryption with S-AES"
        self.assertEqual(
            double_decrypt_bytes(double_encrypt_bytes(data, key), key), data
        )

    def test_triple_32_ede_roundtrip(self) -> None:
        key = 0x1A2B3C4D
        for plaintext in (0x0000, 0x1234, 0xFFFF):
            ciphertext = triple_encrypt_block(plaintext, key, 32)
            self.assertEqual(triple_decrypt_block(ciphertext, key, 32), plaintext)

    def test_triple_48_eee_roundtrip(self) -> None:
        key = 0x1A2B3C4D5E6F
        for plaintext in (0x0000, 0x1234, 0xFFFF):
            ciphertext = triple_encrypt_block(plaintext, key, 48)
            self.assertEqual(triple_decrypt_block(ciphertext, key, 48), plaintext)

    def test_invalid_key_length(self) -> None:
        with self.assertRaises(ValueError):
            triple_encrypt_block(0x1234, 0x1234, 24)


class TestCbc(unittest.TestCase):
    def test_roundtrip(self) -> None:
        key = 0x2D55
        for message in (
            b"",
            b"A",
            b"hello world",
            b"0123456789",
            "信息安全导论 S-AES CBC".encode("utf-8"),
        ):
            iv = random.getrandbits(16)
            ciphertext = cbc_encrypt(message, key, iv)
            self.assertEqual(cbc_decrypt(ciphertext, key, iv), message)

    def test_random_iv_and_different_ciphertext(self) -> None:
        key = 0x2D55
        message = b"same message, different IV"
        first = cbc_encrypt(message, key, 0x0000)
        second = cbc_encrypt(message, key, 0x0001)
        self.assertNotEqual(first, second)

    def test_cbc_chaining(self) -> None:
        key = 0x2D55
        iv = 0x1234
        message = b"ABCD"
        ciphertext = cbc_encrypt(message, key, iv, add_padding=False)
        from s_aes.core import encrypt_block

        expected_first = encrypt_block(0x4142 ^ iv, key)
        expected_second = encrypt_block(0x4344 ^ expected_first, key)
        self.assertEqual(
            ciphertext, expected_first.to_bytes(2, "big") + expected_second.to_bytes(2, "big")
        )

    def test_tamper_effect(self) -> None:
        key = 0x2D55
        iv = 0x1234
        message = b"0123456789"  # 5 个数据分组 + 1 个填充分组
        ciphertext = cbc_encrypt(message, key, iv)
        tampered = flip_ciphertext_bit(ciphertext, 1, 3)

        original_raw = cbc_decrypt(ciphertext, key, iv, remove_padding=False)
        tampered_raw = cbc_decrypt(tampered, key, iv, remove_padding=False)

        # 第 1 组不受影响
        self.assertEqual(original_raw[0:2], tampered_raw[0:2])
        # 被修改的 C2 对应明文 P2 整体随机化
        self.assertNotEqual(original_raw[2:4], tampered_raw[2:4])
        # P3 因 XOR C2 而发生确定性 bit 3 翻转
        self.assertEqual((original_raw[5] ^ tampered_raw[5]), 1 << 3)
        # 后续分组不受影响
        self.assertEqual(original_raw[6:], tampered_raw[6:])

    def test_replace_block(self) -> None:
        key = 0x2D55
        iv = 0x1234
        ciphertext = cbc_encrypt(b"replace a block", key, iv)
        changed = replace_ciphertext_block(ciphertext, 0, 0x0000)
        self.assertNotEqual(ciphertext, changed)
        self.assertEqual(len(ciphertext), len(changed))
        with self.assertRaises(IndexError):
            replace_ciphertext_block(ciphertext, 999, 0)

    def test_invalid_ciphertext(self) -> None:
        with self.assertRaises(ValueError):
            cbc_decrypt(b"A", 0x2D55, 0x1234)
        with self.assertRaises(ValueError):
            cbc_decrypt(b"", 0x2D55, 0x1234)


if __name__ == "__main__":
    unittest.main()
