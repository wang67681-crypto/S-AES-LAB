"""输入解析与格式化测试。"""

from __future__ import annotations

import unittest

from s_aes.utils import (
    InputError,
    escape_bytes,
    format_binary,
    format_hex_bytes,
    parse_bits,
    parse_hex_bytes,
)


class TestParseBits(unittest.TestCase):
    def test_hex_formats(self) -> None:
        for text in ("2D55", "0x2D55", "2d 55", "0x2D:55", "2D_55"):
            self.assertEqual(parse_bits(text, 16, "密钥"), 0x2D55)

    def test_binary_formats(self) -> None:
        self.assertEqual(parse_bits("0010 1101 0101 0101", 16, "密钥"), 0x2D55)
        self.assertEqual(parse_bits("0b0010110101010101", 16, "密钥"), 0x2D55)

    def test_wide_keys(self) -> None:
        self.assertEqual(parse_bits("1A2B3C4D", 32, "密钥"), 0x1A2B3C4D)
        self.assertEqual(parse_bits("1A2B3C4D5E6F", 48, "密钥"), 0x1A2B3C4D5E6F)

    def test_errors(self) -> None:
        with self.assertRaises(InputError):
            parse_bits("", 16, "密钥")
        with self.assertRaises(InputError):
            parse_bits("2D5", 16, "密钥")
        with self.assertRaises(InputError):
            parse_bits("ZZZZ", 16, "密钥")


class TestHexBytes(unittest.TestCase):
    def test_formats(self) -> None:
        expected = bytes.fromhex("E90156CD")
        for text in ("E90156CD", "e9 01 56 cd", "0xE901:56CD"):
            self.assertEqual(parse_hex_bytes(text), expected)

    def test_binary(self) -> None:
        self.assertEqual(parse_hex_bytes("0b1110100100000001"), b"\xe9\x01")

    def test_errors(self) -> None:
        with self.assertRaises(InputError):
            parse_hex_bytes("")
        with self.assertRaises(InputError):
            parse_hex_bytes("ABC")
        with self.assertRaises(InputError):
            parse_hex_bytes("GG")


class TestFormatting(unittest.TestCase):
    def test_hex_bytes(self) -> None:
        self.assertEqual(format_hex_bytes(bytes.fromhex("E90156CD")), "E901 56CD")
        self.assertEqual(format_hex_bytes(b""), "")

    def test_binary(self) -> None:
        self.assertEqual(format_binary(0x6BA3), "0110 1011 1010 0011")

    def test_escape(self) -> None:
        self.assertEqual(escape_bytes(b"A\x00\n\\"), "A\\x00\\n\\\\")


if __name__ == "__main__":
    unittest.main()
