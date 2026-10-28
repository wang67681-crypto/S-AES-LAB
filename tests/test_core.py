"""核心算法与标准测试向量。"""

from __future__ import annotations

import random
import unittest

from s_aes.core import (
    INV_S_BOX,
    S_BOX,
    decrypt_block,
    decrypt_block_with_trace,
    encrypt_block,
    encrypt_block_with_trace,
    expand_key,
    gf_multiply,
    mix_columns_block,
    shift_rows_block,
)


class TestSBox(unittest.TestCase):
    def test_sbox_table(self) -> None:
        self.assertEqual(
            S_BOX,
            (
                0x9, 0x4, 0xA, 0xB,
                0xD, 0x1, 0x8, 0x5,
                0x6, 0x2, 0x0, 0x3,
                0xC, 0xE, 0xF, 0x7,
            ),
        )
        self.assertEqual(INV_S_BOX[0x0], 0xA)
        self.assertEqual(INV_S_BOX[0xA], 0x2)
        self.assertEqual(INV_S_BOX[0x9], 0x0)

    def test_inverse_sbox(self) -> None:
        for value in range(16):
            self.assertEqual(S_BOX[INV_S_BOX[value]], value)
            self.assertEqual(INV_S_BOX[S_BOX[value]], value)

    def test_textbook_sbox_example(self) -> None:
        # 附录 D 示例：状态 81AC 经半字节代替得到 640C
        self.assertEqual(S_BOX[0x8], 0x6)
        self.assertEqual(S_BOX[0x1], 0x4)
        self.assertEqual(S_BOX[0xA], 0x0)
        self.assertEqual(S_BOX[0xC], 0xC)


class TestKeyExpansion(unittest.TestCase):
    def test_appendix_example_2d55(self) -> None:
        schedule = expand_key(0x2D55)
        self.assertEqual(
            schedule.words, (0x2D, 0x55, 0xBC, 0xE9, 0xA3, 0x4A)
        )
        self.assertEqual(schedule.round_keys, (0x2D55, 0xBCE9, 0xA34A))

    def test_round_keys_are_16_bit(self) -> None:
        for key in (0x0000, 0xFFFF, 0x1234, 0xA73A):
            for round_key in expand_key(key).round_keys:
                self.assertGreaterEqual(round_key, 0)
                self.assertLessEqual(round_key, 0xFFFF)


class TestTransforms(unittest.TestCase):
    def test_gf_multiplication(self) -> None:
        # 附录 D：4 * C = 5，9 * 2 = 1
        self.assertEqual(gf_multiply(4, 0xC), 0x5)
        self.assertEqual(gf_multiply(9, 2), 0x1)

    def test_mix_columns_example(self) -> None:
        # 状态 [6 4; C 0] 按列优先编码为 6C40，结果为 [3 4; 7 3] = 3743
        self.assertEqual(mix_columns_block(0x6C40), 0x3743)

    def test_shift_rows_swaps_second_row(self) -> None:
        # 状态 [A 7; 4 9]（列优先编码 A479）-> [A 7; 9 4]（A974）
        self.assertEqual(shift_rows_block(0xA479), 0xA974)
        # 行移位是自逆运算
        self.assertEqual(shift_rows_block(shift_rows_block(0xA479)), 0xA479)


class TestBlockCipher(unittest.TestCase):
    def test_known_vector_encrypt(self) -> None:
        self.assertEqual(encrypt_block(0x6BA3, 0x2D55), 0x3C3B)

    def test_known_vector_decrypt(self) -> None:
        self.assertEqual(decrypt_block(0x3C3B, 0x2D55), 0x6BA3)

    def test_random_roundtrip(self) -> None:
        rng = random.Random(2026)
        for _ in range(500):
            key = rng.getrandbits(16)
            plaintext = rng.getrandbits(16)
            ciphertext = encrypt_block(plaintext, key)
            self.assertEqual(decrypt_block(ciphertext, key), plaintext)

    def test_trace_starts_and_ends(self) -> None:
        ciphertext, trace = encrypt_block_with_trace(0x6BA3, 0x2D55)
        text = "\n".join(trace)
        self.assertEqual(ciphertext, 0x3C3B)
        self.assertIn("密钥扩展", text)
        self.assertIn("第 1 轮 · 列混淆", text)
        self.assertIn("第 2 轮 · 轮密钥加", text)
        self.assertIn("密文 C : 3C3B", text)

        plaintext, trace = decrypt_block_with_trace(0x3C3B, 0x2D55)
        text = "\n".join(trace)
        self.assertEqual(plaintext, 0x6BA3)
        self.assertIn("逆列混淆", text)
        self.assertIn("明文 P : 6BA3", text)

    def test_input_range(self) -> None:
        with self.assertRaises(ValueError):
            encrypt_block(0x10000, 0x0000)
        with self.assertRaises(ValueError):
            decrypt_block(0x0000, -1)


if __name__ == "__main__":
    unittest.main()
