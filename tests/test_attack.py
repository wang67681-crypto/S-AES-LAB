"""中间相遇攻击测试。"""

from __future__ import annotations

import unittest

from s_aes.attacks import mitm_attack
from s_aes.modes import double_encrypt_block


class TestMeetInTheMiddle(unittest.TestCase):
    def test_recover_known_double_key(self) -> None:
        key = 0x1A2B3C4D
        pairs = [
            (plaintext, double_encrypt_block(plaintext, key))
            for plaintext in (0x1234, 0xABCD, 0x0F0F)
        ]
        result = mitm_attack(pairs)
        self.assertFalse(result.cancelled)
        self.assertEqual(result.candidates, [key])
        self.assertGreater(result.table_entries, 0)
        self.assertGreater(result.elapsed_seconds, 0)

    def test_progress_reaches_complete(self) -> None:
        key = 0xCAFEBABE
        pairs = [
            (plaintext, double_encrypt_block(plaintext, key))
            for plaintext in (0x0000, 0xFFFF, 0x5555)
        ]
        percentages = []
        result = mitm_attack(
            pairs, progress=lambda percent, _message: percentages.append(percent)
        )
        self.assertEqual(result.candidates, [key])
        self.assertEqual(percentages[-1], 100)

    def test_insufficient_pairs_leave_many_candidates(self) -> None:
        key = 0x1A2B3C4D
        pair = (0x1234, double_encrypt_block(0x1234, key))
        result = mitm_attack([pair])
        self.assertIn(key, result.candidates)
        self.assertGreater(len(result.candidates), 1000)

    def test_invalid_pairs(self) -> None:
        with self.assertRaises(ValueError):
            mitm_attack([])
        with self.assertRaises(ValueError):
            mitm_attack([(0x10000, 0x0000)])

    def test_stop_request(self) -> None:
        key = 0x1A2B3C4D
        pair = (0x1234, double_encrypt_block(0x1234, key))
        result = mitm_attack([pair], should_stop=lambda: True)
        self.assertTrue(result.cancelled)


if __name__ == "__main__":
    unittest.main()
