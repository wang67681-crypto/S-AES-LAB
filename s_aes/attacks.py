"""针对双重 S-AES 的中间相遇攻击（Meet-in-the-Middle）。

双重加密约定：
    K = K1 || K2
    C = E_K2(E_K1(P))

攻击思路：
    对每个 K1 计算中间值 M = E_K1(P1)，建立 M -> [K1...] 表；
    对每个 K2 计算 M' = D_K2(C1)，查表得到候选 (K1, K2)；
    再用额外的明密文对筛选候选密钥。

时间复杂度约为 2 * 2^16 次分组运算，而不是 2^32 次穷举。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple

from .core import decrypt_block, encrypt_block
from .modes import double_encrypt_block

ProgressCallback = Callable[[int, str], None]
StopCallback = Callable[[], bool]


@dataclass
class MitmResult:
    candidates: List[int] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    table_entries: int = 0
    pair_count: int = 0
    cancelled: bool = False


def _validate_pairs(pairs: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not pairs:
        raise ValueError("至少需要一组明密文对")
    cleaned: List[Tuple[int, int]] = []
    for index, pair in enumerate(pairs, start=1):
        if len(pair) != 2:
            raise ValueError(f"第 {index} 组数据格式不正确")
        plaintext, ciphertext = pair
        if not (0 <= plaintext <= 0xFFFF and 0 <= ciphertext <= 0xFFFF):
            raise ValueError(f"第 {index} 组明文/密文必须是 16 bit")
        cleaned.append((int(plaintext), int(ciphertext)))
    return cleaned


def mitm_attack(
    pairs: Sequence[Tuple[int, int]],
    progress: Optional[ProgressCallback] = None,
    should_stop: Optional[StopCallback] = None,
) -> MitmResult:
    """对双重 S-AES 执行中间相遇攻击。"""
    pairs = _validate_pairs(pairs)
    if progress:
        progress(0, "正在建立中间值表…")
    started = time.perf_counter()

    plaintext0, ciphertext0 = pairs[0]

    # 中间值 -> 可能的所有 K1。不同密钥可能产生相同中间值，因此使用列表。
    table: dict[int, List[int]] = {}
    for key1 in range(0x10000):
        middle = encrypt_block(plaintext0, key1)
        table.setdefault(middle, []).append(key1)
        if should_stop and (key1 & 0x3FF) == 0 and should_stop():
            return MitmResult(
                elapsed_seconds=time.perf_counter() - started,
                table_entries=len(table),
                pair_count=len(pairs),
                cancelled=True,
            )
        if progress and (key1 & 0x7FF) == 0:
            progress(5 + (key1 * 40) // 0x10000, "正在建立中间值表…")

    if progress:
        progress(45, "正在反向扫描 K2…")

    candidates: List[int] = []
    extra_pairs = pairs[1:]
    for key2 in range(0x10000):
        middle = decrypt_block(ciphertext0, key2)
        for key1 in table.get(middle, ()):
            candidate = (key1 << 16) | key2
            if all(
                double_encrypt_block(plaintext, candidate) == ciphertext
                for plaintext, ciphertext in extra_pairs
            ):
                candidates.append(candidate)
        if should_stop and (key2 & 0x3FF) == 0 and should_stop():
            return MitmResult(
                candidates=candidates,
                elapsed_seconds=time.perf_counter() - started,
                table_entries=len(table),
                pair_count=len(pairs),
                cancelled=True,
            )
        if progress and (key2 & 0x7FF) == 0:
            progress(45 + (key2 * 50) // 0x10000, "正在反向扫描 K2…")

    if progress:
        progress(98, "正在整理结果…")
    candidates.sort()
    result = MitmResult(
        candidates=candidates,
        elapsed_seconds=time.perf_counter() - started,
        table_entries=len(table),
        pair_count=len(pairs),
    )
    if progress:
        progress(100, "攻击完成")
    return result
