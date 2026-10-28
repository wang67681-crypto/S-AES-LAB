"""S-AES（简化 AES）核心算法。

算法约定与《密码编码学与网络安全——原理与实践（第 8 版）》附录 D 一致：

* 分组长度：16 bit（2 Byte）
* 密钥长度：16 bit（2 Byte）
* 轮数：2 轮（另有初始轮密钥加）
* 状态矩阵按列优先排列：
      [ s00  s01 ]      [ n0  n2 ]
      [ s10  s11 ]  =   [ n1  n3 ]
* GF(2^4) 的模多项式：x^4 + x + 1（0x13）
* 列混淆矩阵：[[1, 4], [4, 1]]，逆矩阵：[[9, 2], [2, 9]]

本模块只负责单个分组的运算，不涉及填充、工作模式和攻击。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

BLOCK_BITS = 16
BLOCK_BYTES = 2
KEY_BITS = 16
KEY_BYTES = 2

# 表 D.1(a) S 盒，行优先展开
S_BOX: Tuple[int, ...] = (
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7,
)

# 表 D.1(b) 逆 S 盒，由正 S 盒反推，避免手工抄写错误
INV_S_BOX: Tuple[int, ...] = tuple(
    next(index for index, value in enumerate(S_BOX) if value == target)
    for target in range(16)
)

RCON1 = 0x80
RCON2 = 0x30
GF_POLYNOMIAL = 0x13


@dataclass(frozen=True)
class KeySchedule:
    """扩展后的 6 个字节字与 3 个 16 bit 轮密钥。"""

    words: Tuple[int, int, int, int, int, int]
    round_keys: Tuple[int, int, int]

    @property
    def k0(self) -> int:
        return self.round_keys[0]

    @property
    def k1(self) -> int:
        return self.round_keys[1]

    @property
    def k2(self) -> int:
        return self.round_keys[2]


def _sub_byte(value: int) -> int:
    """对一个字节的两个半字节分别查 S 盒。"""
    return (S_BOX[(value >> 4) & 0x0F] << 4) | S_BOX[value & 0x0F]


def _inv_sub_byte(value: int) -> int:
    """对一个字节的两个半字节分别查逆 S 盒。"""
    return (INV_S_BOX[(value >> 4) & 0x0F] << 4) | INV_S_BOX[value & 0x0F]


def _rot_nib(value: int) -> int:
    """RotNib：交换一个字节的高、低半字节。"""
    return ((value & 0x0F) << 4) | ((value >> 4) & 0x0F)


def _g(value: int, rcon: int) -> int:
    """密钥扩展中的 g 函数：RotNib -> SubNib -> XOR RCON。"""
    return _sub_byte(_rot_nib(value)) ^ rcon


def expand_key(key: int) -> KeySchedule:
    """把 16 bit 密钥扩展为 3 个轮密钥。

    附录 D 的扩展公式：
        w2 = w0 XOR g(w1, RCON1)
        w3 = w2 XOR w1
        w4 = w2 XOR g(w3, RCON2)
        w5 = w4 XOR w3
    """
    _check_range(key, 16, "密钥")
    w0 = (key >> 8) & 0xFF
    w1 = key & 0xFF
    w2 = w0 ^ _g(w1, RCON1)
    w3 = w2 ^ w1
    w4 = w2 ^ _g(w3, RCON2)
    w5 = w4 ^ w3
    words = (w0, w1, w2, w3, w4, w5)
    return KeySchedule(
        words=words,
        round_keys=(
            (w0 << 8) | w1,
            (w2 << 8) | w3,
            (w4 << 8) | w5,
        ),
    )


def _check_range(value: int, bits: int, name: str) -> None:
    if not isinstance(value, int):
        raise TypeError(f"{name}必须是整数")
    if not 0 <= value < (1 << bits):
        raise ValueError(f"{name}必须是 {bits} bit 的无符号整数")


def block_to_nibbles(block: int) -> List[int]:
    """按输入顺序取出 4 个半字节 [n0, n1, n2, n3]。"""
    _check_range(block, BLOCK_BITS, "分组")
    return [
        (block >> 12) & 0x0F,
        (block >> 8) & 0x0F,
        (block >> 4) & 0x0F,
        block & 0x0F,
    ]


def nibbles_to_block(nibbles: List[int]) -> int:
    if len(nibbles) != 4:
        raise ValueError("状态必须包含 4 个半字节")
    block = 0
    for nibble in nibbles:
        _check_range(nibble, 4, "半字节")
        block = (block << 4) | nibble
    return block


def _xtime(value: int) -> int:
    """GF(2^4) 中乘以 x（即乘以 2），模 x^4 + x + 1。"""
    value &= 0x0F
    value <<= 1
    if value & 0x10:
        value ^= GF_POLYNOMIAL
    return value & 0x0F


def gf_multiply(left: int, right: int) -> int:
    """GF(2^4) 乘法，使用移位相加（俄罗斯农民乘法）。"""
    _check_range(left, 4, "乘数")
    _check_range(right, 4, "乘数")
    result = 0
    a, b = left, right
    for _ in range(4):
        if b & 1:
            result ^= a
        b >>= 1
        a = _xtime(a)
    return result & 0x0F


def _mul4(value: int) -> int:
    """列混淆中频繁使用的乘 4（即乘 x^2）。"""
    return _xtime(_xtime(value))


def _add_round_key_block(state: int, round_key: int) -> int:
    return state ^ round_key


def _sub_nibbles_block(state: int) -> int:
    return (_sub_byte(state >> 8) << 8) | _sub_byte(state & 0xFF)


def _inv_sub_nibbles_block(state: int) -> int:
    return (_inv_sub_byte(state >> 8) << 8) | _inv_sub_byte(state & 0xFF)


def _shift_rows_nibbles(nibbles: List[int]) -> List[int]:
    """行移位：第二行循环左移一个半字节。

    列优先顺序为 [s00, s10, s01, s11]，
    交换第二行的 s10 与 s11 后得到 [s00, s11, s01, s10]。
    """
    s00, s10, s01, s11 = nibbles
    return [s00, s11, s01, s10]


def _mix_columns_nibbles(nibbles: List[int]) -> List[int]:
    """列混淆：每个列左乘 [[1, 4], [4, 1]]。"""
    s00, s10, s01, s11 = nibbles
    return [
        s00 ^ _mul4(s10),
        _mul4(s00) ^ s10,
        s01 ^ _mul4(s11),
        _mul4(s01) ^ s11,
    ]


def _inv_mix_columns_nibbles(nibbles: List[int]) -> List[int]:
    """逆列混淆：每个列左乘 [[9, 2], [2, 9]]。"""
    s00, s10, s01, s11 = nibbles
    return [
        gf_multiply(9, s00) ^ gf_multiply(2, s10),
        gf_multiply(2, s00) ^ gf_multiply(9, s10),
        gf_multiply(9, s01) ^ gf_multiply(2, s11),
        gf_multiply(2, s01) ^ gf_multiply(9, s11),
    ]


def _shift_rows_block(state: int) -> int:
    return nibbles_to_block(_shift_rows_nibbles(block_to_nibbles(state)))


def _mix_columns_block(state: int) -> int:
    return nibbles_to_block(_mix_columns_nibbles(block_to_nibbles(state)))


def _inv_mix_columns_block(state: int) -> int:
    return nibbles_to_block(_inv_mix_columns_nibbles(block_to_nibbles(state)))


def mix_columns_block(state: int) -> int:
    """公开的列混淆变换，便于测试与教学演示。"""
    _check_range(state, BLOCK_BITS, "状态")
    return _mix_columns_block(state)


def inv_mix_columns_block(state: int) -> int:
    """公开的逆列混淆变换。"""
    _check_range(state, BLOCK_BITS, "状态")
    return _inv_mix_columns_block(state)


def shift_rows_block(state: int) -> int:
    """公开的行移位变换，便于测试与教学演示。"""
    _check_range(state, BLOCK_BITS, "状态")
    return _shift_rows_block(state)


def encrypt_block(plaintext: int, key: int) -> int:
    """加密一个 16 bit 分组。"""
    _check_range(plaintext, BLOCK_BITS, "明文")
    schedule = expand_key(key)

    state = _add_round_key_block(plaintext, schedule.k0)

    # 第 1 轮：NS -> SR -> MC -> AK1
    state = _sub_nibbles_block(state)
    state = _shift_rows_block(state)
    state = _mix_columns_block(state)
    state = _add_round_key_block(state, schedule.k1)

    # 第 2 轮：NS -> SR -> AK2（最后一轮不含列混淆）
    state = _sub_nibbles_block(state)
    state = _shift_rows_block(state)
    state = _add_round_key_block(state, schedule.k2)
    return state


def decrypt_block(ciphertext: int, key: int) -> int:
    """解密一个 16 bit 分组。"""
    _check_range(ciphertext, BLOCK_BITS, "密文")
    schedule = expand_key(key)

    state = _add_round_key_block(ciphertext, schedule.k2)

    # 逆第 2 轮：ISR -> INS -> AK1
    state = _shift_rows_block(state)
    state = _inv_sub_nibbles_block(state)
    state = _add_round_key_block(state, schedule.k1)

    # 逆第 1 轮：IMC -> ISR -> INS -> AK0
    state = _inv_mix_columns_block(state)
    state = _shift_rows_block(state)
    state = _inv_sub_nibbles_block(state)
    state = _add_round_key_block(state, schedule.k0)
    return state


def format_state_matrix(state: int) -> str:
    """把状态格式化为 2x2 矩阵文本（列优先显示）。"""
    n0, n1, n2, n3 = block_to_nibbles(state)
    return f"  [{n0:X}  {n2:X}]\n  [{n1:X}  {n3:X}]"


def _trace_step(trace: List[str], title: str, state: int) -> None:
    trace.append(f"{title}\n  状态字: {state:04X}\n{format_state_matrix(state)}")


def encrypt_block_with_trace(plaintext: int, key: int) -> Tuple[int, List[str]]:
    """加密并返回逐轮状态，供 GUI 教学展示使用。"""
    _check_range(plaintext, BLOCK_BITS, "明文")
    schedule = expand_key(key)
    w = schedule.words

    trace: List[str] = [
        "S-AES 加密过程",
        f"密钥 K : {key:04X}",
        f"明文 P : {plaintext:04X}",
        "",
        "【密钥扩展】",
        f"w0={w[0]:02X}  w1={w[1]:02X}  w2={w[2]:02X}  "
        f"w3={w[3]:02X}  w4={w[4]:02X}  w5={w[5]:02X}",
        f"K0={schedule.k0:04X}  K1={schedule.k1:04X}  K2={schedule.k2:04X}",
        "",
        "（状态矩阵按列优先排列）",
    ]

    state = _add_round_key_block(plaintext, schedule.k0)
    _trace_step(trace, f"初始轮密钥加  AddRoundKey(K0={schedule.k0:04X})", state)

    state = _sub_nibbles_block(state)
    _trace_step(trace, "第 1 轮 · 半字节代替  SubNib", state)
    state = _shift_rows_block(state)
    _trace_step(trace, "第 1 轮 · 行移位  ShiftRows", state)
    state = _mix_columns_block(state)
    _trace_step(trace, "第 1 轮 · 列混淆  MixColumns", state)
    state = _add_round_key_block(state, schedule.k1)
    _trace_step(trace, f"第 1 轮 · 轮密钥加  AddRoundKey(K1={schedule.k1:04X})", state)

    state = _sub_nibbles_block(state)
    _trace_step(trace, "第 2 轮 · 半字节代替  SubNib", state)
    state = _shift_rows_block(state)
    _trace_step(trace, "第 2 轮 · 行移位  ShiftRows", state)
    state = _add_round_key_block(state, schedule.k2)
    _trace_step(trace, f"第 2 轮 · 轮密钥加  AddRoundKey(K2={schedule.k2:04X})", state)

    trace.extend(["", f"密文 C : {state:04X}", f"二进制 : {state:016b}"])
    return state, trace


def decrypt_block_with_trace(ciphertext: int, key: int) -> Tuple[int, List[str]]:
    """解密并返回逐轮状态。"""
    _check_range(ciphertext, BLOCK_BITS, "密文")
    schedule = expand_key(key)
    w = schedule.words

    trace: List[str] = [
        "S-AES 解密过程",
        f"密钥 K : {key:04X}",
        f"密文 C : {ciphertext:04X}",
        "",
        "【密钥扩展】",
        f"w0={w[0]:02X}  w1={w[1]:02X}  w2={w[2]:02X}  "
        f"w3={w[3]:02X}  w4={w[4]:02X}  w5={w[5]:02X}",
        f"K0={schedule.k0:04X}  K1={schedule.k1:04X}  K2={schedule.k2:04X}",
        "",
        "（状态矩阵按列优先排列）",
    ]

    state = _add_round_key_block(ciphertext, schedule.k2)
    _trace_step(trace, f"初始轮密钥加  AddRoundKey(K2={schedule.k2:04X})", state)

    state = _shift_rows_block(state)
    _trace_step(trace, "逆第 2 轮 · 逆行移位  InvShiftRows", state)
    state = _inv_sub_nibbles_block(state)
    _trace_step(trace, "逆第 2 轮 · 逆半字节代替  InvSubNib", state)
    state = _add_round_key_block(state, schedule.k1)
    _trace_step(trace, f"逆第 2 轮 · 轮密钥加  AddRoundKey(K1={schedule.k1:04X})", state)

    state = _inv_mix_columns_block(state)
    _trace_step(trace, "逆第 1 轮 · 逆列混淆  InvMixColumns", state)
    state = _shift_rows_block(state)
    _trace_step(trace, "逆第 1 轮 · 逆行移位  InvShiftRows", state)
    state = _inv_sub_nibbles_block(state)
    _trace_step(trace, "逆第 1 轮 · 逆半字节代替  InvSubNib", state)
    state = _add_round_key_block(state, schedule.k0)
    _trace_step(trace, f"逆第 1 轮 · 轮密钥加  AddRoundKey(K0={schedule.k0:04X})", state)

    trace.extend(["", f"明文 P : {state:04X}", f"二进制 : {state:016b}"])
    return state, trace
