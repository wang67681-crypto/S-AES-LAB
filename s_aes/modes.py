"""S-AES 的字节串、双重/三重加密与 CBC 工作模式。

所有长度均以字节为单位。S-AES 分组固定为 2 字节。
"""

from __future__ import annotations

from typing import Iterable, List, Tuple

from .core import (
    BLOCK_BYTES,
    decrypt_block,
    encrypt_block,
)

PAD_BLOCK_SIZE = BLOCK_BYTES


# ---------------------------------------------------------------------------
# 基础转换
# ---------------------------------------------------------------------------
def _require_bytes(data: bytes, name: str = "数据") -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{name}必须是 bytes")
    return bytes(data)


def split_blocks(data: bytes) -> List[int]:
    """把字节串拆成 16 bit 分组，长度不是偶数时抛出异常。"""
    data = _require_bytes(data)
    if len(data) % BLOCK_BYTES:
        raise ValueError("数据长度必须是 2 字节的整数倍")
    return [
        (data[index] << 8) | data[index + 1]
        for index in range(0, len(data), BLOCK_BYTES)
    ]


def join_blocks(blocks: Iterable[int]) -> bytes:
    result = bytearray()
    for block in blocks:
        if not 0 <= block <= 0xFFFF:
            raise ValueError("分组必须是 16 bit 整数")
        result.extend(((block >> 8) & 0xFF, block & 0xFF))
    return bytes(result)


# ---------------------------------------------------------------------------
# PKCS#7 填充（块长 2 字节）
# ---------------------------------------------------------------------------
def pkcs7_pad(data: bytes, block_size: int = PAD_BLOCK_SIZE) -> bytes:
    """按 PKCS#7 填充，使长度成为 block_size 的整数倍。

    块长为 2 时，奇数长度补 1 个 0x01；偶数长度补 2 个 0x02。
    """
    data = _require_bytes(data)
    if block_size < 1 or block_size > 255:
        raise ValueError("block_size 必须在 1..255 之间")
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes, block_size: int = PAD_BLOCK_SIZE) -> bytes:
    """移除并校验 PKCS#7 填充，失败时抛出 ValueError。"""
    data = _require_bytes(data)
    if not data or len(data) % block_size:
        raise ValueError("带填充的数据长度不合法")
    padding_length = data[-1]
    if not 1 <= padding_length <= block_size:
        raise ValueError("PKCS#7 填充值不合法")
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("PKCS#7 填充字节不一致")
    return data[:-padding_length]


# ---------------------------------------------------------------------------
# 单密钥字节串加解密
# ---------------------------------------------------------------------------
def encrypt_bytes(data: bytes, key: int, add_padding: bool = True) -> bytes:
    data = _require_bytes(data)
    if add_padding:
        data = pkcs7_pad(data)
    elif len(data) % BLOCK_BYTES:
        raise ValueError("不填充时数据长度必须是 2 字节的整数倍")
    return join_blocks(encrypt_block(block, key) for block in split_blocks(data))


def decrypt_bytes(data: bytes, key: int, remove_padding: bool = True) -> bytes:
    data = _require_bytes(data)
    plaintext = join_blocks(
        decrypt_block(block, key) for block in split_blocks(data)
    )
    if remove_padding:
        return pkcs7_unpad(plaintext)
    return plaintext


# ---------------------------------------------------------------------------
# 双重加密：K = K1 || K2，C = E_K2(E_K1(P))
# ---------------------------------------------------------------------------
def split_key32(key: int) -> Tuple[int, int]:
    if not 0 <= key <= 0xFFFFFFFF:
        raise ValueError("双重加密密钥必须是 32 bit")
    return (key >> 16) & 0xFFFF, key & 0xFFFF


def double_encrypt_block(plaintext: int, key: int) -> int:
    key1, key2 = split_key32(key)
    return encrypt_block(encrypt_block(plaintext, key1), key2)


def double_decrypt_block(ciphertext: int, key: int) -> int:
    key1, key2 = split_key32(key)
    return decrypt_block(decrypt_block(ciphertext, key2), key1)


def double_encrypt_bytes(data: bytes, key: int, add_padding: bool = True) -> bytes:
    data = _require_bytes(data)
    if add_padding:
        data = pkcs7_pad(data)
    elif len(data) % BLOCK_BYTES:
        raise ValueError("不填充时数据长度必须是 2 字节的整数倍")
    return join_blocks(double_encrypt_block(block, key) for block in split_blocks(data))


def double_decrypt_bytes(data: bytes, key: int, remove_padding: bool = True) -> bytes:
    plaintext = join_blocks(
        double_decrypt_block(block, key) for block in split_blocks(_require_bytes(data))
    )
    return pkcs7_unpad(plaintext) if remove_padding else plaintext


# ---------------------------------------------------------------------------
# 三重加密
# ---------------------------------------------------------------------------
def triple_encrypt_block(plaintext: int, key: int, key_bits: int = 48) -> int:
    """三重加密。

    key_bits=32：两密钥 EDE 模式，C = E_K1(D_K2(E_K1(P)))，K = K1 || K2。
    key_bits=48：三密钥 EEE 模式，C = E_K3(E_K2(E_K1(P)))，K = K1 || K2 || K3。
    """
    if key_bits == 32:
        key1, key2 = split_key32(key)
        return encrypt_block(
            decrypt_block(encrypt_block(plaintext, key1), key2), key1
        )
    if key_bits == 48:
        if not 0 <= key <= 0xFFFFFFFFFFFF:
            raise ValueError("三重加密密钥必须是 48 bit")
        key1 = (key >> 32) & 0xFFFF
        key2 = (key >> 16) & 0xFFFF
        key3 = key & 0xFFFF
        return encrypt_block(
            encrypt_block(encrypt_block(plaintext, key1), key2), key3
        )
    raise ValueError("三重加密密钥长度只能是 32 bit 或 48 bit")


def triple_decrypt_block(ciphertext: int, key: int, key_bits: int = 48) -> int:
    if key_bits == 32:
        key1, key2 = split_key32(key)
        return decrypt_block(
            encrypt_block(decrypt_block(ciphertext, key1), key2), key1
        )
    if key_bits == 48:
        if not 0 <= key <= 0xFFFFFFFFFFFF:
            raise ValueError("三重加密密钥必须是 48 bit")
        key1 = (key >> 32) & 0xFFFF
        key2 = (key >> 16) & 0xFFFF
        key3 = key & 0xFFFF
        return decrypt_block(
            decrypt_block(decrypt_block(ciphertext, key3), key2), key1
        )
    raise ValueError("三重加密密钥长度只能是 32 bit 或 48 bit")


# ---------------------------------------------------------------------------
# CBC 密码分组链接
# ---------------------------------------------------------------------------
def cbc_encrypt(
    plaintext: bytes,
    key: int,
    iv: int,
    add_padding: bool = True,
) -> bytes:
    """CBC 加密：C_i = E_K(P_i XOR C_{i-1})，C_0 = IV。"""
    plaintext = _require_bytes(plaintext)
    if not 0 <= iv <= 0xFFFF:
        raise ValueError("初始向量 IV 必须是 16 bit")
    if add_padding:
        plaintext = pkcs7_pad(plaintext)
    elif len(plaintext) % BLOCK_BYTES:
        raise ValueError("不填充时明文长度必须是 2 字节的整数倍")

    previous = iv
    ciphertext = bytearray()
    for block in split_blocks(plaintext):
        previous = encrypt_block(block ^ previous, key)
        ciphertext.extend(((previous >> 8) & 0xFF, previous & 0xFF))
    return bytes(ciphertext)


def cbc_decrypt(
    ciphertext: bytes,
    key: int,
    iv: int,
    remove_padding: bool = True,
) -> bytes:
    """CBC 解密。"""
    ciphertext = _require_bytes(ciphertext)
    if not 0 <= iv <= 0xFFFF:
        raise ValueError("初始向量 IV 必须是 16 bit")
    if not ciphertext or len(ciphertext) % BLOCK_BYTES:
        raise ValueError("密文长度必须是 2 字节的正整数倍")

    previous = iv
    plaintext = bytearray()
    for block in split_blocks(ciphertext):
        decoded = decrypt_block(block, key) ^ previous
        plaintext.extend(((decoded >> 8) & 0xFF, decoded & 0xFF))
        previous = block
    result = bytes(plaintext)
    return pkcs7_unpad(result) if remove_padding else result


def flip_ciphertext_bit(ciphertext: bytes, block_index: int, bit_index: int) -> bytes:
    """翻转指定分组中的 1 个比特（bit 0 表示最低位）。"""
    blocks = split_blocks(ciphertext)
    if not 0 <= block_index < len(blocks):
        raise IndexError("分组下标越界")
    if not 0 <= bit_index < 16:
        raise ValueError("比特位必须在 0..15 之间")
    blocks[block_index] ^= 1 << bit_index
    return join_blocks(blocks)


def replace_ciphertext_block(
    ciphertext: bytes, block_index: int, replacement: int = 0
) -> bytes:
    """把指定密文分组整体替换为另一个 16 bit 值。"""
    blocks = split_blocks(ciphertext)
    if not 0 <= block_index < len(blocks):
        raise IndexError("分组下标越界")
    if not 0 <= replacement <= 0xFFFF:
        raise ValueError("替换值必须是 16 bit")
    blocks[block_index] = replacement
    return join_blocks(blocks)


def changed_bit_positions(before: bytes, after: bytes) -> List[int]:
    """返回两个字节串中所有不同比特的位置（从 0 开始，按字节内 LSB 编号）。"""
    length = min(len(before), len(after))
    positions: List[int] = []
    for byte_index in range(length):
        difference = before[byte_index] ^ after[byte_index]
        for bit in range(8):
            if difference & (1 << bit):
                positions.append(byte_index * 8 + bit)
    return positions
