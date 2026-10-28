"""输入解析与显示格式化工具。"""

from __future__ import annotations

import re
from typing import Union

_SEPARATORS = re.compile(r"[\s:_\-,]+")
_HEX_DIGITS = set("0123456789abcdefABCDEF")


class InputError(ValueError):
    """用户输入格式错误。"""


def _strip_prefix(text: str) -> tuple[str, int | None]:
    stripped = text.strip()
    lowered = stripped.lower()
    if lowered.startswith("0x"):
        return stripped[2:], 16
    if lowered.startswith("0b"):
        return stripped[2:], 2
    return stripped, None


def parse_bits(text: str, bits: int, name: str = "数值") -> int:
    """解析 16/32/48 bit 数值，支持十六进制与二进制。

    * 十六进制：可写 0x 前缀、空格、冒号、下划线；
    * 二进制：可写 0b 前缀，也可直接输入 bits 位 0/1（允许按 4 位分组）。
    """
    if not text or not text.strip():
        raise InputError(f"请输入{name}")
    body, explicit_base = _strip_prefix(text)
    cleaned = _SEPARATORS.sub("", body)
    if not cleaned:
        raise InputError(f"{name}不能为空")

    if explicit_base == 2 or (
        explicit_base is None
        and len(cleaned) == bits
        and set(cleaned) <= {"0", "1"}
    ):
        if len(cleaned) != bits or set(cleaned) - {"0", "1"}:
            raise InputError(f"{name}应为 {bits} 位二进制数")
        return int(cleaned, 2)

    if len(cleaned) != bits // 4 or set(cleaned) - _HEX_DIGITS:
        raise InputError(
            f"{name}应为 {bits // 4} 个十六进制字符（{bits} bit），例如 "
            f"{'2D55' if bits == 16 else '1A2B3C4D' if bits == 32 else '1A2B3C4D5E6F'}"
        )
    return int(cleaned, 16)


def parse_hex_bytes(text: str, name: str = "密文") -> bytes:
    """解析连续或分组书写的十六进制字节串。"""
    if not text or not text.strip():
        raise InputError(f"请输入{name}")
    body, base = _strip_prefix(text)
    if base == 2:
        cleaned = _SEPARATORS.sub("", body)
        if not cleaned or set(cleaned) - {"0", "1"} or len(cleaned) % 8:
            raise InputError(f"{name}的二进制长度必须是 8 的整数倍")
        return int(cleaned, 2).to_bytes(len(cleaned) // 8, "big")
    cleaned = _SEPARATORS.sub("", body)
    if not cleaned or len(cleaned) % 2 or set(cleaned) - _HEX_DIGITS:
        raise InputError(f"{name}应为偶数个十六进制字符")
    return bytes.fromhex(cleaned)


def format_hex_block(value: int, bits: int = 16) -> str:
    return f"{value:0{bits // 4}X}"


def format_binary(value: int, bits: int = 16, group: int = 4) -> str:
    raw = f"{value:0{bits}b}"
    return " ".join(raw[index:index + group] for index in range(0, len(raw), group))


def format_hex_bytes(data: bytes, group_bytes: int = 2) -> str:
    """格式化为大写十六进制，每 group_bytes 字节加一个空格。"""
    if group_bytes < 1:
        raise ValueError("group_bytes 必须大于 0")
    raw = data.hex().upper()
    group_chars = group_bytes * 2
    return " ".join(
        raw[index:index + group_chars]
        for index in range(0, len(raw), group_chars)
    )


def escape_bytes(data: Union[bytes, bytearray]) -> str:
    """把字节串转换成可读的单行转义文本。"""
    parts: list[str] = []
    for byte in bytes(data):
        if byte == 0x5C:
            parts.append("\\\\")
        elif byte == 0x0A:
            parts.append("\\n")
        elif byte == 0x0D:
            parts.append("\\r")
        elif byte == 0x09:
            parts.append("\\t")
        elif 0x20 <= byte < 0x7F:
            parts.append(chr(byte))
        else:
            parts.append(f"\\x{byte:02X}")
    return "".join(parts)


def decode_utf8(data: bytes, errors: str = "strict") -> str:
    return data.decode("utf-8", errors=errors)
