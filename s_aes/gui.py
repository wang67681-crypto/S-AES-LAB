"""PyQt5 图形界面：S-AES 五个实验关卡。"""

from __future__ import annotations

import json
import secrets
import sys
import time
from datetime import datetime
from html import escape as html_escape
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QIcon, QPainter, QPixmap, QTextCursor
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .attacks import MitmResult, mitm_attack
from .core import (
    INV_S_BOX,
    S_BOX,
    decrypt_block,
    decrypt_block_with_trace,
    encrypt_block,
    encrypt_block_with_trace,
    expand_key,
    mix_columns_block,
)
from .modes import (
    cbc_decrypt,
    cbc_encrypt,
    double_decrypt_block,
    double_encrypt_block,
    encrypt_bytes,
    decrypt_bytes,
    flip_ciphertext_bit,
    split_blocks,
    triple_decrypt_block,
    triple_encrypt_block,
)
from .utils import (
    InputError,
    decode_utf8,
    escape_bytes,
    format_binary,
    format_hex_bytes,
    parse_bits,
    parse_hex_bytes,
)

APP_NAME = "S-AES 算法实验平台"
MONO_FAMILIES = ("Cascadia Mono", "Consolas", "JetBrains Mono", "Courier New")


def mono_font(size: float = 10, bold: bool = False) -> QFont:
    font = QFont("Cascadia Mono")
    font.setStyleHint(QFont.Monospace)
    font.setFamilies(list(MONO_FAMILIES))
    font.setPointSizeF(size)
    font.setBold(bold)
    return font


def make_label(text: str, object_name: str = "", wrap: bool = False) -> QLabel:
    label = QLabel(text)
    if object_name:
        label.setObjectName(object_name)
    label.setWordWrap(wrap)
    return label


def make_button(
    text: str,
    primary: bool = False,
    small: bool = False,
    ghost: bool = False,
) -> QPushButton:
    button = QPushButton(text)
    if primary:
        button.setObjectName("primary")
    elif small:
        button.setObjectName("small")
    elif ghost:
        button.setObjectName("ghost")
    button.setCursor(Qt.PointingHandCursor)
    return button


def set_status(label: QLabel, text: str, ok: bool = True) -> None:
    color = "#047857" if ok else "#DC2626"
    label.setStyleSheet(f"color: {color}; font-size: 9pt;")
    label.setText(text)


class Card(QFrame):
    """白色圆角卡片容器。"""

    def __init__(
        self,
        title: str = "",
        subtitle: str = "",
        parent: Optional[QWidget] = None,
        compact: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        outer = QVBoxLayout(self)
        if compact:
            outer.setContentsMargins(14, 10, 14, 10)
            outer.setSpacing(4)
        else:
            outer.setContentsMargins(16, 14, 16, 14)
            outer.setSpacing(7)

        if title:
            title_label = make_label(title, "cardTitle")
            outer.addWidget(title_label)
        if subtitle:
            subtitle_label = make_label(subtitle, "cardSubtitle", wrap=True)
            outer.addWidget(subtitle_label)

        self.body = QVBoxLayout()
        self.body.setContentsMargins(0, 2, 0, 0)
        self.body.setSpacing(4 if compact else 7)
        outer.addLayout(self.body, 1)


class MitmWorker(QThread):
    progress = pyqtSignal(int, str)
    completed = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, pairs: Sequence[Tuple[int, int]], parent=None) -> None:
        super().__init__(parent)
        self._pairs = list(pairs)

    def run(self) -> None:
        try:
            result = mitm_attack(
                self._pairs,
                progress=lambda percent, message: self.progress.emit(percent, message),
                should_stop=self.isInterruptionRequested,
            )
            self.completed.emit(result)
        except Exception as exc:  # noqa: BLE001 - 需要把异常反馈到界面
            self.failed.emit(str(exc))


class BasicTab(QWidget):
    """第 1 关：16 bit 分组基本加解密，带逐轮轨迹。"""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(14)

        left = QWidget()
        left.setFixedWidth(405)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(12)

        input_card = Card("参数输入", "16 bit 密钥 + 16 bit 数据")
        input_card.body.addWidget(make_label("密钥 K（16 bit）", "sectionTitle"))
        key_row = QHBoxLayout()
        key_row.setSpacing(8)
        self.key_edit = QLineEdit("2D55")
        self.key_edit.setPlaceholderText("例如 2D55")
        self.key_edit.setFont(mono_font(11, True))
        self.key_edit.setMaxLength(24)
        random_key_button = make_button("随机", small=True)
        random_key_button.clicked.connect(self._random_key)
        key_row.addWidget(self.key_edit, 1)
        key_row.addWidget(random_key_button)
        input_card.body.addLayout(key_row)

        input_card.body.addWidget(make_label("明文 / 密文（16 bit）", "sectionTitle"))
        data_row = QHBoxLayout()
        data_row.setSpacing(8)
        self.data_edit = QLineEdit("6BA3")
        self.data_edit.setPlaceholderText("例如 6BA3")
        self.data_edit.setFont(mono_font(11, True))
        self.data_edit.setMaxLength(24)
        random_data_button = make_button("随机", small=True)
        random_data_button.clicked.connect(self._random_data)
        data_row.addWidget(self.data_edit, 1)
        data_row.addWidget(random_data_button)
        input_card.body.addLayout(data_row)

        action_row = QHBoxLayout()
        action_row.setSpacing(8)
        encrypt_button = make_button("加密", primary=True)
        encrypt_button.clicked.connect(self._encrypt)
        decrypt_button = make_button("解密", ghost=True)
        decrypt_button.clicked.connect(self._decrypt)
        swap_button = make_button("交换", ghost=True)
        swap_button.clicked.connect(self._swap)
        action_row.addWidget(encrypt_button, 2)
        action_row.addWidget(decrypt_button, 2)
        action_row.addWidget(swap_button, 1)
        input_card.body.addLayout(action_row)

        self.status_label = make_label("", wrap=True)
        input_card.body.addWidget(self.status_label)

        tip = make_label(
            "支持 4 位十六进制或 16 位二进制（可带 0x / 0b 前缀）。",
            "hint",
            wrap=True,
        )
        input_card.body.addWidget(tip)
        left_layout.addWidget(input_card)

        result_card = Card("运算结果")
        self.result_kind = make_label("密文 C", "pill")
        self.result_kind.setAlignment(Qt.AlignCenter)
        self.result_kind.setFixedWidth(72)
        self.result_value = make_label("—", "resultValue")
        self.result_value.setAlignment(Qt.AlignCenter)
        self.result_binary = make_label("", "resultBinary")
        self.result_binary.setAlignment(Qt.AlignCenter)
        self.result_binary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.result_value.setTextInteractionFlags(Qt.TextSelectableByMouse)

        result_header = QHBoxLayout()
        result_header.addStretch(1)
        result_header.addWidget(self.result_kind)
        result_header.addStretch(1)
        result_card.body.addLayout(result_header)
        result_card.body.addWidget(self.result_value)
        result_card.body.addWidget(self.result_binary)

        copy_row = QHBoxLayout()
        copy_row.addStretch(1)
        copy_button = make_button("复制结果", small=True)
        copy_button.clicked.connect(self._copy_result)
        copy_row.addWidget(copy_button)
        copy_row.addStretch(1)
        result_card.body.addLayout(copy_row)
        left_layout.addWidget(result_card)
        left_layout.addStretch(1)

        trace_card = Card(
            "逐轮运算轨迹",
            "状态矩阵按列优先显示：左上 s00、右上 s01、左下 s10、右下 s11",
        )
        self.trace_view = QPlainTextEdit()
        self.trace_view.setReadOnly(True)
        self.trace_view.setFont(mono_font(9.7))
        self.trace_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.trace_view.setStyleSheet(
            "QPlainTextEdit { background: #0B1526; color: #DCE9FF; "
            "border: 1px solid #1E3A8A; border-radius: 10px; padding: 12px; "
            "selection-background-color: #1D4ED8; }"
        )
        trace_card.body.addWidget(self.trace_view, 1)

        root.addWidget(left)
        root.addWidget(trace_card, 1)

        self.key_edit.returnPressed.connect(self._encrypt)
        self.data_edit.returnPressed.connect(self._encrypt)
        self._encrypt()

    def _read_key(self) -> int:
        return parse_bits(self.key_edit.text(), 16, "密钥 K")

    def _read_data(self) -> int:
        return parse_bits(self.data_edit.text(), 16, "明文 / 密文")

    def _random_key(self) -> None:
        self.key_edit.setText(f"{secrets.randbits(16):04X}")

    def _random_data(self) -> None:
        self.data_edit.setText(f"{secrets.randbits(16):04X}")

    def _encrypt(self) -> None:
        try:
            key = self._read_key()
            plaintext = self._read_data()
            ciphertext, trace = encrypt_block_with_trace(plaintext, key)
        except (InputError, ValueError, TypeError) as exc:
            set_status(self.status_label, str(exc), ok=False)
            return

        self.result_kind.setText("密文 C")
        self.result_value.setText(f"{ciphertext:04X}")
        self.result_binary.setText(format_binary(ciphertext, 16))
        self.trace_view.setPlainText("\n".join(trace))
        self.trace_view.moveCursor(QTextCursor.Start)
        set_status(self.status_label, "加密完成，逐轮状态已更新。")
        self._result_text = f"{ciphertext:04X}"

    def _decrypt(self) -> None:
        try:
            key = self._read_key()
            ciphertext = self._read_data()
            plaintext, trace = decrypt_block_with_trace(ciphertext, key)
        except (InputError, ValueError, TypeError) as exc:
            set_status(self.status_label, str(exc), ok=False)
            return

        self.result_kind.setText("明文 P")
        self.result_value.setText(f"{plaintext:04X}")
        self.result_binary.setText(format_binary(plaintext, 16))
        self.trace_view.setPlainText("\n".join(trace))
        self.trace_view.moveCursor(QTextCursor.Start)
        set_status(self.status_label, "解密完成，逐轮状态已更新。")
        self._result_text = f"{plaintext:04X}"

    def _swap(self) -> None:
        if self.result_value.text() not in ("", "—"):
            self.data_edit.setText(self.result_value.text())
            set_status(self.status_label, "已把结果放入输入框。")

    def _copy_result(self) -> None:
        if self.result_value.text() not in ("", "—"):
            QApplication.clipboard().setText(self.result_value.text())
            set_status(self.status_label, "结果已复制到剪贴板。")


class AsciiTab(QWidget):
    """第 3 关：ASCII / UTF-8 字符串分组加解密。"""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        key_card = Card("密钥", "字符串按 2 字节分组；采用 PKCS#7 填充以支持任意长度。")
        key_row = QHBoxLayout()
        key_row.setSpacing(8)
        key_row.addWidget(make_label("密钥 K", "sectionTitle"))
        self.key_edit = QLineEdit("2D55")
        self.key_edit.setFont(mono_font(11, True))
        self.key_edit.setFixedWidth(140)
        self.key_edit.setMaxLength(24)
        key_row.addWidget(self.key_edit)
        random_button = make_button("随机", small=True)
        random_button.clicked.connect(self._random_key)
        key_row.addWidget(random_button)
        key_row.addStretch(1)
        pill = make_label("ASCII / UTF-8 · 16 bit 分组", "pill")
        key_row.addWidget(pill)
        key_card.body.addLayout(key_row)
        root.addWidget(key_card)

        text_row = QHBoxLayout()
        text_row.setSpacing(12)

        plain_card = Card("明文 / 解密结果", "输入文本或查看解密后的文本")
        self.plain_edit = QPlainTextEdit()
        self.plain_edit.setPlaceholderText("例如：Hello, S-AES!")
        self.plain_edit.setPlainText("Hello, S-AES!")
        self.plain_edit.setFont(QFont("Microsoft YaHei UI", 11))
        plain_card.body.addWidget(self.plain_edit, 1)
        self.plain_count = make_label("0 字符 · 0 字节", "hint")
        plain_card.body.addWidget(self.plain_count)

        cipher_card = Card("密文（十六进制）", "每 2 字节一个分组，可带空格")
        self.cipher_edit = QPlainTextEdit()
        self.cipher_edit.setPlaceholderText("加密后自动填入，也可粘贴密文后解密")
        self.cipher_edit.setFont(mono_font(10))
        self.cipher_edit.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        cipher_card.body.addWidget(self.cipher_edit, 1)
        self.cipher_info = make_label("等待加密…", "hint", wrap=True)
        cipher_card.body.addWidget(self.cipher_info)

        text_row.addWidget(plain_card, 1)
        text_row.addWidget(cipher_card, 1)
        root.addLayout(text_row, 1)

        actions = QHBoxLayout()
        actions.setSpacing(9)
        encrypt_button = make_button("加密 →", primary=True)
        encrypt_button.clicked.connect(self._encrypt)
        decrypt_button = make_button("← 解密", ghost=True)
        decrypt_button.clicked.connect(self._decrypt)
        clear_button = make_button("清空", ghost=True)
        clear_button.clicked.connect(self._clear)
        copy_button = make_button("复制密文", small=True)
        copy_button.clicked.connect(self._copy_cipher)
        actions.addWidget(encrypt_button)
        actions.addWidget(decrypt_button)
        actions.addWidget(clear_button)
        actions.addStretch(1)
        actions.addWidget(copy_button)
        root.addLayout(actions)

        self.status_label = make_label("", wrap=True)
        root.addWidget(self.status_label)

        self.plain_edit.textChanged.connect(self._update_plain_count)
        self._update_plain_count()

    def _read_key(self) -> int:
        return parse_bits(self.key_edit.text(), 16, "密钥 K")

    def _random_key(self) -> None:
        self.key_edit.setText(f"{secrets.randbits(16):04X}")

    def _update_plain_count(self) -> None:
        text = self.plain_edit.toPlainText()
        self.plain_count.setText(f"{len(text)} 字符 · {len(text.encode('utf-8'))} 字节")

    def _encrypt(self) -> None:
        try:
            key = self._read_key()
            text = self.plain_edit.toPlainText()
            data = text.encode("utf-8")
            ciphertext = encrypt_bytes(data, key)
        except (InputError, ValueError, TypeError) as exc:
            set_status(self.status_label, str(exc), ok=False)
            return

        self.cipher_edit.setPlainText(format_hex_bytes(ciphertext))
        groups = len(ciphertext) // 2
        padding = len(ciphertext) - len(data)
        self.cipher_info.setText(
            f"{len(data)} 字节明文 → {len(ciphertext)} 字节密文 · "
            f"{groups} 组 · PKCS#7 填充 {padding} 字节\n"
            f"ASCII 转义预览：{self._preview(ciphertext)}"
        )
        set_status(
            self.status_label,
            f"加密完成：{len(data)} 字节 → {len(ciphertext)} 字节，共 {groups} 个分组。",
        )

    def _decrypt(self) -> None:
        try:
            key = self._read_key()
            ciphertext = parse_hex_bytes(self.cipher_edit.toPlainText(), "密文")
            data = decrypt_bytes(ciphertext, key)
            text = decode_utf8(data)
        except UnicodeDecodeError:
            text = decode_utf8(data, errors="replace")
            set_status(
                self.status_label,
                "解密完成，但明文字节不是合法 UTF-8，已用替换字符显示。",
                ok=False,
            )
        except (InputError, ValueError, TypeError) as exc:
            set_status(self.status_label, str(exc), ok=False)
            return
        else:
            set_status(self.status_label, "解密完成，已还原明文。")

        self.plain_edit.setPlainText(text)
        groups = len(ciphertext) // 2
        self.cipher_info.setText(
            f"{len(ciphertext)} 字节密文 · {groups} 组 · 已去除 PKCS#7 填充\n"
            f"ASCII 转义预览：{self._preview(ciphertext)}"
        )

    def _clear(self) -> None:
        self.plain_edit.clear()
        self.cipher_edit.clear()
        self.cipher_info.setText("等待加密…")
        set_status(self.status_label, "已清空。")

    def _copy_cipher(self) -> None:
        text = self.cipher_edit.toPlainText().strip()
        if not text:
            set_status(self.status_label, "当前没有可复制的密文。", ok=False)
            return
        QApplication.clipboard().setText(text)
        set_status(self.status_label, "密文已复制到剪贴板。")

    @staticmethod
    def _preview(data: bytes, limit: int = 72) -> str:
        preview = escape_bytes(data[:limit])
        if len(data) > limit:
            preview += "…"
        return preview


class MultiTab(QWidget):
    """第 4 关：双重加密、中间相遇攻击、三重加密。"""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._demo_key: Optional[int] = None
        self._filling_pairs = False
        self._worker: Optional[MitmWorker] = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        content.setObjectName("root")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(2, 2, 8, 8)
        layout.setSpacing(12)

        top_row = QHBoxLayout()
        top_row.setSpacing(12)
        top_row.addWidget(self._build_double_card(), 1)
        top_row.addWidget(self._build_triple_card(), 1)
        layout.addLayout(top_row)
        layout.addWidget(self._build_mitm_card(), 1)
        scroll.setWidget(content)
        outer.addWidget(scroll)

        self._fill_demo_pairs()

    # ------------------------------------------------------------------
    # 双重加密
    # ------------------------------------------------------------------
    def _build_double_card(self) -> Card:
        card = Card(
            "双重加密",
            "K = K1 || K2，C = E_K2(E_K1(P))；分组仍为 16 bit，密钥扩展到 32 bit。",
            compact=True,
        )
        form = QGridLayout()
        form.setHorizontalSpacing(8)
        form.setVerticalSpacing(7)
        form.addWidget(make_label("密钥 K（32 bit）", "sectionTitle"), 0, 0)
        self.double_key_edit = QLineEdit("1A2B3C4D")
        self.double_key_edit.setFont(mono_font(10.5, True))
        self.double_key_edit.setMaxLength(40)
        form.addWidget(self.double_key_edit, 0, 1)
        double_random = make_button("随机", small=True)
        double_random.clicked.connect(self._random_double_key)
        form.addWidget(double_random, 0, 2)
        form.addWidget(make_label("明文 / 密文（16 bit）", "sectionTitle"), 1, 0)
        self.double_block_edit = QLineEdit("1234")
        self.double_block_edit.setFont(mono_font(10.5, True))
        self.double_block_edit.setMaxLength(24)
        form.addWidget(self.double_block_edit, 1, 1, 1, 2)
        card.body.addLayout(form)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        encrypt_button = make_button("加密", primary=True)
        encrypt_button.clicked.connect(self._double_encrypt)
        decrypt_button = make_button("解密", ghost=True)
        decrypt_button.clicked.connect(self._double_decrypt)
        actions.addWidget(encrypt_button)
        actions.addWidget(decrypt_button)
        actions.addStretch(1)
        copy_button = make_button("复制", small=True)
        copy_button.clicked.connect(
            lambda: self._copy_value(self.double_result.text(), self.double_status)
        )
        actions.addWidget(copy_button)
        card.body.addLayout(actions)

        self.double_result = make_label("—", "resultValue")
        self.double_result.setAlignment(Qt.AlignCenter)
        self.double_result.setFont(mono_font(21, True))
        self.double_result.setTextInteractionFlags(Qt.TextSelectableByMouse)
        card.body.addWidget(self.double_result)
        self.double_status = make_label("", "hint", wrap=True)
        card.body.addWidget(self.double_status)
        return card

    def _random_double_key(self) -> None:
        self.double_key_edit.setText(f"{secrets.randbits(32):08X}")

    def _double_encrypt(self) -> None:
        try:
            key = parse_bits(self.double_key_edit.text(), 32, "双重加密密钥")
            plaintext = parse_bits(self.double_block_edit.text(), 16, "明文")
            ciphertext = double_encrypt_block(plaintext, key)
        except (InputError, ValueError, TypeError) as exc:
            set_status(self.double_status, str(exc), ok=False)
            return
        self.double_result.setText(f"{ciphertext:04X}")
        set_status(self.double_status, f"{plaintext:04X} → {ciphertext:04X}")

    def _double_decrypt(self) -> None:
        try:
            key = parse_bits(self.double_key_edit.text(), 32, "双重加密密钥")
            ciphertext = parse_bits(self.double_block_edit.text(), 16, "密文")
            plaintext = double_decrypt_block(ciphertext, key)
        except (InputError, ValueError, TypeError) as exc:
            set_status(self.double_status, str(exc), ok=False)
            return
        self.double_result.setText(f"{plaintext:04X}")
        set_status(self.double_status, f"{ciphertext:04X} → {plaintext:04X}")

    # ------------------------------------------------------------------
    # 三重加密
    # ------------------------------------------------------------------
    def _build_triple_card(self) -> Card:
        card = Card(
            "三重加密",
            "可选两密钥 EDE（32 bit）或三密钥 EEE（48 bit）两种模式。",
            compact=True,
        )
        form = QGridLayout()
        form.setHorizontalSpacing(8)
        form.setVerticalSpacing(7)
        form.addWidget(make_label("模式", "sectionTitle"), 0, 0)
        self.triple_mode_combo = QComboBox()
        self.triple_mode_combo.addItem("32 bit · K1+K2（EDE）", 32)
        self.triple_mode_combo.addItem("48 bit · K1+K2+K3（EEE）", 48)
        self.triple_mode_combo.currentIndexChanged.connect(self._triple_mode_changed)
        form.addWidget(self.triple_mode_combo, 0, 1, 1, 2)

        form.addWidget(make_label("密钥 K", "sectionTitle"), 1, 0)
        self.triple_key_edit = QLineEdit("1A2B3C4D")
        self.triple_key_edit.setFont(mono_font(10.5, True))
        form.addWidget(self.triple_key_edit, 1, 1)
        triple_random = make_button("随机", small=True)
        triple_random.clicked.connect(self._random_triple_key)
        form.addWidget(triple_random, 1, 2)

        form.addWidget(make_label("明文 / 密文（16 bit）", "sectionTitle"), 2, 0)
        self.triple_block_edit = QLineEdit("1234")
        self.triple_block_edit.setFont(mono_font(10.5, True))
        self.triple_block_edit.setMaxLength(24)
        form.addWidget(self.triple_block_edit, 2, 1, 1, 2)
        card.body.addLayout(form)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        encrypt_button = make_button("加密", primary=True)
        encrypt_button.clicked.connect(self._triple_encrypt)
        decrypt_button = make_button("解密", ghost=True)
        decrypt_button.clicked.connect(self._triple_decrypt)
        actions.addWidget(encrypt_button)
        actions.addWidget(decrypt_button)
        actions.addStretch(1)
        copy_button = make_button("复制", small=True)
        copy_button.clicked.connect(
            lambda: self._copy_value(self.triple_result.text(), self.triple_status)
        )
        actions.addWidget(copy_button)
        card.body.addLayout(actions)

        self.triple_result = make_label("—", "resultValue")
        self.triple_result.setAlignment(Qt.AlignCenter)
        self.triple_result.setFont(mono_font(21, True))
        self.triple_result.setTextInteractionFlags(Qt.TextSelectableByMouse)
        card.body.addWidget(self.triple_result)
        self.triple_status = make_label(
            "EDE：C = E_K1(D_K2(E_K1(P)))", "formula", wrap=True
        )
        card.body.addWidget(self.triple_status)
        return card

    def _triple_mode_changed(self) -> None:
        bits = self.triple_mode_combo.currentData()
        if bits == 32:
            self.triple_key_edit.setPlaceholderText("例如 1A2B3C4D")
            self.triple_key_edit.setMaxLength(40)
            if len(self.triple_key_edit.text().replace(" ", "")) == 12:
                self.triple_key_edit.setText("1A2B3C4D")
            set_status(
                self.triple_status, "EDE：C = E_K1(D_K2(E_K1(P)))", ok=True
            )
        else:
            self.triple_key_edit.setPlaceholderText("例如 1A2B3C4D5E6F")
            self.triple_key_edit.setMaxLength(56)
            if len(self.triple_key_edit.text().replace(" ", "")) == 8:
                self.triple_key_edit.setText("1A2B3C4D5E6F")
            set_status(
                self.triple_status, "EEE：C = E_K3(E_K2(E_K1(P)))", ok=True
            )

    def _random_triple_key(self) -> None:
        bits = self.triple_mode_combo.currentData()
        self.triple_key_edit.setText(f"{secrets.randbits(bits):0{bits // 4}X}")

    def _triple_encrypt(self) -> None:
        try:
            bits = self.triple_mode_combo.currentData()
            key = parse_bits(self.triple_key_edit.text(), bits, "三重加密密钥")
            plaintext = parse_bits(self.triple_block_edit.text(), 16, "明文")
            ciphertext = triple_encrypt_block(plaintext, key, bits)
        except (InputError, ValueError, TypeError) as exc:
            set_status(self.triple_status, str(exc), ok=False)
            return
        self.triple_result.setText(f"{ciphertext:04X}")
        set_status(
            self.triple_status,
            f"{bits} bit 密钥 · {plaintext:04X} → {ciphertext:04X}",
        )

    def _triple_decrypt(self) -> None:
        try:
            bits = self.triple_mode_combo.currentData()
            key = parse_bits(self.triple_key_edit.text(), bits, "三重加密密钥")
            ciphertext = parse_bits(self.triple_block_edit.text(), 16, "密文")
            plaintext = triple_decrypt_block(ciphertext, key, bits)
        except (InputError, ValueError, TypeError) as exc:
            set_status(self.triple_status, str(exc), ok=False)
            return
        self.triple_result.setText(f"{plaintext:04X}")
        set_status(
            self.triple_status,
            f"{bits} bit 密钥 · {ciphertext:04X} → {plaintext:04X}",
        )

    # ------------------------------------------------------------------
    # 中间相遇攻击
    # ------------------------------------------------------------------
    def _build_mitm_card(self) -> Card:
        card = Card(
            "中间相遇攻击（Meet-in-the-Middle）",
            "对每个 K1 计算 E_K1(P1) 建表，对每个 K2 计算 D_K2(C1) 查表；"
            "再用额外明密文对筛选。建议至少 3 组数据，才能把候选缩小到唯一密钥。",
            compact=True,
        )
        body = QHBoxLayout()
        body.setSpacing(14)

        left = QVBoxLayout()
        left.setSpacing(7)
        self.pair_table = QTableWidget(0, 2)
        self.pair_table.setHorizontalHeaderLabels(["明文 P（hex）", "密文 C（hex）"])
        self.pair_table.verticalHeader().setVisible(True)
        self.pair_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.pair_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.pair_table.setEditTriggers(
            QAbstractItemView.DoubleClicked
            | QAbstractItemView.SelectedClicked
            | QAbstractItemView.EditKeyPressed
        )
        self.pair_table.setMinimumHeight(125)
        self.pair_table.setMaximumHeight(145)
        self.pair_table.itemChanged.connect(self._pair_table_changed)
        left.addWidget(self.pair_table)

        pair_actions = QHBoxLayout()
        pair_actions.setSpacing(6)
        demo_button = make_button("生成 3 组随机数据", small=True)
        demo_button.clicked.connect(self._fill_demo_pairs)
        add_button = make_button("添加一组", small=True)
        add_button.clicked.connect(self._add_pair_row)
        remove_button = make_button("删除末组", small=True)
        remove_button.clicked.connect(self._remove_pair_row)
        pair_actions.addWidget(demo_button)
        pair_actions.addWidget(add_button)
        pair_actions.addWidget(remove_button)
        pair_actions.addStretch(1)
        left.addLayout(pair_actions)

        attack_actions = QHBoxLayout()
        attack_actions.setSpacing(8)
        self.attack_button = make_button("开始攻击", primary=True)
        self.attack_button.clicked.connect(self._start_attack)
        self.stop_button = make_button("停止", ghost=True)
        self.stop_button.clicked.connect(self._stop_attack)
        self.stop_button.setEnabled(False)
        attack_actions.addWidget(self.attack_button)
        attack_actions.addWidget(self.stop_button)
        attack_actions.addStretch(1)
        left.addLayout(attack_actions)

        self.attack_progress = QProgressBar()
        self.attack_progress.setRange(0, 100)
        self.attack_progress.setValue(0)
        self.attack_progress.setFixedHeight(10)
        left.addWidget(self.attack_progress)
        self.attack_status = make_label("等待攻击…", "hint", wrap=True)
        left.addWidget(self.attack_status)

        right = QVBoxLayout()
        right.setSpacing(7)
        right.addWidget(make_label("攻击结果", "sectionTitle"))
        self.attack_result = QPlainTextEdit()
        self.attack_result.setReadOnly(True)
        self.attack_result.setFont(mono_font(9.4))
        self.attack_result.setMinimumHeight(160)
        self.attack_result.setPlaceholderText("点击“开始攻击”后在此显示候选密钥…")
        self.attack_result.setStyleSheet(
            "QPlainTextEdit { background: #0B1526; color: #DCE9FF; "
            "border: 1px solid #1E3A8A; border-radius: 10px; padding: 10px; }"
        )
        right.addWidget(self.attack_result, 1)

        body.addLayout(left, 3)
        body.addLayout(right, 2)
        card.body.addLayout(body, 1)
        return card

    def _fill_demo_pairs(self) -> None:
        self._demo_key = secrets.randbits(32)
        plans = [0x1234, 0xABCD, 0x0F0F]
        self._filling_pairs = True
        self.pair_table.setRowCount(0)
        for index, plaintext in enumerate(plans, start=1):
            ciphertext = double_encrypt_block(plaintext, self._demo_key)
            self._append_pair_row(plaintext, ciphertext)
        self._filling_pairs = False
        self._update_row_headers()
        self.attack_result.clear()
        self.attack_progress.setValue(0)
        set_status(
            self.attack_status,
            "已生成 3 组随机明密文，隐藏密钥将在攻击完成后自动核验。",
        )

    def _append_pair_row(self, plaintext: int, ciphertext: int) -> None:
        row = self.pair_table.rowCount()
        self.pair_table.insertRow(row)
        self.pair_table.setItem(row, 0, QTableWidgetItem(f"{plaintext:04X}"))
        self.pair_table.setItem(row, 1, QTableWidgetItem(f"{ciphertext:04X}"))
        for column in range(2):
            item = self.pair_table.item(row, column)
            item.setTextAlignment(Qt.AlignCenter)
            item.setFont(mono_font(10))
        self.pair_table.setRowHeight(row, 30)
        self._update_row_headers()

    def _add_pair_row(self) -> None:
        self._filling_pairs = True
        row = self.pair_table.rowCount()
        self.pair_table.insertRow(row)
        for column in range(2):
            item = QTableWidgetItem("")
            item.setTextAlignment(Qt.AlignCenter)
            item.setFont(mono_font(10))
            self.pair_table.setItem(row, column, item)
        self.pair_table.setRowHeight(row, 30)
        self._update_row_headers()
        self._filling_pairs = False
        self._demo_key = None
        set_status(self.attack_status, "已添加空行，请填写 4 位十六进制。")

    def _remove_pair_row(self) -> None:
        if self.pair_table.rowCount() == 0:
            return
        self.pair_table.removeRow(self.pair_table.rowCount() - 1)
        self._update_row_headers()
        self._demo_key = None

    def _update_row_headers(self) -> None:
        for row in range(self.pair_table.rowCount()):
            self.pair_table.setVerticalHeaderItem(row, QTableWidgetItem(str(row + 1)))

    def _pair_table_changed(self, _item: QTableWidgetItem) -> None:
        if not self._filling_pairs:
            self._demo_key = None

    def _collect_pairs(self) -> List[Tuple[int, int]]:
        pairs: List[Tuple[int, int]] = []
        for row in range(self.pair_table.rowCount()):
            p_item = self.pair_table.item(row, 0)
            c_item = self.pair_table.item(row, 1)
            p_text = p_item.text().strip() if p_item else ""
            c_text = c_item.text().strip() if c_item else ""
            if not p_text and not c_text:
                continue
            if not p_text or not c_text:
                raise InputError(f"第 {row + 1} 行只填写了一半，请补全明文和密文")
            plaintext = parse_bits(p_text, 16, f"第 {row + 1} 行明文")
            ciphertext = parse_bits(c_text, 16, f"第 {row + 1} 行密文")
            pairs.append((plaintext, ciphertext))
        if not pairs:
            raise InputError("请至少填写一组明密文对")
        return pairs

    def _start_attack(self) -> None:
        if self._worker and self._worker.isRunning():
            return
        try:
            pairs = self._collect_pairs()
        except InputError as exc:
            set_status(self.attack_status, str(exc), ok=False)
            return

        if len(pairs) < 3:
            set_status(
                self.attack_status,
                f"注意：当前只有 {len(pairs)} 组数据，候选密钥可能很多；建议至少 3 组。",
                ok=False,
            )
        else:
            set_status(self.attack_status, "攻击进行中…")
        self.attack_result.clear()
        self.attack_progress.setValue(0)
        self.attack_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self._worker = MitmWorker(pairs, self)
        self._worker.progress.connect(self._on_attack_progress)
        self._worker.completed.connect(self._on_attack_complete)
        self._worker.failed.connect(self._on_attack_failed)
        self._worker.start()

    def _stop_attack(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.requestInterruption()
            self.stop_button.setEnabled(False)
            set_status(self.attack_status, "正在停止攻击…")

    def _on_attack_progress(self, percent: int, message: str) -> None:
        self.attack_progress.setValue(percent)
        self.attack_status.setText(message)

    def _on_attack_complete(self, result: MitmResult) -> None:
        self.attack_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.attack_progress.setValue(100 if not result.cancelled else 0)
        if result.cancelled:
            set_status(self.attack_status, "攻击已停止。", ok=False)
            return

        lines = [
            f"耗时        : {result.elapsed_seconds:.2f} s",
            f"输入对数    : {result.pair_count}",
            f"中间值表项  : {result.table_entries:,}",
            f"候选密钥数  : {len(result.candidates)}",
            "",
        ]
        if result.pair_count < 3:
            lines.insert(
                0,
                f"提示：仅 {result.pair_count} 组明密文，候选密钥会非常多；"
                "建议至少 3 组。\n",
            )
        if result.candidates:
            for index, key in enumerate(result.candidates[:20], start=1):
                key1 = (key >> 16) & 0xFFFF
                key2 = key & 0xFFFF
                lines.append(
                    f"[{index:>2}] K={key:08X}   K1={key1:04X}   K2={key2:04X}"
                )
            if len(result.candidates) > 20:
                lines.append(f"… 其余 {len(result.candidates) - 20} 个候选未显示")
            lines.append("")
            if self._demo_key is not None:
                if self._demo_key in result.candidates:
                    lines.append(f"隐藏示例密钥 {self._demo_key:08X} 已在候选集中 ✓")
                else:
                    lines.append("未在候选集中找到隐藏示例密钥，请检查输入数据。")
        else:
            lines.append("未找到任何候选密钥。")

        self.attack_result.setPlainText("\n".join(lines))
        if result.candidates:
            set_status(
                self.attack_status,
                f"攻击完成，找到 {len(result.candidates)} 个候选密钥，用时 {result.elapsed_seconds:.2f} s。",
            )
        else:
            set_status(self.attack_status, "攻击完成，但未找到候选密钥。", ok=False)

    def _on_attack_failed(self, message: str) -> None:
        self.attack_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.attack_progress.setValue(0)
        set_status(self.attack_status, f"攻击出错：{message}", ok=False)

    def shutdown(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.requestInterruption()
            self._worker.wait(2500)

    def _copy_value(self, value: str, status_label: QLabel) -> None:
        if value in ("", "—"):
            set_status(status_label, "当前没有可复制的结果。", ok=False)
            return
        QApplication.clipboard().setText(value)
        set_status(status_label, "结果已复制到剪贴板。")


class CbcTab(QWidget):
    """第 5 关：CBC 工作模式与密文篡改演示。"""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._last_cipher: Optional[bytes] = None

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        param_card = Card(
            "CBC 参数",
            "IV 无需保密，但必须与密文一同共享；每次加密建议使用新的随机 IV。",
        )
        params = QHBoxLayout()
        params.setSpacing(10)
        params.addWidget(make_label("密钥 K", "sectionTitle"))
        self.key_edit = QLineEdit("2D55")
        self.key_edit.setFont(mono_font(11, True))
        self.key_edit.setFixedWidth(125)
        self.key_edit.setMaxLength(24)
        params.addWidget(self.key_edit)
        key_random = make_button("随机", small=True)
        key_random.clicked.connect(self._random_key)
        params.addWidget(key_random)

        params.addSpacing(12)
        params.addWidget(make_label("初始向量 IV", "sectionTitle"))
        self.iv_edit = QLineEdit(f"{secrets.randbits(16):04X}")
        self.iv_edit.setFont(mono_font(11, True))
        self.iv_edit.setFixedWidth(125)
        self.iv_edit.setMaxLength(24)
        params.addWidget(self.iv_edit)
        iv_random = make_button("生成 IV", small=True)
        iv_random.clicked.connect(self._random_iv)
        params.addWidget(iv_random)
        params.addStretch(1)
        params.addWidget(make_label("PKCS#7 填充 · 2 字节分组", "pill"))
        param_card.body.addLayout(params)
        root.addWidget(param_card)

        text_row = QHBoxLayout()
        text_row.setSpacing(12)
        plain_card = Card("明文 / 解密结果", "UTF-8 文本，分组后按 CBC 链接")
        self.plain_edit = QPlainTextEdit()
        self.plain_edit.setPlainText("信息安全导论 · S-AES CBC 工作模式演示。")
        self.plain_edit.setFont(QFont("Microsoft YaHei UI", 11))
        self.plain_edit.setMinimumHeight(100)
        plain_card.body.addWidget(self.plain_edit, 1)
        self.plain_info = make_label("", "hint")
        plain_card.body.addWidget(self.plain_info)
        plain_card.setMinimumHeight(190)
        plain_card.setMaximumHeight(205)

        cipher_card = Card("密文（十六进制）", "C_i = E_K(P_i ⊕ C_{i-1})")
        self.cipher_edit = QPlainTextEdit()
        self.cipher_edit.setFont(mono_font(9.6))
        self.cipher_edit.setPlaceholderText("CBC 加密后自动填入；也可粘贴密文解密")
        self.cipher_edit.setMinimumHeight(100)
        cipher_card.body.addWidget(self.cipher_edit, 1)
        self.cipher_info = make_label("等待加密…", "hint", wrap=True)
        cipher_card.body.addWidget(self.cipher_info)
        cipher_card.setMinimumHeight(190)
        cipher_card.setMaximumHeight(205)
        text_row.addWidget(plain_card, 1)
        text_row.addWidget(cipher_card, 1)
        root.addLayout(text_row, 0)

        action_row = QHBoxLayout()
        action_row.setSpacing(8)
        encrypt_button = make_button("CBC 加密", primary=True)
        encrypt_button.clicked.connect(self._encrypt)
        decrypt_button = make_button("CBC 解密", ghost=True)
        decrypt_button.clicked.connect(self._decrypt)
        clear_button = make_button("清空", ghost=True)
        clear_button.clicked.connect(self._clear)
        copy_button = make_button("复制 IV + 密文", small=True)
        copy_button.clicked.connect(self._copy_share)
        action_row.addWidget(encrypt_button)
        action_row.addWidget(decrypt_button)
        action_row.addWidget(clear_button)
        action_row.addStretch(1)
        action_row.addWidget(copy_button)
        root.addLayout(action_row)

        self.status_label = make_label("", wrap=True)
        root.addWidget(self.status_label)

        tamper_card = Card(
            "密文篡改实验",
            "修改一个密文分组后解密：被改分组对应的明文整体随机化；"
            "下一分组发生确定性比特变化；其余分组不受影响。",
            compact=True,
        )
        tamper_controls = QHBoxLayout()
        tamper_controls.setSpacing(7)
        tamper_controls.addWidget(make_label("分组", "sectionTitle"))
        self.tamper_block_combo = QComboBox()
        self.tamper_block_combo.setMinimumWidth(145)
        tamper_controls.addWidget(self.tamper_block_combo)
        tamper_controls.addWidget(make_label("操作", "sectionTitle"))
        self.tamper_mode_combo = QComboBox()
        self.tamper_mode_combo.addItem("翻转指定比特", "flip")
        self.tamper_mode_combo.addItem("整组替换为 0000", "replace")
        self.tamper_mode_combo.currentIndexChanged.connect(self._tamper_mode_changed)
        tamper_controls.addWidget(self.tamper_mode_combo)
        tamper_controls.addWidget(make_label("比特位", "sectionTitle"))
        self.tamper_bit_spin = QSpinBox()
        self.tamper_bit_spin.setRange(0, 15)
        self.tamper_bit_spin.setValue(5)
        self.tamper_bit_spin.setToolTip("bit 0 为最低位")
        tamper_controls.addWidget(self.tamper_bit_spin)
        tamper_button = make_button("执行篡改并解密", primary=True)
        tamper_button.clicked.connect(self._tamper)
        tamper_controls.addWidget(tamper_button)
        tamper_controls.addStretch(1)
        tamper_card.body.addLayout(tamper_controls)

        self.tamper_summary = QLabel("尚未执行篡改实验。")
        self.tamper_summary.setWordWrap(True)
        self.tamper_summary.setTextFormat(Qt.RichText)
        self.tamper_summary.setStyleSheet(
            "QLabel { background: #EFF6FF; border: 1px solid #BFDBFE; "
            "border-radius: 8px; padding: 7px 9px; color: #1E3A8A; "
            "font-size: 9pt; }"
        )
        tamper_card.body.addWidget(self.tamper_summary)

        self.tamper_output = QPlainTextEdit()
        self.tamper_output.setReadOnly(True)
        self.tamper_output.setFont(mono_font(9.3))
        self.tamper_output.setMinimumHeight(110)
        self.tamper_output.setStyleSheet(
            "QPlainTextEdit { background: #0B1526; color: #DCE9FF; "
            "border: 1px solid #1E3A8A; border-radius: 10px; padding: 10px; }"
        )
        tamper_card.body.addWidget(self.tamper_output, 1)
        root.addWidget(tamper_card, 1)

    def _read_key(self) -> int:
        return parse_bits(self.key_edit.text(), 16, "密钥 K")

    def _read_iv(self) -> int:
        return parse_bits(self.iv_edit.text(), 16, "初始向量 IV")

    def _random_key(self) -> None:
        self.key_edit.setText(f"{secrets.randbits(16):04X}")

    def _random_iv(self) -> None:
        self.iv_edit.setText(f"{secrets.randbits(16):04X}")

    def _encrypt(self) -> None:
        try:
            key = self._read_key()
            iv = self._read_iv()
            text = self.plain_edit.toPlainText()
            if not text:
                raise InputError("请输入要加密的明文")
            data = text.encode("utf-8")
            ciphertext = cbc_encrypt(data, key, iv)
        except (InputError, ValueError, TypeError) as exc:
            set_status(self.status_label, str(exc), ok=False)
            return

        self._last_cipher = ciphertext
        self.cipher_edit.setPlainText(format_hex_bytes(ciphertext))
        groups = len(ciphertext) // 2
        self.cipher_info.setText(
            f"{len(ciphertext)} 字节 · {groups} 个分组 · 填充 {len(ciphertext) - len(data)} 字节"
        )
        self.plain_info.setText(f"{len(text)} 字符 · {len(data)} 字节")
        self._populate_tamper_blocks(ciphertext)
        self.tamper_output.clear()
        self._reset_tamper_summary()
        set_status(
            self.status_label,
            f"CBC 加密完成：{len(data)} 字节 → {len(ciphertext)} 字节，共 {groups} 组。",
        )

    def _decrypt(self) -> None:
        try:
            key = self._read_key()
            iv = self._read_iv()
            ciphertext = parse_hex_bytes(self.cipher_edit.toPlainText(), "密文")
            data = cbc_decrypt(ciphertext, key, iv)
            text = decode_utf8(data)
        except UnicodeDecodeError:
            text = decode_utf8(data, errors="replace")
            set_status(
                self.status_label,
                "解密完成，但明文不是合法 UTF-8，已用替换字符显示。",
                ok=False,
            )
        except (InputError, ValueError, TypeError) as exc:
            set_status(
                self.status_label,
                f"{exc}（请检查密钥、IV、密文或填充是否完整。）",
                ok=False,
            )
            return
        else:
            set_status(self.status_label, "CBC 解密完成，PKCS#7 填充校验通过。")

        self._last_cipher = ciphertext
        self.plain_edit.setPlainText(text)
        self.plain_info.setText(f"{len(text)} 字符 · {len(data)} 字节")
        self.cipher_info.setText(
            f"{len(ciphertext)} 字节 · {len(ciphertext) // 2} 个分组"
        )
        self._populate_tamper_blocks(ciphertext)
        self.tamper_output.clear()
        self._reset_tamper_summary()

    def _clear(self) -> None:
        self.plain_edit.clear()
        self.cipher_edit.clear()
        self.cipher_info.setText("等待加密…")
        self.plain_info.setText("")
        self.tamper_block_combo.clear()
        self.tamper_output.clear()
        self._reset_tamper_summary()
        self._last_cipher = None
        set_status(self.status_label, "已清空。")

    def _copy_share(self) -> None:
        try:
            iv = self._read_iv()
            ciphertext = parse_hex_bytes(self.cipher_edit.toPlainText(), "密文")
        except (InputError, ValueError) as exc:
            set_status(self.status_label, str(exc), ok=False)
            return
        share_text = f"IV={iv:04X}\nC={format_hex_bytes(ciphertext)}"
        QApplication.clipboard().setText(share_text)
        set_status(self.status_label, "IV 与密文已复制，可发送给解密方。")

    def _populate_tamper_blocks(self, ciphertext: bytes) -> None:
        self.tamper_block_combo.clear()
        for index, block in enumerate(split_blocks(ciphertext)):
            self.tamper_block_combo.addItem(f"第 {index + 1} 组 · {block:04X}", index)
        if self.tamper_block_combo.count() > 1:
            self.tamper_block_combo.setCurrentIndex(1)

    def _reset_tamper_summary(self) -> None:
        self.tamper_summary.setText("尚未执行篡改实验。")

    def _tamper_mode_changed(self) -> None:
        self.tamper_bit_spin.setEnabled(
            self.tamper_mode_combo.currentData() == "flip"
        )

    def _tamper(self) -> None:
        try:
            key = self._read_key()
            iv = self._read_iv()
            ciphertext = parse_hex_bytes(self.cipher_edit.toPlainText(), "密文")
            if not ciphertext:
                raise InputError("当前没有密文，请先加密或粘贴密文")
            block_index = self.tamper_block_combo.currentData()
            if block_index is None:
                raise InputError("请选择要篡改的密文分组")
            mode = self.tamper_mode_combo.currentData()
            if mode == "flip":
                tampered = flip_ciphertext_bit(
                    ciphertext, int(block_index), self.tamper_bit_spin.value()
                )
                action_text = f"第 {block_index + 1} 组翻转 bit {self.tamper_bit_spin.value()}"
            else:
                blocks = split_blocks(ciphertext)
                blocks[int(block_index)] = 0
                tampered = b"".join(block.to_bytes(2, "big") for block in blocks)
                action_text = f"第 {block_index + 1} 组替换为 0000"

            original_raw = cbc_decrypt(ciphertext, key, iv, remove_padding=False)
            tampered_raw = cbc_decrypt(tampered, key, iv, remove_padding=False)
        except (InputError, ValueError, TypeError, IndexError) as exc:
            set_status(self.status_label, f"篡改实验失败：{exc}", ok=False)
            return

        try:
            original_text = decode_utf8(
                cbc_decrypt(ciphertext, key, iv, remove_padding=True)
            )
        except (ValueError, UnicodeDecodeError):
            original_text = decode_utf8(original_raw, errors="replace")

        tampered_text = decode_utf8(tampered_raw, errors="replace")
        original_blocks = split_blocks(original_raw)
        tampered_blocks = split_blocks(tampered_raw)

        lines = [
            f"操作：{action_text}",
            f"原始明文：{original_text}",
            f"篡改后明文（含填充）：{tampered_text}",
            "",
            f"密文共 {len(original_blocks)} 组；被篡改组："
            f"{original_blocks[block_index]:04X} → {tampered_blocks[block_index]:04X}",
            "",
            "仅列出发生变化的分组：",
            "分组   原始明文   篡改后明文   变化",
            "----   --------   ----------   --------------------------------",
        ]
        changed_rows = 0
        for index, (before, after) in enumerate(
            zip(original_blocks, tampered_blocks), start=1
        ):
            if before == after:
                continue
            changed_rows += 1
            positions = [
                bit for bit in range(16) if (before ^ after) & (1 << bit)
            ]
            if len(positions) == 1:
                change = f"bit {positions[0]} 翻转"
            else:
                change = f"{len(positions)} 个 bit 变化（整体随机化）"
            lines.append(
                f"{index:>2}     {before:04X}       {after:04X}         {change}"
            )
        if changed_rows == 0:
            lines.append("（没有分组发生变化）")
        else:
            unchanged = len(original_blocks) - changed_rows
            if unchanged:
                lines.append(f"其余 {unchanged} 组未变化。")

        lines.append("")
        lines.append("影响分析：")
        lines.append(
            f"• 第 {block_index + 1} 组明文由 D_K(篡改后的 C) 决定，整体随机变化。"
        )
        if block_index + 2 <= len(original_blocks):
            lines.append(
                f"• 第 {block_index + 2} 组明文因 C_{block_index + 1} 被直接异或，"
                "发生与篡改位置对应的确定性变化。"
            )
        else:
            lines.append("• 被篡改的是最后一组，没有后继分组受到影响。")
        lines.append("• 其余分组解密结果保持不变。")

        next_exists = block_index + 2 <= len(original_blocks)
        affected_blocks = 2 if next_exists else 1
        unchanged_blocks = max(0, len(original_blocks) - affected_blocks)
        summary_parts = [
            f"<b>影响：</b>第 {block_index + 1} 组明文整体随机化；"
        ]
        if next_exists:
            summary_parts.append(
                f"第 {block_index + 2} 组发生确定性 bit 变化；"
            )
        summary_parts.append(f"其余 {unchanged_blocks} 组保持不变。")
        summary_parts.append(
            "<br><b>对比：</b>"
            f"原始 “{html_escape(self._short_text(original_text), quote=False)}” → "
            f"篡改后 “{html_escape(self._short_text(tampered_text), quote=False)}”"
        )
        self.tamper_summary.setText("".join(summary_parts))

        self.tamper_output.setPlainText("\n".join(lines))
        self._last_cipher = ciphertext
        set_status(
            self.status_label,
            "篡改实验完成：请对比分组变化与后续分组是否受影响。",
        )

    @staticmethod
    def _short_text(text: str, limit: int = 38) -> str:
        flat = text.replace("\r", " ").replace("\n", " ")
        return flat if len(flat) <= limit else flat[:limit] + "…"


class SelfTestTab(QWidget):
    """第 2 关：标准参数、测试向量、自检和交叉测试文件导出。"""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        top = QHBoxLayout()
        top.setSpacing(12)

        param_card = Card("算法标准参数", "与附录 D 的简化 AES 完全一致")
        param_text = QLabel(
            "<b>分组长度</b> 16 bit（2 Byte）&nbsp;&nbsp;&nbsp; "
            "<b>密钥长度</b> 16 bit（2 Byte）&nbsp;&nbsp;&nbsp; <b>轮数</b> 2<br>"
            "<b>有限域</b> GF(2<sup>4</sup>)，模多项式 x<sup>4</sup> + x + 1（0x13）<br>"
            "<b>状态布局</b> 列优先 [s00 s01; s10 s11] → 输入半字节 [n0 n1 n2 n3]<br>"
            "<b>S 盒</b> 9 4 A B / D 1 8 5 / 6 2 0 3 / C E F 7<br>"
            "<b>列混淆</b> [[1,4],[4,1]]；<b>逆矩阵</b> [[9,2],[2,9]]"
        )
        param_text.setTextFormat(Qt.RichText)
        param_text.setWordWrap(True)
        param_text.setStyleSheet("color: #334155; line-height: 150%;")
        param_card.body.addWidget(param_text)
        param_card.body.addStretch(1)

        vector_card = Card("标准测试向量", "用于异构实现之间的交叉验证")
        self.vector_table = QTableWidget(4, 3)
        self.vector_table.setHorizontalHeaderLabels(["项目", "输入", "标准输出"])
        self.vector_table.verticalHeader().setVisible(False)
        self.vector_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        self.vector_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.vector_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.vector_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.vector_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.vector_table.setMinimumHeight(158)
        rows = [
            ("基本加密", "K=2D55, P=6BA3", "C=3C3B"),
            ("基本解密", "K=2D55, C=3C3B", "P=6BA3"),
            ("密钥扩展", "K=2D55", "w=2D 55 BC E9 A3 4A"),
            ("列混淆", "状态 6C40", "3743"),
        ]
        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setTextAlignment(Qt.AlignCenter)
                self.vector_table.setItem(row, column, item)
            self.vector_table.setRowHeight(row, 31)
        vector_card.body.addWidget(self.vector_table)

        top.addWidget(param_card, 3)
        top.addWidget(vector_card, 4)
        root.addLayout(top)

        action_row = QHBoxLayout()
        action_row.setSpacing(8)
        run_button = make_button("运行全部自检", primary=True)
        run_button.clicked.connect(self._run_self_test)
        export_button = make_button("导出交叉测试向量", ghost=True)
        export_button.clicked.connect(self._export_vectors)
        action_row.addWidget(run_button)
        action_row.addWidget(export_button)
        action_row.addStretch(1)
        root.addLayout(action_row)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(mono_font(9.7))
        self.log_view.setStyleSheet(
            "QPlainTextEdit { background: #0B1526; color: #DCE9FF; "
            "border: 1px solid #1E3A8A; border-radius: 10px; padding: 12px; }"
        )
        root.addWidget(self.log_view, 1)

        self.status_label = make_label("", wrap=True)
        root.addWidget(self.status_label)
        self._run_self_test(initial=True)

    def _run_self_test(self, initial: bool = False) -> None:
        started = time.perf_counter()
        results: List[Tuple[str, bool, str]] = []

        def check(name: str, condition: bool, detail: str = "") -> None:
            results.append((name, bool(condition), detail))

        key = 0x2D55
        schedule = expand_key(key)
        check(
            "密钥扩展 w0..w5",
            schedule.words == (0x2D, 0x55, 0xBC, 0xE9, 0xA3, 0x4A),
            f"w={['%02X' % word for word in schedule.words]}",
        )
        check(
            "轮密钥 K0/K1/K2",
            schedule.round_keys == (0x2D55, 0xBCE9, 0xA34A),
            "/".join(f"{value:04X}" for value in schedule.round_keys),
        )
        ciphertext = encrypt_block(0x6BA3, key)
        check("标准向量加密", ciphertext == 0x3C3B, f"C={ciphertext:04X}")
        check("标准向量解密", decrypt_block(0x3C3B, key) == 0x6BA3)
        check(
            "列混淆示例",
            mix_columns_block(0x6C40) == 0x3743,
            f"6C40→{mix_columns_block(0x6C40):04X}",
        )
        check("S 盒 S(A)=0", S_BOX[0xA] == 0, f"S(A)={S_BOX[0xA]:X}")
        check(
            "逆 S 盒完整性",
            all(S_BOX[INV_S_BOX[value]] == value for value in range(16)),
            "16/16",
        )

        roundtrip_ok = True
        for _ in range(120):
            random_key = secrets.randbits(16)
            random_block = secrets.randbits(16)
            if decrypt_block(encrypt_block(random_block, random_key), random_key) != random_block:
                roundtrip_ok = False
                break
        check("120 组随机分组往返", roundtrip_ok)

        key32 = 0x1A2B3C4D
        double_ok = double_decrypt_block(double_encrypt_block(0x1234, key32), key32) == 0x1234
        check("双重加密往返", double_ok)
        key48 = 0x1A2B3C4D5E6F
        triple_ok = (
            triple_decrypt_block(triple_encrypt_block(0x1234, key48, 48), key48, 48)
            == 0x1234
        )
        check("三重加密 EEE 往返", triple_ok)

        message = b"0123456789"
        iv = 0x1234
        cbc_cipher = cbc_encrypt(message, key, iv)
        check("CBC 往返", cbc_decrypt(cbc_cipher, key, iv) == message)
        tampered = flip_ciphertext_bit(cbc_cipher, 1, 3)
        original_raw = cbc_decrypt(cbc_cipher, key, iv, remove_padding=False)
        tampered_raw = cbc_decrypt(tampered, key, iv, remove_padding=False)
        tamper_ok = (
            original_raw[:2] == tampered_raw[:2]
            and original_raw[2:4] != tampered_raw[2:4]
            and (original_raw[5] ^ tampered_raw[5]) == (1 << 3)
            and original_raw[6:] == tampered_raw[6:]
        )
        check("CBC 篡改影响范围", tamper_ok)

        elapsed = time.perf_counter() - started
        passed = sum(1 for _, ok, _ in results if ok)
        lines = [
            "S-AES 自检报告",
            f"时间      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"运行环境  : Python {sys.version.split()[0]} · PyQt5",
            f"标准      : 附录 D 简化 AES（16 bit 分组 / 16 bit 密钥 / 2 轮）",
            "-" * 62,
        ]
        for index, (name, ok, detail) in enumerate(results, start=1):
            mark = "PASS" if ok else "FAIL"
            suffix = f"  ({detail})" if detail else ""
            lines.append(f"[{mark}] {index:>2}. {name}{suffix}")
        lines.extend(
            [
                "-" * 62,
                f"结果      : {passed}/{len(results)} 项通过，用时 {elapsed:.3f} s",
                "状态      : " + ("全部通过 ✓" if passed == len(results) else "存在失败项 ✗"),
            ]
        )
        self.log_view.setPlainText("\n".join(lines))
        if passed == len(results):
            set_status(
                self.status_label,
                f"自检全部通过（{passed}/{len(results)}）。"
                + ("" if initial else " 可导出 JSON 与同组同学交叉验证。"),
            )
        else:
            set_status(
                self.status_label,
                f"自检存在失败项：{passed}/{len(results)}。",
                ok=False,
            )

    def _export_vectors(self) -> None:
        default_path = Path.home() / "s_aes_cross_test_vectors.json"
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "导出交叉测试向量",
            str(default_path),
            "JSON 文件 (*.json);;所有文件 (*)",
        )
        if not file_name:
            return
        payload = {
            "name": "S-AES cross-test vectors",
            "standard": "Stallings, Cryptography and Network Security 8e, Appendix D",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "parameters": {
                "block_bits": 16,
                "key_bits": 16,
                "rounds": 2,
                "gf_polynomial": "x^4 + x + 1 (0x13)",
                "state_layout": "column-major: [s00 s01; s10 s11] = nibbles [n0 n1 n2 n3]",
            },
            "sbox": [f"{value:X}" for value in S_BOX],
            "inverse_sbox": [f"{value:X}" for value in INV_S_BOX],
            "key_expansion": {
                "key": "2D55",
                "words": ["2D", "55", "BC", "E9", "A3", "4A"],
                "round_keys": ["2D55", "BCE9", "A34A"],
            },
            "test_vectors": [
                {
                    "operation": "encrypt",
                    "key": "2D55",
                    "plaintext": "6BA3",
                    "ciphertext": "3C3B",
                },
                {
                    "operation": "decrypt",
                    "key": "2D55",
                    "ciphertext": "3C3B",
                    "plaintext": "6BA3",
                },
                {
                    "operation": "mix_columns",
                    "input_state": "6C40",
                    "output_state": "3743",
                },
            ],
            "notes": [
                "All values are hexadecimal.",
                "Use PKCS#7 padding with 2-byte blocks for byte strings.",
                "Double encryption: C = E_K2(E_K1(P)), K = K1 || K2.",
                "CBC: C_i = E_K(P_i XOR C_{i-1}), C_0 = IV.",
            ],
        }
        try:
            Path(file_name).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            set_status(self.status_label, f"导出失败：{exc}", ok=False)
            return
        set_status(self.status_label, f"交叉测试向量已导出到：{file_name}")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(self._create_icon())
        self.resize(1220, 850)
        self.setMinimumSize(1060, 720)

        root = QWidget()
        root.setObjectName("root")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(18, 15, 18, 12)
        layout.setSpacing(12)

        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(82)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(22, 12, 22, 12)
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        text_layout.addWidget(make_label(APP_NAME, "appTitle"))
        text_layout.addWidget(
            make_label(
                "16-bit 分组 · 16-bit 密钥 · 2 轮 · 附录 D 简化 AES",
                "appSubtitle",
            )
        )
        header_layout.addLayout(text_layout)
        header_layout.addStretch(1)
        header_layout.addWidget(make_label("标准实现 · 教学演示", "headerBadge"))
        layout.addWidget(header)

        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)
        self.tab_widget.setUsesScrollButtons(False)
        self.basic_tab = BasicTab()
        self.ascii_tab = AsciiTab()
        self.multi_tab = MultiTab()
        self.cbc_tab = CbcTab()
        self.self_test_tab = SelfTestTab()
        self.tab_widget.addTab(self.basic_tab, "01  基本测试")
        self.tab_widget.addTab(self.ascii_tab, "02  ASCII 扩展")
        self.tab_widget.addTab(self.multi_tab, "03  多重加密")
        self.tab_widget.addTab(self.cbc_tab, "04  CBC 模式")
        self.tab_widget.addTab(self.self_test_tab, "05  交叉测试")
        layout.addWidget(self.tab_widget, 1)

        self.setCentralWidget(root)
        self.statusBar().showMessage(
            "就绪 · 算法约定：附录 D 简化 AES · 输入支持十六进制/二进制"
        )

    @staticmethod
    def _create_icon() -> QIcon:
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#1D4ED8"))
        painter.drawRoundedRect(4, 4, 56, 56, 14, 14)
        painter.setPen(QColor("#FFFFFF"))
        font = QFont("Segoe UI", 24, QFont.Bold)
        painter.setFont(font)
        painter.drawText(pixmap.rect(), Qt.AlignCenter, "SA")
        painter.end()
        return QIcon(pixmap)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt 接口
        self.multi_tab.shutdown()
        super().closeEvent(event)
