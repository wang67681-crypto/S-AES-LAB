"""S-AES 算法实验平台入口。

运行：
    python main.py

算法约定见 s_aes/core.py 与 README.md。
"""

from __future__ import annotations

import sys

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication

from s_aes.gui import MainWindow
from s_aes.theme import APP_STYLE


def main() -> int:
    # 高 DPI 支持必须在创建 QApplication 之前设置。
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("S-AES 算法实验平台")
    app.setOrganizationName("Information Security Course")
    app.setStyle("Fusion")
    app.setFont(QFont("Microsoft YaHei UI", 10))
    app.setStyleSheet(APP_STYLE)

    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
