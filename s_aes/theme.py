"""应用界面样式。"""

APP_STYLE = """
QWidget {
    color: #0F172A;
    font-family: "Microsoft YaHei UI", "Segoe UI", "PingFang SC", sans-serif;
    font-size: 10pt;
}
QMainWindow, #root {
    background: #F3F6FC;
}
#header {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                stop:0 #0F2A5C, stop:0.55 #1D4ED8, stop:1 #0E7490);
    border-radius: 16px;
}
#appTitle {
    color: #FFFFFF;
    font-size: 23pt;
    font-weight: 700;
}
#appSubtitle {
    color: #DCE9FF;
    font-size: 9.5pt;
}
#headerBadge {
    color: #FFFFFF;
    background: rgba(255, 255, 255, 0.14);
    border: 1px solid rgba(255, 255, 255, 0.28);
    border-radius: 12px;
    padding: 5px 12px;
    font-size: 9pt;
    font-weight: 600;
}
#card {
    background: #FFFFFF;
    border: 1px solid #E1E8F3;
    border-radius: 12px;
}
#cardTitle {
    font-size: 11pt;
    font-weight: 700;
    color: #0F172A;
}
#cardSubtitle {
    color: #64748B;
    font-size: 9pt;
}
#sectionTitle {
    color: #1E3A8A;
    font-size: 10pt;
    font-weight: 700;
}
#hint {
    color: #64748B;
    font-size: 9pt;
}
#errorLabel {
    color: #DC2626;
    font-size: 9pt;
}
#okLabel {
    color: #047857;
    font-size: 9pt;
}
#resultValue {
    color: #1D4ED8;
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 25pt;
    font-weight: 700;
}
#resultBinary {
    color: #475569;
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 10pt;
}
#formula {
    color: #475569;
    background: #F8FAFC;
    border: 1px dashed #CBD5E1;
    border-radius: 8px;
    padding: 6px 9px;
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 9pt;
}
#pill {
    color: #1D4ED8;
    background: #EFF6FF;
    border: 1px solid #BFDBFE;
    border-radius: 10px;
    padding: 2px 8px;
    font-size: 8.5pt;
}
#pillSuccess {
    color: #047857;
    background: #ECFDF5;
    border: 1px solid #A7F3D0;
    border-radius: 10px;
    padding: 2px 8px;
    font-size: 8.5pt;
}
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox {
    background: #FFFFFF;
    border: 1px solid #CBD5E1;
    border-radius: 8px;
    padding: 6px 9px;
    selection-background-color: #BFDBFE;
    selection-color: #0F172A;
}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus,
QComboBox:focus, QSpinBox:focus {
    border: 1px solid #2563EB;
}
QLineEdit:disabled, QPlainTextEdit:disabled {
    background: #F1F5F9;
    color: #94A3B8;
}
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QComboBox QAbstractItemView {
    background: #FFFFFF;
    border: 1px solid #CBD5E1;
    selection-background-color: #EFF6FF;
    selection-color: #1D4ED8;
    padding: 3px;
}
QPushButton {
    background: #E8EEF9;
    color: #1E3A8A;
    border: 1px solid #D7E2F3;
    border-radius: 8px;
    padding: 7px 15px;
    font-weight: 600;
}
QPushButton:hover {
    background: #DCE7F8;
    border-color: #BFD3EF;
}
QPushButton:pressed {
    background: #CBDDF5;
}
QPushButton:disabled {
    background: #F1F5F9;
    color: #94A3B8;
    border-color: #E2E8F0;
}
QPushButton#primary {
    background: #2563EB;
    color: #FFFFFF;
    border: 1px solid #2563EB;
}
QPushButton#primary:hover {
    background: #1D4ED8;
    border-color: #1D4ED8;
}
QPushButton#primary:pressed {
    background: #1E40AF;
}
QPushButton#ghost {
    background: transparent;
    border: 1px solid #CBD5E1;
    color: #334155;
}
QPushButton#ghost:hover {
    background: #F8FAFC;
}
QPushButton#small {
    padding: 4px 9px;
    font-size: 9pt;
}
QTabWidget::pane {
    border: none;
    background: transparent;
    top: -1px;
}
QTabBar::tab {
    background: transparent;
    color: #64748B;
    padding: 9px 15px;
    margin-right: 3px;
    border-radius: 9px;
    font-weight: 600;
}
QTabBar::tab:hover {
    background: #E8EEF9;
    color: #1E3A8A;
}
QTabBar::tab:selected {
    background: #FFFFFF;
    color: #1D4ED8;
    border: 1px solid #D7E5FB;
}
QTableWidget {
    background: #FFFFFF;
    border: 1px solid #E1E8F3;
    border-radius: 8px;
    gridline-color: #EEF2F7;
    selection-background-color: #EFF6FF;
    selection-color: #1D4ED8;
}
QHeaderView::section {
    background: #F8FAFC;
    color: #475569;
    border: none;
    border-bottom: 1px solid #E2E8F0;
    padding: 7px;
    font-weight: 600;
}
QTableCornerButton::section {
    background: #F8FAFC;
    border: none;
}
QProgressBar {
    background: #E8EEF9;
    border: none;
    border-radius: 5px;
    height: 10px;
    text-align: center;
    color: transparent;
}
QProgressBar::chunk {
    background: #2563EB;
    border-radius: 5px;
}
QScrollArea {
    border: none;
    background: transparent;
}
QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 2px;
}
QScrollBar::handle:vertical {
    background: #CBD5E1;
    border-radius: 5px;
    min-height: 28px;
}
QScrollBar::handle:vertical:hover {
    background: #94A3B8;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    background: transparent;
    height: 10px;
    margin: 2px;
}
QScrollBar::handle:horizontal {
    background: #CBD5E1;
    border-radius: 5px;
    min-width: 28px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
QStatusBar {
    background: transparent;
    color: #64748B;
}
QToolTip {
    background: #0F172A;
    color: #FFFFFF;
    border: none;
    padding: 5px 8px;
}
"""
