"""Dark theme + programmatic icons for the Svoboda shell.

No image assets ship with the repo, so the tray/window icon is drawn at runtime
with QPainter. Icon colour encodes engine state at a glance (green=active,
amber=searching, grey=stopped, red=error).
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap, QBrush, QPen, QFont

from brain.status_writer import (
    STATE_ACTIVE, STATE_SEARCHING, STATE_STARTING, STATE_STOPPED, STATE_ERROR,
)

# ─── Palette ────────────────────────────────────────────────────────────────
BG        = "#14151a"
PANEL     = "#20222b"
PANEL_2   = "#262934"
BORDER    = "#333747"
TEXT      = "#e6e8ef"
MUTED     = "#8b8fa3"
ACCENT    = "#4f8cff"

STATE_COLORS = {
    STATE_ACTIVE:   "#3ad29f",   # green
    STATE_SEARCHING:"#ffb454",   # amber
    STATE_STARTING: "#ffb454",
    STATE_STOPPED:  "#6b7080",   # grey
    STATE_ERROR:    "#ff5c6c",   # red
}

STATE_LABELS_RU = {
    STATE_ACTIVE:   "Защита включена",
    STATE_SEARCHING:"Подбираю стратегию…",
    STATE_STARTING: "Запуск…",
    STATE_STOPPED:  "Выключено",
    STATE_ERROR:    "Ошибка",
}
STATE_LABELS_EN = {
    STATE_ACTIVE:   "Protected",
    STATE_SEARCHING:"Finding strategy…",
    STATE_STARTING: "Starting…",
    STATE_STOPPED:  "Off",
    STATE_ERROR:    "Error",
}


def state_color(state: str) -> QColor:
    return QColor(STATE_COLORS.get(state, STATE_COLORS[STATE_STOPPED]))


def state_label(state: str, lang: str = "ru") -> str:
    table = STATE_LABELS_EN if lang == "en" else STATE_LABELS_RU
    return table.get(state, table[STATE_STOPPED])


def make_icon(state: str = STATE_STOPPED, size: int = 64) -> QIcon:
    """Draw a rounded shield-dot icon tinted by engine state."""
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    color = state_color(state)

    # outer disc
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(QColor(BG)))
    p.drawEllipse(2, 2, size - 4, size - 4)
    # state ring
    pen = QPen(color)
    pen.setWidth(max(3, size // 14))
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    p.drawEllipse(6, 6, size - 12, size - 12)
    # centre "S"
    p.setPen(QPen(color))
    f = QFont("Segoe UI", int(size * 0.42), QFont.Bold)
    p.setFont(f)
    p.drawText(QRectF(0, 0, size, size), Qt.AlignCenter, "S")
    p.end()
    return QIcon(pm)


def status_dot(state: str, diameter: int = 14) -> QPixmap:
    """Small filled dot for inline status display."""
    pm = QPixmap(diameter, diameter)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(state_color(state)))
    p.drawEllipse(1, 1, diameter - 2, diameter - 2)
    p.end()
    return pm


QSS = f"""
* {{
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
    color: {TEXT};
}}
QWidget#root, QMainWindow {{ background: {BG}; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 10px; background: {PANEL}; top: -1px; }}
QTabBar::tab {{
    background: transparent; color: {MUTED};
    padding: 8px 18px; margin-right: 4px; border-radius: 8px;
}}
QTabBar::tab:selected {{ background: {PANEL_2}; color: {TEXT}; }}
QTabBar::tab:hover {{ color: {TEXT}; }}

QFrame#card {{ background: {PANEL_2}; border: 1px solid {BORDER}; border-radius: 12px; }}
QLabel#h1 {{ font-size: 22px; font-weight: 700; }}
QLabel#muted {{ color: {MUTED}; }}
QLabel#statusBig {{ font-size: 26px; font-weight: 700; }}

QPushButton {{
    background: {PANEL_2}; border: 1px solid {BORDER};
    border-radius: 9px; padding: 9px 16px;
}}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:disabled {{ color: {MUTED}; }}

QPushButton#power {{
    background: {ACCENT}; border: none; color: white;
    border-radius: 28px; font-size: 16px; font-weight: 700;
}}
QPushButton#power:hover {{ background: #5f97ff; }}
QPushButton#powerOn {{ background: #ff5c6c; }}
QPushButton#powerOn:hover {{ background: #ff6f7d; }}

QPlainTextEdit, QTextEdit, QLineEdit {{
    background: {BG}; border: 1px solid {BORDER}; border-radius: 8px;
    padding: 6px; selection-background-color: {ACCENT};
}}
QCheckBox {{ spacing: 8px; }}
QComboBox {{ background: {PANEL_2}; border: 1px solid {BORDER}; border-radius: 8px; padding: 6px 10px; }}
QComboBox QAbstractItemView {{ background: {PANEL_2}; border: 1px solid {BORDER}; selection-background-color: {ACCENT}; }}
QScrollBar:vertical {{ background: transparent; width: 10px; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 5px; min-height: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
"""
