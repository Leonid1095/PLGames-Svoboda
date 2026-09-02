"""MainWindow — the Svoboda desktop shell.

Tabs: Status (power button + live state + log), Domains (hostlist / exclude
editors), Settings (toggles, language, donate), About. Plus a system-tray icon
whose colour tracks engine state. Closing the window hides to tray; Quit stops
the engine and cleans up.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QDesktopServices
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTabWidget, QPlainTextEdit, QFrame, QCheckBox, QComboBox,
    QSystemTrayIcon, QMenu, QMessageBox, QGridLayout, QSizePolicy,
)

from brain.status_writer import (
    STATE_ACTIVE, STATE_STOPPED, STATE_STARTING, STATE_SEARCHING,
)
from gui import theme
from gui.engine_bridge import EngineBridge

APP_NAME = "PLGames Svoboda"
DONATE_URL = "https://api.svaboda-shwe.online/donate"
SITE_URL = "https://github.com/"  # landing / repo

# Minimal i18n: key -> (ru, en)
STR = {
    "tab_status": ("Статус", "Status"),
    "tab_domains": ("Домены", "Domains"),
    "tab_settings": ("Настройки", "Settings"),
    "tab_about": ("О программе", "About"),
    "power_on": ("Включить защиту", "Turn on"),
    "power_off": ("Выключить", "Turn off"),
    "tagline": ("Одна кнопка — приложение само найдёт рабочую стратегию",
                "One button — the app finds a working strategy by itself"),
    "isp": ("Провайдер", "ISP"),
    "strategy": ("Стратегия", "Strategy"),
    "sites": ("Сайты", "Sites"),
    "log": ("Журнал", "Log"),
    "hostlist": ("Список доменов для обхода (hostlist.txt)",
                 "Domains to bypass (hostlist.txt)"),
    "exclude": ("Исключения — НИКОГДА не трогать (list-exclude.txt)",
                "Exclusions — NEVER touch (list-exclude.txt)"),
    "save": ("Сохранить", "Save"),
    "reload": ("Перечитать", "Reload"),
    "streamer": ("Режим стримера (меньше нагрузка для OBS)",
                 "Streamer mode (lower overhead for OBS)"),
    "autostart": ("Запускать при входе в Windows (с правами админа)",
                  "Start with Windows (as admin)"),
    "minimized": ("Запускаться свёрнутым в трей", "Start minimized to tray"),
    "language": ("Язык", "Language"),
    "donate": ("Поддержать проект", "Support the project"),
    "saved": ("Сохранено", "Saved"),
    "quit_confirm": ("Выключить защиту и выйти?", "Turn off protection and quit?"),
    "stopping": ("Останавливаю…", "Stopping…"),
    "running_note": ("Защита работает в фоне. Закрытие окна свернёт его в трей.",
                     "Protection runs in background. Closing hides to tray."),
}


class MainWindow(QMainWindow):
    def __init__(self, root_dir: str):
        super().__init__()
        self.root = root_dir
        self.config_path = os.path.join(root_dir, "config.json")
        self.config = self._load_config()
        self.lang = self.config.get("gui_language", "ru")
        self._quitting = False

        self.bridge = EngineBridge(root_dir, self)
        self.bridge.log_line.connect(self._on_log)
        self.bridge.stopped.connect(self._on_engine_stopped)

        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(720, 560)
        self.setWindowIcon(theme.make_icon(STATE_STOPPED))

        self._build_ui()
        self._build_tray()
        self.setStyleSheet(theme.QSS)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(1000)
        self._refresh()

    # ─── i18n ───────────────────────────────────────────────────────────
    def t(self, key: str) -> str:
        ru, en = STR.get(key, (key, key))
        return en if self.lang == "en" else ru

    # ─── UI build ───────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        root = QWidget(objectName="root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(16, 16, 16, 16)

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs)
        self.tabs.addTab(self._tab_status(), self.t("tab_status"))
        self.tabs.addTab(self._tab_domains(), self.t("tab_domains"))
        self.tabs.addTab(self._tab_settings(), self.t("tab_settings"))
        self.tabs.addTab(self._tab_about(), self.t("tab_about"))

    def _card(self) -> QFrame:
        f = QFrame(objectName="card")
        return f

    def _tab_status(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(14)

        # Header card with power button + state
        card = self._card()
        cl = QGridLayout(card)
        cl.setContentsMargins(20, 20, 20, 20)
        cl.setHorizontalSpacing(20)

        self.power_btn = QPushButton(self.t("power_on"), objectName="power")
        self.power_btn.setFixedSize(150, 56)
        self.power_btn.clicked.connect(self._toggle_power)
        cl.addWidget(self.power_btn, 0, 0, 2, 1)

        self.state_lbl = QLabel("—", objectName="statusBig")
        cl.addWidget(self.state_lbl, 0, 1)
        self.tag_lbl = QLabel(self.t("tagline"), objectName="muted")
        self.tag_lbl.setWordWrap(True)
        cl.addWidget(self.tag_lbl, 1, 1)
        cl.setColumnStretch(1, 1)
        lay.addWidget(card)

        # Detail grid
        info = self._card()
        ig = QGridLayout(info)
        ig.setContentsMargins(20, 16, 20, 16)
        ig.setVerticalSpacing(10)
        self.isp_val = QLabel("—")
        self.strat_val = QLabel("—")
        self.strat_val.setWordWrap(True)
        self.sites_val = QLabel("—")
        rows = [("isp", self.isp_val), ("strategy", self.strat_val), ("sites", self.sites_val)]
        for i, (key, val) in enumerate(rows):
            k = QLabel(self.t(key), objectName="muted")
            k.setMinimumWidth(110)
            ig.addWidget(k, i, 0, Qt.AlignTop)
            ig.addWidget(val, i, 1)
        ig.setColumnStretch(1, 1)
        lay.addWidget(info)

        # Live log
        loglbl = QLabel(self.t("log"), objectName="muted")
        lay.addWidget(loglbl)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(500)
        self.log_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        lay.addWidget(self.log_view, 1)
        return w

    def _tab_domains(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)

        lay.addWidget(QLabel(self.t("hostlist"), objectName="muted"))
        self.host_edit = QPlainTextEdit()
        lay.addWidget(self.host_edit, 1)

        lay.addWidget(QLabel(self.t("exclude"), objectName="muted"))
        self.excl_edit = QPlainTextEdit()
        lay.addWidget(self.excl_edit, 1)

        row = QHBoxLayout()
        row.addStretch(1)
        reload_btn = QPushButton(self.t("reload"))
        reload_btn.clicked.connect(self._load_domain_files)
        save_btn = QPushButton(self.t("save"))
        save_btn.clicked.connect(self._save_domain_files)
        row.addWidget(reload_btn)
        row.addWidget(save_btn)
        lay.addLayout(row)

        self._load_domain_files()
        return w

    def _tab_settings(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(14)
        lay.setContentsMargins(6, 6, 6, 6)

        self.cb_streamer = QCheckBox(self.t("streamer"))
        self.cb_streamer.setChecked(bool(self.config.get("streamer_mode")))
        self.cb_streamer.toggled.connect(lambda v: self._set_cfg("streamer_mode", v))
        lay.addWidget(self.cb_streamer)

        self.cb_autostart = QCheckBox(self.t("autostart"))
        self.cb_autostart.setChecked(bool(self.config.get("gui_autostart")))
        self.cb_autostart.toggled.connect(self._toggle_autostart)
        lay.addWidget(self.cb_autostart)

        self.cb_min = QCheckBox(self.t("minimized"))
        self.cb_min.setChecked(bool(self.config.get("gui_start_minimized")))
        self.cb_min.toggled.connect(lambda v: self._set_cfg("gui_start_minimized", v))
        lay.addWidget(self.cb_min)

        lang_row = QHBoxLayout()
        lang_row.addWidget(QLabel(self.t("language"), objectName="muted"))
        self.lang_combo = QComboBox()
        self.lang_combo.addItem("Русский", "ru")
        self.lang_combo.addItem("English", "en")
        self.lang_combo.setCurrentIndex(0 if self.lang == "ru" else 1)
        self.lang_combo.currentIndexChanged.connect(self._change_language)
        lang_row.addWidget(self.lang_combo)
        lang_row.addStretch(1)
        lay.addLayout(lang_row)

        lay.addStretch(1)
        donate = QPushButton("❤  " + self.t("donate"))
        donate.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(DONATE_URL)))
        lay.addWidget(donate)
        return w

    def _tab_about(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(10)
        title = QLabel(APP_NAME, objectName="h1")
        lay.addWidget(title)
        desc = QLabel(
            "Умный обход DPI/ТСПУ. В отличие от инструментов с готовыми пресетами, "
            "Svoboda сама подбирает рабочую стратегию (GA + AI) и чинит обход, "
            "когда провайдер меняет правила."
            if self.lang == "ru" else
            "Smart DPI/TSPU bypass. Unlike preset-based tools, Svoboda finds a "
            "working strategy by itself (GA + AI) and self-heals when the ISP "
            "changes the rules."
        )
        desc.setWordWrap(True)
        desc.setObjectName("muted")
        lay.addWidget(desc)
        link = QPushButton("GitHub / " + ("Сайт" if self.lang == "ru" else "Website"))
        link.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(SITE_URL)))
        lay.addWidget(link)
        lay.addStretch(1)
        return w

    # ─── tray ───────────────────────────────────────────────────────────
    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(theme.make_icon(STATE_STOPPED), self)
        self.tray.setToolTip(APP_NAME)
        menu = QMenu()
        self.act_toggle = QAction(self.t("power_on"), self)
        self.act_toggle.triggered.connect(self._toggle_power)
        act_show = QAction("Открыть" if self.lang == "ru" else "Open", self)
        act_show.triggered.connect(self._show_window)
        act_quit = QAction("Выход" if self.lang == "ru" else "Quit", self)
        act_quit.triggered.connect(self._quit)
        menu.addAction(self.act_toggle)
        menu.addAction(act_show)
        menu.addSeparator()
        menu.addAction(act_quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_activated)
        self.tray.show()

    def _tray_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.DoubleClick:
            self._show_window()

    def _show_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    # ─── actions ────────────────────────────────────────────────────────
    def _toggle_power(self) -> None:
        if self.bridge.is_stopping():
            return
        if self.bridge.is_running():
            # Stop takes a few seconds (graceful request -> cleanup); keep the
            # UI responsive and the button locked until the bridge reports back.
            self.power_btn.setEnabled(False)
            self.act_toggle.setEnabled(False)
            self.bridge.stop_async()
        else:
            self.log_view.clear()
            self.bridge.start(streamer=bool(self.config.get("streamer_mode")))
        self._refresh()

    def _on_engine_stopped(self) -> None:
        self.power_btn.setEnabled(True)
        self.act_toggle.setEnabled(True)
        self._refresh()

    def _on_log(self, line: str) -> None:
        self.log_view.appendPlainText(line)

    def _refresh(self) -> None:
        st = self.bridge.status()
        state = st.get("state", STATE_STOPPED)
        running = self.bridge.is_running()

        self.state_lbl.setText(theme.state_label(state, self.lang))
        self.state_lbl.setStyleSheet(f"color: {theme.state_color(state).name()};")
        self.isp_val.setText(st.get("isp") or "—")
        self.strat_val.setText(st.get("strategy") or "—")
        sites = st.get("sites") or "—"
        fit = st.get("fitness")
        self.sites_val.setText(f"{sites}" + (f"   (fitness {fit})" if fit else ""))

        icon = theme.make_icon(state)
        self.tray.setIcon(icon)
        self.setWindowIcon(icon)
        self.tray.setToolTip(f"{APP_NAME} — {theme.state_label(state, self.lang)}")

        label = self.t("power_off") if running else self.t("power_on")
        if self.bridge.is_stopping():
            label = self.t("stopping")
        self.power_btn.setText(label)
        self.power_btn.setObjectName("powerOn" if running else "power")
        self.power_btn.setStyleSheet("")  # re-eval objectName-based QSS
        self.power_btn.style().unpolish(self.power_btn)
        self.power_btn.style().polish(self.power_btn)
        self.act_toggle.setText(label)

    # ─── config + files ─────────────────────────────────────────────────
    def _load_config(self) -> dict:
        try:
            with open(self.config_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}

    def _set_cfg(self, key: str, value) -> None:
        self.config[key] = value
        try:
            with open(self.config_path, "w", encoding="utf-8") as fh:
                json.dump(self.config, fh, ensure_ascii=False, indent=2)
        except Exception as exc:
            QMessageBox.warning(self, APP_NAME, f"Config save failed: {exc}")

    def _domain_paths(self):
        return (os.path.join(self.root, "hostlist.txt"),
                os.path.join(self.root, "list-exclude.txt"))

    def _load_domain_files(self) -> None:
        host_p, excl_p = self._domain_paths()
        self.host_edit.setPlainText(self._read_text(host_p))
        self.excl_edit.setPlainText(self._read_text(excl_p))

    def _save_domain_files(self) -> None:
        host_p, excl_p = self._domain_paths()
        try:
            self._write_text(host_p, self.host_edit.toPlainText())
            self._write_text(excl_p, self.excl_edit.toPlainText())
            self.tray.showMessage(APP_NAME, self.t("saved"), theme.make_icon(STATE_ACTIVE), 2000)
        except Exception as exc:
            QMessageBox.warning(self, APP_NAME, f"Save failed: {exc}")

    @staticmethod
    def _read_text(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read()
        except Exception:
            return ""

    @staticmethod
    def _write_text(path: str, text: str) -> None:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    def _change_language(self) -> None:
        self.lang = self.lang_combo.currentData()
        self._set_cfg("gui_language", self.lang)
        QMessageBox.information(
            self, APP_NAME,
            "Перезапустите приложение, чтобы сменить язык интерфейса."
            if self.lang == "ru" else
            "Restart the app to apply the interface language.")

    def _toggle_autostart(self, enabled: bool) -> None:
        self._set_cfg("gui_autostart", enabled)
        try:
            from gui.autostart import set_autostart
            set_autostart(enabled, self.root)
        except Exception as exc:
            QMessageBox.warning(self, APP_NAME, f"Autostart: {exc}")

    # ─── window close / quit ────────────────────────────────────────────
    def closeEvent(self, event) -> None:
        if self._quitting:
            event.accept()
            return
        # Hide to tray instead of quitting
        event.ignore()
        self.hide()
        self.tray.showMessage(APP_NAME, self.t("running_note"),
                              theme.make_icon(self.bridge.status().get("state", STATE_STOPPED)), 3000)

    def _quit(self) -> None:
        if self.bridge.is_running():
            res = QMessageBox.question(self, APP_NAME, self.t("quit_confirm"))
            if res != QMessageBox.Yes:
                return
        self._quitting = True
        self.bridge.stop()
        self.tray.hide()
        QApplication.quit()
