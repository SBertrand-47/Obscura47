"""
Obscura47 - Desktop Client
Launch this file to run the Obscura Network GUI.
Users join as relay nodes and use the local proxy to browse anonymously.
Exit node status requires admin approval.

The interface is built with PySide6 (Qt 6): a left navigation rail switches
between Dashboard, Sites, Activity and Settings pages. All network/backend
logic is unchanged from the original client - only the UI layer is Qt.
"""

import sys
import os
import json
import platform
import argparse
import threading
import time

from PySide6.QtCore import Qt, QTimer, QObject, Signal
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QLabel,
    QPushButton,
    QFrame,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QStackedWidget,
    QButtonGroup,
    QCheckBox,
    QTextEdit,
    QScrollArea,
    QDialog,
    QLineEdit,
    QFileDialog,
    QMessageBox,
    QInputDialog,
)

# ── Autostart / settings helpers ──────────────────────────────────────────────

_SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".obscura47_settings.json")
_APP_SCRIPT    = os.path.abspath(__file__)
_PYTHON_EXEC   = sys.executable


def _load_settings() -> dict:
    try:
        with open(_SETTINGS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_settings(s: dict):
    with open(_SETTINGS_PATH, "w") as f:
        json.dump(s, f)


def _autostart_cmd(background: bool) -> list[str]:
    """Return the command list that should be registered for autostart."""
    exe = _PYTHON_EXEC
    # On Windows prefer pythonw.exe so no console window appears
    if platform.system() == "Windows":
        exe = exe.replace("python.exe", "pythonw.exe")
    cmd = [exe, _APP_SCRIPT]
    if background:
        cmd.append("--background")
    return cmd


def setup_autostart(background: bool = True):
    """Register Obscura47 to launch at login (current user only)."""
    cmd = _autostart_cmd(background)
    s = platform.system()
    if s == "Windows":
        _autostart_win_set(cmd)
    elif s == "Darwin":
        _autostart_mac_set(cmd)
    else:
        _autostart_linux_set(cmd)


def remove_autostart():
    """Remove Obscura47 from login items."""
    s = platform.system()
    if s == "Windows":
        _autostart_win_del()
    elif s == "Darwin":
        _autostart_mac_del()
    else:
        _autostart_linux_del()


# ── Windows ───────────────────────────────────────────────────────────────────

def _autostart_win_set(cmd: list[str]):
    import winreg
    value = " ".join(f'"{a}"' for a in cmd)
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        0, winreg.KEY_SET_VALUE,
    )
    winreg.SetValueEx(key, "Obscura47", 0, winreg.REG_SZ, value)
    winreg.CloseKey(key)


def _autostart_win_del():
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE,
        )
        winreg.DeleteValue(key, "Obscura47")
        winreg.CloseKey(key)
    except Exception:
        pass


# ── macOS ─────────────────────────────────────────────────────────────────────

_MAC_PLIST = os.path.expanduser("~/Library/LaunchAgents/com.obscura47.app.plist")


def _autostart_mac_set(cmd: list[str]):
    os.makedirs(os.path.dirname(_MAC_PLIST), exist_ok=True)
    args_xml = "\n".join(f"        <string>{a}</string>" for a in cmd)
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.obscura47.app</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
"""
    with open(_MAC_PLIST, "w") as f:
        f.write(plist)


def _autostart_mac_del():
    try:
        os.remove(_MAC_PLIST)
    except Exception:
        pass


# ── Linux (XDG autostart) ─────────────────────────────────────────────────────

_LINUX_DESKTOP = os.path.expanduser("~/.config/autostart/obscura47.desktop")


def _autostart_linux_set(cmd: list[str]):
    os.makedirs(os.path.dirname(_LINUX_DESKTOP), exist_ok=True)
    exec_str = " ".join(f'"{a}"' for a in cmd)
    content = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Obscura47\n"
        f"Exec={exec_str}\n"
        "Hidden=false\n"
        "NoDisplay=false\n"
        "X-GNOME-Autostart-enabled=true\n"
    )
    with open(_LINUX_DESKTOP, "w") as f:
        f.write(content)


def _autostart_linux_del():
    try:
        os.remove(_LINUX_DESKTOP)
    except Exception:
        pass

# Ensure UTF-8 on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ── Colour palette ────────────────────────────────────────────────
BG           = "#0d1117"
BG_CARD      = "#161b22"
BG_CARD_HI   = "#1c2333"
BG_RAIL      = "#0a0e14"
ACCENT       = "#58a6ff"
ACCENT_DIM   = "#1f6feb"
GREEN        = "#3fb950"
RED          = "#f85149"
YELLOW       = "#d29922"
TEXT         = "#c9d1d9"
TEXT_DIM     = "#8b949e"
BORDER       = "#30363d"

DOT = "●"


from src.utils.app_helpers import (  # noqa: E402
    build_quick_start_text,
    count_unique_peers,
    format_hosted_site_summary,
    resolve_hosted_site_selection,
)


# ── Global stylesheet ─────────────────────────────────────────────
# One central QSS sheet keeps the look consistent and the widget code
# free of inline styling. Object names / dynamic properties drive the
# per-widget variations (cards, accent buttons, nav rail, etc.).
STYLESHEET = f"""
* {{
    font-family: "SF Pro Display", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    color: {TEXT};
}}
QMainWindow, #Root {{ background: {BG}; }}

/* ── Left navigation rail ── */
#NavRail {{ background: {BG_RAIL}; border-right: 1px solid {BORDER}; }}
#Wordmark {{ font-size: 20px; font-weight: 700; color: {ACCENT}; }}
#WordmarkSub {{ font-size: 10px; color: {TEXT_DIM}; }}
QPushButton#NavButton {{
    text-align: left;
    padding: 11px 16px;
    border: none;
    border-radius: 8px;
    background: transparent;
    color: {TEXT_DIM};
    font-size: 13px;
}}
QPushButton#NavButton:hover {{ background: {BG_CARD}; color: {TEXT}; }}
QPushButton#NavButton:checked {{ background: {BG_CARD_HI}; color: {ACCENT}; font-weight: 600; }}

/* ── Top bar ── */
#TopBar {{ background: {BG}; border-bottom: 1px solid {BORDER}; }}
#PageTitle {{ font-size: 22px; font-weight: 700; color: {TEXT}; }}
#StatusPill {{
    background: {BG_CARD}; border: 1px solid {BORDER};
    border-radius: 14px; padding: 6px 14px; font-weight: 600;
}}

/* ── Cards ── */
QFrame#Card {{
    background: {BG_CARD};
    border: 1px solid {BORDER};
    border-radius: 12px;
}}
#CardTitle {{ font-size: 13px; font-weight: 600; color: {TEXT}; }}
#CardSub   {{ font-size: 11px; color: {TEXT_DIM}; }}
#Metric    {{ font-size: 30px; font-weight: 700; }}
#MetricLabel {{ font-size: 11px; color: {TEXT_DIM}; }}

/* ── Buttons ── */
QPushButton#Primary {{
    background: {ACCENT_DIM}; color: white; font-weight: 600; font-size: 14px;
    border: none; border-radius: 10px; padding: 12px 28px;
}}
QPushButton#Primary:hover {{ background: {ACCENT}; }}
QPushButton#Danger {{
    background: #6e2b2b; color: white; font-weight: 600; font-size: 14px;
    border: none; border-radius: 10px; padding: 12px 28px;
}}
QPushButton#Danger:hover {{ background: {RED}; }}
QPushButton#Action {{
    background: {BG_CARD_HI}; color: {TEXT}; font-size: 12px; font-weight: 500;
    border: 1px solid {BORDER}; border-radius: 9px; padding: 14px 12px; text-align: left;
}}
QPushButton#Action:hover {{ background: {ACCENT_DIM}; color: white; border-color: {ACCENT_DIM}; }}
QPushButton#Subtle {{
    background: transparent; color: {TEXT_DIM}; font-size: 12px;
    border: 1px solid {BORDER}; border-radius: 9px; padding: 9px 16px;
}}
QPushButton#Subtle:hover {{ background: {BG_CARD}; color: {TEXT}; }}

/* ── Misc ── */
QCheckBox {{ font-size: 12px; color: {TEXT}; spacing: 8px; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 4px;
    border: 1px solid {BORDER}; background: {BG}; }}
QCheckBox::indicator:checked {{ background: {ACCENT_DIM}; border-color: {ACCENT_DIM}; }}
QTextEdit#Log {{
    background: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 12px;
    color: {TEXT_DIM}; font-family: "SF Mono", "Consolas", "Menlo", monospace;
    font-size: 12px; padding: 10px;
}}
QLineEdit {{
    background: {BG}; border: 1px solid {BORDER}; border-radius: 8px;
    padding: 8px 10px; color: {TEXT}; font-size: 13px;
}}
QLineEdit:focus {{ border-color: {ACCENT}; }}
QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {TEXT_DIM}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QDialog {{ background: {BG}; }}
"""


def _card(title: str | None = None) -> tuple[QFrame, QVBoxLayout]:
    """Create a rounded card frame and return (frame, content_layout)."""
    frame = QFrame()
    frame.setObjectName("Card")
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(18, 16, 18, 16)
    lay.setSpacing(8)
    if title:
        t = QLabel(title)
        t.setObjectName("CardTitle")
        lay.addWidget(t)
    return frame, lay


class _Worker(QObject):
    """Signal hub so background threads can update the UI thread safely."""
    log = Signal(str)
    diagnostic = Signal(str, bool)
    discovery = Signal(str, bool)


class ObscuraApp(QMainWindow):
    """Main application window."""

    def __init__(self, background: bool = False):
        super().__init__()

        self.setWindowTitle("Obscura47")
        self.resize(980, 680)
        self.setMinimumSize(820, 560)

        # ── Persisted settings ─────────────────────────────────────
        self._settings = _load_settings()

        # ── State ─────────────────────────────────────────────────
        self._threads: dict[str, threading.Thread] = {}
        self._running: dict[str, bool] = {"proxy": False, "node": False}
        self._status_labels: dict[str, QLabel] = {}
        self._peer_labels: dict[str, QLabel] = {}
        self._log_lines: list[str] = []
        self._connected = False
        self._banner_green = False

        # ── Cross-thread signalling ────────────────────────────────
        self._signals = _Worker()
        self._signals.log.connect(self._append_log)
        self._signals.diagnostic.connect(self._show_diagnostic_result)
        self._signals.discovery.connect(self._show_discovery_result)

        self._build_ui()

        # Poll component status every second (Qt timer, UI thread)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._poll)
        self._timer.start(1000)

        self._log("Welcome to Obscura47. Connect, then use the Sites tab to visit or publish sites.")

        # ── Background / autostart startup behaviour ───────────────
        if background or self._settings.get("start_minimized", False):
            QTimer.singleShot(100, self.showMinimized)
            QTimer.singleShot(200, self._connect)

    # ── UI construction ───────────────────────────────────────────

    def _build_ui(self):
        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._build_nav_rail())

        # ── Right side: top bar + stacked pages ──
        right = QWidget()
        right_lay = QVBoxLayout(right)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.setSpacing(0)
        right_lay.addWidget(self._build_top_bar())

        self._stack = QStackedWidget()
        self._stack.addWidget(self._build_dashboard_page())  # 0
        self._stack.addWidget(self._build_sites_page())      # 1
        self._stack.addWidget(self._build_activity_page())   # 2
        self._stack.addWidget(self._build_settings_page())   # 3
        right_lay.addWidget(self._stack, 1)

        outer.addWidget(right, 1)

    def _build_nav_rail(self) -> QWidget:
        rail = QWidget()
        rail.setObjectName("NavRail")
        rail.setFixedWidth(200)
        lay = QVBoxLayout(rail)
        lay.setContentsMargins(16, 24, 16, 16)
        lay.setSpacing(6)

        wordmark = QLabel("OBSCURA47")
        wordmark.setObjectName("Wordmark")
        sub = QLabel("Anonymous Overlay")
        sub.setObjectName("WordmarkSub")
        lay.addWidget(wordmark)
        lay.addWidget(sub)
        lay.addSpacing(28)

        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        pages = [
            ("\U0001F4CA  Dashboard", 0),
            ("\U0001F310  Sites", 1),
            ("\U0001F4DC  Activity", 2),
            ("⚙️  Settings", 3),
        ]
        for label, idx in pages:
            btn = QPushButton(label)
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _checked, i=idx: self._stack.setCurrentIndex(i))
            self._nav_group.addButton(btn, idx)
            lay.addWidget(btn)
        self._nav_group.button(0).setChecked(True)

        lay.addStretch(1)

        ver = QLabel("v2 · Qt edition")
        ver.setObjectName("CardSub")
        lay.addWidget(ver)
        return rail

    def _build_top_bar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("TopBar")
        bar.setFixedHeight(72)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(28, 0, 28, 0)

        self._page_title = QLabel("Dashboard")
        self._page_title.setObjectName("PageTitle")
        # Keep the title in sync with the active page.
        self._stack_titles = ["Dashboard", "Sites", "Activity", "Settings"]
        lay.addWidget(self._page_title)
        lay.addStretch(1)

        self._status_pill = QLabel(f"{DOT}  Disconnected")
        self._status_pill.setObjectName("StatusPill")
        self._set_pill_color(RED)
        lay.addWidget(self._status_pill)
        lay.addSpacing(12)

        self._connect_btn = QPushButton("▶  Connect")
        self._connect_btn.setObjectName("Primary")
        self._connect_btn.setCursor(Qt.PointingHandCursor)
        self._connect_btn.clicked.connect(self._toggle_connection)
        lay.addWidget(self._connect_btn)
        return bar

    def _scroll_page(self) -> tuple[QScrollArea, QVBoxLayout]:
        """A scrollable page body. Returns (scroll_area, content_layout)."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(16)
        scroll.setWidget(body)
        return scroll, lay

    # ── Dashboard page ────────────────────────────────────────────

    def _build_dashboard_page(self) -> QWidget:
        scroll, lay = self._scroll_page()

        # Status banner
        banner, b_lay = _card()
        b_lay.setSpacing(4)
        row = QHBoxLayout()
        self._banner_dot = QLabel(DOT)
        self._banner_dot.setStyleSheet(f"color: {RED}; font-size: 16px;")
        self._banner_text = QLabel("Disconnected")
        self._banner_text.setStyleSheet(f"color: {RED}; font-size: 16px; font-weight: 700;")
        row.addWidget(self._banner_dot)
        row.addWidget(self._banner_text)
        row.addStretch(1)
        self._banner_detail = QLabel("Connect, then open or publish from the Sites tab")
        self._banner_detail.setObjectName("CardSub")
        row.addWidget(self._banner_detail)
        b_lay.addLayout(row)
        lay.addWidget(banner)

        # Peer metric cards
        metrics = QHBoxLayout()
        metrics.setSpacing(16)
        for key, label, color in [
            ("relays", "Relay Nodes", ACCENT),
            ("healthy", "Healthy", GREEN),
            ("exits", "Exit Nodes", ACCENT),
        ]:
            card, c_lay = _card()
            c_lay.setSpacing(2)
            c_lay.setAlignment(Qt.AlignCenter)
            num = QLabel("0")
            num.setObjectName("Metric")
            num.setStyleSheet(f"color: {color};")
            num.setAlignment(Qt.AlignCenter)
            cap = QLabel(label)
            cap.setObjectName("MetricLabel")
            cap.setAlignment(Qt.AlignCenter)
            c_lay.addWidget(num)
            c_lay.addWidget(cap)
            self._peer_labels[key] = num
            metrics.addWidget(card)
        lay.addLayout(metrics)

        # Role indicator
        role_card, r_lay = _card("Node Role")
        self._role_label = QLabel("Detecting…")
        self._role_label.setObjectName("CardSub")
        r_lay.addWidget(self._role_label)
        lay.addWidget(role_card)

        # Component status cards
        comp_card, comp_lay = _card("Components")
        descriptions = {
            "proxy": ("Local Proxy", "Browse anonymously via 127.0.0.1:9047"),
            "node":  ("Relay Node", "Forward encrypted traffic for the network"),
        }
        for role, (label, desc) in descriptions.items():
            comp_lay.addWidget(self._build_status_row(role, label, desc))
        lay.addWidget(comp_card)

        # Exit node request
        self._exit_request_btn = QPushButton("Request Exit Node Status")
        self._exit_request_btn.setObjectName("Subtle")
        self._exit_request_btn.setCursor(Qt.PointingHandCursor)
        self._exit_request_btn.clicked.connect(self._request_exit_status)
        exit_row = QHBoxLayout()
        exit_row.addWidget(self._exit_request_btn)
        exit_row.addStretch(1)
        lay.addLayout(exit_row)

        lay.addStretch(1)
        return scroll

    def _build_status_row(self, role: str, label: str, desc: str) -> QWidget:
        w = QFrame()
        w.setStyleSheet(f"background: {BG_CARD_HI}; border-radius: 9px;")
        lay = QHBoxLayout(w)
        lay.setContentsMargins(14, 10, 14, 10)
        left = QVBoxLayout()
        left.setSpacing(1)
        name = QLabel(label)
        name.setStyleSheet("font-size: 13px; font-weight: 600;")
        sub = QLabel(desc)
        sub.setObjectName("CardSub")
        left.addWidget(name)
        left.addWidget(sub)
        lay.addLayout(left)
        lay.addStretch(1)
        status = QLabel(f"{DOT} Stopped")
        status.setStyleSheet(f"color: {TEXT_DIM}; font-size: 12px;")
        lay.addWidget(status)
        self._status_labels[role] = status
        return w

    # ── Sites page ────────────────────────────────────────────────

    def _build_sites_page(self) -> QWidget:
        scroll, lay = self._scroll_page()

        intro, i_lay = _card("Getting Started")
        hint = QLabel(
            "Use the actions below to open, browse, or publish .obscura sites. "
            "To browse, your web browser must route .obscura traffic through the "
            "local Obscura proxy at 127.0.0.1:9047 (see Open .obscura Address)."
        )
        hint.setObjectName("CardSub")
        hint.setWordWrap(True)
        i_lay.addWidget(hint)
        lay.addWidget(intro)

        actions_card, a_lay = _card("Quick Actions")
        grid = QGridLayout()
        grid.setSpacing(10)
        actions = [
            ("ℹ️  Quick Start", self._show_quick_start),
            ("\U0001F517  Open .obscura Address", self._open_visitor),
            ("\U0001F310  Discover Sites", self._discover_sites),
            ("\U0001F4C2  Browse Directory", self._browse_directory),
            ("\U0001F4CB  My Hosted Sites", self._show_hosted_sites),
            ("➕  Add Site", self._add_hosted_site),
            ("\U0001F4E4  Publish Site", self._publish_hosted_site),
            ("\U0001F5D1️  Remove Site", self._remove_hosted_site_daemon),
            ("\U0001FA7A  Diagnose Connection", self._diagnose_connection),
        ]
        for col in range(2):
            grid.setColumnStretch(col, 1)
        for idx, (label, command) in enumerate(actions):
            btn = QPushButton(label)
            btn.setObjectName("Action")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _checked=False, c=command: c())
            r, c = divmod(idx, 2)
            grid.addWidget(btn, r, c)
        a_lay.addLayout(grid)
        lay.addWidget(actions_card)

        lay.addStretch(1)
        return scroll

    # ── Activity page ─────────────────────────────────────────────

    def _build_activity_page(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(12)

        label = QLabel("Activity Log")
        label.setObjectName("CardTitle")
        lay.addWidget(label)

        self._log_text = QTextEdit()
        self._log_text.setObjectName("Log")
        self._log_text.setReadOnly(True)
        lay.addWidget(self._log_text, 1)
        return page

    # ── Settings page ─────────────────────────────────────────────

    def _build_settings_page(self) -> QWidget:
        scroll, lay = self._scroll_page()

        card, c_lay = _card("Startup")
        c_lay.setSpacing(14)

        self._autostart_chk = QCheckBox("Start Obscura47 on login")
        self._autostart_chk.setChecked(bool(self._settings.get("autostart", False)))
        self._autostart_chk.toggled.connect(self._on_autostart_toggle)
        c_lay.addWidget(self._autostart_chk)

        self._minimized_chk = QCheckBox("Start minimized and auto-connect")
        self._minimized_chk.setChecked(bool(self._settings.get("start_minimized", False)))
        self._minimized_chk.toggled.connect(self._on_minimized_toggle)
        c_lay.addWidget(self._minimized_chk)

        lay.addWidget(card)

        about, ab_lay = _card("About")
        info = QLabel(
            "Obscura47 - Anonymous Overlay Network\n"
            "Join as a relay node and browse anonymously through the local proxy. "
            "Exit node status requires admin approval."
        )
        info.setObjectName("CardSub")
        info.setWordWrap(True)
        ab_lay.addWidget(info)
        lay.addWidget(about)

        lay.addStretch(1)
        return scroll

    # ── Pill / banner helpers ─────────────────────────────────────

    def _set_pill_color(self, color: str):
        self._status_pill.setStyleSheet(
            f"#StatusPill {{ background: {BG_CARD}; border: 1px solid {BORDER};"
            f" border-radius: 14px; padding: 6px 14px; font-weight: 600; color: {color}; }}"
        )

    # ── Settings toggles ──────────────────────────────────────────

    def _on_autostart_toggle(self, enabled: bool):
        self._settings["autostart"] = enabled
        _save_settings(self._settings)
        try:
            if enabled:
                setup_autostart(background=self._minimized_chk.isChecked())
                self._log("Auto-start on login enabled.")
            else:
                remove_autostart()
                self._log("Auto-start on login disabled.")
        except Exception as e:
            self._log(f"Could not update auto-start: {e}")

    def _on_minimized_toggle(self, enabled: bool):
        self._settings["start_minimized"] = enabled
        _save_settings(self._settings)
        # Re-register autostart so the --background flag is added/removed
        if self._autostart_chk.isChecked():
            try:
                setup_autostart(background=enabled)
            except Exception as e:
                self._log(f"Could not update auto-start: {e}")

    # ── Connection lifecycle ──────────────────────────────────────

    def _toggle_connection(self):
        if self._connected:
            self._disconnect()
        else:
            self._connect()

    def _connect(self):
        if self._connected:
            return
        self._connected = True
        self._log("Connecting to the Obscura Network...")
        for role in ("node", "proxy"):
            if not self._running[role]:
                self._running[role] = True
                t = threading.Thread(target=self._run_component, args=(role,), daemon=True)
                self._threads[role] = t
                t.start()

    def _disconnect(self):
        if not self._connected:
            return
        self._connected = False
        for role in self._running:
            self._running[role] = False
        self._log("Disconnecting from the Obscura Network...")
        # Signed self-deregister so the registry drops us within seconds
        # instead of waiting out PEER_TTL. Best-effort; we log and move on
        # if it fails (e.g. registry unreachable on local cleanup).
        try:
            from src.core.internet_discovery import stop_heartbeat
            for role in ("node", "proxy"):
                stop_heartbeat(role)
        except Exception as exc:
            self._log(f"[disconnect] deregister failed: {exc}")

    def _run_component(self, role: str):
        try:
            if role == "proxy":
                from src.core.proxy import start_proxy
                start_proxy()
            elif role == "node":
                from src.core.node import ObscuraNode
                from src.utils.config import NODE_LISTEN_PORT
                node = ObscuraNode(port=NODE_LISTEN_PORT)
                node.run()
                while self._running[role]:
                    time.sleep(1)
        except Exception as exc:
            self._log(f"[{role}] Error: {exc}")
        finally:
            self._running[role] = False

    # ── Exit node application ─────────────────────────────────────

    def _request_exit_status(self):
        """Send an exit-node application to the registry.

        The registry stores the registration with approved=0. An admin must
        approve it before this node appears as an exit to proxies.
        """
        if not self._connected:
            QMessageBox.information(
                self, "Not Connected",
                "You must be connected to the network before requesting exit status.",
            )
            return

        confirm = QMessageBox.question(
            self, "Request Exit Node Status",
            "This will submit a request to become an exit node.\n\n"
            "Exit nodes route traffic to the public internet on behalf of "
            "other users. Your request will be reviewed by a network admin.\n\n"
            "Do you want to continue?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        self._log("Submitting exit node application...")
        threading.Thread(target=self._submit_exit_application, daemon=True).start()

    def _submit_exit_application(self):
        """Register with the registry as an exit node (will be unapproved)."""
        try:
            from src.core.encryptions import ecc_load_or_create_keypair, ecdsa_sign
            from src.utils.config import (
                EXIT_KEY_PATH, EXIT_LISTEN_PORT, EXIT_WS_PORT,
                REGISTRY_URL, WS_TLS_ACTIVE,
            )
            import json
            import urllib.request
            import urllib.error

            priv_key, pub_pem = ecc_load_or_create_keypair(EXIT_KEY_PATH)

            # Step 1: Register as exit (will receive challenge)
            reg_data = json.dumps({
                "port": EXIT_LISTEN_PORT,
                "role": "exit",
                "pub": pub_pem,
                "ws_port": EXIT_WS_PORT,
                "ws_tls": WS_TLS_ACTIVE or None,
            }).encode()
            req = urllib.request.Request(
                f"{REGISTRY_URL}/register",
                data=reg_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())

            if result.get("ok"):
                self._log("Exit application submitted (already registered).")
                return

            # Step 2: Sign the challenge nonce
            challenge = result.get("challenge")
            peer_id = result.get("peer_id")
            if not challenge or not peer_id:
                self._log("Exit application failed: no challenge received.")
                return

            sig = ecdsa_sign(priv_key, challenge.encode())
            verify_data = json.dumps({
                "peer_id": peer_id,
                "signature": sig,
            }).encode()
            req2 = urllib.request.Request(
                f"{REGISTRY_URL}/register/verify",
                data=verify_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req2, timeout=10) as resp2:
                result2 = json.loads(resp2.read())

            if result2.get("ok"):
                self._log("Exit node application submitted. Awaiting admin approval.")
            else:
                self._log("Exit application failed: verification rejected.")

        except Exception as e:
            self._log(f"Exit application error: {e}")

    # ── User utility actions ─────────────────────────────────────

    def _prompt_text(self, title: str, prompt: str, initial: str = "") -> str | None:
        text, ok = QInputDialog.getText(self, title, prompt, QLineEdit.Normal, initial)
        if not ok:
            return None
        return text

    def _prompt_publish_target(self, title: str, initial: str = "") -> str | None:
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.setMinimumWidth(460)
        lay = QVBoxLayout(dialog)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)

        lbl = QLabel("Directory path or host:port to publish:")
        lbl.setStyleSheet("font-size: 13px;")
        lay.addWidget(lbl)

        row = QHBoxLayout()
        entry = QLineEdit(initial)
        row.addWidget(entry, 1)
        browse = QPushButton("Browse Folder…")
        browse.setObjectName("Subtle")
        browse.setCursor(Qt.PointingHandCursor)
        row.addWidget(browse)
        lay.addLayout(row)

        def _browse_folder():
            start = os.path.expanduser(initial) if initial else os.path.expanduser("~")
            chosen = QFileDialog.getExistingDirectory(dialog, "Choose Site Folder", start)
            if chosen:
                entry.setText(chosen)
                entry.setFocus()

        browse.clicked.connect(_browse_folder)

        result = {"value": None}

        def _submit():
            text = entry.text().strip()
            result["value"] = text or None
            dialog.accept()

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.setObjectName("Subtle")
        cancel.clicked.connect(dialog.reject)
        ok_btn = QPushButton("OK")
        ok_btn.setObjectName("Primary")
        ok_btn.clicked.connect(_submit)
        buttons.addWidget(cancel)
        buttons.addWidget(ok_btn)
        lay.addLayout(buttons)

        entry.returnPressed.connect(_submit)
        entry.setFocus()
        entry.selectAll()
        dialog.exec()
        return result["value"]

    def _get_hosted_sites(self) -> list:
        try:
            from src.utils.sites import list_sites

            return list(list_sites())
        except Exception:
            return []

    @staticmethod
    def _address_from_pub(pub: str) -> str:
        from src.utils.onion_addr import address_from_pubkey

        return address_from_pubkey(pub)

    def _open_address_in_browser(self, address: str):
        from src.utils.visitor import open_in_browser

        if not open_in_browser(url=address):
            raise RuntimeError("proxy startup or browser launch failed")

    def _show_quick_start(self):
        QMessageBox.information(
            self, "Quick Start",
            build_quick_start_text(connected=self._connected),
        )

    def _open_visitor(self):
        address = self._prompt_text(
            "Open .obscura Address",
            "Address or URL to open:\n\n"
            "Obscura47 launches your browser pre-configured with the right "
            "proxy routing - you do not need to change Firefox/Chrome proxy "
            "settings manually.",
        )
        if not address:
            return
        try:
            self._open_address_in_browser(address)
            self._log(f"Opened {address} in browser.")
        except Exception as exc:
            QMessageBox.critical(self, "Open .obscura Address", str(exc))
            self._log(f"Could not open address: {exc}")
            return
        # Offer a follow-up diagnostic - the browser may succeed in
        # launching but still fail to reach the site if the network
        # has no live peers or the registry lacks /hs routes.
        if self._is_obscura_address(address):
            if QMessageBox.question(
                self, "Open .obscura Address",
                "Browser launched. If the page does not load, run a "
                "connection diagnostic now?",
                QMessageBox.Yes | QMessageBox.No,
            ) == QMessageBox.Yes:
                self._diagnose_connection(default_address=address)

    @staticmethod
    def _is_obscura_address(value: str) -> bool:
        try:
            from src.utils.onion_addr import is_obscura_address
        except Exception:
            return False
        candidate = (value or "").strip()
        # Strip scheme + path so "http://alpha.obscura/x" still matches.
        if "://" in candidate:
            candidate = candidate.split("://", 1)[1]
        candidate = candidate.split("/", 1)[0]
        return is_obscura_address(candidate)

    def _diagnose_connection(self, default_address: str = ""):
        """Run the registry/HS lookup walk and show a structured report."""
        address = self._prompt_text(
            "Diagnose Connection",
            "Optional .obscura address to test (leave blank for registry-only):",
            initial=self._strip_to_obscura(default_address),
        )
        # getText returns None on cancel, "" on submit-with-empty.
        # Cancel aborts; empty submit runs a registry-only check.
        if address is None:
            return
        address = address.strip()
        self._log("Running connection diagnostic…")

        def _worker():
            from src.utils.diagnose import run_diagnostics, format_report_text
            try:
                report = run_diagnostics(address or None)
                text = format_report_text(report)
                ok = report.ok
            except Exception as exc:
                text = f"Diagnostic crashed: {exc}"
                ok = False
            self._signals.diagnostic.emit(text, ok)

        threading.Thread(target=_worker, daemon=True).start()

    def _show_diagnostic_result(self, text: str, ok: bool):
        if ok:
            QMessageBox.information(self, "Diagnose Connection", text)
        else:
            QMessageBox.warning(self, "Diagnose Connection", text)
        self._log("Connection diagnostic complete.")

    @staticmethod
    def _strip_to_obscura(value: str) -> str:
        v = (value or "").strip()
        if "://" in v:
            v = v.split("://", 1)[1]
        return v.split("/", 1)[0]

    def _show_hosted_sites(self):
        hosted = self._get_hosted_sites()
        if not hosted:
            QMessageBox.information(self, "My Hosted Sites", "No hosted sites yet.")
            return

        from src.utils.daemon import daemon_installed

        message = "\n\n".join(
            format_hosted_site_summary(
                site,
                background_enabled=daemon_installed(site.name),
            )
            for site in hosted
        )
        QMessageBox.information(self, "My Hosted Sites", message)

        selected = self._prompt_text(
            "Open Hosted Site",
            "Site name or .obscura address to open now (optional):",
            initial=hosted[0].name,
        )
        if not selected:
            return
        try:
            address = resolve_hosted_site_selection(selected, hosted)
            self._open_address_in_browser(address)
            self._log(f"Opened hosted site {address}.")
        except Exception as exc:
            QMessageBox.critical(self, "Open Hosted Site", str(exc))
            self._log(f"Could not open hosted site: {exc}")

    def _add_hosted_site(self):
        name = self._prompt_text("Add .obscura Site", "Site name:")
        if not name:
            return

        remembered_target = ""
        remembered_key_path = None
        try:
            from src.utils.sites import load_site_config

            config = load_site_config(name)
            if config:
                if config.target:
                    remembered_target = config.target
                remembered_key_path = config.key_path
        except Exception:
            remembered_target = ""
            remembered_key_path = None

        target = self._prompt_publish_target(
            "Add .obscura Site",
            initial=remembered_target,
        )
        if not target:
            return

        try:
            from src.utils.daemon import install_daemon
            from src.utils.sites import load_or_create_site_key, save_site_config

            _, pub, key_path, _created = load_or_create_site_key(
                name=name,
                key=remembered_key_path,
            )
            save_site_config(name, key_path=key_path, target=target)
            reference = install_daemon(name, target, key_path=key_path)
            address = self._address_from_pub(pub)
            QMessageBox.information(
                self, "Add .obscura Site",
                f"Installed background host for {name}.\n\n"
                f"Address: {address}\n"
                f"Target: {target}\n"
                f"Service: {reference}",
            )
            self._log(f"Installed background host for {address}.")
        except Exception as exc:
            QMessageBox.critical(self, "Add .obscura Site", str(exc))
            self._log(f"Could not add hosted site: {exc}")

    def _publish_hosted_site(self):
        name = self._prompt_text("Publish .obscura Site", "Site name:")
        if not name:
            return

        remembered_target = ""
        remembered_key_path = None
        try:
            from src.utils.sites import load_site_config

            config = load_site_config(name)
            if config:
                if config.target:
                    remembered_target = config.target
                remembered_key_path = config.key_path
        except Exception:
            remembered_target = ""
            remembered_key_path = None

        target = self._prompt_publish_target(
            "Publish .obscura Site",
            initial=remembered_target,
        )
        if not target:
            return

        directory_addr = self._prompt_text(
            "Publish .obscura Site",
            "Optional directory address to announce in:",
        )
        directory_addr = (directory_addr or "").strip()

        try:
            import join_network
            from src.utils.daemon import install_daemon
            from src.utils.sites import (
                load_or_create_site_key,
                save_site_config,
                write_site_manifest,
            )

            _, pub, key_path, _created = load_or_create_site_key(
                name=name,
                key=remembered_key_path,
            )
            address = self._address_from_pub(pub)
            save_site_config(name, key_path=key_path, target=target)

            resolved_target = os.path.abspath(os.path.expanduser(target))
            if os.path.isdir(resolved_target):
                write_site_manifest(
                    resolved_target,
                    address,
                    title=name,
                )

            reference = install_daemon(name, target, key_path=key_path)
            if directory_addr:
                join_network._schedule_directory_registration(name, directory_addr)

            message = (
                f"Published background host for {name}.\n\n"
                f"Address: {address}\n"
                f"Target: {target}\n"
                f"Service: {reference}"
            )
            if directory_addr:
                message += f"\nDirectory: {directory_addr}"
            QMessageBox.information(self, "Publish .obscura Site", message)
            self._log(f"Published hosted site {address}.")
        except Exception as exc:
            QMessageBox.critical(self, "Publish .obscura Site", str(exc))
            self._log(f"Could not publish hosted site: {exc}")

    def _remove_hosted_site_daemon(self):
        name = self._prompt_text("Remove Site Daemon", "Site name:")
        if not name:
            return
        try:
            from src.utils.daemon import uninstall_daemon

            if not uninstall_daemon(name):
                raise RuntimeError(f"no background service found for {name!r}")
            QMessageBox.information(
                self, "Remove Site Daemon",
                f"Removed background service for {name}.",
            )
            self._log(f"Removed background service for site {name}.")
        except Exception as exc:
            QMessageBox.critical(self, "Remove Site Daemon", str(exc))
            self._log(f"Could not remove hosted site daemon: {exc}")

    def _discover_sites(self):
        """List every live .obscura site the registry knows about.

        Unlike Browse Directory (which queries one opt-in directory you must
        already know the address of), this reads the registry's global
        /hs/list, so it works with zero prior knowledge - the answer to
        "what's out there?". Enriches with each site's manifest when the
        proxy is connected.
        """
        self._log("Discovering live .obscura sites…")
        connected = self._connected

        def _worker():
            try:
                from src.utils.site_directory import (
                    fetch_live_sites, enrich_with_manifests, format_site_listing,
                )
                sites = fetch_live_sites()
                if sites and connected:
                    # Best-effort titles/descriptions; only when the proxy is
                    # up to route the manifest fetches.
                    try:
                        enrich_with_manifests(sites)
                    except Exception:
                        pass
                text = format_site_listing(sites)
                ok = True
            except Exception as exc:
                text = (f"Could not reach the registry to list sites:\n{exc}")
                ok = False
            self._signals.discovery.emit(text, ok)

        threading.Thread(target=_worker, daemon=True).start()

    def _show_discovery_result(self, text: str, ok: bool):
        if ok:
            QMessageBox.information(self, "Discover Sites", text)
            self._log("Site discovery complete.")
        else:
            QMessageBox.warning(self, "Discover Sites", text)
            self._log("Site discovery failed.")
            return
        # Offer to open one of the discovered addresses straight away.
        selected = self._prompt_text(
            "Open Discovered Site",
            "Paste a .obscura address from the list to open it now (optional):",
        )
        if not selected:
            return
        try:
            self._open_address_in_browser(selected)
            self._log(f"Opened {selected}.")
        except Exception as exc:
            QMessageBox.critical(self, "Open Discovered Site", str(exc))

    def _browse_directory(self):
        directory_addr = self._prompt_text(
            "Browse Directory",
            "Directory address:",
        )
        if not directory_addr:
            return
        query = self._prompt_text(
            "Browse Directory",
            "Search query (optional):",
        )
        try:
            from src.agent.directory import DirectoryClient
            from src.utils.visitor import ensure_proxy_running

            if not ensure_proxy_running():
                raise RuntimeError("could not start the local proxy")

            result = DirectoryClient(directory_addr).list(
                query=(query or "").strip(),
                limit=10,
            )
            listings = result.get("listings", [])
            if not listings:
                message = "No listings found."
            else:
                rows = []
                for row in listings[:10]:
                    line = f"{row.get('address', '')}"
                    if row.get("title"):
                        line += f" - {row['title']}"
                    rows.append(line)
                message = "\n".join(rows)
            QMessageBox.information(
                self, "Browse Directory",
                f"Directory: {directory_addr}\n\n{message}",
            )
            if listings:
                selected = self._prompt_text(
                    "Open Directory Listing",
                    "Address to open now (optional):",
                    initial=listings[0].get("address", ""),
                )
                if selected:
                    self._open_address_in_browser(selected)
                    self._log(f"Opened directory listing {selected}.")
        except Exception as exc:
            QMessageBox.critical(self, "Browse Directory", str(exc))
            self._log(f"Could not browse directory: {exc}")

    # ── Status polling ────────────────────────────────────────────

    def _get_peer_counts(self) -> dict:
        counts = {"relays": 0, "healthy": 0, "exits": 0}
        try:
            import src.core.proxy as proxy_mod
            from src.core import peer_health
            from src.utils.config import PEER_EXPIRY_SECONDS

            # Purge stale peers before counting - observe_discovery only
            # cleans up when a new multicast message arrives, so if a node
            # disconnects and stops broadcasting, stale entries linger.
            now = time.time()
            cutoff = now - PEER_EXPIRY_SECONDS
            relay_list = getattr(proxy_mod, "relay_peers", [])
            exit_list = getattr(proxy_mod, "exit_peers", [])
            relay_list[:] = [p for p in relay_list if p.get("ts", 0) >= cutoff]
            exit_list[:] = [p for p in exit_list if p.get("ts", 0) >= cutoff]

            counts["relays"] = count_unique_peers(relay_list)
            counts["exits"] = count_unique_peers(exit_list)
            # Healthy = relays this client can actually route through right now,
            # judged by what our own WS probes have observed (peer_health). A
            # relay we've seen fail repeatedly is excluded even while it's still
            # in the list and heartbeating to the registry.
            counts["healthy"] = count_unique_peers(peer_health.filter_healthy(relay_list))
        except Exception:
            pass
        return counts

    def _poll(self):
        # Keep the top-bar title in sync with the active page
        idx = self._stack.currentIndex()
        if 0 <= idx < len(self._stack_titles):
            self._page_title.setText(self._stack_titles[idx])

        # Update peer counts
        counts = self._get_peer_counts()
        for key, lbl in self._peer_labels.items():
            lbl.setText(str(counts[key]))

        for role, lbl in self._status_labels.items():
            running = self._running.get(role, False)
            if running:
                lbl.setText(f"{DOT} Running")
                lbl.setStyleSheet(f"color: {GREEN}; font-size: 12px;")
            else:
                lbl.setText(f"{DOT} Stopped")
                lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 12px;")

        # Role indicator: primary public node vs internal sibling. Reads the
        # classification the registry returned at registration time; while
        # we're not connected, fall back to a neutral placeholder.
        try:
            from src.core.internet_discovery import get_role_kind, get_primary_peer
            kind = get_role_kind("node")
            primary = get_primary_peer()
        except Exception:
            kind, primary = None, None
        if not self._running.get("node", False):
            self._set_role("Detecting…", TEXT_DIM)
        elif kind == "primary":
            self._set_role("Primary public node", GREEN)
        elif kind == "sibling":
            if primary and primary.get("host"):
                gw = f"{primary['host']}:{primary.get('port', '?')}"
                self._set_role(f"Internal sibling, gateway {gw}", ACCENT)
            else:
                self._set_role("Internal sibling, waiting for primary", ACCENT)
        else:
            self._set_role("Detecting…", TEXT_DIM)

        # Network banner / status pill
        both_running = self._running.get("proxy", False) and self._running.get("node", False)
        if both_running and not self._banner_green:
            self._banner_green = True
            self._set_status(GREEN, "Connected",
                             "Use the Sites tab to visit or publish .obscura sites")
            self._log("Connected. Use the Sites tab to open, browse, or publish sites.")
        elif not both_running and self._banner_green:
            self._banner_green = False
            self._set_status(RED, "Disconnected",
                             "Connect, then open or publish from the Sites tab")
            self._log("Disconnected from the Obscura Network.")

        # Connect button
        if self._connected:
            self._connect_btn.setText("■  Disconnect")
            self._connect_btn.setObjectName("Danger")
        else:
            self._connect_btn.setText("▶  Connect")
            self._connect_btn.setObjectName("Primary")
        # Re-polish so the objectName change re-applies the stylesheet
        self._connect_btn.style().unpolish(self._connect_btn)
        self._connect_btn.style().polish(self._connect_btn)

    def _set_role(self, text: str, color: str):
        self._role_label.setText(text)
        self._role_label.setStyleSheet(f"color: {color}; font-size: 12px;")

    def _set_status(self, color: str, text: str, detail: str):
        self._banner_dot.setStyleSheet(f"color: {color}; font-size: 16px;")
        self._banner_text.setText(text)
        self._banner_text.setStyleSheet(f"color: {color}; font-size: 16px; font-weight: 700;")
        self._banner_detail.setText(detail)
        self._status_pill.setText(f"{DOT}  {text}")
        self._set_pill_color(color)

    # ── Logging ───────────────────────────────────────────────────

    def _log(self, msg: str):
        """Thread-safe log entry point - marshals onto the UI thread."""
        self._signals.log.emit(msg)

    def _append_log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        self._log_lines.append(line)
        if len(self._log_lines) > 200:
            self._log_lines = self._log_lines[-200:]
        self._log_text.append(line)
        sb = self._log_text.verticalScrollBar()
        sb.setValue(sb.maximum())

    # ── Shutdown ──────────────────────────────────────────────────

    def closeEvent(self, event):
        for role in self._running:
            self._running[role] = False
        self._connected = False
        super().closeEvent(event)


def main():
    parser = argparse.ArgumentParser(description="Obscura47")
    parser.add_argument(
        "--background", action="store_true",
        help="Start minimized and connect automatically (used by autostart)",
    )
    args, _ = parser.parse_known_args()

    app = QApplication(sys.argv)
    app.setApplicationName("Obscura47")
    app.setStyleSheet(STYLESHEET)

    window = ObscuraApp(background=args.background)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
