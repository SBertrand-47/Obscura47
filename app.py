"""
Obscura47 - Desktop Client
Launch this file to run the Obscura Network GUI.
Users join as relay nodes and use the local proxy to browse anonymously.
Exit node status requires admin approval.

The interface is built with PySide6 (Qt 6). By default it launches the Qt
Quick (QML) UI in ui/Main.qml, driven by the Backend bridge below; all
behaviour is delegated to a headless ObscuraApp - the original QWidgets logic
engine - so the network code is shared and unchanged. Pass --classic to run
that QWidgets interface directly (also the automatic fallback if QML fails to
load). The nav rail switches between Dashboard, Sites, Activity and Settings.
"""

import sys
import os
import json
import platform
import argparse
import threading
import time

from PySide6.QtCore import Qt, QTimer, QObject, Signal, Property, Slot, QUrl
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
    QProgressBar,
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
QPushButton#MiniPrimary {{
    background: {ACCENT_DIM}; color: white; font-weight: 600; font-size: 12px;
    border: none; border-radius: 8px; padding: 8px 18px;
}}
QPushButton#MiniPrimary:hover {{ background: {ACCENT}; }}
QPushButton#Mini {{
    background: transparent; color: {TEXT_DIM}; font-size: 12px;
    border: 1px solid {BORDER}; border-radius: 8px; padding: 8px 14px;
}}
QPushButton#Mini:hover {{ background: {BG_CARD}; color: {TEXT}; }}

/* ── Indeterminate progress (Discover loading) ── */
QProgressBar {{
    background: {BG_CARD_HI}; border: 1px solid {BORDER};
    border-radius: 6px; max-height: 8px; min-height: 8px;
}}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 6px; }}
#AddressMono {{
    color: {ACCENT};
    font-family: "SF Mono", "Consolas", "Menlo", monospace; font-size: 12px;
}}

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


def _hint_card(text: str) -> QFrame:
    """A plain card holding a wrapped message (empty/error states)."""
    card, lay = _card()
    lbl = QLabel(text)
    lbl.setObjectName("CardSub")
    lbl.setWordWrap(True)
    lay.addWidget(lbl)
    return card


def _obscura_url(address: str) -> str:
    """A copy/paste-ready URL: ensure a scheme so the address works when pasted
    straight into a browser, no manual editing needed."""
    a = (address or "").strip()
    if a and not a.startswith(("http://", "https://")):
        return "http://" + a
    return a


def _site_card(
    *,
    title: str,
    address: str,
    info_lines: list[str],
    badge: str | None = None,
    badge_color: str = TEXT_DIM,
    on_open,
    on_copy,
) -> QFrame:
    """One result/listing row: title, mono address, info, Copy + Open.

    ``on_open`` / ``on_copy`` are called with the address string. Shared by
    the Discover and My Hosted Sites dialogs so both look and behave alike.
    """
    card = QFrame()
    card.setObjectName("Card")
    lay = QVBoxLayout(card)
    lay.setContentsMargins(16, 14, 16, 14)
    lay.setSpacing(6)

    top = QHBoxLayout()
    name = QLabel(title or address)
    name.setObjectName("CardTitle")
    name.setWordWrap(True)
    top.addWidget(name, 1)
    if badge:
        chip = QLabel(badge)
        chip.setStyleSheet(f"color: {badge_color}; font-size: 11px; font-weight: 600;")
        top.addWidget(chip, 0, Qt.AlignTop)
    lay.addLayout(top)

    # Show (and copy) a browser-ready URL so users do not have to add a scheme.
    url = _obscura_url(address)
    addr = QLabel(url)
    addr.setObjectName("AddressMono")
    addr.setWordWrap(True)
    addr.setTextInteractionFlags(Qt.TextSelectableByMouse)
    lay.addWidget(addr)

    for line in info_lines:
        if not line:
            continue
        info = QLabel(line)
        info.setObjectName("CardSub")
        info.setWordWrap(True)
        lay.addWidget(info)

    btns = QHBoxLayout()
    btns.addStretch(1)
    copy_btn = QPushButton("Copy address")
    copy_btn.setObjectName("Mini")
    copy_btn.setCursor(Qt.PointingHandCursor)

    def _do_copy():
        on_copy(url)
        # Visible confirmation: flip the label briefly, then restore.
        copy_btn.setText("Copied!")
        QTimer.singleShot(1400, lambda: copy_btn.setText("Copy address"))

    copy_btn.clicked.connect(_do_copy)
    open_btn = QPushButton("Open")
    open_btn.setObjectName("MiniPrimary")
    open_btn.setCursor(Qt.PointingHandCursor)
    open_btn.clicked.connect(lambda: on_open(address))
    btns.addWidget(copy_btn)
    btns.addWidget(open_btn)
    lay.addLayout(btns)
    return card


class _DiscoverDialog(QDialog):
    """List every live .obscura site, with a visible loading state.

    Opens immediately showing an indeterminate progress bar so the user sees
    work is happening, runs the registry query on a background thread, then
    swaps in a scrollable list of site cards (or an empty/error message).
    """

    # sites, ok, error_text - emitted from the worker thread, handled on UI thread.
    _loaded = Signal(list, bool, str)

    def __init__(self, parent, *, connected: bool, on_open, on_copy, on_log):
        super().__init__(parent)
        self.setWindowTitle("Discover Sites")
        self.setMinimumSize(560, 540)
        self._connected = connected
        self._on_open = on_open
        self._on_copy = on_copy
        self._on_log = on_log

        outer = QVBoxLayout(self)
        outer.setContentsMargins(22, 20, 22, 18)
        outer.setSpacing(14)

        header = QLabel("Live .obscura sites")
        header.setObjectName("CardTitle")
        header.setStyleSheet("font-size: 16px; font-weight: 700;")
        outer.addWidget(header)
        sub = QLabel("Every site currently published to the network registry.")
        sub.setObjectName("CardSub")
        outer.addWidget(sub)

        self._stack = QStackedWidget()
        outer.addWidget(self._stack, 1)

        # Page 0: loading
        loading = QWidget()
        l_lay = QVBoxLayout(loading)
        l_lay.setAlignment(Qt.AlignCenter)
        l_lay.setSpacing(18)
        l_lay.addStretch(1)
        spinner = QProgressBar()
        spinner.setRange(0, 0)  # indeterminate "busy" animation
        spinner.setTextVisible(False)
        spinner.setFixedWidth(260)
        msg = QLabel("Discovering live sites…")
        msg.setObjectName("CardTitle")
        msg.setAlignment(Qt.AlignCenter)
        note = QLabel("Querying the registry for every published .obscura address.")
        note.setObjectName("CardSub")
        note.setAlignment(Qt.AlignCenter)
        l_lay.addWidget(msg)
        l_lay.addWidget(spinner, 0, Qt.AlignCenter)
        l_lay.addWidget(note)
        l_lay.addStretch(1)
        self._stack.addWidget(loading)

        # Page 1: results
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        body = QWidget()
        self._results = QVBoxLayout(body)
        self._results.setContentsMargins(2, 2, 2, 2)
        self._results.setSpacing(10)
        self._results.addStretch(1)
        self._scroll.setWidget(body)
        self._stack.addWidget(self._scroll)

        # Footer: count + refresh/close
        footer = QHBoxLayout()
        self._count = QLabel("")
        self._count.setObjectName("CardSub")
        footer.addWidget(self._count)
        footer.addStretch(1)
        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.setObjectName("Mini")
        self._refresh_btn.setCursor(Qt.PointingHandCursor)
        self._refresh_btn.clicked.connect(self._start)
        close_btn = QPushButton("Close")
        close_btn.setObjectName("Mini")
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.clicked.connect(self.accept)
        footer.addWidget(self._refresh_btn)
        footer.addWidget(close_btn)
        outer.addLayout(footer)

        self._loaded.connect(self._on_loaded)
        self._start()

    def _start(self):
        self._stack.setCurrentIndex(0)
        self._count.setText("")
        self._refresh_btn.setEnabled(False)
        threading.Thread(target=self._fetch, daemon=True).start()

    def _fetch(self):
        try:
            from src.utils.site_directory import (
                fetch_live_sites, enrich_with_manifests,
            )
            sites = fetch_live_sites()
            if sites and self._connected:
                # Best-effort titles/descriptions; only when the proxy is up
                # to route the manifest fetches.
                try:
                    enrich_with_manifests(sites)
                except Exception:
                    pass
            self._loaded.emit(sites, True, "")
        except Exception as exc:
            self._loaded.emit([], False, str(exc))

    def _on_loaded(self, sites: list, ok: bool, err: str):
        self._refresh_btn.setEnabled(True)
        # Clear previous cards (keep the trailing stretch at the end).
        while self._results.count() > 1:
            item = self._results.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
        self._stack.setCurrentIndex(1)

        if not ok:
            self._count.setText("Registry unreachable")
            self._results.insertWidget(0, _hint_card(
                "Could not reach the registry to list sites.\n\n"
                f"{err}\n\nCheck your connection and try Refresh."))
            self._on_log("Site discovery failed.")
            return
        if not sites:
            self._count.setText("0 sites")
            self._results.insertWidget(0, _hint_card(
                "No live .obscura sites are currently published to the "
                "registry.\n\nIf you're hosting one, make sure it's running "
                "and connected."))
            self._on_log("Site discovery complete: no live sites.")
            return

        self._count.setText(f"{len(sites)} live site(s)")
        now = time.time()
        for i, site in enumerate(sites):
            self._results.insertWidget(i, self._build_card(site, now))
        self._on_log(f"Site discovery complete: {len(sites)} live site(s).")

    def _build_card(self, site: dict, now: float) -> QFrame:
        addr = site.get("addr", "?")
        title = (site.get("title") or "").strip()
        info_lines = []
        desc = (site.get("description") or "").strip()
        if desc:
            info_lines.append(desc[:200])
        updated = site.get("updated")
        if isinstance(updated, (int, float)):
            info_lines.append(f"Last seen: {_format_age(now - updated)}")
        return _site_card(
            title=title or addr,
            address=addr,
            info_lines=info_lines,
            on_open=self._on_open,
            on_copy=self._on_copy,
        )


def _format_age(seconds: float) -> str:
    """Compact 'time ago' for the Discover list (mirrors site_directory)."""
    seconds = max(0, int(seconds))
    if seconds < 90:
        return "just now"
    minutes = seconds // 60
    if minutes < 90:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 36:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


class _HostedSitesDialog(QDialog):
    """A proper scrollable list of the user's hosted .obscura sites.

    Replaces the old single message box dump - each site is a card showing
    its address, target, and background/manual mode, with Copy and Open.
    """

    def __init__(self, parent, *, sites: list, background_for, on_open, on_copy):
        super().__init__(parent)
        self.setWindowTitle("My Hosted Sites")
        self.setMinimumSize(560, 540)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(22, 20, 22, 18)
        outer.setSpacing(14)

        header = QLabel("My hosted sites")
        header.setObjectName("CardTitle")
        header.setStyleSheet("font-size: 16px; font-weight: 700;")
        outer.addWidget(header)
        sub = QLabel(f"{len(sites)} site(s) on this machine.")
        sub.setObjectName("CardSub")
        outer.addWidget(sub)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(2, 2, 2, 2)
        lay.setSpacing(10)
        for site in sites:
            try:
                background = bool(background_for(site.name))
            except Exception:
                background = False
            target = getattr(site, "target", None) or "(target not saved yet)"
            lay.addWidget(_site_card(
                title=site.name,
                address=site.address,
                info_lines=[f"Target: {target}"],
                badge="● background" if background else "● manual",
                badge_color=GREEN if background else TEXT_DIM,
                on_open=on_open,
                on_copy=on_copy,
            ))
        lay.addStretch(1)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        footer = QHBoxLayout()
        footer.addStretch(1)
        close_btn = QPushButton("Close")
        close_btn.setObjectName("Mini")
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.clicked.connect(self.accept)
        footer.addWidget(close_btn)
        outer.addLayout(footer)


class _Worker(QObject):
    """Signal hub so background threads can update the UI thread safely."""
    log = Signal(str)
    diagnostic = Signal(str, bool)


class ObscuraApp(QMainWindow):
    """Main application window."""

    def __init__(self, background: bool = False, headless: bool = False):
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

        self._build_ui()

        # Poll component status every second (Qt timer, UI thread)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._poll)
        self._timer.start(1000)

        self._log("Welcome to Obscura47. Connect, then use the Sites tab to visit or publish sites.")

        # ── Background / autostart startup behaviour ───────────────
        # In headless mode the QWidgets window is only a logic engine behind
        # the QML UI, so it must never show itself - the QML launcher handles
        # minimize/auto-connect instead.
        if not headless and (background or self._settings.get("start_minimized", False)):
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
            QMessageBox.information(
                self, "My Hosted Sites",
                "No hosted sites yet.\n\nUse Add Site or Publish Site to "
                "create one.",
            )
            return

        try:
            from src.utils.daemon import daemon_installed
        except Exception:
            def daemon_installed(_name):  # background status unavailable
                return False

        dlg = _HostedSitesDialog(
            self,
            sites=hosted,
            background_for=daemon_installed,
            on_open=self._open_site_address,
            on_copy=self._copy_to_clipboard,
        )
        dlg.exec()

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
        name = self._prompt_text("Remove Site", "Site name:")
        if not name:
            return

        # Stop the background service (if any).
        removed_daemon = False
        try:
            from src.utils.daemon import uninstall_daemon
            removed_daemon = bool(uninstall_daemon(name))
        except Exception as exc:
            self._log(f"Could not remove background service for {name}: {exc}")

        # Withdraw the descriptor from the registry so the site stops showing
        # up when others run Discover.
        withdrawn = False
        try:
            from src.core.hidden_service import withdraw_descriptor_by_name
            withdrawn = withdraw_descriptor_by_name(name)
        except Exception as exc:
            self._log(f"Could not withdraw descriptor for {name}: {exc}")

        if not removed_daemon and not withdrawn:
            QMessageBox.information(
                self, "Remove Site",
                f"Nothing to remove for {name!r} - no background service or "
                f"published descriptor was found.",
            )
            self._log(f"Remove Site: nothing to remove for {name}.")
            return

        parts = []
        if removed_daemon:
            parts.append("background service removed")
        if withdrawn:
            parts.append("descriptor withdrawn from the registry")
        summary = f"{name}: " + ", ".join(parts) + "."
        QMessageBox.information(self, "Remove Site", summary)
        self._log(f"Remove Site - {summary}")

    def _discover_sites(self):
        """List every live .obscura site the registry knows about.

        Unlike Browse Directory (which queries one opt-in directory you must
        already know the address of), this reads the registry's global
        /hs/list, so it works with zero prior knowledge - the answer to
        "what's out there?". The dialog shows a loading state immediately,
        fetches on a background thread, then lists each site as a card with
        Open / Copy actions. Manifests are enriched when the proxy is up.
        """
        self._log("Discovering live .obscura sites…")
        dlg = _DiscoverDialog(
            self,
            connected=self._connected,
            on_open=self._open_site_address,
            on_copy=self._copy_to_clipboard,
            on_log=self._log,
        )
        dlg.exec()

    def _open_site_address(self, address: str):
        """Open a .obscura address in the browser, surfacing any error."""
        try:
            self._open_address_in_browser(address)
            self._log(f"Opened {address}.")
        except Exception as exc:
            QMessageBox.critical(self, "Open Site", str(exc))
            self._log(f"Could not open {address}: {exc}")

    def _copy_to_clipboard(self, text: str):
        QApplication.clipboard().setText(text)
        self._log(f"Copied {text} to clipboard.")

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


class Backend(QObject):
    """Bridge between the QML shell and the existing Obscura47 logic.

    The QML window is the face of the app; all behaviour is delegated to a
    headless :class:`ObscuraApp` (the proven QWidgets logic engine, never
    shown). That keeps every action - connect, discover, publish, diagnose,
    settings - identical to the classic UI while the visible surface is QML.
    Dialogs opened by those actions are themed by the same dark stylesheet.
    """

    changed = Signal()          # connection / metric / role state changed
    settingsChanged = Signal()  # autostart / start-minimized changed
    logLine = Signal(str)       # one formatted activity-log line

    def __init__(self, logic: "ObscuraApp"):
        super().__init__()
        self._logic = logic
        self._settings = _load_settings()

        # Mirror state, refreshed by _poll.
        self._connected = False
        self._relays = self._healthy = self._exits = 0
        self._status = "Disconnected"
        self._role = "Not connected"
        self._proxy = self._node = False

        # Forward the logic engine's log stream into the QML activity page.
        logic._signals.log.connect(self._forward_log)
        self.logLine.emit(self._stamp(
            "Welcome to Obscura47. Connect, then use Sites to visit or publish."))

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._poll)
        self._timer.start(1000)
        self._poll()

    # ── log forwarding ────────────────────────────────────────────────
    @staticmethod
    def _stamp(msg: str) -> str:
        return f"[{time.strftime('%H:%M:%S')}] {msg}"

    def _forward_log(self, msg: str):
        self.logLine.emit(self._stamp(msg))

    # ── read-only state properties ────────────────────────────────────
    def _g_connected(self):  return self._connected
    def _g_relays(self):     return self._relays
    def _g_healthy(self):    return self._healthy
    def _g_exits(self):      return self._exits
    def _g_status(self):     return self._status
    def _g_role(self):       return self._role
    def _g_proxy(self):      return self._proxy
    def _g_node(self):       return self._node

    connected     = Property(bool, _g_connected, notify=changed)
    relays        = Property(int,  _g_relays,    notify=changed)
    healthy       = Property(int,  _g_healthy,   notify=changed)
    exits         = Property(int,  _g_exits,     notify=changed)
    statusText    = Property(str,  _g_status,    notify=changed)
    roleText      = Property(str,  _g_role,      notify=changed)
    proxyRunning  = Property(bool, _g_proxy,     notify=changed)
    nodeRunning   = Property(bool, _g_node,      notify=changed)

    # ── settings properties ───────────────────────────────────────────
    def _g_autostart(self):       return bool(self._settings.get("autostart", False))
    def _g_start_minimized(self): return bool(self._settings.get("start_minimized", False))

    autostartEnabled     = Property(bool, _g_autostart,       notify=settingsChanged)
    startMinimizedEnabled = Property(bool, _g_start_minimized, notify=settingsChanged)

    # ── action slots (delegate to the logic engine) ───────────────────
    @Slot()
    def toggle(self):          self._logic._toggle_connection()
    @Slot()
    def openAddress(self):     self._logic._open_visitor()
    @Slot()
    def discover(self):        self._logic._discover_sites()
    @Slot()
    def browseDirectory(self): self._logic._browse_directory()
    @Slot()
    def hostedSites(self):     self._logic._show_hosted_sites()
    @Slot()
    def addSite(self):         self._logic._add_hosted_site()
    @Slot()
    def publishSite(self):     self._logic._publish_hosted_site()
    @Slot()
    def removeSite(self):      self._logic._remove_hosted_site_daemon()
    @Slot()
    def diagnose(self):        self._logic._diagnose_connection()
    @Slot()
    def quickStart(self):      self._logic._show_quick_start()
    @Slot()
    def requestExit(self):     self._logic._request_exit_status()

    # ── settings slots (handled here to stay independent of the hidden
    #    QWidgets checkboxes) ───────────────────────────────────────────
    @Slot(bool)
    def setAutostart(self, enabled: bool):
        self._settings["autostart"] = enabled
        _save_settings(self._settings)
        try:
            if enabled:
                setup_autostart(background=self._g_start_minimized())
                self.logLine.emit(self._stamp("Auto-start on login enabled."))
            else:
                remove_autostart()
                self.logLine.emit(self._stamp("Auto-start on login disabled."))
        except Exception as exc:
            self.logLine.emit(self._stamp(f"Could not update auto-start: {exc}"))
        self.settingsChanged.emit()

    @Slot(bool)
    def setStartMinimized(self, enabled: bool):
        self._settings["start_minimized"] = enabled
        _save_settings(self._settings)
        if self._g_autostart():
            try:
                setup_autostart(background=enabled)
            except Exception as exc:
                self.logLine.emit(self._stamp(f"Could not update auto-start: {exc}"))
        self.settingsChanged.emit()

    # ── polling ───────────────────────────────────────────────────────
    def _poll(self):
        counts = self._logic._get_peer_counts()
        connected = bool(self._logic._connected)
        proxy = bool(self._logic._running.get("proxy", False))
        node = bool(self._logic._running.get("node", False))
        both = proxy and node
        status = "Connected" if both else ("Connecting…" if connected else "Disconnected")
        # The hidden engine's own _poll keeps this label current.
        try:
            role = self._logic._role_label.text()
        except Exception:
            role = "Not connected"
        if not connected:
            role = "Not connected"

        new = (connected, counts["relays"], counts["healthy"], counts["exits"],
               status, role, proxy, node)
        old = (self._connected, self._relays, self._healthy, self._exits,
               self._status, self._role, self._proxy, self._node)
        if new != old:
            (self._connected, self._relays, self._healthy, self._exits,
             self._status, self._role, self._proxy, self._node) = new
            self.changed.emit()


def _run_qml(app: "QApplication", background: bool) -> int:
    """Launch the QML shell backed by a headless ObscuraApp. Returns exit code.

    Raises if the QML fails to load so the caller can fall back to classic.
    """
    from PySide6.QtQml import QQmlApplicationEngine

    logic = ObscuraApp(background=False, headless=True)  # hidden logic engine
    backend = Backend(logic)

    engine = QQmlApplicationEngine()
    engine.rootContext().setContextProperty("backend", backend)
    # When frozen by PyInstaller the data files live under sys._MEIPASS, not
    # next to this script - resolve both cases.
    base_dir = getattr(sys, "_MEIPASS", os.path.dirname(_APP_SCRIPT))
    qml_path = os.path.join(base_dir, "ui", "Main.qml")
    engine.load(QUrl.fromLocalFile(qml_path))
    if not engine.rootObjects():
        raise RuntimeError("QML failed to load")

    # Keep strong refs alive for the lifetime of the app.
    app._obscura_refs = (logic, backend, engine)

    # Autostart / start-minimized behaviour, driven from the QML side.
    if background or logic._settings.get("start_minimized", False):
        root = engine.rootObjects()[0]
        try:
            root.showMinimized()
        except Exception:
            pass
        backend.toggle()  # auto-connect

    return app.exec()


def main():
    parser = argparse.ArgumentParser(description="Obscura47")
    parser.add_argument(
        "--background", action="store_true",
        help="Start minimized and connect automatically (used by autostart)",
    )
    parser.add_argument(
        "--classic", action="store_true",
        help="Use the classic QWidgets interface instead of the QML UI",
    )
    args, _ = parser.parse_known_args()

    app = QApplication(sys.argv)
    app.setApplicationName("Obscura47")
    app.setStyleSheet(STYLESHEET)

    if not args.classic:
        try:
            sys.exit(_run_qml(app, background=args.background))
        except Exception as exc:
            # Never leave the user without a GUI: fall back to the classic UI.
            print(f"[gui] QML unavailable ({exc}); using classic interface.",
                  file=sys.stderr)

    window = ObscuraApp(background=args.background)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
