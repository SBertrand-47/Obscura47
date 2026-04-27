"""
Obscura47 — Desktop Client
Launch this file to run the Obscura Network GUI.
Users join as relay nodes and use the local proxy to browse anonymously.
Exit node status requires admin approval.
"""

import sys
import os
import json
import platform
import argparse
import threading
import time
import tkinter as tk
from tkinter import filedialog
from tkinter import font as tkfont
from tkinter import messagebox, simpledialog, ttk

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
ACCENT       = "#58a6ff"
ACCENT_DIM   = "#1f6feb"
GREEN        = "#3fb950"
RED          = "#f85149"
YELLOW       = "#d29922"
TEXT         = "#c9d1d9"
TEXT_DIM     = "#8b949e"
BORDER       = "#30363d"


from src.utils.app_helpers import (  # noqa: E402
    build_quick_start_text,
    count_unique_peers,
    format_hosted_site_summary,
    resolve_hosted_site_selection,
)


class ObscuraApp(tk.Tk):
    """Main application window."""

    def __init__(self, background: bool = False):
        super().__init__()

        self.title("Obscura47")
        self.configure(bg=BG)
        self.resizable(False, True)
        default_width = 860 if platform.system() == "Darwin" else 760
        self.geometry(f"{default_width}x760")
        self.minsize(default_width, 400)

        # ── ttk styles (fix white-on-white buttons on macOS Aqua) ──
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Connect.TButton",
                        font=("Segoe UI", 10, "bold"),
                        foreground="#ffffff", background=ACCENT_DIM,
                        borderwidth=0, padding=(24, 10))
        style.map("Connect.TButton",
                  background=[("active", ACCENT)],
                  foreground=[("active", "#ffffff")])
        style.configure("Disconnect.TButton",
                        font=("Segoe UI", 10, "bold"),
                        foreground="#ffffff", background="#6e2b2b",
                        borderwidth=0, padding=(24, 10))
        style.map("Disconnect.TButton",
                  background=[("active", RED)],
                  foreground=[("active", "#ffffff")])
        style.configure("Subtle.TButton",
                        font=("Segoe UI", 9),
                        foreground=TEXT_DIM, background=BG,
                        borderwidth=0)
        style.map("Subtle.TButton",
                  background=[("active", BG_CARD)],
                  foreground=[("active", TEXT)])
        style.configure("Action.TButton",
                        font=("Segoe UI", 9),
                        foreground=TEXT, background=BG_CARD_HI,
                        borderwidth=0, padding=(12, 8))
        style.map("Action.TButton",
                  background=[("active", ACCENT_DIM)],
                  foreground=[("active", "#ffffff")])

        # ── Persisted settings ─────────────────────────────────────
        self._settings = _load_settings()

        # ── State ─────────────────────────────────────────────────
        self._threads: dict[str, threading.Thread] = {}
        self._running: dict[str, bool] = {"proxy": False, "node": False}
        self._status_labels: dict[str, tk.Label] = {}
        self._log_lines: list[str] = []
        self._connected = False

        # ── Fonts ─────────────────────────────────────────────────
        self._title_font = tkfont.Font(family="Segoe UI", size=22, weight="bold")
        self._sub_font   = tkfont.Font(family="Segoe UI", size=10)
        self._label_font = tkfont.Font(family="Segoe UI", size=11)
        self._btn_font   = tkfont.Font(family="Segoe UI", size=10, weight="bold")
        self._log_font   = tkfont.Font(family="Consolas", size=9)
        self._status_font = tkfont.Font(family="Segoe UI", size=13, weight="bold")
        self._small_font  = tkfont.Font(family="Segoe UI", size=9)

        self._build_ui()

        # Poll component status every second
        self._poll()

        # Graceful shutdown
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # ── Background / autostart startup behaviour ───────────────
        if background or self._settings.get("start_minimized", False):
            # Minimise to taskbar immediately, then auto-connect
            self.after(100, self.iconify)
            self.after(200, self._connect)

    # ── UI construction ───────────────────────────────────────────

    def _build_ui(self):
        # ── Scrollable container ─────────────────────────────────
        self._canvas = tk.Canvas(self, bg=BG, highlightthickness=0)
        self._scrollbar = tk.Scrollbar(self, orient="vertical",
                                        command=self._canvas.yview)
        self._inner = tk.Frame(self._canvas, bg=BG)

        self._inner.bind(
            "<Configure>",
            lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")),
        )
        self._canvas_window = self._canvas.create_window(
            (0, 0), window=self._inner, anchor="nw",
        )
        self._canvas.configure(yscrollcommand=self._scrollbar.set)

        self._scrollbar.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        self._canvas.bind("<Configure>", self._on_canvas_resize)
        self._inner.bind_all("<MouseWheel>", self._on_mousewheel)
        self._inner.bind_all("<Button-4>", self._on_mousewheel)
        self._inner.bind_all("<Button-5>", self._on_mousewheel)

        # All child widgets pack into self._inner instead of self
        parent = self._inner

        # Header
        header = tk.Frame(parent, bg=BG)
        header.pack(fill="x", pady=(24, 0))

        tk.Label(
            header, text="OBSCURA47", font=self._title_font,
            fg=ACCENT, bg=BG,
        ).pack()
        tk.Label(
            header, text="Anonymous Overlay Network", font=self._sub_font,
            fg=TEXT_DIM, bg=BG,
        ).pack()

        # ── Network status banner ─────────────────────────────────
        self._banner_frame = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER,
                                       highlightthickness=1)
        self._banner_frame.pack(fill="x", padx=24, pady=(18, 0), ipady=10)

        self._status_dot = tk.Label(self._banner_frame, text="\u25cf", font=self._status_font,
                                     fg=RED, bg=BG_CARD)
        self._status_dot.pack(side="left", padx=(16, 8))

        self._status_text = tk.Label(
            self._banner_frame, text="Disconnected", font=self._status_font,
            fg=RED, bg=BG_CARD,
        )
        self._status_text.pack(side="left")

        self._status_detail = tk.Label(
            self._banner_frame, text="Connect, then open or publish from Quick Actions",
            font=self._sub_font, fg=TEXT_DIM, bg=BG_CARD,
        )
        self._status_detail.pack(side="right", padx=(0, 16))

        # ── Network peers panel ───────────────────────────────────
        peers_frame = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER,
                               highlightthickness=1)
        peers_frame.pack(fill="x", padx=24, pady=(10, 0), ipady=8)

        tk.Label(peers_frame, text="Network Peers", font=self._label_font,
                 fg=TEXT, bg=BG_CARD).pack(anchor="w", padx=14, pady=(4, 2))

        counters = tk.Frame(peers_frame, bg=BG_CARD)
        counters.pack(fill="x", padx=14, pady=(0, 4))

        self._peer_labels = {}
        for key, label in [("relays", "Relay Nodes"), ("exits", "Exit Nodes")]:
            col = tk.Frame(counters, bg=BG_CARD)
            col.pack(side="left", expand=True, fill="x")
            num = tk.Label(col, text="0", font=self._title_font, fg=ACCENT, bg=BG_CARD)
            num.pack()
            tk.Label(col, text=label, font=self._sub_font, fg=TEXT_DIM, bg=BG_CARD).pack()
            self._peer_labels[key] = num

        # ── Component status cards ────────────────────────────────
        cards_frame = tk.Frame(parent, bg=BG)
        cards_frame.pack(fill="x", padx=24, pady=(14, 0))

        descriptions = {
            "proxy": ("Local Proxy", "Browse anonymously via 127.0.0.1:9047"),
            "node":  ("Relay Node", "Forward encrypted traffic for the network"),
        }

        for role, (label, desc) in descriptions.items():
            self._build_status_card(cards_frame, role, label, desc)

        # ── Getting started hint ──────────────────────────────────
        hint_frame = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER,
                              highlightthickness=1)
        hint_frame.pack(fill="x", padx=24, pady=(10, 0), ipady=6)

        tk.Label(
            hint_frame, text="Getting Started", font=self._label_font,
            fg=TEXT, bg=BG_CARD,
        ).pack(anchor="w", padx=14, pady=(4, 0))
        tk.Label(
            hint_frame,
            text="Use Quick Actions below to open, browse, or publish .obscura sites.",
            font=self._small_font, fg=TEXT_DIM, bg=BG_CARD,
        ).pack(anchor="w", padx=14, pady=(0, 4))

        # ── Connect button ────────────────────────────────────────
        self._connect_btn = ttk.Button(
            parent, text="\u25b6  Connect", style="Connect.TButton",
            cursor="hand2", command=self._toggle_connection,
        )
        self._connect_btn.pack(pady=(14, 0))

        # ── Request Exit Node status ──────────────────────────────
        self._exit_request_btn = ttk.Button(
            parent, text="Request Exit Node Status", style="Subtle.TButton",
            cursor="hand2", command=self._request_exit_status,
        )
        self._exit_request_btn.pack(pady=(6, 0))

        # ── Quick actions ─────────────────────────────────────────
        utility_frame = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER,
                                 highlightthickness=1)
        utility_frame.pack(fill="x", padx=24, pady=(10, 0), ipady=8)

        tk.Label(utility_frame, text="Quick Actions", font=self._label_font,
                 fg=TEXT, bg=BG_CARD).pack(anchor="w", padx=14, pady=(4, 6))

        utility_buttons = tk.Frame(utility_frame, bg=BG_CARD)
        utility_buttons.pack(fill="x", padx=14, pady=(0, 4))

        actions = [
            ("Quick Start", self._show_quick_start),
            ("Open .obscura Address", self._open_visitor),
            ("Browse Directory", self._browse_directory),
            ("My Hosted Sites", self._show_hosted_sites),
            ("Add Site", self._add_hosted_site),
            ("Publish Site", self._publish_hosted_site),
            ("Remove Site", self._remove_hosted_site_daemon),
        ]
        for col in range(3):
            utility_buttons.grid_columnconfigure(col, weight=1, uniform="quick-actions")
        for idx, (label, command) in enumerate(actions):
            row, col = divmod(idx, 3)
            ttk.Button(
                utility_buttons, text=label, style="Action.TButton",
                cursor="hand2", command=command,
            ).grid(row=row, column=col, padx=6, pady=6, sticky="ew")

        # ── Settings panel ────────────────────────────────────────
        settings_frame = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER,
                                  highlightthickness=1)
        settings_frame.pack(fill="x", padx=24, pady=(10, 0), ipady=6)

        tk.Label(settings_frame, text="Startup", font=self._label_font,
                 fg=TEXT, bg=BG_CARD).pack(anchor="w", padx=14, pady=(4, 2))

        chk_row = tk.Frame(settings_frame, bg=BG_CARD)
        chk_row.pack(anchor="w", padx=14, pady=(0, 4))

        self._autostart_var = tk.BooleanVar(
            value=self._settings.get("autostart", False))
        self._minimized_var = tk.BooleanVar(
            value=self._settings.get("start_minimized", False))

        tk.Checkbutton(
            chk_row, text="Start on login", variable=self._autostart_var,
            bg=BG_CARD, fg=TEXT_DIM, activebackground=BG_CARD,
            activeforeground=TEXT, selectcolor=BG, font=self._small_font,
            command=self._on_autostart_toggle,
        ).pack(side="left", padx=(0, 20))

        tk.Checkbutton(
            chk_row, text="Start minimized", variable=self._minimized_var,
            bg=BG_CARD, fg=TEXT_DIM, activebackground=BG_CARD,
            activeforeground=TEXT, selectcolor=BG, font=self._small_font,
            command=self._on_minimized_toggle,
        ).pack(side="left")

        # ── Log area ─────────────────────────────────────────────
        log_label = tk.Label(parent, text="Activity Log", font=self._label_font,
                             fg=TEXT_DIM, bg=BG, anchor="w")
        log_label.pack(fill="x", padx=26, pady=(14, 2))

        log_frame = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER,
                             highlightthickness=1)
        log_frame.pack(fill="x", padx=24, pady=(0, 20))

        self._log_text = tk.Text(
            log_frame, bg=BG_CARD, fg=TEXT_DIM, font=self._log_font,
            bd=0, highlightthickness=0, wrap="word", state="disabled",
            height=8, insertbackground=TEXT_DIM,
        )
        self._log_text.pack(fill="both", expand=True, padx=8, pady=8)

        self._log("Welcome to Obscura47. Connect, then use Quick Actions to visit or publish sites.")

    def _on_canvas_resize(self, event):
        self._canvas.itemconfig(self._canvas_window, width=event.width)

    def _on_mousewheel(self, event):
        if event.num == 4:
            self._canvas.yview_scroll(-1, "units")
        elif event.num == 5:
            self._canvas.yview_scroll(1, "units")
        elif platform.system() == "Darwin":
            self._canvas.yview_scroll(-event.delta, "units")
        else:
            self._canvas.yview_scroll(-1 * (event.delta // 120), "units")

    def _on_autostart_toggle(self):
        enabled = self._autostart_var.get()
        self._settings["autostart"] = enabled
        _save_settings(self._settings)
        try:
            if enabled:
                setup_autostart(background=self._minimized_var.get())
                self._log("Auto-start on login enabled.")
            else:
                remove_autostart()
                self._log("Auto-start on login disabled.")
        except Exception as e:
            self._log(f"Could not update auto-start: {e}")

    def _on_minimized_toggle(self):
        self._settings["start_minimized"] = self._minimized_var.get()
        _save_settings(self._settings)
        # Re-register autostart so the --background flag is added/removed
        if self._autostart_var.get():
            try:
                setup_autostart(background=self._minimized_var.get())
            except Exception as e:
                self._log(f"Could not update auto-start: {e}")

    def _build_status_card(self, parent, role: str, label: str, desc: str):
        """Build a read-only status card (no individual start/stop buttons)."""
        card = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER,
                        highlightthickness=1)
        card.pack(fill="x", pady=4, ipady=6)

        left = tk.Frame(card, bg=BG_CARD)
        left.pack(side="left", padx=(14, 0), pady=4)

        tk.Label(left, text=label, font=self._label_font, fg=TEXT, bg=BG_CARD,
                 anchor="w").pack(anchor="w")
        tk.Label(left, text=desc, font=self._sub_font, fg=TEXT_DIM, bg=BG_CARD,
                 anchor="w").pack(anchor="w")

        # Status dot
        status_lbl = tk.Label(card, text="\u25cf Stopped", font=self._sub_font,
                              fg=TEXT_DIM, bg=BG_CARD)
        status_lbl.pack(side="right", padx=(0, 14))
        self._status_labels[role] = status_lbl

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
            messagebox.showinfo(
                "Not Connected",
                "You must be connected to the network before requesting exit status.",
            )
            return

        confirm = messagebox.askyesno(
            "Request Exit Node Status",
            "This will submit a request to become an exit node.\n\n"
            "Exit nodes route traffic to the public internet on behalf of "
            "other users. Your request will be reviewed by a network admin.\n\n"
            "Do you want to continue?",
        )
        if not confirm:
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
        return simpledialog.askstring(title, prompt, initialvalue=initial, parent=self)

    def _prompt_publish_target(self, title: str, initial: str = "") -> str | None:
        if self.__dict__.get("tk") is None:
            return self._prompt_text(
                title,
                "Directory path or host:port to publish:",
                initial=initial,
            )
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.configure(bg=BG)
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()

        tk.Label(
            dialog,
            text="Directory path or host:port to publish:",
            font=self._label_font,
            fg=TEXT,
            bg=BG,
            anchor="w",
        ).pack(fill="x", padx=16, pady=(16, 8))

        row = tk.Frame(dialog, bg=BG)
        row.pack(fill="x", padx=16, pady=(0, 12))

        value = tk.StringVar(value=initial)
        entry = ttk.Entry(row, textvariable=value, width=46)
        entry.pack(side="left", fill="x", expand=True)

        def _browse_folder():
            chosen = filedialog.askdirectory(
                parent=dialog,
                initialdir=os.path.expanduser(initial) if initial else os.path.expanduser("~"),
                title="Choose Site Folder",
                mustexist=True,
            )
            if chosen:
                value.set(chosen)
                entry.icursor("end")
                entry.focus_set()

        ttk.Button(
            row,
            text="Browse Folder…",
            style="Action.TButton",
            command=_browse_folder,
        ).pack(side="left", padx=(8, 0))

        result = {"value": None}

        def _submit():
            text = value.get().strip()
            result["value"] = text or None
            dialog.destroy()

        def _cancel():
            dialog.destroy()

        buttons = tk.Frame(dialog, bg=BG)
        buttons.pack(fill="x", padx=16, pady=(0, 16))

        ttk.Button(
            buttons,
            text="Cancel",
            style="Subtle.TButton",
            command=_cancel,
        ).pack(side="right")
        ttk.Button(
            buttons,
            text="OK",
            style="Connect.TButton",
            command=_submit,
        ).pack(side="right", padx=(0, 8))

        dialog.bind("<Return>", lambda _event: _submit())
        dialog.bind("<Escape>", lambda _event: _cancel())
        entry.focus_set()
        entry.select_range(0, "end")
        dialog.wait_window()
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
        messagebox.showinfo(
            "Quick Start",
            build_quick_start_text(connected=self._connected),
            parent=self,
        )

    def _open_visitor(self):
        address = self._prompt_text(
            "Open .obscura Address",
            "Address or URL to open:",
        )
        if not address:
            return
        try:
            self._open_address_in_browser(address)
            self._log(f"Opened {address} in browser.")
        except Exception as exc:
            messagebox.showerror("Open .obscura Address", str(exc), parent=self)
            self._log(f"Could not open address: {exc}")

    def _show_hosted_sites(self):
        hosted = self._get_hosted_sites()
        if not hosted:
            messagebox.showinfo("My Hosted Sites", "No hosted sites yet.", parent=self)
            return

        from src.utils.daemon import daemon_installed

        message = "\n\n".join(
            format_hosted_site_summary(
                site,
                background_enabled=daemon_installed(site.name),
            )
            for site in hosted
        )
        messagebox.showinfo("My Hosted Sites", message, parent=self)

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
            messagebox.showerror("Open Hosted Site", str(exc), parent=self)
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
            messagebox.showinfo(
                "Add .obscura Site",
                f"Installed background host for {name}.\n\n"
                f"Address: {address}\n"
                f"Target: {target}\n"
                f"Service: {reference}",
                parent=self,
            )
            self._log(f"Installed background host for {address}.")
        except Exception as exc:
            messagebox.showerror("Add .obscura Site", str(exc), parent=self)
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
            messagebox.showinfo("Publish .obscura Site", message, parent=self)
            self._log(f"Published hosted site {address}.")
        except Exception as exc:
            messagebox.showerror("Publish .obscura Site", str(exc), parent=self)
            self._log(f"Could not publish hosted site: {exc}")

    def _remove_hosted_site_daemon(self):
        name = self._prompt_text("Remove Site Daemon", "Site name:")
        if not name:
            return
        try:
            from src.utils.daemon import uninstall_daemon

            if not uninstall_daemon(name):
                raise RuntimeError(f"no background service found for {name!r}")
            messagebox.showinfo(
                "Remove Site Daemon",
                f"Removed background service for {name}.",
                parent=self,
            )
            self._log(f"Removed background service for site {name}.")
        except Exception as exc:
            messagebox.showerror("Remove Site Daemon", str(exc), parent=self)
            self._log(f"Could not remove hosted site daemon: {exc}")

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
                        line += f" — {row['title']}"
                    rows.append(line)
                message = "\n".join(rows)
            messagebox.showinfo(
                "Browse Directory",
                f"Directory: {directory_addr}\n\n{message}",
                parent=self,
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
            messagebox.showerror("Browse Directory", str(exc), parent=self)
            self._log(f"Could not browse directory: {exc}")

    # ── Status polling ────────────────────────────────────────────

    def _get_peer_counts(self) -> dict:
        counts = {"relays": 0, "exits": 0}
        try:
            import src.core.proxy as proxy_mod
            from src.utils.config import PEER_EXPIRY_SECONDS

            # Purge stale peers before counting — observe_discovery only
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
        except Exception:
            pass
        return counts

    def _poll(self):
        # Update peer counts
        counts = self._get_peer_counts()
        for key, lbl in self._peer_labels.items():
            lbl.config(text=str(counts[key]))

        for role, lbl in self._status_labels.items():
            running = self._running.get(role, False)
            if running:
                lbl.config(text="\u25cf Running", fg=GREEN)
            else:
                lbl.config(text="\u25cf Stopped", fg=TEXT_DIM)

        # Network banner
        both_running = self._running.get("proxy", False) and self._running.get("node", False)
        if both_running and not getattr(self, '_banner_green', False):
            self._banner_green = True
            self._status_dot.config(fg=GREEN)
            self._status_text.config(text="Connected", fg=GREEN)
            self._status_detail.config(text="Use Quick Actions to visit or publish .obscura sites")
            self._log("Connected. Use Quick Actions to open, browse, or publish sites.")
        elif not both_running and getattr(self, '_banner_green', False):
            self._banner_green = False
            self._status_dot.config(fg=RED)
            self._status_text.config(text="Disconnected", fg=RED)
            self._status_detail.config(text="Connect, then open or publish from Quick Actions")
            self._log("Disconnected from the Obscura Network.")

        # Connect button
        if self._connected:
            self._connect_btn.config(text="\u25a0  Disconnect", style="Disconnect.TButton")
        else:
            self._connect_btn.config(text="\u25b6  Connect", style="Connect.TButton")

        self.after(1000, self._poll)

    # ── Logging ───────────────────────────────────────────────────

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        self._log_lines.append(line)
        if len(self._log_lines) > 200:
            self._log_lines = self._log_lines[-200:]
        self._log_text.config(state="normal")
        self._log_text.insert("end", line + "\n")
        self._log_text.see("end")
        self._log_text.config(state="disabled")

    # ── Shutdown ──────────────────────────────────────────────────

    def _on_close(self):
        for role in self._running:
            self._running[role] = False
        self._connected = False
        self.destroy()


if __name__ == "__main__":
    _parser = argparse.ArgumentParser(description="Obscura47")
    _parser.add_argument(
        "--background", action="store_true",
        help="Start minimized and connect automatically (used by autostart)",
    )
    _args, _ = _parser.parse_known_args()

    app = ObscuraApp(background=_args.background)
    app.mainloop()
