"""
Obscura47 — Windows Desktop App
Launch this file to run the Obscura Network GUI.
"""

import sys
import os
import threading
import time
import tkinter as tk
from tkinter import font as tkfont

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


class ObscuraApp(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        self.title("Obscura47")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.geometry("520x780")

        # ── State ─────────────────────────────────────────────────
        self._threads: dict[str, threading.Thread] = {}
        self._running: dict[str, bool] = {"registry": False, "proxy": False, "node": False, "exit": False}
        self._status_labels: dict[str, tk.Label] = {}
        self._toggle_btns: dict[str, tk.Button] = {}
        self._log_lines: list[str] = []
        self._network_active = False

        # ── Fonts ─────────────────────────────────────────────────
        self._title_font = tkfont.Font(family="Segoe UI", size=22, weight="bold")
        self._sub_font   = tkfont.Font(family="Segoe UI", size=10)
        self._label_font = tkfont.Font(family="Segoe UI", size=11)
        self._btn_font   = tkfont.Font(family="Segoe UI", size=10, weight="bold")
        self._log_font   = tkfont.Font(family="Consolas", size=9)
        self._status_font = tkfont.Font(family="Segoe UI", size=13, weight="bold")

        self._build_ui()

        # Poll component status every second
        self._poll()

        # Graceful shutdown
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── UI construction ───────────────────────────────────────────

    def _build_ui(self):
        # Header
        header = tk.Frame(self, bg=BG)
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
        self._banner_frame = tk.Frame(self, bg=BG_CARD, highlightbackground=BORDER,
                                       highlightthickness=1)
        self._banner_frame.pack(fill="x", padx=24, pady=(18, 0), ipady=10)

        self._status_dot = tk.Label(self._banner_frame, text="\u25cf", font=self._status_font,
                                     fg=RED, bg=BG_CARD)
        self._status_dot.pack(side="left", padx=(16, 8))

        self._status_text = tk.Label(
            self._banner_frame, text="Offline", font=self._status_font,
            fg=RED, bg=BG_CARD,
        )
        self._status_text.pack(side="left")

        self._status_detail = tk.Label(
            self._banner_frame, text="Start components below to join the network",
            font=self._sub_font, fg=TEXT_DIM, bg=BG_CARD,
        )
        self._status_detail.pack(side="right", padx=(0, 16))

        # ── Network peers panel ───────────────────────────────────
        peers_frame = tk.Frame(self, bg=BG_CARD, highlightbackground=BORDER,
                               highlightthickness=1)
        peers_frame.pack(fill="x", padx=24, pady=(10, 0), ipady=8)

        tk.Label(peers_frame, text="Network Peers", font=self._label_font,
                 fg=TEXT, bg=BG_CARD).pack(anchor="w", padx=14, pady=(4, 2))

        counters = tk.Frame(peers_frame, bg=BG_CARD)
        counters.pack(fill="x", padx=14, pady=(0, 4))

        self._peer_labels = {}
        for i, (key, label) in enumerate([("clients", "Clients"),
                                           ("relays", "Relay Nodes"),
                                           ("exits", "Exit Nodes")]):
            col = tk.Frame(counters, bg=BG_CARD)
            col.pack(side="left", expand=True, fill="x")
            num = tk.Label(col, text="0", font=self._title_font, fg=ACCENT, bg=BG_CARD)
            num.pack()
            tk.Label(col, text=label, font=self._sub_font, fg=TEXT_DIM, bg=BG_CARD).pack()
            self._peer_labels[key] = num

        # ── Component cards ───────────────────────────────────────
        cards_frame = tk.Frame(self, bg=BG)
        cards_frame.pack(fill="x", padx=24, pady=(14, 0))

        descriptions = {
            "registry": ("Registry", "Bootstrap server for internet discovery"),
            "proxy": ("Proxy", "Local SOCKS proxy on port 9047"),
            "node":  ("Relay Node", "Forward encrypted traffic"),
            "exit":  ("Exit Node", "Egress to the internet"),
        }

        for role, (label, desc) in descriptions.items():
            self._build_card(cards_frame, role, label, desc)

        # ── Quick-start button ────────────────────────────────────
        self._quick_btn = tk.Button(
            self, text="\u25b6  Start All", font=self._btn_font,
            fg="#ffffff", bg=ACCENT_DIM, activebackground=ACCENT,
            activeforeground="#ffffff", bd=0, padx=20, pady=8,
            cursor="hand2", command=self._toggle_all,
        )
        self._quick_btn.pack(pady=(14, 0))

        # ── Log area ─────────────────────────────────────────────
        log_label = tk.Label(self, text="Activity Log", font=self._label_font,
                             fg=TEXT_DIM, bg=BG, anchor="w")
        log_label.pack(fill="x", padx=26, pady=(14, 2))

        log_frame = tk.Frame(self, bg=BG_CARD, highlightbackground=BORDER,
                             highlightthickness=1)
        log_frame.pack(fill="both", expand=True, padx=24, pady=(0, 20))

        self._log_text = tk.Text(
            log_frame, bg=BG_CARD, fg=TEXT_DIM, font=self._log_font,
            bd=0, highlightthickness=0, wrap="word", state="disabled",
            height=8, insertbackground=TEXT_DIM,
        )
        self._log_text.pack(fill="both", expand=True, padx=8, pady=8)

        self._log("Welcome to Obscura47.")

    def _build_card(self, parent, role: str, label: str, desc: str):
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
        status_lbl.pack(side="right", padx=(0, 8))
        self._status_labels[role] = status_lbl

        btn = tk.Button(
            card, text="Start", font=self._btn_font, width=7,
            fg="#ffffff", bg=ACCENT_DIM, activebackground=ACCENT,
            activeforeground="#ffffff", bd=0, cursor="hand2",
            command=lambda r=role: self._toggle(r),
        )
        btn.pack(side="right", padx=(0, 10), pady=4)
        self._toggle_btns[role] = btn

    # ── Component lifecycle ───────────────────────────────────────

    def _toggle(self, role: str):
        if self._running[role]:
            self._stop(role)
        else:
            self._start(role)

    def _start(self, role: str):
        if self._running[role]:
            return
        self._running[role] = True
        self._log(f"Starting {role}...")
        t = threading.Thread(target=self._run_component, args=(role,), daemon=True)
        self._threads[role] = t
        t.start()

    def _run_component(self, role: str):
        try:
            if role == "registry":
                from src.core.registry import run_registry
                run_registry()
            elif role == "proxy":
                from src.core.proxy import start_proxy
                start_proxy()
            elif role == "node":
                from src.core.node import ObscuraNode
                from src.utils.config import NODE_LISTEN_PORT
                node = ObscuraNode(port=NODE_LISTEN_PORT)
                node.run()
                while self._running[role]:
                    time.sleep(1)
            elif role == "exit":
                from src.core.exit_node import ExitNode
                from src.utils.config import EXIT_LISTEN_PORT
                exit_node = ExitNode(port=EXIT_LISTEN_PORT)
                exit_node.start_server()
        except Exception as exc:
            self._log(f"[{role}] Error: {exc}")
        finally:
            self._running[role] = False

    def _stop(self, role: str):
        if not self._running[role]:
            return
        self._running[role] = False
        self._log(f"Stopping {role}... (will stop on next cycle)")
        # Daemon threads will be cleaned up on app exit;
        # for a graceful per-component stop we'd need cancellation
        # hooks in each server — fine for MVP.

    def _toggle_all(self):
        all_running = all(self._running.values())
        if all_running:
            for role in self._running:
                self._stop(role)
        else:
            for role in self._running:
                if not self._running[role]:
                    self._start(role)

    # ── Status polling ────────────────────────────────────────────

    def _get_peer_counts(self) -> dict:
        """Read live peer lists from the proxy module (includes both LAN and internet peers)."""
        counts = {"clients": 0, "relays": 0, "exits": 0}
        try:
            import src.core.proxy as proxy_mod
            counts["clients"] = len(getattr(proxy_mod, "client_peers", []))
            counts["relays"]  = len(getattr(proxy_mod, "relay_peers", []))
            counts["exits"]   = len(getattr(proxy_mod, "exit_peers", []))
        except Exception:
            pass
        return counts

    def _poll(self):
        # Update peer counts
        counts = self._get_peer_counts()
        for key, lbl in self._peer_labels.items():
            lbl.config(text=str(counts[key]))

        any_active = False
        for role, lbl in self._status_labels.items():
            running = self._running[role]
            if running:
                any_active = True
                lbl.config(text="\u25cf Running", fg=GREEN)
                self._toggle_btns[role].config(text="Stop", bg="#6e2b2b")
            else:
                lbl.config(text="\u25cf Stopped", fg=TEXT_DIM)
                self._toggle_btns[role].config(text="Start", bg=ACCENT_DIM)

        # Network banner
        if any_active and not self._network_active:
            self._network_active = True
            self._status_dot.config(fg=GREEN)
            self._status_text.config(text="Connected", fg=GREEN)
            self._status_detail.config(text="Your computer is part of the Obscura Network")
            self._log("You are now part of the Obscura Network.")
        elif not any_active and self._network_active:
            self._network_active = False
            self._status_dot.config(fg=RED)
            self._status_text.config(text="Offline", fg=RED)
            self._status_detail.config(text="Start components below to join the network")
            self._log("Disconnected from the Obscura Network.")

        # Quick-start button
        if all(self._running.values()):
            self._quick_btn.config(text="\u25a0  Stop All", bg="#6e2b2b")
        else:
            self._quick_btn.config(text="\u25b6  Start All", bg=ACCENT_DIM)

        self.after(1000, self._poll)

    # ── Logging ───────────────────────────────────────────────────

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        self._log_lines.append(line)
        # Keep last 200 lines
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
        self.destroy()


if __name__ == "__main__":
    app = ObscuraApp()
    app.mainloop()
