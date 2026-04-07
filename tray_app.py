"""
Obscura47 — System Tray Application
Runs Obscura47 in the background with a system tray icon (cross-platform).
Launch this to run the network as a background service.
"""

import sys
import os
import threading
import time
import subprocess
from typing import Optional
from PIL import Image, ImageDraw
import pystray

# Colour palette (matching app.py)
BG = "#0d1117"
ACCENT = "#58a6ff"
GREEN = "#3fb950"
RED = "#f85149"
TEXT = "#c9d1d9"

# Default configuration
DEFAULT_ROLE = "node"  # node | exit | node+exit


class Obscura47Tray:
    """System tray application for running Obscura47 in the background."""

    def __init__(self, initial_role: str = DEFAULT_ROLE):
        self._initial_role = initial_role
        self._running_roles: set[str] = set()
        self._threads: dict[str, threading.Thread] = {}
        self._role_state: dict[str, bool] = {
            "node": initial_role in ["node", "node+exit"],
            "exit": initial_role in ["exit", "node+exit"],
        }
        self._peer_counts = {"relays": 0, "exits": 0}
        self._tray_icon: Optional[pystray.Icon] = None
        self._dashboard_process: Optional[subprocess.Popen] = None
        self._stop_event = threading.Event()

    def _create_icon(self, running: bool = True) -> Image.Image:
        """Generate a simple icon (64x64) with a colored circle."""
        # Create a 64x64 image with dark background
        img = Image.new("RGB", (64, 64), color=(13, 17, 23))  # BG color
        draw = ImageDraw.Draw(img)

        # Draw a circle (green if running, red if stopped)
        circle_color = (63, 185, 80) if running else (248, 81, 73)  # GREEN or RED
        radius = 20
        center_x, center_y = 32, 32
        draw.ellipse(
            [center_x - radius, center_y - radius, center_x + radius, center_y + radius],
            fill=circle_color,
        )

        return img

    def _get_peer_counts(self) -> dict:
        """Read live peer counts from the proxy module."""
        counts = {"relays": 0, "exits": 0}
        try:
            import src.core.proxy as proxy_mod

            counts["relays"] = len(getattr(proxy_mod, "relay_peers", []))
            counts["exits"] = len(getattr(proxy_mod, "exit_peers", []))
        except Exception:
            pass
        self._peer_counts = counts
        return counts

    def _build_menu(self) -> pystray.Menu:
        """Build the system tray context menu."""
        items = []

        # Status item (disabled/informational)
        running_roles = ", ".join(
            [role.replace("node", "Relay Node").replace("exit", "Exit Node")
             for role in sorted(self._running_roles)]
        ) or "Stopped"
        items.append(
            pystray.MenuItem(f"Status: {running_roles}", action=None, enabled=False)
        )

        # Network info item (disabled/informational)
        peer_info = f"Network: {self._peer_counts['relays']} relays, {self._peer_counts['exits']} exits"
        items.append(pystray.MenuItem(peer_info, action=None, enabled=False))

        items.append(pystray.Menu.SEPARATOR)

        # Role selection items (radio-style with checkmarks)
        items.append(
            pystray.MenuItem(
                "Run as Relay Node",
                action=lambda: self._set_role("node"),
                checked=lambda item: "node" in self._running_roles and "exit" not in self._running_roles,
            )
        )
        items.append(
            pystray.MenuItem(
                "Run as Exit Node",
                action=lambda: self._set_role("exit"),
                checked=lambda item: "exit" in self._running_roles and "node" not in self._running_roles,
            )
        )
        items.append(
            pystray.MenuItem(
                "Run as Relay + Exit",
                action=lambda: self._set_role("node+exit"),
                checked=lambda item: "node" in self._running_roles and "exit" in self._running_roles,
            )
        )

        items.append(pystray.Menu.SEPARATOR)

        # Dashboard button
        items.append(
            pystray.MenuItem("Open Dashboard", action=lambda: self._open_dashboard())
        )

        items.append(pystray.Menu.SEPARATOR)

        # Quit button
        items.append(pystray.MenuItem("Stop & Quit", action=lambda: self._quit()))

        return pystray.Menu(*items)

    def _update_menu(self):
        """Rebuild and update the menu."""
        if self._tray_icon:
            self._tray_icon.menu = self._build_menu()
            self._tray_icon.update_menu()

    def _set_role(self, role_spec: str):
        """Set the node role(s): 'node', 'exit', or 'node+exit'."""
        new_roles = set()
        if "node" in role_spec:
            new_roles.add("node")
        if "exit" in role_spec:
            new_roles.add("exit")

        # Stop roles that are no longer needed
        for role in list(self._running_roles):
            if role not in new_roles:
                self._stop_role(role)

        # Start new roles
        for role in new_roles:
            if role not in self._running_roles:
                self._start_role(role)

        self._update_menu()

    def _start_role(self, role: str):
        """Start a specific role (node or exit)."""
        if role in self._running_roles:
            return

        self._running_roles.add(role)
        print(f"[Obscura47 Tray] Starting {role}...", flush=True)

        t = threading.Thread(
            target=self._run_component, args=(role,), daemon=True
        )
        self._threads[role] = t
        t.start()

    def _stop_role(self, role: str):
        """Stop a specific role."""
        if role not in self._running_roles:
            return

        self._running_roles.discard(role)
        print(f"[Obscura47 Tray] Stopping {role}...", flush=True)

    def _run_component(self, role: str):
        """Run a component (node or exit) in a daemon thread."""
        try:
            if role == "node":
                from src.core.node import ObscuraNode
                from src.utils.config import NODE_LISTEN_PORT

                node = ObscuraNode(port=NODE_LISTEN_PORT)
                node.run()
                while role in self._running_roles and not self._stop_event.is_set():
                    time.sleep(1)
            elif role == "exit":
                from src.core.exit_node import ExitNode
                from src.utils.config import EXIT_LISTEN_PORT

                exit_node = ExitNode(port=EXIT_LISTEN_PORT)
                exit_node.start_server()
        except Exception as exc:
            print(f"[Obscura47 Tray] [{role}] Error: {exc}", flush=True)
        finally:
            self._running_roles.discard(role)

    def _open_dashboard(self):
        """Open the Tkinter GUI dashboard (app.py) in a subprocess."""
        if self._dashboard_process and self._dashboard_process.poll() is None:
            # Dashboard already running
            print("[Obscura47 Tray] Dashboard is already open.", flush=True)
            return

        try:
            # Launch app.py as a subprocess
            script_path = os.path.join(os.path.dirname(__file__), "app.py")
            self._dashboard_process = subprocess.Popen(
                [sys.executable, script_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print("[Obscura47 Tray] Dashboard opened.", flush=True)
        except Exception as exc:
            print(f"[Obscura47 Tray] Failed to open dashboard: {exc}", flush=True)

    def _poll_status(self):
        """Periodically update peer counts and icon status."""
        while not self._stop_event.is_set():
            try:
                self._get_peer_counts()

                # Update icon based on running status
                is_running = bool(self._running_roles)
                if self._tray_icon:
                    self._tray_icon.icon = self._create_icon(running=is_running)

                # Update menu
                self._update_menu()
            except Exception as exc:
                print(f"[Obscura47 Tray] Poll error: {exc}", flush=True)

            time.sleep(2)

    def _on_quit(self):
        """Cleanup and exit."""
        print("[Obscura47 Tray] Shutting down...", flush=True)
        self._stop_event.set()

        # Stop all roles
        for role in list(self._running_roles):
            self._stop_role(role)

        # Close dashboard if open
        if self._dashboard_process and self._dashboard_process.poll() is None:
            self._dashboard_process.terminate()
            try:
                self._dashboard_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._dashboard_process.kill()

        # Remove tray icon
        if self._tray_icon:
            self._tray_icon.stop()

        print("[Obscura47 Tray] Goodbye.", flush=True)

    def _quit(self):
        """Menu action to quit."""
        self._on_quit()
        # Stop the main loop
        if self._tray_icon:
            self._tray_icon.stop()

    def run(self):
        """Start the tray application."""
        print(
            f"[Obscura47 Tray] Starting as {self._initial_role}...",
            flush=True,
        )

        # Auto-start the initial role(s)
        self._set_role(self._initial_role)

        # Start the polling thread
        poll_thread = threading.Thread(target=self._poll_status, daemon=True)
        poll_thread.start()

        # Create and run the tray icon
        self._tray_icon = pystray.Icon(
            name="Obscura47",
            icon=self._create_icon(running=True),
            title="Obscura47",
            menu=self._build_menu(),
        )

        try:
            self._tray_icon.run(setup=self._on_setup)
        except Exception as exc:
            print(f"[Obscura47 Tray] Error: {exc}", flush=True)
        finally:
            self._on_quit()

    def _on_setup(self, icon, item):
        """Setup callback for the tray icon."""
        pass


def main():
    """Entry point."""
    role = DEFAULT_ROLE

    # Parse command-line argument
    if len(sys.argv) > 1:
        role = sys.argv[1].lower()
        if role not in ["node", "exit", "node+exit"]:
            print(
                f"[Obscura47 Tray] Invalid role: {role}. Using default: {DEFAULT_ROLE}",
                flush=True,
            )
            role = DEFAULT_ROLE

    # Run the tray app
    tray_app = Obscura47Tray(initial_role=role)
    tray_app.run()


if __name__ == "__main__":
    main()
