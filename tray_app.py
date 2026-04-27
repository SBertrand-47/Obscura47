"""
Obscura47 — System Tray Application
Runs Obscura47 in the background with a system tray icon (cross-platform).
Launch this to run the network as a background service.

Users join as relay nodes by default. Exit node status requires admin approval.
"""

import sys
import os
import threading
import time
import subprocess
from typing import Optional
from PIL import Image, ImageDraw
import pystray
from src.utils.app_helpers import count_unique_peers

# Colour palette (matching app.py)
BG = "#0d1117"
ACCENT = "#58a6ff"
GREEN = "#3fb950"
RED = "#f85149"
TEXT = "#c9d1d9"


class Obscura47Tray:
    """System tray application for running Obscura47 in the background."""

    def __init__(self):
        self._running_roles: set[str] = set()
        self._threads: dict[str, threading.Thread] = {}
        self._hosted_sites: dict[str, threading.Thread] = {}
        self._peer_counts = {"relays": 0, "exits": 0}
        self._tray_icon: Optional[pystray.Icon] = None
        self._dashboard_process: Optional[subprocess.Popen] = None
        self._stop_event = threading.Event()

    def _create_icon(self, running: bool = True) -> Image.Image:
        """Generate a simple icon (64x64) with a colored circle."""
        img = Image.new("RGB", (64, 64), color=(13, 17, 23))
        draw = ImageDraw.Draw(img)

        circle_color = (63, 185, 80) if running else (248, 81, 73)
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

            counts["relays"] = count_unique_peers(getattr(proxy_mod, "relay_peers", []))
            counts["exits"] = count_unique_peers(getattr(proxy_mod, "exit_peers", []))
        except Exception:
            pass
        self._peer_counts = counts
        return counts

    def _build_menu(self) -> pystray.Menu:
        """Build the system tray context menu."""
        items = []

        # Status item
        running_roles = ", ".join(
            [role.replace("node", "Relay Node").replace("proxy", "Proxy")
             for role in sorted(self._running_roles)]
        ) or "Stopped"
        items.append(
            pystray.MenuItem(f"Status: {running_roles}", action=None, enabled=False)
        )

        # Network info
        peer_info = f"Network: {self._peer_counts['relays']} relays, {self._peer_counts['exits']} exits"
        items.append(pystray.MenuItem(peer_info, action=None, enabled=False))

        # Proxy address hint
        if "proxy" in self._running_roles:
            items.append(
                pystray.MenuItem("Proxy: 127.0.0.1:9047", action=None, enabled=False)
            )

        items.append(pystray.Menu.SEPARATOR)

        # Connect / Disconnect
        is_connected = bool(self._running_roles)
        if is_connected:
            items.append(
                pystray.MenuItem(
                    "Disconnect",
                    action=lambda: self._disconnect(),
                )
            )
        else:
            items.append(
                pystray.MenuItem(
                    "Connect to Network",
                    action=lambda: self._connect(),
                )
            )

        items.append(pystray.Menu.SEPARATOR)

        # Hosted sites submenu
        hosted = self._get_hosted_sites()
        site_items = []
        if hosted:
            from src.utils.daemon import daemon_installed

            for s in hosted:
                status = "daemon" if daemon_installed(s.name) else "manual"
                label = f"{s.name}  {s.address}  [{status}]"
                site_items.append(pystray.MenuItem(label, action=None, enabled=False))
            site_items.append(pystray.Menu.SEPARATOR)
        else:
            site_items.append(
                pystray.MenuItem("No hosted sites yet", action=None, enabled=False)
            )
            site_items.append(pystray.Menu.SEPARATOR)

        site_items.append(
            pystray.MenuItem(
                "My site addresses...",
                action=lambda: self._show_hosted_sites(),
            )
        )
        if hosted:
            site_items.append(
                pystray.MenuItem(
                    "Open hosted site...",
                    action=lambda: self._open_hosted_site(),
                )
            )
        site_items.append(
            pystray.MenuItem(
                "Add .obscura site...",
                action=lambda: self._add_hosted_site(),
            )
        )
        site_items.append(
            pystray.MenuItem(
                "Publish and announce site...",
                action=lambda: self._publish_hosted_site(),
            )
        )
        if hosted:
            site_items.append(
                pystray.MenuItem(
                    "Remove site daemon...",
                    action=lambda: self._remove_hosted_site_daemon(),
                )
            )
        items.append(pystray.MenuItem(
            f".obscura sites ({len(hosted)})",
            pystray.Menu(*site_items),
        ))

        items.append(pystray.Menu.SEPARATOR)

        # Visitor launcher
        items.append(
            pystray.MenuItem(
                "Open .obscura in browser",
                action=lambda: self._open_visitor(),
            )
        )
        items.append(
            pystray.MenuItem(
                "Browse directory...",
                action=lambda: self._browse_directory(),
            )
        )

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

    def _connect(self):
        """Start as relay node + proxy (the standard client role)."""
        for role in ("node", "proxy"):
            if role not in self._running_roles:
                self._start_role(role)
        self._update_menu()

    def _disconnect(self):
        """Stop all running roles."""
        for role in list(self._running_roles):
            self._stop_role(role)
        self._update_menu()

    def _start_role(self, role: str):
        """Start a specific role."""
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
        """Run a component in a daemon thread."""
        try:
            if role == "node":
                from src.core.node import ObscuraNode
                from src.utils.config import NODE_LISTEN_PORT

                node = ObscuraNode(port=NODE_LISTEN_PORT)
                node.run()
                while role in self._running_roles and not self._stop_event.is_set():
                    time.sleep(1)
            elif role == "proxy":
                from src.core.proxy import start_proxy
                start_proxy()
        except Exception as exc:
            print(f"[Obscura47 Tray] [{role}] Error: {exc}", flush=True)
        finally:
            self._running_roles.discard(role)

    def _open_dashboard(self):
        """Open the Tkinter GUI dashboard (app.py) in a subprocess."""
        if self._dashboard_process and self._dashboard_process.poll() is None:
            print("[Obscura47 Tray] Dashboard is already open.", flush=True)
            return

        try:
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

                is_running = bool(self._running_roles)
                if self._tray_icon:
                    self._tray_icon.icon = self._create_icon(running=is_running)

                self._update_menu()
            except Exception as exc:
                print(f"[Obscura47 Tray] Poll error: {exc}", flush=True)

            time.sleep(2)

    def _on_quit(self):
        """Cleanup and exit."""
        print("[Obscura47 Tray] Shutting down...", flush=True)
        self._stop_event.set()

        for role in list(self._running_roles):
            self._stop_role(role)

        if self._dashboard_process and self._dashboard_process.poll() is None:
            self._dashboard_process.terminate()
            try:
                self._dashboard_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._dashboard_process.kill()

        if self._tray_icon:
            self._tray_icon.stop()

        print("[Obscura47 Tray] Goodbye.", flush=True)

    def _quit(self):
        """Menu action to quit."""
        self._on_quit()
        if self._tray_icon:
            self._tray_icon.stop()

    def run(self):
        """Start the tray application."""
        print("[Obscura47 Tray] Starting...", flush=True)

        # Auto-connect on launch
        self._connect()

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

    def _open_visitor(self):
        try:
            url = self._prompt_text(
                "Open .obscura Address",
                "Address or URL to open (leave blank for a new tab):",
            )
            if url is None:
                return
            from src.utils.visitor import open_in_browser
            if not open_in_browser(url=url):
                raise RuntimeError("proxy startup or browser launch failed")
            print("[Obscura47 Tray] Browser opened with .obscura routing.", flush=True)
        except Exception as exc:
            print(f"[Obscura47 Tray] Failed to open browser: {exc}", flush=True)

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
            self._show_dialog(
                "Obscura47",
                f"Directory: {directory_addr}\n\n{message}",
            )
            if listings:
                initial = listings[0].get("address", "")
                selected = self._prompt_text(
                    "Open Directory Listing",
                    "Address to open now (optional):",
                    initial=initial,
                )
                if selected:
                    self._open_address_in_browser(selected)
        except Exception as exc:
            self._show_dialog("Obscura47", f"Could not browse directory:\n{exc}", error=True)

    def _get_hosted_sites(self) -> list:
        try:
            from src.utils.sites import list_sites
            return list(list_sites())
        except Exception:
            return []

    def _prompt_text(self, title: str, prompt: str, initial: str = "") -> str | None:
        import tkinter as tk
        from tkinter import simpledialog

        root = tk.Tk()
        root.withdraw()
        try:
            return simpledialog.askstring(title, prompt, initialvalue=initial, parent=root)
        finally:
            root.destroy()

    def _show_dialog(self, title: str, message: str, *, error: bool = False):
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        try:
            if error:
                messagebox.showerror(title, message, parent=root)
            else:
                messagebox.showinfo(title, message, parent=root)
        finally:
            root.destroy()

    def _open_address_in_browser(self, address: str):
        from src.utils.visitor import open_in_browser

        if not open_in_browser(url=address):
            raise RuntimeError("proxy startup or browser launch failed")

    def _resolve_hosted_site_address(self, raw_value: str) -> str:
        value = (raw_value or "").strip()
        if not value:
            raise ValueError("site name or address is required")
        if value.endswith(".obscura"):
            return value
        for site in self._get_hosted_sites():
            if site.name == value:
                return site.address
        raise ValueError(f"unknown hosted site: {value}")

    def _format_site_summary(self, site) -> str:
        from src.utils.daemon import daemon_installed

        status = "background" if daemon_installed(site.name) else "manual"
        target = site.target or "(target not saved yet)"
        return (
            f"{site.name}\n"
            f"  Address: {site.address}\n"
            f"  Target: {target}\n"
            f"  Mode: {status}"
        )

    def _show_hosted_sites(self):
        hosted = self._get_hosted_sites()
        if not hosted:
            self._show_dialog("Obscura47", "No hosted sites yet.")
            return
        message = "\n\n".join(self._format_site_summary(site) for site in hosted)
        self._show_dialog("Obscura47", message)

    def _open_hosted_site(self):
        hosted = self._get_hosted_sites()
        if not hosted:
            self._show_dialog("Obscura47", "No hosted sites yet.")
            return

        choices = ", ".join(site.name for site in hosted)
        selected = self._prompt_text(
            "Open Hosted Site",
            f"Site name or .obscura address:\n\nAvailable: {choices}",
            initial=hosted[0].name,
        )
        if not selected:
            return

        try:
            address = self._resolve_hosted_site_address(selected)
            self._open_address_in_browser(address)
            self._show_dialog("Obscura47", f"Opened {address} in your browser.")
        except Exception as exc:
            self._show_dialog("Obscura47", f"Could not open hosted site:\n{exc}", error=True)

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
        target = self._prompt_text(
            "Add .obscura Site",
            "Directory path or host:port to publish:",
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
            self._show_dialog(
                "Obscura47",
                f"Installed background host for {name}.\n\n"
                f"Address: {self._address_from_pub(pub)}\n"
                f"Target: {target}\n"
                f"Service: {reference}",
            )
        except Exception as exc:
            self._show_dialog("Obscura47", f"Could not add site:\n{exc}", error=True)
        finally:
            self._update_menu()

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
        target = self._prompt_text(
            "Publish .obscura Site",
            "Directory path or host:port to publish:",
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
            self._show_dialog("Obscura47", message)
        except Exception as exc:
            self._show_dialog("Obscura47", f"Could not publish site:\n{exc}", error=True)
        finally:
            self._update_menu()

    def _remove_hosted_site_daemon(self):
        name = self._prompt_text("Remove Site Daemon", "Site name:")
        if not name:
            return

        try:
            from src.utils.daemon import uninstall_daemon

            if not uninstall_daemon(name):
                raise RuntimeError(f"no background service found for {name!r}")
            self._show_dialog("Obscura47", f"Removed background service for {name}.")
        except Exception as exc:
            self._show_dialog("Obscura47", f"Could not remove site daemon:\n{exc}", error=True)
        finally:
            self._update_menu()

    @staticmethod
    def _address_from_pub(pub: str) -> str:
        from src.utils.onion_addr import address_from_pubkey

        return address_from_pubkey(pub)

    def _on_setup(self, icon, item):
        """Setup callback for the tray icon."""
        pass


def main():
    """Entry point."""
    tray_app = Obscura47Tray()
    tray_app.run()


if __name__ == "__main__":
    main()
