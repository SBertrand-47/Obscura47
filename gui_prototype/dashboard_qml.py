"""Obscura47 - QML dashboard prototype.

A standalone, *runnable* preview of what an Electron-grade UI looks like in
pure Python + Qt Quick (QML). It reuses the real backend (proxy + relay node
and the same peer-count logic as app.py), so the Connect button actually
joins the network and the metric cards show live numbers - this is a working
dashboard, not a mockup.

    python gui_prototype/dashboard_qml.py

Nothing here imports or modifies app.py; it is a side-by-side prototype so you
can compare the QML look against the current QWidgets app before deciding on a
full migration. Only QtQuick / QtQuick.Controls / QtQuick.Layouts are used -
all shipped in PySide6-Essentials, so there is no extra dependency.
"""

from __future__ import annotations

import os
import sys
import threading
import time

# Make `import src...` work when run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import QObject, Property, Signal, Slot, QTimer, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine

from src.utils.app_helpers import count_unique_peers


class DashboardBackend(QObject):
    """Bridge between the QML UI and the real Obscura47 network code.

    Exposes connection state, peer metrics, and the node role as QML
    properties, plus a ``toggle()`` slot wired to the Connect button. The
    network itself runs on daemon threads exactly like the production app.
    """

    changed = Signal()  # one notify signal drives every read-only property

    def __init__(self):
        super().__init__()
        self._connected = False
        self._running = {"proxy": False, "node": False}
        self._threads: dict[str, threading.Thread] = {}
        self._relays = 0
        self._healthy = 0
        self._exits = 0
        self._status = "Disconnected"
        self._role = "Not connected"

        # Poll live state once a second, same cadence as the QWidgets app.
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._poll)
        self._timer.start(1000)

    # ── Properties exposed to QML ─────────────────────────────────────
    def _get_connected(self):
        return self._connected

    def _get_relays(self):
        return self._relays

    def _get_healthy(self):
        return self._healthy

    def _get_exits(self):
        return self._exits

    def _get_status(self):
        return self._status

    def _get_role(self):
        return self._role

    connected = Property(bool, _get_connected, notify=changed)
    relays = Property(int, _get_relays, notify=changed)
    healthy = Property(int, _get_healthy, notify=changed)
    exits = Property(int, _get_exits, notify=changed)
    statusText = Property(str, _get_status, notify=changed)
    roleText = Property(str, _get_role, notify=changed)

    # ── Connect / disconnect ──────────────────────────────────────────
    @Slot()
    def toggle(self):
        if self._connected:
            self._disconnect()
        else:
            self._connect()

    def _connect(self):
        self._connected = True
        self._status = "Connecting…"
        self.changed.emit()
        for role in ("node", "proxy"):
            if not self._running[role]:
                self._running[role] = True
                t = threading.Thread(target=self._run_component, args=(role,), daemon=True)
                self._threads[role] = t
                t.start()

    def _disconnect(self):
        self._connected = False
        for role in self._running:
            self._running[role] = False
        self._status = "Disconnected"
        self._role = "Not connected"
        try:
            from src.core.internet_discovery import stop_heartbeat
            for role in ("node", "proxy"):
                stop_heartbeat(role)
        except Exception:
            pass
        self.changed.emit()

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
            print(f"[{role}] error: {exc}", file=sys.stderr)
        finally:
            self._running[role] = False

    # ── Live polling ──────────────────────────────────────────────────
    def _poll(self):
        counts = self._peer_counts()
        role = self._role_text()
        both = self._running.get("proxy") and self._running.get("node")
        status = self._status
        if self._connected:
            status = "Connected" if both else "Connecting…"
        else:
            status = "Disconnected"

        if (counts["relays"], counts["healthy"], counts["exits"], status, role) != (
            self._relays, self._healthy, self._exits, self._status, self._role
        ):
            self._relays = counts["relays"]
            self._healthy = counts["healthy"]
            self._exits = counts["exits"]
            self._status = status
            self._role = role
            self.changed.emit()

    def _peer_counts(self) -> dict:
        counts = {"relays": 0, "healthy": 0, "exits": 0}
        try:
            import src.core.proxy as proxy_mod
            from src.core import peer_health
            from src.utils.config import PEER_EXPIRY_SECONDS

            cutoff = time.time() - PEER_EXPIRY_SECONDS
            relay_list = getattr(proxy_mod, "relay_peers", [])
            exit_list = getattr(proxy_mod, "exit_peers", [])
            relay_list[:] = [p for p in relay_list if p.get("ts", 0) >= cutoff]
            exit_list[:] = [p for p in exit_list if p.get("ts", 0) >= cutoff]
            counts["relays"] = count_unique_peers(relay_list)
            counts["exits"] = count_unique_peers(exit_list)
            counts["healthy"] = count_unique_peers(peer_health.filter_healthy(relay_list))
        except Exception:
            pass
        return counts

    def _role_text(self) -> str:
        if not self._running.get("node"):
            return "Detecting…" if self._connected else "Not connected"
        try:
            from src.core.internet_discovery import get_role_kind, get_primary_peer
            kind = get_role_kind("node")
            primary = get_primary_peer()
        except Exception:
            return "Detecting…"
        if kind == "primary":
            return "Primary public node"
        if kind == "sibling":
            if primary and primary.get("host"):
                return f"Internal sibling · gateway {primary['host']}:{primary.get('port', '?')}"
            return "Internal sibling · waiting for primary"
        return "Detecting…"


def main():
    app = QGuiApplication(sys.argv)
    app.setApplicationName("Obscura47 (QML preview)")

    engine = QQmlApplicationEngine()
    backend = DashboardBackend()
    engine.rootContext().setContextProperty("backend", backend)

    qml_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Dashboard.qml")
    engine.load(QUrl.fromLocalFile(qml_path))
    if not engine.rootObjects():
        print("Failed to load Dashboard.qml", file=sys.stderr)
        sys.exit(1)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
