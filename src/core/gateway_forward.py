"""Gateway inbound port forwarder.

A NAT "sibling" relay shares a public-IP slot with the gateway, so it can only
register on its LAN address and is unreachable to off-LAN dialers - which makes
it useless as a rendezvous/intro point even though it is online and healthy.

This module runs on the GATEWAY: it opens one or more inbound public ports and
relays each, byte-for-byte, to a sibling's LAN WebSocket port. The relay is
transparent - the WS upgrade, ECDSA authentication, and onion frames all pass
through untouched, terminated by the sibling's own ``WSServer``. The sibling
then advertises the gateway's public host plus the forwarded port (see the
``NODE_ADVERTISED_*`` config knobs) and dialers reach it like any public relay.

Mappings are static operator config (``OBSCURA_GATEWAY_FORWARDS``); dynamic
auto-provisioning is intentionally out of scope.
"""

import socket
import threading

from src.utils.config import SOCKET_CONNECT_TIMEOUT
from src.utils.logger import get_logger

log = get_logger(__name__)

# How long an accept() call blocks before waking to re-check self.running, so
# stop() takes effect promptly without a dedicated wakeup socket.
_ACCEPT_TIMEOUT = 1.0


class GatewayForwarder:
    """Relay inbound public ports to sibling LAN sockets (one mapping each).

    ``mappings`` is a list of ``(listen_port, target_host, target_port)``.
    Each listen_port gets a dedicated accept-loop thread; each accepted
    connection gets two pump threads (client->target and target->client).
    All threads are daemons, so the forwarder never blocks process exit.
    """

    def __init__(self, mappings: list[tuple[int, str, int]],
                 listen_host: str = "0.0.0.0", buf_size: int = 65536,
                 pool: list[int] | None = None):
        self.mappings = list(mappings)
        self.listen_host = listen_host
        self.buf_size = buf_size
        self.pool = list(pool or [])
        self.running = False
        # listen_port -> the bound server socket (so remove_mapping closes one)
        self._listeners: dict[int, socket.socket] = {}
        # (target_host, target_port) -> listen_port, for idempotent add_mapping
        self._active: dict[tuple[str, int], int] = {}
        self._lock = threading.Lock()

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        for listen_port, target_host, target_port in self.mappings:
            self._start_mapping(listen_port, target_host, target_port)

    def stop(self) -> None:
        self.running = False
        with self._lock:
            socks = list(self._listeners.values())
            self._listeners.clear()
            self._active.clear()
        for s in socks:
            try:
                s.close()
            except OSError:
                pass

    def add_mapping(self, target_host: str, target_port: int) -> int | None:
        """Allocate the next free pool port, start relaying to the target, and
        return the public listen port. Idempotent on (target_host, target_port):
        a repeat call returns the already-assigned port. Returns None if the
        pool is exhausted or the chosen port can't be bound.
        """
        self.running = True  # allow dynamic use even without a prior start()
        key = (target_host, int(target_port))
        with self._lock:
            existing = self._active.get(key)
            if existing is not None:
                return existing
            used = set(self._listeners) | set(self._active.values())
            listen_port = next((p for p in self.pool if p not in used), None)
            if listen_port is None:
                log.warning("Gateway forward: pool exhausted (%d ports), cannot "
                            "forward to %s:%s", len(self.pool), target_host, target_port)
                return None
            # Reserve the slot before releasing the lock so concurrent callers
            # don't pick the same port.
            self._active[key] = listen_port
        if self._start_mapping(listen_port, target_host, target_port):
            return listen_port
        with self._lock:
            self._active.pop(key, None)
        return None

    def remove_mapping(self, target_host: str, target_port: int) -> None:
        """Tear down the forward for a target, freeing its pool port."""
        key = (target_host, int(target_port))
        with self._lock:
            listen_port = self._active.pop(key, None)
            srv = self._listeners.pop(listen_port, None) if listen_port is not None else None
        if srv is not None:
            try:
                srv.close()  # unblocks the accept loop, which then exits
            except OSError:
                pass

    def _start_mapping(self, listen_port: int, target_host: str,
                       target_port: int) -> bool:
        srv = self._bind_listener(listen_port)
        if srv is None:
            return False
        with self._lock:
            self._listeners[listen_port] = srv
        log.info("Gateway forward: %s:%s -> %s:%s",
                 self.listen_host, listen_port, target_host, target_port)
        threading.Thread(
            target=self._accept_loop,
            args=(srv, listen_port, target_host, target_port),
            name=f"gw-forward-{listen_port}",
            daemon=True,
        ).start()
        return True

    def _bind_listener(self, listen_port: int) -> socket.socket | None:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.listen_host, listen_port))
            srv.listen(128)
            srv.settimeout(_ACCEPT_TIMEOUT)
            return srv
        except OSError as e:
            log.error("Gateway forward: cannot listen on %s:%s (%s)",
                      self.listen_host, listen_port, e)
            return None

    def _accept_loop(self, srv: socket.socket, listen_port: int,
                     target_host: str, target_port: int) -> None:
        while self.running:
            try:
                client_sock, _addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break  # listen socket closed by stop() / remove_mapping()
            threading.Thread(
                target=self._handle_conn,
                args=(client_sock, target_host, target_port),
                name=f"gw-forward-conn-{listen_port}",
                daemon=True,
            ).start()

        try:
            srv.close()
        except OSError:
            pass

    def _handle_conn(self, client_sock: socket.socket, target_host: str,
                     target_port: int) -> None:
        try:
            target_sock = socket.create_connection(
                (target_host, target_port), timeout=SOCKET_CONNECT_TIMEOUT)
        except OSError as e:
            log.warning("Gateway forward: cannot reach target %s:%s (%s)",
                        target_host, target_port, e)
            _close(client_sock)
            return

        # Two directions; either side closing tears down the other (a pump's
        # finally shuts down the peer socket, unblocking the paired recv).
        threading.Thread(target=self._pump, args=(client_sock, target_sock),
                         daemon=True).start()
        self._pump(target_sock, client_sock)

    def _pump(self, src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(self.buf_size)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass  # WS idle-close / reset is expected, not an error
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            _close(src)
            _close(dst)


def _close(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass
