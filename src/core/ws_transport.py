"""
Obscura47 — WebSocket Transport Layer

Provides WSServer and WSClient for authenticated, persistent WebSocket
connections between nodes. Replaces raw TCP for node-to-node communication
while keeping the same frame format: {"encrypted_data": "<onion-sealed>"}

Each connection performs an ECDSA challenge-response handshake before
accepting frames.
"""

import asyncio
import json
import os
import secrets
import ssl
import threading
import time
from typing import Callable

import websockets
from websockets.asyncio.server import serve as ws_serve
from websockets.asyncio.client import connect as ws_connect

from src.core.encryptions import ecdsa_sign, ecdsa_verify
from src.utils.logger import get_logger

log = get_logger(__name__)


def _ws_is_open(ws) -> bool:
    """Return whether a websockets connection is still usable.

    websockets has changed its public connection-state API across releases:
    older versions expose ``open`` / ``closed`` booleans, while newer asyncio
    connections expose a ``state`` enum.  Keep the pool compatible so tunnel
    frames reuse the same WebSocket and preserve their reverse channel.
    """
    open_attr = getattr(ws, "open", None)
    if isinstance(open_attr, bool):
        return open_attr

    closed_attr = getattr(ws, "closed", None)
    if isinstance(closed_attr, bool):
        return not closed_attr

    state = getattr(ws, "state", None)
    state_name = getattr(state, "name", None)
    if isinstance(state_name, str):
        return state_name.upper() == "OPEN"
    if isinstance(state, int):
        return state == 1

    return True


def _build_server_ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    """Build an SSL context for the WSServer (TLS termination)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


def _build_client_ssl_context(verify: bool) -> ssl.SSLContext:
    """Build an SSL context for the WSClient, optionally skipping verification."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# -- WSServer -----------------------------------------------------

class WSServer:
    """
    Async WebSocket server that authenticates connecting peers via ECDSA
    and dispatches received frames to a callback.
    """

    def __init__(self, host: str, port: int, priv_key, pub_pem: str,
                 on_frame: Callable[[str], None],
                 tls_cert: str | None = None, tls_key: str | None = None):
        """
        Args:
            host: Bind address
            port: WebSocket port
            priv_key: This node's ECC private key (for identity)
            pub_pem: This node's public key PEM
            on_frame: Callback invoked with each received frame (JSON string)
            tls_cert: Optional path to TLS certificate (enables wss://)
            tls_key: Optional path to TLS private key
        """
        self.host = host
        self.port = port
        self.priv_key = priv_key
        self.pub_pem = pub_pem
        self.on_frame = on_frame
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.tls_enabled = bool(tls_cert and tls_key)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server = None

    async def _authenticate(self, websocket) -> bool:
        """Run ECDSA challenge-response handshake with connecting peer."""
        try:
            # Wait for auth message from connector
            raw = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            msg = json.loads(raw)

            if msg.get("type") != "auth" or not msg.get("pub"):
                await websocket.close(4001, "Expected auth message")
                return False

            peer_pub = msg["pub"]

            # Send challenge nonce
            nonce = secrets.token_hex(32)
            await websocket.send(json.dumps({
                "type": "challenge",
                "nonce": nonce,
            }))

            # Wait for proof
            raw = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            proof = json.loads(raw)

            if proof.get("type") != "proof" or not proof.get("sig"):
                await websocket.close(4002, "Expected proof message")
                return False

            # Verify ECDSA signature
            if not ecdsa_verify(peer_pub, nonce.encode(), proof["sig"]):
                await websocket.close(4003, "Invalid signature")
                return False

            # Auth OK
            await websocket.send(json.dumps({"type": "auth_ok"}))
            return True

        except (asyncio.TimeoutError, Exception) as e:
            try:
                await websocket.close(4000, f"Auth failed: {e}")
            except Exception:
                pass
            return False

    async def _handler(self, websocket):
        """Handle a single WebSocket connection after authentication."""
        if not await self._authenticate(websocket):
            return

        # Create a thread-safe send-back function for reverse-channel responses
        loop = self._loop or asyncio.get_event_loop()

        def _reverse_send(data: str):
            """Send data back to this connected peer (fire-and-forget)."""
            try:
                asyncio.run_coroutine_threadsafe(websocket.send(data), loop)
            except Exception:
                pass

        try:
            async for message in websocket:
                try:
                    self.on_frame(message, _reverse_send)
                except TypeError:
                    # Backward compat: on_frame doesn't accept reverse_send
                    self.on_frame(message)
                except Exception as e:
                    log.error(f"Frame handler error: {e}")
        except websockets.exceptions.ConnectionClosed:
            pass

    async def _serve(self):
        """Start the WebSocket server."""
        ssl_ctx = None
        if self.tls_enabled:
            ssl_ctx = _build_server_ssl_context(self.tls_cert, self.tls_key)
        self._server = await ws_serve(
            self._handler,
            self.host,
            self.port,
            ssl=ssl_ctx,
        )
        scheme = "wss" if self.tls_enabled else "ws"
        log.info(f"WebSocket server listening on {scheme}://{self.host}:{self.port}")
        try:
            await self._server.serve_forever()
        except asyncio.CancelledError:
            pass

    def start(self):
        """Start the WebSocket server in a dedicated background thread."""
        def _run():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._serve())

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return t

    def stop(self):
        """Stop the WebSocket server."""
        if self._server:
            self._server.close()


# -- WSClient -----------------------------------------------------

class WSClient:
    """
    Persistent WebSocket connection pool with ECDSA authentication.
    Manages connections to remote nodes, auto-reconnects on failure.
    """

    def __init__(self, priv_key, pub_pem: str,
                 queue_max: int = 100, idle_close_seconds: float = 60.0,
                 tls_verify: bool = True, on_receive=None):
        """
        Args:
            priv_key: This node's ECC private key (for signing challenges)
            pub_pem: This node's public key PEM
            queue_max: Max queued frames per connection before backpressure
            idle_close_seconds: Close connections idle longer than this
            tls_verify: Verify TLS certs when connecting via wss:// (False for dev)
            on_receive: Optional callback invoked with each message received on
                        outbound connections (used for reverse-channel frames).
        """
        self.priv_key = priv_key
        self.pub_pem = pub_pem
        self.queue_max = queue_max
        self.idle_close_seconds = idle_close_seconds
        self.tls_verify = tls_verify
        self.on_receive = on_receive

        # Connection pool: (host, port, tls) -> {"ws": websocket, "last": timestamp}
        self._connections: dict[tuple, dict] = {}
        self._conn_lock = threading.Lock()

        # Dedicated event loop for async WebSocket operations
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._run_loop, daemon=True)
        self._loop_thread.start()

        # Start idle sweeper
        threading.Thread(target=self._idle_sweeper, daemon=True).start()

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    async def _authenticate_to_server(self, ws) -> bool:
        """Perform ECDSA auth handshake as the connecting client."""
        # Send auth with our public key
        await ws.send(json.dumps({
            "type": "auth",
            "pub": self.pub_pem,
        }))

        # Receive challenge
        raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
        msg = json.loads(raw)
        if msg.get("type") != "challenge" or not msg.get("nonce"):
            return False

        # Sign the nonce
        sig = ecdsa_sign(self.priv_key, msg["nonce"].encode())
        await ws.send(json.dumps({
            "type": "proof",
            "sig": sig,
        }))

        # Wait for auth_ok
        raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
        result = json.loads(raw)
        return result.get("type") == "auth_ok"

    async def _receive_loop(self, ws):
        """Listen for incoming frames on an outbound WS connection.

        This enables the *reverse-channel* pattern: downstream nodes send
        response frames back on the same WebSocket the forward request
        travelled through, avoiding new inbound connections.
        """
        try:
            async for message in ws:
                if self.on_receive:
                    try:
                        self.on_receive(message)
                    except Exception as e:
                        log.error(f"WS receive handler error: {e}")
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception:
            pass

    async def _connect(self, host: str, port: int, tls: bool):
        """Establish and authenticate a WebSocket connection."""
        scheme = "wss" if tls else "ws"
        uri = f"{scheme}://{host}:{port}"
        kwargs = {}
        if tls:
            kwargs["ssl"] = _build_client_ssl_context(self.tls_verify)
        ws = await ws_connect(uri, **kwargs)
        if not await self._authenticate_to_server(ws):
            await ws.close()
            raise ConnectionRefusedError(f"Auth failed to {host}:{port}")
        # Start a listener for reverse-channel frames on this connection
        if self.on_receive:
            asyncio.ensure_future(self._receive_loop(ws))
        return ws

    async def _get_or_create(self, host: str, port: int, tls: bool):
        """Get existing connection or create a new one."""
        key = (host, port, tls)
        with self._conn_lock:
            entry = self._connections.get(key)
            if entry and entry.get("ws") and _ws_is_open(entry["ws"]):
                entry["last"] = time.time()
                return entry["ws"]

        # Create new connection (outside lock to avoid blocking)
        ws = await self._connect(host, port, tls)
        with self._conn_lock:
            self._connections[key] = {
                "ws": ws,
                "last": time.time(),
            }
        scheme = "wss" if tls else "ws"
        log.info(f"Connected via {scheme}:// to {host}:{port}")
        return ws

    async def _send_frame_async(self, host: str, port: int, frame_json: str,
                                 tls: bool) -> bool:
        """Send a frame over WebSocket, with auto-reconnect on failure."""
        key = (host, port, tls)
        try:
            ws = await self._get_or_create(host, port, tls)
            await ws.send(frame_json)
            with self._conn_lock:
                if key in self._connections:
                    self._connections[key]["last"] = time.time()
            return True
        except Exception as e:
            # Drop stale connection and retry once
            with self._conn_lock:
                old = self._connections.pop(key, None)
                if old and old.get("ws"):
                    try:
                        asyncio.ensure_future(old["ws"].close())
                    except Exception:
                        pass

            try:
                ws = await self._connect(host, port, tls)
                with self._conn_lock:
                    self._connections[key] = {
                        "ws": ws,
                        "last": time.time(),
                    }
                await ws.send(frame_json)
                return True
            except Exception as e2:
                log.error(f"Failed to send to {host}:{port}: {e2}")
                return False

    def send_frame(self, host: str, port: int, frame_json: str,
                   tls: bool = False) -> bool:
        """
        Send a frame to a remote node via WebSocket. Thread-safe.
        Returns True on success, False on failure.
        """
        future = asyncio.run_coroutine_threadsafe(
            self._send_frame_async(host, port, frame_json, tls),
            self._loop,
        )
        try:
            return future.result(timeout=5.0)
        except Exception as e:
            log.error(f"Send timeout/error to {host}:{port}: {e}")
            return False

    def close_connection(self, host: str, port: int, tls: bool = False):
        """Close a specific connection."""
        key = (host, port, tls)
        with self._conn_lock:
            entry = self._connections.pop(key, None)
        if entry and entry.get("ws"):
            asyncio.run_coroutine_threadsafe(entry["ws"].close(), self._loop)

    def close_all(self):
        """Close all connections."""
        with self._conn_lock:
            entries = list(self._connections.values())
            self._connections.clear()
        for entry in entries:
            if entry.get("ws"):
                try:
                    asyncio.run_coroutine_threadsafe(entry["ws"].close(), self._loop)
                except Exception:
                    pass

    def _idle_sweeper(self):
        """Background thread to close idle WebSocket connections."""
        while True:
            time.sleep(5)
            now = time.time()
            to_close = []
            with self._conn_lock:
                for key, entry in list(self._connections.items()):
                    if now - entry.get("last", now) > self.idle_close_seconds:
                        to_close.append((key, self._connections.pop(key)))
            for key, entry in to_close:
                if entry.get("ws"):
                    try:
                        asyncio.run_coroutine_threadsafe(entry["ws"].close(), self._loop)
                    except Exception:
                        pass
                    host, port = key[0], key[1]
                    log.info(f"Closed idle connection to {host}:{port}")


# -- Singleton client instance (lazily initialized per node) ------

_global_client: WSClient | None = None
_client_lock = threading.Lock()


def get_ws_client(priv_key=None, pub_pem: str = "", on_receive=None) -> WSClient | None:
    """Get or create the global WSClient instance.

    ``on_receive`` is an optional callback invoked with each message received
    on outbound WebSocket connections.  This enables the reverse-channel
    pattern where downstream nodes send response frames back through the
    same connection.
    """
    global _global_client
    with _client_lock:
        if _global_client is None and priv_key is not None:
            from src.utils.config import (
                CHANNEL_QUEUE_MAX, CHANNEL_IDLE_CLOSE_SECONDS, TLS_VERIFY,
            )
            _global_client = WSClient(
                priv_key, pub_pem,
                queue_max=CHANNEL_QUEUE_MAX,
                idle_close_seconds=CHANNEL_IDLE_CLOSE_SECONDS,
                tls_verify=TLS_VERIFY,
                on_receive=on_receive,
            )
        return _global_client
