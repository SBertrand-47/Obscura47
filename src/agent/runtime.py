"""Reference harness that publishes a local HTTP app as a `.obscura` service.

Composes:
    - an :class:`AgentApp` (the local application surface)
    - a :class:`HiddenServiceHost` pointing at the bound app port
    - a background descriptor-republish loop

It is intentionally thin. The host process is expected to:

    1. construct an :class:`AgentApp` and register routes,
    2. instantiate :class:`AgentRuntime` with a service key path,
    3. call :meth:`AgentRuntime.start`.

Once started, the runtime exposes the address (``<label>.obscura``)
and bridges every inbound rendezvous session to the local app's bound
TCP port.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any

from src.agent.app import AgentApp, Request, Response, serve_app
from src.agent.sandbox import Sandbox, SandboxPolicy
from src.agent.tools import ParamSpec, ToolRegistry
from src.core.hidden_service import HiddenServiceHost
from src.core.router import set_proxy_ws_client, set_reverse_frame_callback
from src.utils.logger import get_logger
from src.utils.onion_addr import DESCRIPTOR_TTL

if TYPE_CHECKING:
    from src.agent.observatory import Observer

log = get_logger(__name__)


class AgentRuntime:
    """Bring up a `.obscura` service backed by a local HTTP app.

    Parameters
    ----------
    name:
        Display name embedded in the default ``/info`` route. Has no
        wire-protocol meaning.
    key_path:
        Path to the service ECC keypair on disk. Created if missing.
        The address is derived deterministically from the public key.
    app:
        Optional :class:`AgentApp`. If omitted, a default app is
        installed with ``/``, ``/health``, and ``/info`` routes.
    bind_host / bind_port:
        Local interface for the HTTP server. ``bind_port=0`` picks a
        free port. The host is local-only by default; the public
        address is the `.obscura` one.
    """

    def __init__(
        self,
        name: str,
        key_path: str,
        app: AgentApp | None = None,
        tools: ToolRegistry | None = None,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
        observer: "Observer | None" = None,
        policy: SandboxPolicy | None = None,
    ):
        self.name = name
        self.key_path = key_path
        self.bind_host = bind_host
        self.bind_port = int(bind_port)
        self.observer = observer
        self.policy = policy

        self._http_server = None
        self._http_thread: threading.Thread | None = None
        self._host: HiddenServiceHost | None = None
        self._republish_thread: threading.Thread | None = None
        self._stopped = threading.Event()
        self._started_at: float = 0.0
        self._sandbox_installed = False

        installed_default_app = False
        if app is None:
            app = AgentApp()
            _install_default_routes(app, self)
            installed_default_app = True
        self.app = app

        if tools is None:
            tools = ToolRegistry()
            if installed_default_app:
                _install_default_tools(tools, self)
        self.tools = tools
        self.tools.mount(self.app)

        if observer is not None:
            if self.app.observer is None:
                self.app.observer = observer
            if self.tools.observer is None:
                self.tools.observer = observer

    @property
    def address(self) -> str:
        if not self._host:
            raise RuntimeError("AgentRuntime not started")
        return self._host.address

    @property
    def pub_pem(self) -> str:
        if not self._host:
            raise RuntimeError("AgentRuntime not started")
        return self._host.pub_pem

    @property
    def local_url(self) -> str:
        if not self._http_server:
            raise RuntimeError("AgentRuntime not started")
        host, port = self._http_server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def started_at(self) -> float:
        return self._started_at

    def start(self, peers: list[dict[str, Any]] | None = None) -> bool:
        """Bind the local app, establish intro circuits, publish.

        Returns True on success. On any failure the partial state is
        torn down before returning.
        """
        self._http_server, self._http_thread = serve_app(
            self.app, self.bind_host, self.bind_port,
        )
        bound_host, bound_port = self._http_server.server_address[:2]
        log.info("Agent %s app on http://%s:%s", self.name, bound_host, bound_port)

        self._host = HiddenServiceHost(bound_host, bound_port, self.key_path)

        set_reverse_frame_callback(self._host._on_tcp_reverse)
        set_proxy_ws_client(self._host.ws_client)

        if not self._host.establish(peers=peers):
            log.error("Agent %s failed to establish intro circuits", self.name)
            self.stop()
            return False
        if not self._host.publish_descriptor():
            log.error("Agent %s failed to publish descriptor", self.name)
            self.stop()
            return False

        if self.policy is not None and not self._sandbox_installed:
            try:
                effective = _augment_policy_for_runtime(self.policy, peers=peers)
                Sandbox.install(effective, observer=self.observer)
                self._sandbox_installed = True
            except Exception as e:
                log.error("Agent %s failed to install sandbox: %s", self.name, e)
                self.stop()
                return False

        self._started_at = time.time()
        self._republish_thread = threading.Thread(
            target=self._republish_loop,
            name=f"agent-republish-{self.name}",
            daemon=True,
        )
        self._republish_thread.start()

        if self.observer is not None:
            try:
                self.observer.emit(
                    "runtime.start",
                    agent=self.name,
                    address=self.address,
                    local_url=self.local_url,
                )
            except Exception:
                log.exception("observer emit (runtime.start) failed")

        log.info("Agent %s reachable at %s → %s", self.name, self.address, self.local_url)
        return True

    def stop(self) -> None:
        """Tear down the HTTP server and the hidden-service host."""
        if self.observer is not None and not self._stopped.is_set():
            try:
                uptime = round(time.time() - self._started_at, 1) if self._started_at else 0.0
                self.observer.emit(
                    "runtime.stop", agent=self.name, uptime_s=uptime,
                )
            except Exception:
                pass
        self._stopped.set()
        if self._sandbox_installed:
            try:
                Sandbox.uninstall()
            except Exception:
                log.exception("sandbox uninstall failed")
            finally:
                self._sandbox_installed = False
        if self._http_server is not None:
            try:
                self._http_server.shutdown()
            except Exception:
                pass
            try:
                self._http_server.server_close()
            except Exception:
                pass
            self._http_server = None
        if self._host is not None:
            self._host._stopped.set()
            try:
                self._host.ws_client.close_all()
            except Exception:
                pass

    def join(self) -> None:
        """Block until :meth:`stop` is called or the process is interrupted."""
        try:
            while not self._stopped.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop()

    def _republish_loop(self) -> None:
        interval = max(60, DESCRIPTOR_TTL // 2)
        while not self._stopped.is_set():
            for _ in range(interval):
                if self._stopped.is_set():
                    return
                time.sleep(1)
            if self._stopped.is_set():
                return
            try:
                if self._host is not None:
                    self._host.publish_descriptor()
            except Exception as e:
                log.warning("descriptor republish failed: %s", e)


def _augment_policy_for_runtime(
    policy: SandboxPolicy,
    *,
    peers: list[dict[str, Any]] | None = None,
) -> SandboxPolicy:
    """Add the registry + bootstrap-peer endpoints to a user-supplied policy.

    The runtime's republish loop hits the registry over HTTP, and the
    rendezvous machinery dials peers' WebSocket ports. The operator
    generally won't think to allowlist these explicitly, so the
    runtime does it for them based on the bootstrap configuration.
    """
    from dataclasses import replace as _replace
    from urllib.parse import urlparse

    from src.utils.config import REGISTRY_URL

    extras = list(policy.relay_endpoints)
    parsed = urlparse(REGISTRY_URL)
    host = parsed.hostname
    if host:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        extras.append((host, int(port)))

    for peer in peers or []:
        peer_host = peer.get("host")
        if not peer_host:
            continue
        for key in ("port", "ws_port"):
            peer_port = peer.get(key)
            if peer_port:
                extras.append((str(peer_host), int(peer_port)))

    return _replace(policy, relay_endpoints=tuple(extras))


def _install_default_routes(app: AgentApp, runtime: AgentRuntime) -> None:
    @app.get("/")
    def _root(_req: Request) -> Response:
        return Response(200, {
            "agent": runtime.name,
            "endpoints": [
                "/health",
                "/info",
                "/.well-known/obscura/tools",
            ],
        })

    @app.get("/health")
    def _health(_req: Request) -> Response:
        return Response(200, {"ok": True})

    @app.get("/info")
    def _info(_req: Request) -> Response:
        try:
            address = runtime.address
        except RuntimeError:
            address = ""
        uptime = 0.0
        if runtime.started_at:
            uptime = round(time.time() - runtime.started_at, 1)
        return Response(200, {
            "agent": runtime.name,
            "address": address,
            "uptime_s": uptime,
        })


def _install_default_tools(tools: ToolRegistry, runtime: AgentRuntime) -> None:
    @tools.tool(
        "ping",
        description="Round-trip echo so callers can verify reachability.",
        params=[ParamSpec("payload", type="any", required=False,
                          description="optional value reflected back to the caller")],
        returns="object",
    )
    def _ping(args: dict, req: Request) -> dict:
        return {
            "agent": runtime.name,
            "received": args.get("payload"),
            "caller": req.caller_fingerprint,
            "ts": time.time(),
        }
