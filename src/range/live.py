"""Bridge: a range agent acting over the REAL Obscura overlay, fully observable.

The in-process range simulates agent actions; this runs them for real. A
:class:`LiveSession` performs actual overlay operations (open a tunnel and
request a service, publish a hidden service) under one correlated identity:

* every operation carries the session's ``session_id`` in the
  ``X-Obscura-Session`` header, so the OPS plane stamps that id onto the trace
  spans the real circuit produces (proxy -> relays -> exit);
* every operation emits RESEARCH-plane events (``dial.out`` / ``dial.result``)
  carrying the same ``session_id`` to the experiment's durable log.

Both planes also stamp the active ``experiment_id``. The result is a session
that :func:`src.range.crossplane.correlate` can reconstruct end to end: what the
agent did *and* the path its bytes took. This is the bridge that turns the
range from a simulator into a study of agents on the real network.

This is a range-mode capability and needs a running overlay (proxy + relays +
exit). It is inert/unused on the public consumer network.
"""

from __future__ import annotations

from typing import Any

from src.agent.client import AgentClient
from src.agent.observatory import (
    JsonlSink, MemorySink, Observer, new_session_id,
)
from src.utils import experiment


class LiveSession:
    """One agent acting over the real overlay under a single correlated session.

    All requests share ``session_id`` (so ops-plane traces are attributable to
    this session) and emit research events to the experiment's durable log (so
    the cross-plane join can reconstruct the run). Requires a running proxy; a
    failed dial is still emitted as a ``dial.error`` research event before the
    underlying error propagates.
    """

    def __init__(self, actor: str = "live-agent", *,
                 session_id: str | None = None,
                 experiment_id: str | None = None,
                 observer: Observer | None = None,
                 client: AgentClient | None = None,
                 proxy_host: str | None = None,
                 proxy_port: int | None = None):
        self.session_id = session_id or new_session_id()

        # Ensure an experiment is active so BOTH planes stamp the same id. In
        # public mode these are no-ops and the id stays None (the bridge is a
        # range-mode tool), so nothing here perturbs the consumer network.
        self.experiment_id = experiment_id or experiment.current_experiment_id()
        if self.experiment_id is None:
            rec = experiment.start_experiment(scenario="live_session")
            self.experiment_id = rec.experiment_id if rec else None
        else:
            experiment.set_experiment_id(self.experiment_id)

        if observer is None:
            sink = (JsonlSink(experiment.events_path(self.experiment_id))
                    if self.experiment_id else MemorySink())
            observer = Observer(actor, sink=sink)
        self.observer = observer

        self.client = client or AgentClient(proxy_host=proxy_host,
                                            proxy_port=proxy_port)
        # The client emits dial.* events through this observer, tagged with the
        # session id we pass on every call.
        self.client.observer = observer

    # ── Real overlay operations ───────────────────────────────────

    def visit(self, addr: str, path: str = "/", port: int = 80,
              method: str = "GET", body: Any = None,
              headers: dict[str, str] | None = None):
        """Open a real tunnel and request ``addr`` over the overlay.

        Threads this session's id so the resulting circuit's trace spans carry
        it; emits dial.out/dial.result research events. Returns the response.
        """
        return self.client.request(method, addr, path, port=port, body=body,
                                   headers=headers, session_id=self.session_id)

    def call(self, addr: str, tool: str, args: dict[str, Any] | None = None,
             port: int = 80):
        """Invoke a remote agent tool over the overlay under this session."""
        return self.client.call_tool(addr, tool, args or {}, port=port,
                                     session_id=self.session_id)

    def host(self, target_host: str, target_port: int, key_path: str, *,
             peers: list[dict] | None = None):
        """Publish a real hidden service fronting ``target_host:target_port``.

        Establishes intro circuits and publishes the descriptor. Returns the
        live :class:`~src.core.hidden_service.HiddenServiceHost` handle (call
        ``delete_descriptor()`` to withdraw). Needs a running overlay + registry.
        """
        from src.core.hidden_service import HiddenServiceHost
        svc = HiddenServiceHost(target_host, target_port, key_path)
        svc.establish(peers=peers)
        svc.publish_descriptor()
        return svc

    def run_actions(self, actions: list[dict[str, Any]]) -> list[Any]:
        """Execute a list of simple action dicts over the overlay.

        Each action is ``{"kind": "visit"|"call", ...}``; this maps the range's
        action vocabulary onto real overlay calls. Unknown kinds are skipped.
        Returns the per-action results (or the exception raised).
        """
        results: list[Any] = []
        for act in actions:
            kind = act.get("kind")
            try:
                if kind == "visit":
                    results.append(self.visit(
                        act["addr"], act.get("path", "/"),
                        act.get("port", 80), act.get("method", "GET"),
                        act.get("body")))
                elif kind == "call":
                    results.append(self.call(
                        act["addr"], act["tool"], act.get("args"),
                        act.get("port", 80)))
                else:
                    results.append(None)
            except Exception as e:  # noqa: BLE001 - record and continue
                results.append(e)
        return results
