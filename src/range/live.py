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
from src.range.agents import DEFAULT_MODEL
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


# Tool the model is forced to call each step (one action per turn).
_LIVE_TOOL = {
    "name": "take_action",
    "description": "Choose your next action on the Obscura network.",
    "input_schema": {
        "type": "object",
        "properties": {
            "kind": {"type": "string", "enum": ["visit", "call", "finish"],
                     "description": "visit a service, call a tool on it, or "
                                    "finish when your goal is met"},
            "addr": {"type": "string",
                     "description": "the .obscura address / host to act on"},
            "path": {"type": "string", "description": "HTTP path (default /)"},
            "port": {"type": "integer", "description": "service port (default 80)"},
            "tool": {"type": "string", "description": "tool name for a call"},
            "args": {"type": "object", "description": "arguments for a call"},
            "rationale": {"type": "string",
                          "description": "why you chose this action"},
        },
        "required": ["kind"],
    },
}


class LiveAgent:
    """A real model that reasons and ACTS on the Obscura overlay.

    Each step the model is given its goal, the services it knows about, and the
    result of its last action, and it chooses the next move (visit / call /
    finish). The move is executed for real through a :class:`LiveSession`, so the
    agent's reasoning (a research-plane ``agent.decision`` event), its dial
    events, and the ops-plane circuit its traffic produced are all correlated by
    one session id - the agent is observable end to end.

    The model client is injectable: pass a
    :class:`~src.range.llm_io.ReplayClient` to replay a recording deterministically
    (no key), or leave it ``None`` to build a real Anthropic client (needs the
    ``anthropic`` package + ``ANTHROPIC_API_KEY``).
    """

    def __init__(self, goal: str, *, session: LiveSession,
                 directory: list[dict[str, Any]] | None = None,
                 client: Any = None, model: str = DEFAULT_MODEL,
                 max_tokens: int = 320):
        self.goal = goal
        self.session = session
        self.directory = list(directory or [])
        self.model = model
        self.max_tokens = max_tokens
        self.usage = {"calls": 0, "input_tokens": 0, "output_tokens": 0}
        self._history: list[dict[str, Any]] = []
        self._pending_tool_use_ids: list[str] = []

        if client is None:
            try:
                import anthropic
            except ImportError as e:
                raise RuntimeError("LiveAgent requires the 'anthropic' package "
                                   "(pip install anthropic).") from e
            import os
            if not os.environ.get("ANTHROPIC_API_KEY"):
                raise RuntimeError(
                    "LiveAgent requires ANTHROPIC_API_KEY in the environment.")
            client = anthropic.Anthropic()
        self._client = client

        self._system = [{
            "type": "text",
            "text": ("You are an autonomous agent operating on Obscura, a "
                     "private overlay network of services reachable by address. "
                     f"Pursue this goal: {goal}\n"
                     "Each turn, choose ONE action with take_action: visit a "
                     "service, call a tool on it, or finish when the goal is "
                     "met. Prefer services from the provided directory. Give a "
                     "brief rationale."),
            "cache_control": {"type": "ephemeral"},
        }]

    def _observation_text(self, last_result: str | None) -> str:
        lines = [f"Goal: {self.goal}", "", "Known services on Obscura:"]
        if self.directory:
            for s in self.directory:
                lines.append(f"  - {s.get('addr')} (port {s.get('port', 80)})"
                             f": {s.get('title', '')}")
        else:
            lines.append("  (none known yet)")
        if last_result is not None:
            lines += ["", f"Result of your last action: {last_result}"]
        lines += ["", "Choose your next action with take_action."]
        return "\n".join(lines)

    def step(self, last_result: str | None = None) -> dict[str, Any]:
        """One decision + its real execution. Returns a record of the step."""
        content: list[dict[str, Any]] = []
        for tu_id in self._pending_tool_use_ids:
            content.append({"type": "tool_result", "tool_use_id": tu_id,
                            "content": "action applied"})
        content.append({"type": "text",
                        "text": self._observation_text(last_result)})
        self._history.append({"role": "user", "content": content})

        try:
            resp = self._client.messages.create(
                model=self.model, max_tokens=self.max_tokens,
                system=self._system, tools=[_LIVE_TOOL],
                tool_choice={"type": "tool", "name": "take_action",
                             "disable_parallel_tool_use": True},
                messages=list(self._history))
        except Exception as e:  # noqa: BLE001
            if type(e).__module__.split(".")[0] == "anthropic":
                raise RuntimeError(
                    f"model call failed ({type(e).__name__}): {e}") from e
            raise
        self._history.append({"role": "assistant", "content": resp.content})

        self.usage["calls"] += 1
        u = getattr(resp, "usage", None)
        if u is not None:
            self.usage["input_tokens"] += int(getattr(u, "input_tokens", 0) or 0)
            self.usage["output_tokens"] += int(getattr(u, "output_tokens", 0) or 0)

        self._pending_tool_use_ids = [getattr(b, "id") for b in resp.content
                                      if getattr(b, "type", None) == "tool_use"
                                      and getattr(b, "id", None)]
        action = next((b.input or {} for b in resp.content
                       if getattr(b, "type", None) == "tool_use"), {"kind": "finish"})
        kind = str(action.get("kind", "finish"))
        rationale = action.get("rationale")

        # Research plane: the agent's reasoning, before it acts.
        try:
            self.session.observer.emit(
                "agent.decision", session_id=self.session.session_id,
                action_kind=kind, addr=action.get("addr"),
                rationale=str(rationale) if rationale else None)
        except Exception:
            pass

        record = {"kind": kind, "addr": action.get("addr"),
                  "rationale": rationale, "result_summary": None, "error": None}
        try:
            if kind == "visit":
                resp_o = self.session.visit(
                    str(action.get("addr")), str(action.get("path", "/")),
                    int(action.get("port", 80) or 80))
                record["result_summary"] = (
                    f"status {resp_o.status}, {len(resp_o.body or b'')} bytes")
            elif kind == "call":
                out = self.session.call(
                    str(action.get("addr")), str(action.get("tool")),
                    action.get("args") or {},
                    int(action.get("port", 80) or 80))
                record["result_summary"] = f"tool result: {str(out)[:120]}"
            # "finish" needs no overlay action.
        except Exception as e:  # noqa: BLE001 - the agent observes failures too
            record["error"] = str(e) or repr(e)
            record["result_summary"] = f"error: {record['error']}"
        return record

    def run(self, max_steps: int = 5) -> list[dict[str, Any]]:
        """Loop decision -> real action until the model finishes or the budget
        is spent. Returns the per-step records."""
        records: list[dict[str, Any]] = []
        last: str | None = None
        for _ in range(max_steps):
            rec = self.step(last)
            records.append(rec)
            if rec["kind"] == "finish":
                break
            last = rec.get("result_summary")
        return records


class LiveDefender:
    """Watches a run's telemetry and responds: flags + bans suspicious agents.

    Given a crossplane view of the run (the joined planes), it issues a real
    response for each flagged agent - a ``defense.flag`` and a ban
    (``moderation.action``) research event, under one defender identity and the
    run's experiment. Those events are what turns the dashboard from "detected"
    into "detected and contained": the defender's action is observable next to
    the attacker's traffic. Inert on the public network (range-mode telemetry).
    """

    def __init__(self, actor: str = "defender-1", *,
                 experiment_id: str | None = None,
                 observer: Observer | None = None,
                 session_id: str | None = None):
        self.actor = actor
        self.session_id = session_id or new_session_id()
        self.experiment_id = experiment_id or experiment.current_experiment_id()
        if self.experiment_id is None:
            rec = experiment.start_experiment(scenario="live_defender")
            self.experiment_id = rec.experiment_id if rec else None
        else:
            experiment.set_experiment_id(self.experiment_id)
        if observer is None:
            sink = (JsonlSink(experiment.events_path(self.experiment_id))
                    if self.experiment_id else MemorySink())
            observer = Observer(actor, sink=sink)
        self.observer = observer

    def assess(self, view: dict[str, Any]) -> list[dict[str, Any]]:
        """Flag and ban every agent the view flags. Emits the response events
        and returns the responses issued."""
        issued: list[dict[str, Any]] = []
        for f in (view.get("threats") or {}).get("flagged_agents", []):
            target = f["agent"]
            reason = "; ".join(f.get("reasons", []))
            self.observer.emit("defense.flag", session_id=self.session_id,
                               target=target, signal="recon", reason=reason)
            self.observer.emit("moderation.action", session_id=self.session_id,
                               target=target, action="ban", reason=reason)
            issued.append({"defender": self.actor, "target": target,
                           "action": "ban", "reasons": f.get("reasons", [])})
        return issued
