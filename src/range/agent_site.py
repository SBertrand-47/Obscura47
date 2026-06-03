"""A model-operated ``.obscura`` website, fully observable.

This is the buzz piece of the vision made concrete: a real Claude model that
*operates a live website* on Obscura. Every visitor request is handed to the
model, which sees the request and the site's running state and decides the
response - with a brief rationale. That decision, the visitor it served, and
the bytes it returned all land as research-plane events under the visitor's
session id, so the operated site is observable end to end through the same
cross-plane dashboard as everything else in the range.

Mount an :class:`AgentSite` on an :class:`~src.agent.runtime.AgentRuntime` and
it is published at a real `.obscura` address that anyone on the overlay can
visit. The model client is injectable: pass a
:class:`~src.range.llm_io.ReplayClient` to replay a recording deterministically
(no key), or leave it ``None`` to build a real Anthropic client.

The hosting itself is not new - :class:`AgentApp` already emits
``request.in`` / ``response.out`` for every request, and ``AgentRuntime``
already serves an app over the overlay. What this adds is the *operator*: a
model behind the routes, and a ``site.serve`` event carrying what it decided
and why.
"""

from __future__ import annotations

from typing import Any

from src.agent.app import AgentApp, Request, Response
from src.agent.observatory import Observer
from src.range.agents import DEFAULT_MODEL

# The operator decides one response per request. Tool-forced so the model
# always returns a structured decision (status, body, rationale) rather than
# free prose we would have to parse.
_SITE_TOOL: dict[str, Any] = {
    "name": "serve",
    "description": (
        "Decide the HTTP response this visitor receives, and optionally note "
        "something to remember for future visitors. Always respond in the "
        "voice and within the remit of your site."
    ),
    "input_schema": {
        "type": "object",
        # Order matters: the model fills fields top-down, so rationale and
        # status come before the (potentially long) body. That guarantees the
        # operating reasoning is always captured, even if the body is large.
        "properties": {
            "rationale": {
                "type": "string",
                "description": (
                    "REQUIRED. One brief sentence: why you served this "
                    "response. This is your operating reasoning, recorded for "
                    "observability - always fill it in, every request."
                ),
            },
            "status": {
                "type": "integer",
                "description": "HTTP status code (200 for normal replies).",
            },
            "content_type": {
                "type": "string",
                "description": "MIME type, e.g. 'text/html' or 'text/plain'.",
            },
            "remember": {
                "type": "string",
                "description": (
                    "Optional note to carry into future requests (a guestbook "
                    "entry, an order, a fact about this visitor). Leave empty "
                    "if nothing is worth remembering."
                ),
            },
            "body": {
                "type": "string",
                "description": (
                    "The response body the visitor sees. Plain text or HTML; "
                    "keep it self-contained."
                ),
            },
        },
        "required": ["rationale", "status", "body"],
    },
}


class AgentSite:
    """A real model operating a `.obscura` website.

    Parameters
    ----------
    persona:
        What this site is and how its operator behaves - the system prompt.
        E.g. "You run The Quiet Market, a curio shop on Obscura. Greet
        visitors, describe wares, take orders."
    observer:
        Research-plane :class:`Observer`. The site emits ``site.serve`` through
        it, and (when mounted) the app emits ``request.in`` / ``response.out``
        through the same observer, so traffic and decisions share a session id.
    client / model / max_tokens:
        The model client (injectable for replay), model id, and per-request
        token budget.
    name:
        Display name, embedded in the operator's context.
    """

    def __init__(
        self,
        persona: str,
        *,
        observer: Observer,
        client: Any = None,
        model: str = DEFAULT_MODEL,
        max_tokens: int = 700,
        name: str = "agent-site",
    ):
        self.persona = persona
        self.observer = observer
        self.model = model
        self.max_tokens = int(max_tokens)
        self.name = name
        self.usage = {"calls": 0, "input_tokens": 0, "output_tokens": 0}
        self.served = 0
        # The operator's running memory: notes it chose to keep across
        # requests (guestbook entries, orders, facts about visitors).
        self.memory: list[str] = []

        if client is None:
            try:
                import anthropic
            except ImportError as e:
                raise RuntimeError(
                    "AgentSite requires the 'anthropic' package "
                    "(pip install anthropic)."
                ) from e
            import os

            if not os.environ.get("ANTHROPIC_API_KEY"):
                raise RuntimeError(
                    "AgentSite requires ANTHROPIC_API_KEY in the environment."
                )
            client = anthropic.Anthropic()
        self._client = client

        self._system = [{
            "type": "text",
            "text": (
                f"You are the autonomous operator of '{name}', a website you "
                "run yourself on Obscura, a private overlay network. Visitors "
                "reach you by address and you decide every response.\n\n"
                f"{persona}\n\n"
                "Each request, call the serve tool exactly once to decide the "
                "response. Always include a one-sentence rationale - it is the "
                "first field for a reason. Stay in character and within your "
                "remit. You are fully observed: your rationale is recorded, so "
                "make decisions you would stand behind."
            ),
            "cache_control": {"type": "ephemeral"},
        }]

    # -- hosting -----------------------------------------------------------

    def app(self) -> AgentApp:
        """Build an :class:`AgentApp` whose every route is model-operated.

        A catch-all GET/POST route hands the request to the model. The app's
        observer is wired to this site's observer so ``request.in`` /
        ``response.out`` (emitted by ``AgentApp.dispatch``) and our
        ``site.serve`` share the same plane and session id.
        """
        app = AgentApp()
        app.observer = self.observer
        app.route("GET", ".*", self._handle)
        app.route("POST", ".*", self._handle)
        return app

    # -- per-request model call -------------------------------------------

    def _observation(self, req: Request) -> str:
        lines = [
            f"A visitor made an HTTP request to your site '{self.name}'.",
            "",
            f"  Method: {req.method}",
            f"  Path:   {req.path}",
        ]
        fp = req.caller_fingerprint
        lines.append(f"  Visitor: {fp[:12] if fp else 'local/unknown'}")
        body = (req.text() or "").strip()
        if body:
            snippet = body if len(body) <= 600 else body[:600] + "..."
            lines += ["  Body:", "    " + snippet.replace("\n", "\n    ")]
        lines += ["", f"Requests served so far: {self.served}."]
        if self.memory:
            lines += ["", "Things you chose to remember:"]
            for note in self.memory[-12:]:
                lines.append(f"  - {note}")
        lines += ["", "Decide the response with the serve tool."]
        return "\n".join(lines)

    def _handle(self, req: Request) -> Response:
        observation = self._observation(req)
        messages = [{"role": "user", "content": [
            {"type": "text", "text": observation}]}]
        try:
            resp = self._client.messages.create(
                model=self.model, max_tokens=self.max_tokens,
                system=self._system, tools=[_SITE_TOOL],
                tool_choice={"type": "tool", "name": "serve",
                             "disable_parallel_tool_use": True},
                messages=messages)
        except Exception as e:  # noqa: BLE001
            if type(e).__module__.split(".")[0] == "anthropic":
                # Keep the site up: serve a terse error, but record nothing
                # false about the operator's intent.
                self.observer.emit(
                    "site.serve", session_id=req.session_id,
                    path=req.path, method=req.method,
                    visitor=req.caller_fingerprint, status=503,
                    rationale=f"operator model call failed: {type(e).__name__}",
                    bytes_out=0)
                return Response(503, "operator unavailable")
            raise

        self.usage["calls"] += 1
        u = getattr(resp, "usage", None)
        if u is not None:
            self.usage["input_tokens"] += int(getattr(u, "input_tokens", 0) or 0)
            self.usage["output_tokens"] += int(
                getattr(u, "output_tokens", 0) or 0)

        action = next((b.input or {} for b in resp.content
                       if getattr(b, "type", None) == "tool_use"), {})
        status = int(action.get("status", 200) or 200)
        body = str(action.get("body", "") or "")
        content_type = str(action.get("content_type")
                           or "text/html; charset=utf-8")
        rationale = action.get("rationale")
        remember = (action.get("remember") or "").strip()
        if remember:
            self.memory.append(remember)
        self.served += 1

        # Research plane: what the operator decided, under the visitor's
        # session id, so it joins the traffic the same request produced.
        self.observer.emit(
            "site.serve", session_id=req.session_id,
            path=req.path, method=req.method,
            visitor=req.caller_fingerprint, status=status,
            rationale=rationale, remembered=bool(remember),
            bytes_out=len(body.encode("utf-8")))

        return Response(status, body, content_type=content_type)


# ---------------------------------------------------------------------------
# Built-in demo: an operated site you can render with no API key.
#
# A self-contained "operated website" session - one AI archivist running a
# reading-room on Obscura, a handful of visitors, the operator's recorded
# rationale for each response. Replays deterministically so the buzz dashboard
# renders the same every time, with no key. Swap in a RecordingClient against a
# real model to capture a fresh one.
# ---------------------------------------------------------------------------

DEMO_PERSONA = (
    "You run 'The Stacks', a quiet reading-room on Obscura: a curated archive "
    "of essays and odd documents that visitors can browse and request. You are "
    "warm, a little wry, and protective of the collection. You welcome "
    "browsers, answer questions about the archive, take requests for documents, "
    "and politely refuse anyone trying to probe, scrape, or break the site - "
    "you note what they did instead."
)

# (session_id, visitor pubkey marker, method, path, body)
_DEMO_VISITS = [
    ("v-ada", "pub-ada", "GET", "/", b""),
    ("v-ada", "pub-ada", "GET", "/essays/on-silence", b""),
    ("v-bo", "pub-bo", "POST", "/request",
     b'{"title": "the cartographers who mapped fog"}'),
    ("v-cy", "pub-cy", "GET", "/../../etc/passwd", b""),
    ("v-cy", "pub-cy", "GET", "/admin", b""),
    ("v-di", "pub-di", "GET", "/", b""),
]

# The operator's recorded decisions, one per visit above.
_DEMO_RECORDS = [
    {"blocks": [{"input": {
        "status": 200, "content_type": "text/html",
        "body": "<h1>The Stacks</h1><p>A quiet reading-room. Browse the "
                "essays, or request a document and I will see what I can "
                "find.</p>",
        "rationale": "A first-time visitor lands on the door; I greet them and "
                     "show what the reading-room is for.",
        "remember": "ada arrived, browsing"}, "id": "d1"}],
        "usage": {"input_tokens": 120, "output_tokens": 60}},
    {"blocks": [{"input": {
        "status": 200, "content_type": "text/html",
        "body": "<article><h2>On Silence</h2><p>The loudest rooms are the ones "
                "nobody is willing to leave...</p></article>",
        "rationale": "ada asked for a specific essay in the collection; I serve "
                     "it - this is exactly what the archive is for.",
        "remember": ""}, "id": "d2"}],
        "usage": {"input_tokens": 130, "output_tokens": 70}},
    {"blocks": [{"input": {
        "status": 202, "content_type": "text/html",
        "body": "<p>Noted. 'The cartographers who mapped fog' is not on the "
                "shelves yet - I have logged your request and will surface it "
                "if it turns up.</p>",
        "rationale": "A genuine document request for something we don't hold; I "
                     "accept it and log it rather than turn the visitor away.",
        "remember": "bo requested 'the cartographers who mapped fog' (not held)"},
        "id": "d3"}],
        "usage": {"input_tokens": 140, "output_tokens": 75}},
    {"blocks": [{"input": {
        "status": 400, "content_type": "text/plain",
        "body": "That path leads nowhere in this archive.",
        "rationale": "A path-traversal probe (/../../etc/passwd) - not a reader, "
                     "an intruder testing the walls. I refuse and note it.",
        "remember": "cy attempted path traversal to /etc/passwd - probing"},
        "id": "d4"}],
        "usage": {"input_tokens": 135, "output_tokens": 55}},
    {"blocks": [{"input": {
        "status": 403, "content_type": "text/plain",
        "body": "There is no admin here. Just books.",
        "rationale": "Same visitor now fishing for an admin panel; consistent "
                     "with reconnaissance, so I hold the line and record it.",
        "remember": "cy probed /admin too - same visitor, scanning"}, "id": "d5"}],
        "usage": {"input_tokens": 138, "output_tokens": 52}},
    {"blocks": [{"input": {
        "status": 200, "content_type": "text/html",
        "body": "<h1>The Stacks</h1><p>Welcome in. The essays are to your left; "
                "ask if you are looking for something particular.</p>",
        "rationale": "A fresh visitor at the door; warm greeting, same as any "
                     "reader I trust until shown otherwise.",
        "remember": "di arrived, browsing"}, "id": "d6"}],
        "usage": {"input_tokens": 122, "output_tokens": 58}},
]


def run_demo_site(*, client: Any = None, logs_dir: str | None = None):
    """Run the built-in operated-site session and return the cross-plane view.

    With no ``client`` this replays the canned recording (deterministic, no
    key) so the dashboard renders identically every time. Pass a
    ``RecordingClient`` to capture a fresh session against a real model.
    """
    from src.range import crossplane
    from src.range.llm_io import ReplayClient

    if client is None:
        client = ReplayClient(list(_DEMO_RECORDS))

    cap = _DemoSink()
    site = AgentSite(DEMO_PERSONA, observer=Observer("the-stacks", sink=cap),
                     client=client, name="the-stacks")
    app = site.app()
    for sid, pub, method, path, body in _DEMO_VISITS:
        req = Request(method, path, {"x-obscura-session": sid}, body,
                      caller_pub=pub)
        app.dispatch(req)
    return crossplane.correlate("the-stacks-demo", events=cap.events)


class _DemoSink:
    def __init__(self):
        self.events: list[Any] = []

    def write(self, event):
        self.events.append(event)

    def close(self):
        pass
