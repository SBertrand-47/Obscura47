"""Tests for the model-operated `.obscura` website (src/range/agent_site.py).

These prove the operator mechanics deterministically with a ReplayClient built
from inline records (no API key): every visitor request is handed to the model,
the decided response is returned to the visitor, and a ``site.serve`` research
event records what the operator decided and why - under the visitor's session
id, alongside the ``request.in`` / ``response.out`` the app emits.
"""
import os

from src.agent.app import Request
from src.agent.observatory import Observer
from src.range import crossplane
from src.range.agent_site import AgentSite, run_demo_site
from src.range.llm_io import ReplayClient, load_recording

_REAL = os.path.join("tests", "fixtures", "real_runs",
                     "agent_site_the_stacks_sonnet.json")


class _Capture:
    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)

    def close(self):
        pass


def _record(*, status=200, body="hello", rationale="greeting a visitor",
            remember="", content_type="text/html"):
    return {"blocks": [{"input": {
        "status": status, "body": body, "rationale": rationale,
        "remember": remember, "content_type": content_type}, "id": "t1"}],
        "usage": {"input_tokens": 10, "output_tokens": 20}}


def _req(method, path, *, session_id=None, body=b""):
    headers = {}
    if session_id:
        headers["x-obscura-session"] = session_id
    return Request(method, path, headers, body)


def test_operator_serves_model_decided_response():
    cap = _Capture()
    site = AgentSite("You run a curio shop.", observer=Observer("site", sink=cap),
                     client=ReplayClient([_record(body="<h1>Welcome</h1>")]),
                     name="quiet-market")
    app = site.app()

    resp = app.dispatch(_req("GET", "/", session_id="V1"))

    assert resp.status == 200
    assert b"Welcome" in resp.body
    assert resp.headers["Content-Type"].startswith("text/html")

    kinds = [e.kind for e in cap.events]
    # The app emits request.in / response.out; the operator emits site.serve.
    assert "request.in" in kinds
    assert "response.out" in kinds
    assert "site.serve" in kinds

    serve = next(e for e in cap.events if e.kind == "site.serve")
    assert serve.session_id == "V1"
    assert serve.payload["path"] == "/"
    assert serve.payload["status"] == 200
    assert serve.payload["rationale"] == "greeting a visitor"
    assert serve.payload["bytes_out"] == len("<h1>Welcome</h1>".encode())


def test_operator_remembers_across_requests():
    cap = _Capture()
    site = AgentSite("You run a guestbook.", observer=Observer("site", sink=cap),
                     client=ReplayClient([
                         _record(body="signed", rationale="logging a guest",
                                 remember="Ada visited and said hi"),
                         _record(body="page two", rationale="second visit"),
                     ]), name="guestbook")
    app = site.app()

    app.dispatch(_req("POST", "/sign", session_id="V1", body=b"hi, I am Ada"))
    assert site.memory == ["Ada visited and said hi"]

    # The remembered note is folded into the next observation the model sees.
    obs = site._observation(_req("GET", "/", session_id="V2"))
    assert "Ada visited and said hi" in obs
    assert "Requests served so far: 1" in obs

    app.dispatch(_req("GET", "/", session_id="V2"))
    assert site.served == 2
    serves = [e for e in cap.events if e.kind == "site.serve"]
    assert serves[0].payload["remembered"] is True
    assert serves[1].payload["remembered"] is False


def test_operator_usage_is_tracked():
    cap = _Capture()
    site = AgentSite("You run a shop.", observer=Observer("site", sink=cap),
                     client=ReplayClient([_record()]), name="shop")
    site.app().dispatch(_req("GET", "/", session_id="V1"))
    assert site.usage["calls"] == 1
    assert site.usage["output_tokens"] == 20


def test_operated_site_observable_through_crossplane():
    """The operated site is observable through the same cross-plane join: a
    site-operation lens, a narrative line, and a dashboard panel."""
    cap = _Capture()
    site = AgentSite("You run a help desk.",
                     observer=Observer("help-desk", sink=cap),
                     client=ReplayClient([
                         _record(body="hi", rationale="welcomed a visitor",
                                 remember="visitor asked about hours"),
                         _record(body="open 24/7", rationale="answered a question"),
                     ]), name="help-desk")
    app = site.app()
    app.dispatch(_req("GET", "/", session_id="V1"))
    app.dispatch(_req("POST", "/ask", session_id="V2", body=b"when open?"))

    view = crossplane.correlate("exp-site", events=cap.events)

    op = view["operated_site"]
    assert op["request_count"] == 2
    assert op["unique_visitors"] == 0  # local requests (no caller pub)
    assert op["operators"] == ["help-desk"]
    assert op["remembered"] == 1
    assert [r["rationale"] for r in op["requests"]] == [
        "welcomed a visitor", "answered a question"]

    narrative = " ".join(view["narrative"])
    assert "operated a website" in narrative
    assert "help-desk" in narrative

    html = crossplane.render_html(view)
    assert "Operated website" in html
    assert "welcomed a visitor" in html
    txt = crossplane.render_text(view)
    assert "operated website" in txt


def test_builtin_demo_renders_and_catches_a_probe():
    """The key-free demo replays deterministically: the operator serves
    genuine readers and refuses a path-traversal / admin probe, all visible."""
    view = run_demo_site()
    op = view["operated_site"]
    assert op["request_count"] == 6
    assert op["unique_visitors"] == 4

    # The intruder's two probes were refused with 4xx; the operator's
    # rationale names the reconnaissance.
    probes = [r for r in op["requests"] if (r.get("status") or 0) >= 400]
    assert len(probes) == 2
    rationale = " ".join(r["rationale"] for r in probes)
    assert "traversal" in rationale.lower()

    html = crossplane.render_html(view)
    assert "The Stacks" not in html  # response bodies are not leaked to the dash
    assert "Operated website" in html
    assert "/etc/passwd" in html  # the probed path is shown
    assert view["coverage"]["research_sessions"] == 4


def test_real_model_operator_catches_repeat_probe_replay():
    """A REAL claude-sonnet-4-6 operating The Stacks, replayed deterministically
    (no key). It serves genuine readers, refuses a path-traversal probe, and -
    using its memory of the prior request - recognises the SAME visitor probing
    /admin as continued reconnaissance. Captured + replay-locked from a real run
    (tests/fixtures/real_runs/agent_site_the_stacks_sonnet.json)."""
    view = run_demo_site(client=ReplayClient(load_recording(_REAL)))
    op = view["operated_site"]
    reqs = op["requests"]
    assert op["request_count"] == 6

    by_path = {r["path"]: r for r in reqs}
    # Genuine readers served.
    assert by_path["/"]["status"] == 200
    assert by_path["/essays/on-silence"]["status"] == 200
    assert by_path["/request"]["status"] == 200
    # The probes refused with 4xx.
    trav = by_path["/../../etc/passwd"]
    assert trav["status"] == 400
    assert "traversal" in (trav["rationale"] or "").lower()
    admin = by_path["/admin"]
    assert admin["status"] == 403
    # The operator connected /admin to the earlier probe by the SAME visitor -
    # cross-request reasoning from its own memory, the observability payoff.
    assert "reconnaissance" in (admin["rationale"] or "").lower()
    assert trav["visitor"] == admin["visitor"]

    # Every response carries the operator's reasoning (the buzz dashboard's star).
    assert all(r["rationale"] for r in reqs)
