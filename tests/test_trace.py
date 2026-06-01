"""Tests for ops-plane distributed tracing (src/utils/trace.py).

Tracing is operator-only: a hard no-op unless BOTH range mode and diag are on.
When active it must build a proper parent/child span chain along the route.
"""
import pytest

from src.utils import config, diag, trace


@pytest.fixture
def captured(monkeypatch):
    """Activate tracing (range + diag) and capture diag emissions."""
    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setenv("OBSCURA_DIAG", "1")
    spans = []
    monkeypatch.setattr(diag, "emit", lambda event, **f: spans.append((event, f)))
    return spans


@pytest.fixture
def public(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    monkeypatch.setenv("OBSCURA_DIAG", "1")  # even with diag on, public stays inert
    spans = []
    monkeypatch.setattr(diag, "emit", lambda event, **f: spans.append((event, f)))
    return spans


class TestInert:
    def test_inactive_without_range(self, public):
        assert trace.is_active() is False
        assert trace.start_trace("r1", exit="e:9") is None
        assert trace.relay_span(
            {"id": "r1", "parent": "p", "hop": 1}, request_id="r1",
            frame_type="connect", next_host="h", next_port=1) is None
        trace.terminal_span({"id": "r1", "parent": "p", "hop": 2},
                            request_id="r1", role="exit")
        assert public == []  # nothing emitted

    def test_inactive_without_diag(self, monkeypatch):
        monkeypatch.setattr(config, "IS_RANGE_MODE", True)
        monkeypatch.setenv("OBSCURA_DIAG", "")
        monkeypatch.setenv("OBSCURA_DIAG_REGISTRY", "")
        assert trace.is_active() is False
        assert trace.start_trace("r1") is None


class TestChain:
    def test_full_route_forms_a_tree(self, captured):
        assert trace.is_active() is True
        block = trace.start_trace("reqA", exit="e:9", route_len=3)
        assert block == {"id": "reqA", "parent": block["parent"], "hop": 1}

        b1 = trace.relay_span(block, request_id="reqA", frame_type="connect",
                              next_host="r2", next_port=2)
        b2 = trace.relay_span(b1, request_id="reqA", frame_type="connect",
                              next_host="e", next_port=9)
        trace.terminal_span(b2, request_id="reqA", role="exit",
                            target_host="ex.com", target_port=443)

        kinds = [e for e, _ in captured]
        assert kinds == ["trace.start", "hop.forward", "hop.forward", "trace.terminal"]

        fields = [f for _, f in captured]
        # All share the trace_id (== request_id).
        assert all(f["trace_id"] == "reqA" for f in fields)
        # hop_index increases monotonically along the path.
        assert [f["hop_index"] for f in fields] == [0, 1, 2, 3]
        # Each span's parent is the previous span -> a single linked chain.
        assert fields[0]["parent_span_id"] is None
        assert fields[1]["parent_span_id"] == fields[0]["span_id"]
        assert fields[2]["parent_span_id"] == fields[1]["span_id"]
        assert fields[3]["parent_span_id"] == fields[2]["span_id"]
        # Relay spans name the next hop (operator-only path visibility).
        assert fields[1]["next_host"] == "r2"
        assert fields[2]["next_host"] == "e"

    def test_relay_span_ignores_missing_block(self, captured):
        assert trace.relay_span(None, request_id="x", frame_type="data",
                                next_host="h", next_port=1) is None
        assert captured == []

    def test_hidden_service_dial_chain(self, captured):
        # Mirrors the HS dial path: rendezvous origin -> relay hops ->
        # rendezvous-point terminal. Tagged kind=hs_dial / role=rendezvous.
        b = trace.start_trace("C1", kind="hs_dial", addr="alpha.obscura")
        b = trace.relay_span(b, request_id="C1", frame_type="rv_establish",
                             next_host="m1", next_port=1)
        b = trace.relay_span(b, request_id="C1", frame_type="rv_establish",
                             next_host="rv", next_port=2)
        trace.terminal_span(b, request_id="C1", role="rendezvous")

        kinds = [e for e, _ in captured]
        assert kinds == ["trace.start", "hop.forward", "hop.forward",
                         "trace.terminal"]
        fields = [f for _, f in captured]
        assert fields[0]["kind"] == "hs_dial"
        assert fields[-1]["role"] == "rendezvous"
        assert fields[-1]["parent_span_id"] == fields[-2]["span_id"]
        assert all(f["trace_id"] == "C1" for f in fields)


class TestEnvelopeInjection:
    def _stub_send(self, monkeypatch):
        import src.core.router as router
        sent = {}
        monkeypatch.setattr(router, "_send_frame_via_route",
                            lambda hops, env: sent.update(env) or True)
        return router, sent

    def test_public_envelope_has_no_trace(self, public, monkeypatch):
        router, sent = self._stub_send(monkeypatch)
        router.start_tunnel({"host": "e", "port": 9, "pub": "x"}, [], "reqX",
                            "ex.com", 443, {"pub": "p", "request_id": "reqX"},
                            route=[{"host": "r1", "port": 1, "pub": "k"}])
        assert "trace" not in sent

    def test_range_envelope_carries_trace(self, captured, monkeypatch):
        router, sent = self._stub_send(monkeypatch)
        router.start_tunnel({"host": "e", "port": 9, "pub": "x"}, [], "reqY",
                            "ex.com", 443, {"pub": "p", "request_id": "reqY"},
                            route=[{"host": "r1", "port": 1, "pub": "k"}])
        assert sent.get("trace", {}).get("id") == "reqY"
        assert ("trace.start", ) == (captured[0][0], )


class TestSessionBridge:
    """The agent session_id is carried on the local CONNECT and linked to the
    circuit's trace_id, so an agent's logical session ties to its network path."""

    def test_client_connect_carries_session_header(self):
        from src.agent.client import _connect_request
        with_sess = _connect_request("a.obscura", 80, "s1").decode()
        assert "X-Obscura-Session: s1" in with_sess
        assert "X-Obscura-Session" not in _connect_request("a.obscura", 80).decode()

    def test_proxy_extracts_session(self):
        from src.core.proxy import _connect_session_id
        data = ("CONNECT a.obscura:80 HTTP/1.1\r\nHost: a.obscura:80\r\n"
                "X-Obscura-Session: s1\r\n\r\n")
        assert _connect_session_id(data) == "s1"
        assert _connect_session_id(
            "CONNECT a:80 HTTP/1.1\r\nHost: a\r\n\r\n") is None

    def test_session_links_to_circuit_in_span(self, captured, monkeypatch):
        import src.core.router as router
        monkeypatch.setattr(router, "_send_frame_via_route",
                            lambda hops, env: True)
        router.start_tunnel({"host": "e", "port": 9, "pub": "x"}, [], "reqZ",
                            "ex.com", 443, {"pub": "p", "request_id": "reqZ"},
                            route=[{"host": "r1", "port": 1, "pub": "k"}],
                            session_id="sess-9")
        start = [f for e, f in captured if e == "trace.start"][0]
        assert start["trace_id"] == "reqZ"
        assert start["session_id"] == "sess-9"

    def test_no_session_means_no_field(self, captured, monkeypatch):
        import src.core.router as router
        monkeypatch.setattr(router, "_send_frame_via_route",
                            lambda hops, env: True)
        router.start_tunnel({"host": "e", "port": 9, "pub": "x"}, [], "reqW",
                            "ex.com", 443, {"pub": "p", "request_id": "reqW"},
                            route=[{"host": "r1", "port": 1, "pub": "k"}])
        start = [f for e, f in captured if e == "trace.start"][0]
        assert "session_id" not in start
