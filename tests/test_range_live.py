"""Live ops-plane trace exercise over a real loopback overlay.

This is the bridge from the in-process research range to the *real* network: it
stands up an actual node + exit + proxy, opens a real multi-hop tunnel, and
asserts that the ops-plane distributed-trace spans (trace.start -> hop.forward
-> trace.terminal) were emitted on genuine traffic when range mode + diag are
on. The unit tests in test_trace.py prove the span logic; this proves it fires
end to end on the wire.

Skipped by default: it binds real ports (proxy on 9047) and uses threads, so it
is environment-dependent (it conflicts with a running Obscura proxy) and noisy.
Run it explicitly in a clean environment:

    OBSCURA_MODE=range OBSCURA_DIAG=1 pytest tests/test_range_live.py -p no:cacheprovider --no-header -q -rs --run-live

(remove the skip mark, or run the body directly). It is the loopback-scale
stand-in for the live multi-machine network exercise.
"""
import socket
import time

import pytest

pytestmark = pytest.mark.skip(
    reason="live loopback overlay (binds real ports, thread-timed); run "
           "explicitly in a clean environment with OBSCURA_MODE=range "
           "OBSCURA_DIAG=1")


def test_trace_spans_fire_on_real_tunnel_traffic(monkeypatch):
    from src.utils import config, diag
    from tests.test_e2e_tunnel import (
        start_echo_server, start_node_and_exit,
        start_proxy_with_injected_peers)

    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setenv("OBSCURA_DIAG", "1")
    diag.set_role("test")

    spans = []          # event names, for the basic assertions
    span_records = []   # full normalized spans, for cross-plane correlation
    real_emit = diag.emit

    def capture(event, **fields):
        if event.startswith("trace.") or event == "hop.forward":
            spans.append(event)
            span_records.append({
                "ts": fields.get("ts"),
                "role": diag._role,
                "event": event,
                "experiment_id": None,
                "trace_id": fields.get("trace_id"),
                "span_id": fields.get("span_id"),
                "parent_span_id": fields.get("parent_span_id"),
                "hop_index": fields.get("hop_index"),
                "session_id": fields.get("session_id"),
                "fields": dict(fields),
            })
        return real_emit(event, **fields)
    monkeypatch.setattr(diag, "emit", capture)

    start_echo_server(port=18080)
    start_node_and_exit()
    start_proxy_with_injected_peers()

    # A correlatable agent session: the id rides the CONNECT as X-Obscura-Session
    # and the proxy stamps it onto the trace it produces.
    session_id = "live-sess-1"
    s = socket.socket()
    s.settimeout(8.0)
    s.connect(("127.0.0.1", 9047))
    s.sendall(f"CONNECT 127.0.0.1:18080 HTTP/1.1\r\n"
              f"Host: 127.0.0.1:18080\r\n"
              f"X-Obscura-Session: {session_id}\r\n\r\n".encode())
    assert "200" in s.recv(4096).decode(errors="ignore")
    s.sendall(b"hello obscura")
    assert s.recv(13) == b"hello obscura"
    s.close()
    time.sleep(0.5)

    # The circuit was traced on real traffic: origin span, a relay hop, and a
    # terminal span at the exit.
    assert "trace.start" in spans
    assert "hop.forward" in spans
    assert "trace.terminal" in spans

    # Cross-plane: the ops spans reconstruct into a circuit carrying the agent's
    # session id - the join that makes a real session fully observable.
    from src.range import crossplane
    circuits = crossplane.build_circuits(span_records)
    assert any(c["session_id"] == session_id and c["length"] >= 3
               for c in circuits), "no traced circuit carried the session id"
