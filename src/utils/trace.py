"""Distributed trace context for the ops plane.

Reconstructs the path a request takes through the overlay --
``agent -> entry -> relay -> ... -> exit/service`` -- as a tree of spans, the
way a tracing backend (e.g. Grafana Tempo) represents one request moving
through a distributed system:

    trace.start (origin / proxy)
      └── hop.forward (relay A)
           └── hop.forward (relay B)
                └── trace.terminal (exit / service)

This is an OPERATOR-ONLY, RANGE-MODE feature and a deliberate privacy
regression: each hop span names the next hop, so it reveals the path. That is
exactly what an operator studying their own closed world wants, and exactly
what the public anonymity network must never do. It is therefore a hard no-op
unless BOTH hold:

  * ``OBSCURA_MODE=range``  -- we are in a closed study network, and
  * diag is enabled         -- ``OBSCURA_DIAG`` / ``OBSCURA_DIAG_REGISTRY``

so public-mode frames never carry a correlatable trace token and no path is
ever emitted. See ``docs/observability.md``.

Spans are emitted through :mod:`src.utils.diag` (the ops-plane sink), so they
inherit its out-of-band shipping and the active ``experiment_id`` stamp -- a
trace is automatically tied to the experiment that produced it.

Mechanically, a small ``trace`` block rides *in-band* inside the tunnel / HS
envelope. ``router.forward_message`` already re-encrypts that envelope
hop-by-hop, so the block propagates for free; each relay rewrites the parent
pointer and hop index before forwarding, yielding the parent/child chain.
"""

from __future__ import annotations

import uuid
from typing import Any

from src.utils import config, diag

# Envelope field that carries the in-band trace block.
TRACE_KEY = "trace"


def is_active() -> bool:
    """True only when tracing should attach to frames and emit spans.

    Gated on range mode AND diag so the consumer network is provably
    unaffected and no trace token is ever added to public-mode traffic.
    """
    return config.IS_RANGE_MODE and diag.is_enabled()


def new_span_id() -> str:
    return uuid.uuid4().hex[:16]


def start_trace(request_id: str, **fields: Any) -> dict | None:
    """Origin: emit the root span and return the in-band block to embed.

    ``trace_id`` is the circuit's ``request_id`` -- already the cross-hop
    correlator for tunnels -- so spans, ledger events and ops events all join
    on it. Returns ``None`` (attach nothing) when tracing is inactive.
    """
    if not is_active():
        return None
    root = new_span_id()
    diag.emit(
        "trace.start",
        trace_id=request_id,
        span_id=root,
        parent_span_id=None,
        hop_index=0,
        request_id=request_id,
        **fields,
    )
    return {"id": request_id, "parent": root, "hop": 1}


def relay_span(
    block: Any,
    *,
    request_id: str,
    frame_type: str,
    next_host: str,
    next_port: Any,
) -> dict | None:
    """Relay: emit a hop span for ``block`` and return the rewritten block.

    The returned block (new parent = this hop's span, incremented hop index)
    should replace the envelope's trace block before forwarding. Returns
    ``None`` when there is nothing to trace.
    """
    if not block or not isinstance(block, dict) or not is_active():
        return None
    span = new_span_id()
    hop = int(block.get("hop", 0) or 0)
    diag.emit(
        "hop.forward",
        trace_id=block.get("id"),
        span_id=span,
        parent_span_id=block.get("parent"),
        hop_index=hop,
        request_id=request_id,
        frame_type=frame_type,
        next_host=next_host,
        next_port=next_port,
    )
    return {"id": block.get("id"), "parent": span, "hop": hop + 1}


def terminal_span(block: Any, *, request_id: str, role: str, **fields: Any) -> None:
    """Terminal hop (exit / hidden service): emit the leaf span."""
    if not block or not isinstance(block, dict) or not is_active():
        return
    diag.emit(
        "trace.terminal",
        trace_id=block.get("id"),
        span_id=new_span_id(),
        parent_span_id=block.get("parent"),
        hop_index=int(block.get("hop", 0) or 0),
        request_id=request_id,
        role=role,
        **fields,
    )
