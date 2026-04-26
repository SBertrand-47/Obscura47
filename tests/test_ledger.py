"""Unit tests for the ledger primitives and tool surface."""

from __future__ import annotations

import json
import os
import threading
from typing import Any

import pytest

from src.agent.app import AgentApp, Request
from src.agent.ledger import (
    ACCOUNT_HEX_LEN,
    HISTORY_DEFAULT_LIMIT,
    LEDGER_PROTOCOL_VERSION,
    LedgerClient,
    LedgerError,
    LedgerState,
    _resolve_admin_fingerprint,
    build_ledger_app,
)
from src.agent.tools import DEFAULT_PREFIX, ToolError, ToolRegistry
from src.utils.identity import fingerprint_pubkey


def _acct(prefix: str) -> str:
    """Synthesise a 64-hex-char fingerprint from a short prefix."""
    base = (prefix * (ACCOUNT_HEX_LEN // len(prefix) + 1))[:ACCOUNT_HEX_LEN]
    return base.lower()


ALICE = _acct("a1")
BOB = _acct("b2")
CHARLIE = _acct("c3")
ADMIN = _acct("ad")


def _request_with_caller(
    method: str,
    path: str,
    body: bytes = b"",
    caller_pub: str | None = None,
    caller_fingerprint: str | None = None,
) -> Request:
    """Construct a Request whose caller_fingerprint is forced to a value.

    Uses a sentinel ``caller_pub`` string when ``caller_fingerprint`` is
    supplied — the lazy property would normally derive the fingerprint
    from the pub PEM, but tests want to inject a synthetic id directly.
    """
    req = Request(method, path, {}, body, caller_pub=caller_pub)
    if caller_fingerprint is not None:
        req._caller_fingerprint = caller_fingerprint  # type: ignore[attr-defined]
    return req


# ---------------------------------------------------------------------------
# LedgerState — balances, transfers, mint
# ---------------------------------------------------------------------------


def test_balance_unknown_account_is_zero():
    s = LedgerState()
    assert s.balance(ALICE) == 0


def test_initial_balances_seeded():
    s = LedgerState(initial_balances={ALICE: 100, BOB: 50})
    assert s.balance(ALICE) == 100
    assert s.balance(BOB) == 50
    assert s.supply == 150


def test_transfer_moves_funds_and_returns_tx():
    s = LedgerState(initial_balances={ALICE: 100})
    tx = s.transfer(from_account=ALICE, to_account=BOB, amount=30,
                    memo="payment", nonce="n1")
    assert tx.from_account == ALICE
    assert tx.to_account == BOB
    assert tx.amount == 30
    assert tx.memo == "payment"
    assert tx.nonce == "n1"
    assert s.balance(ALICE) == 70
    assert s.balance(BOB) == 30
    assert s.supply == 100  # transfers don't change supply


def test_transfer_rejects_negative_amount():
    s = LedgerState(initial_balances={ALICE: 100})
    with pytest.raises(LedgerError) as exc:
        s.transfer(from_account=ALICE, to_account=BOB, amount=-1, nonce="n1")
    assert exc.value.code == "bad_amount"


def test_transfer_rejects_zero_amount():
    s = LedgerState(initial_balances={ALICE: 100})
    with pytest.raises(LedgerError) as exc:
        s.transfer(from_account=ALICE, to_account=BOB, amount=0, nonce="n1")
    assert exc.value.code == "bad_amount"


def test_transfer_rejects_non_int_amount():
    s = LedgerState(initial_balances={ALICE: 100})
    with pytest.raises(LedgerError) as exc:
        s.transfer(from_account=ALICE, to_account=BOB,
                   amount="30", nonce="n1")  # type: ignore[arg-type]
    assert exc.value.code == "bad_amount"


def test_transfer_rejects_bool_amount():
    """Python bools are ints — make sure we reject them explicitly."""
    s = LedgerState(initial_balances={ALICE: 100})
    with pytest.raises(LedgerError) as exc:
        s.transfer(from_account=ALICE, to_account=BOB,
                   amount=True, nonce="n1")  # type: ignore[arg-type]
    assert exc.value.code == "bad_amount"


def test_transfer_rejects_self_transfer():
    s = LedgerState(initial_balances={ALICE: 100})
    with pytest.raises(LedgerError) as exc:
        s.transfer(from_account=ALICE, to_account=ALICE, amount=5, nonce="n1")
    assert exc.value.code == "self_transfer"


def test_transfer_rejects_insufficient_balance():
    s = LedgerState(initial_balances={ALICE: 10})
    with pytest.raises(LedgerError) as exc:
        s.transfer(from_account=ALICE, to_account=BOB, amount=100, nonce="n1")
    assert exc.value.code == "insufficient_funds"
    assert exc.value.status == 402
    assert s.balance(ALICE) == 10
    assert s.balance(BOB) == 0


def test_transfer_requires_nonce():
    s = LedgerState(initial_balances={ALICE: 100})
    with pytest.raises(LedgerError) as exc:
        s.transfer(from_account=ALICE, to_account=BOB, amount=5, nonce=None)
    assert exc.value.code == "missing_nonce"


def test_transfer_idempotent_with_same_nonce():
    s = LedgerState(initial_balances={ALICE: 100})
    tx1 = s.transfer(from_account=ALICE, to_account=BOB, amount=20,
                     memo="rent", nonce="rent-2026-04")
    tx2 = s.transfer(from_account=ALICE, to_account=BOB, amount=20,
                     memo="rent", nonce="rent-2026-04")
    assert tx1.tx_id == tx2.tx_id
    assert s.balance(ALICE) == 80
    assert s.balance(BOB) == 20


def test_transfer_with_same_nonce_different_params_errors():
    s = LedgerState(initial_balances={ALICE: 100})
    s.transfer(from_account=ALICE, to_account=BOB, amount=20, nonce="dup")
    with pytest.raises(LedgerError) as exc:
        s.transfer(from_account=ALICE, to_account=BOB, amount=21, nonce="dup")
    assert exc.value.code == "nonce_reuse"
    assert exc.value.status == 409


def test_transfer_nonce_scoped_per_caller():
    """Same nonce used by two different callers does not collide."""
    s = LedgerState(initial_balances={ALICE: 100, BOB: 100})
    s.transfer(from_account=ALICE, to_account=CHARLIE, amount=5, nonce="x")
    s.transfer(from_account=BOB, to_account=CHARLIE, amount=7, nonce="x")
    assert s.balance(CHARLIE) == 12


def test_mint_requires_no_caller_in_state_layer():
    """LedgerState.mint is unauthenticated — auth lives in the tool layer."""
    s = LedgerState()
    tx = s.mint(to_account=ALICE, amount=1000, memo="genesis")
    assert tx.from_account is None
    assert s.balance(ALICE) == 1000
    assert s.supply == 1000


def test_mint_rejects_negative_amount():
    s = LedgerState()
    with pytest.raises(LedgerError) as exc:
        s.mint(to_account=ALICE, amount=-1)
    assert exc.value.code == "bad_amount"


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------


def test_history_is_chronological_and_filtered_by_account():
    s = LedgerState(initial_balances={ALICE: 100, BOB: 100})
    s.transfer(from_account=ALICE, to_account=BOB, amount=10, nonce="n1")
    s.transfer(from_account=BOB, to_account=CHARLIE, amount=20, nonce="n2")
    s.transfer(from_account=ALICE, to_account=CHARLIE, amount=5, nonce="n3")

    all_rows = s.history()
    assert [t.nonce for t in all_rows] == ["n3", "n2", "n1"]

    bob_rows = s.history(account=BOB)
    assert [t.nonce for t in bob_rows] == ["n2", "n1"]

    charlie_rows = s.history(account=CHARLIE)
    assert [t.nonce for t in charlie_rows] == ["n3", "n2"]


def test_history_limit_clamps():
    s = LedgerState(initial_balances={ALICE: 1000})
    for i in range(5):
        s.transfer(from_account=ALICE, to_account=BOB, amount=1, nonce=f"n{i}")
    rows = s.history(limit=2)
    assert len(rows) == 2
    assert [t.nonce for t in rows] == ["n4", "n3"]


def test_history_rejects_non_positive_limit():
    s = LedgerState()
    with pytest.raises(LedgerError):
        s.history(limit=0)
    with pytest.raises(LedgerError):
        s.history(limit=-1)
    with pytest.raises(LedgerError):
        s.history(limit=True)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Account validation
# ---------------------------------------------------------------------------


def test_validate_rejects_short_account():
    s = LedgerState()
    with pytest.raises(LedgerError) as exc:
        s.balance("abc")
    assert exc.value.code == "bad_account"


def test_validate_rejects_non_hex_account():
    s = LedgerState()
    with pytest.raises(LedgerError) as exc:
        s.balance("z" * ACCOUNT_HEX_LEN)
    assert exc.value.code == "bad_account"


def test_validate_rejects_uppercase_account():
    s = LedgerState()
    with pytest.raises(LedgerError) as exc:
        s.balance(ALICE.upper())
    assert exc.value.code == "bad_account"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_persistence_round_trip(tmp_path):
    path = str(tmp_path / "ledger.json")
    s1 = LedgerState(path=path, initial_balances={ALICE: 100})
    s1.transfer(from_account=ALICE, to_account=BOB, amount=40, nonce="x")

    s2 = LedgerState(path=path)
    assert s2.balance(ALICE) == 60
    assert s2.balance(BOB) == 40
    rows = s2.history()
    assert len(rows) == 1
    assert rows[0].nonce == "x"


def test_persistence_initial_balances_ignored_when_state_exists(tmp_path):
    path = str(tmp_path / "ledger.json")
    LedgerState(path=path, initial_balances={ALICE: 100})

    s2 = LedgerState(path=path, initial_balances={ALICE: 999})
    assert s2.balance(ALICE) == 100


def test_persistence_atomic_write_uses_replace(tmp_path, monkeypatch):
    path = str(tmp_path / "ledger.json")
    s = LedgerState(path=path, initial_balances={ALICE: 100})

    s.transfer(from_account=ALICE, to_account=BOB, amount=10, nonce="x")
    assert os.path.isfile(path)
    assert not os.path.isfile(path + ".tmp")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["balances"][ALICE] == 90
    assert data["balances"][BOB] == 10


def test_persistence_failure_rolls_back(tmp_path, monkeypatch):
    path = str(tmp_path / "ledger.json")
    s = LedgerState(path=path, initial_balances={ALICE: 100})

    real_replace = os.replace

    def boom(*_a, **_kw):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(LedgerError) as exc:
        s.transfer(from_account=ALICE, to_account=BOB, amount=10, nonce="x")
    assert exc.value.code == "persistence_failed"
    monkeypatch.setattr(os, "replace", real_replace)

    assert s.balance(ALICE) == 100
    assert s.balance(BOB) == 0
    assert s.history() == []


def test_persistence_loads_admin_fingerprint(tmp_path):
    path = str(tmp_path / "ledger.json")
    LedgerState(path=path, admin_fingerprint=ADMIN, initial_balances={ALICE: 1})

    s2 = LedgerState(path=path)
    assert s2.admin_fingerprint == ADMIN


# ---------------------------------------------------------------------------
# Concurrency: many parallel transfers must conserve supply
# ---------------------------------------------------------------------------


def test_concurrent_transfers_conserve_supply():
    s = LedgerState(initial_balances={ALICE: 1000})
    errors: list[Exception] = []

    def worker(i: int):
        try:
            s.transfer(from_account=ALICE, to_account=BOB, amount=1,
                       nonce=f"n{i}")
        except LedgerError as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert s.balance(ALICE) == 950
    assert s.balance(BOB) == 50
    assert s.supply == 1000


# ---------------------------------------------------------------------------
# Tool layer wiring
# ---------------------------------------------------------------------------


def test_root_route_exposes_endpoints():
    state = LedgerState()
    app, _ = build_ledger_app(state)
    resp = app.dispatch(_request_with_caller("GET", "/"))
    assert resp.status == 200
    body = json.loads(resp.body)
    assert body["service"] == "ledger"
    assert body["protocol"] == LEDGER_PROTOCOL_VERSION
    assert "/health" in body["endpoints"]
    assert any("tools" in p for p in body["endpoints"])


def test_health_route_reports_stats():
    state = LedgerState(initial_balances={ALICE: 5})
    app, _ = build_ledger_app(state)
    resp = app.dispatch(_request_with_caller("GET", "/health"))
    body = json.loads(resp.body)
    assert body["ok"] is True
    assert body["accounts"] == 1
    assert body["supply"] == 5


def test_balance_tool_uses_caller_when_no_account_arg():
    state = LedgerState(initial_balances={ALICE: 42})
    _, tools = build_ledger_app(state)
    req = _request_with_caller("POST", "/x", caller_fingerprint=ALICE)
    resp = tools.invoke("balance", {}, req)
    body = json.loads(resp.body)
    assert body == {"ok": True, "result": {"account": ALICE, "balance": 42}}


def test_balance_tool_explicit_account_arg():
    state = LedgerState(initial_balances={BOB: 7})
    _, tools = build_ledger_app(state)
    req = _request_with_caller("POST", "/x", caller_fingerprint=ALICE)
    resp = tools.invoke("balance", {"account": BOB}, req)
    body = json.loads(resp.body)
    assert body["result"]["account"] == BOB
    assert body["result"]["balance"] == 7


def test_balance_tool_unauthenticated_without_account_errors():
    state = LedgerState()
    _, tools = build_ledger_app(state)
    req = _request_with_caller("POST", "/x")
    resp = tools.invoke("balance", {}, req)
    body = json.loads(resp.body)
    assert body["ok"] is False
    assert body["error"]["code"] == "missing_account"


def test_transfer_tool_requires_authenticated_caller():
    state = LedgerState(initial_balances={ALICE: 100})
    _, tools = build_ledger_app(state)
    req = _request_with_caller("POST", "/x")  # no caller
    resp = tools.invoke(
        "transfer",
        {"to": BOB, "amount": 10, "nonce": "n1"},
        req,
    )
    assert resp.status == 401
    body = json.loads(resp.body)
    assert body["error"]["code"] == "not_authenticated"
    assert state.balance(ALICE) == 100


def test_transfer_tool_uses_caller_fingerprint_as_from():
    state = LedgerState(initial_balances={ALICE: 100})
    _, tools = build_ledger_app(state)
    req = _request_with_caller("POST", "/x", caller_fingerprint=ALICE)
    resp = tools.invoke(
        "transfer",
        {"to": BOB, "amount": 25, "memo": "thanks", "nonce": "n1"},
        req,
    )
    assert resp.status == 200
    body = json.loads(resp.body)
    assert body["ok"] is True
    result = body["result"]
    assert result["from"] == ALICE
    assert result["to"] == BOB
    assert result["amount"] == 25
    assert result["memo"] == "thanks"
    assert result["balance_after"] == 75


def test_transfer_tool_surfaces_insufficient_funds():
    state = LedgerState(initial_balances={ALICE: 5})
    _, tools = build_ledger_app(state)
    req = _request_with_caller("POST", "/x", caller_fingerprint=ALICE)
    resp = tools.invoke(
        "transfer",
        {"to": BOB, "amount": 100, "nonce": "n1"},
        req,
    )
    assert resp.status == 402
    body = json.loads(resp.body)
    assert body["error"]["code"] == "insufficient_funds"


def test_transfer_tool_publishes_to_topic():
    state = LedgerState(initial_balances={ALICE: 100})
    _, tools = build_ledger_app(state)
    topic = tools.topic("transactions")
    sub = topic.subscribe()
    req = _request_with_caller("POST", "/x", caller_fingerprint=ALICE)
    tools.invoke("transfer",
                 {"to": BOB, "amount": 10, "nonce": "n1"}, req)
    event = sub.get_nowait()
    assert event["from"] == ALICE
    assert event["to"] == BOB
    assert event["amount"] == 10


def test_history_tool_defaults_to_caller():
    state = LedgerState(initial_balances={ALICE: 100, BOB: 100})
    state.transfer(from_account=ALICE, to_account=BOB, amount=5, nonce="n1")
    state.transfer(from_account=BOB, to_account=CHARLIE, amount=10, nonce="n2")
    _, tools = build_ledger_app(state)

    req = _request_with_caller("POST", "/x", caller_fingerprint=ALICE)
    resp = tools.invoke("history", {}, req)
    rows = json.loads(resp.body)["result"]
    assert len(rows) == 1
    assert rows[0]["nonce"] == "n1"


def test_mint_tool_requires_admin_fingerprint_configured():
    state = LedgerState()  # no admin
    _, tools = build_ledger_app(state)
    req = _request_with_caller("POST", "/x", caller_fingerprint=ALICE)
    resp = tools.invoke(
        "mint", {"to": BOB, "amount": 100}, req,
    )
    body = json.loads(resp.body)
    assert resp.status == 403
    assert body["error"]["code"] == "minting_disabled"


def test_mint_tool_rejects_non_admin_caller():
    state = LedgerState(admin_fingerprint=ADMIN)
    _, tools = build_ledger_app(state)
    req = _request_with_caller("POST", "/x", caller_fingerprint=ALICE)
    resp = tools.invoke(
        "mint", {"to": BOB, "amount": 100}, req,
    )
    body = json.loads(resp.body)
    assert resp.status == 403
    assert body["error"]["code"] == "forbidden"


def test_mint_tool_admin_creates_balance():
    state = LedgerState(admin_fingerprint=ADMIN)
    _, tools = build_ledger_app(state)
    req = _request_with_caller("POST", "/x", caller_fingerprint=ADMIN)
    resp = tools.invoke(
        "mint", {"to": BOB, "amount": 250, "memo": "seed"}, req,
    )
    body = json.loads(resp.body)
    assert resp.status == 200
    assert body["result"]["from"] is None
    assert body["result"]["to"] == BOB
    assert body["result"]["amount"] == 250
    assert state.balance(BOB) == 250


def test_mint_tool_unauthenticated_caller_rejected():
    state = LedgerState(admin_fingerprint=ADMIN)
    _, tools = build_ledger_app(state)
    req = _request_with_caller("POST", "/x")
    resp = tools.invoke(
        "mint", {"to": BOB, "amount": 100}, req,
    )
    body = json.loads(resp.body)
    assert resp.status == 401
    assert body["error"]["code"] == "not_authenticated"


# ---------------------------------------------------------------------------
# build_ledger_app — full mount onto AgentApp
# ---------------------------------------------------------------------------


def test_build_ledger_app_mounts_tool_routes():
    state = LedgerState(initial_balances={ALICE: 50})
    app, _ = build_ledger_app(state)
    resp = app.dispatch(_request_with_caller("GET", DEFAULT_PREFIX + "tools"))
    assert resp.status == 200
    manifest = json.loads(resp.body)
    names = [t["name"] for t in manifest["tools"]]
    assert {"balance", "transfer", "history", "mint"}.issubset(set(names))
    assert "transactions" in manifest["topics"]


def test_build_ledger_app_dispatches_invocation():
    state = LedgerState(initial_balances={ALICE: 50})
    app, _ = build_ledger_app(state)
    body = json.dumps({"args": {"account": ALICE}}).encode()
    req = _request_with_caller(
        "POST", DEFAULT_PREFIX + "tools/balance", body,
        caller_fingerprint=ALICE,
    )
    resp = app.dispatch(req)
    assert resp.status == 200
    body_out = json.loads(resp.body)
    assert body_out["result"]["balance"] == 50


# ---------------------------------------------------------------------------
# Admin-key resolver
# ---------------------------------------------------------------------------


def test_resolve_admin_fingerprint_accepts_hex():
    fp = _resolve_admin_fingerprint(ADMIN)
    assert fp == ADMIN


def test_resolve_admin_fingerprint_uppercase_hex_normalised():
    fp = _resolve_admin_fingerprint(ADMIN.upper())
    assert fp == ADMIN


def test_resolve_admin_fingerprint_none_returns_none():
    assert _resolve_admin_fingerprint(None) is None
    assert _resolve_admin_fingerprint("") is None


def test_resolve_admin_fingerprint_pem_path(tmp_path):
    from src.core.encryptions import ecc_generate_keypair

    _, pub_pem = ecc_generate_keypair()
    pem_path = tmp_path / "admin.pub"
    pem_path.write_text(pub_pem)

    fp = _resolve_admin_fingerprint(str(pem_path))
    assert fp == fingerprint_pubkey(pub_pem)


def test_resolve_admin_fingerprint_inline_pem():
    from src.core.encryptions import ecc_generate_keypair

    _, pub_pem = ecc_generate_keypair()
    fp = _resolve_admin_fingerprint(pub_pem)
    assert fp == fingerprint_pubkey(pub_pem)


def test_resolve_admin_fingerprint_rejects_garbage():
    with pytest.raises(SystemExit):
        _resolve_admin_fingerprint("not-a-key")


# ---------------------------------------------------------------------------
# LedgerClient — wire-shape smoke test against an in-process registry
# ---------------------------------------------------------------------------


class _FakeAgent:
    """Minimal AgentClient stand-in that dispatches to a ToolRegistry."""

    def __init__(self, tools: ToolRegistry, caller_fingerprint: str | None):
        self._tools = tools
        self._caller_fingerprint = caller_fingerprint

    def call_tool(self, addr, name, args=None, *, port=80, prefix=DEFAULT_PREFIX) -> Any:
        req = Request("POST", f"/tools/{name}", {}, b"")
        if self._caller_fingerprint is not None:
            req._caller_fingerprint = self._caller_fingerprint  # type: ignore[attr-defined]
        resp = self._tools.invoke(name, args or {}, req)
        envelope = json.loads(resp.body)
        if envelope.get("ok") is True:
            return envelope.get("result")
        from src.agent.client import ToolCallError

        err = envelope.get("error") or {}
        raise ToolCallError(err.get("code") or "unknown",
                            err.get("message") or "fail",
                            status=resp.status)


def test_ledger_client_balance_transfer_history_round_trip():
    state = LedgerState(initial_balances={ALICE: 100})
    _, tools = build_ledger_app(state)
    agent = _FakeAgent(tools, caller_fingerprint=ALICE)
    client = LedgerClient("ledger.obscura", agent=agent)

    assert client.balance() == 100
    assert client.balance(BOB) == 0
    tx = client.transfer(to=BOB, amount=30, memo="lunch", nonce="n1")
    assert tx["from"] == ALICE
    assert tx["to"] == BOB
    assert tx["amount"] == 30
    assert tx["balance_after"] == 70

    rows = client.history()
    assert len(rows) == 1
    assert rows[0]["nonce"] == "n1"


def test_ledger_client_transfer_idempotent_on_retry():
    state = LedgerState(initial_balances={ALICE: 100})
    _, tools = build_ledger_app(state)
    agent = _FakeAgent(tools, caller_fingerprint=ALICE)
    client = LedgerClient("ledger.obscura", agent=agent)

    tx1 = client.transfer(to=BOB, amount=10, nonce="retry-key")
    tx2 = client.transfer(to=BOB, amount=10, nonce="retry-key")
    assert tx1["tx_id"] == tx2["tx_id"]
    assert state.balance(ALICE) == 90


def test_ledger_client_mint_admin_only():
    state = LedgerState(admin_fingerprint=ADMIN)
    _, tools = build_ledger_app(state)

    non_admin = LedgerClient(
        "ledger.obscura", agent=_FakeAgent(tools, caller_fingerprint=ALICE),
    )
    from src.agent.client import ToolCallError
    with pytest.raises(ToolCallError) as exc:
        non_admin.mint(to=BOB, amount=100)
    assert exc.value.code == "forbidden"

    admin = LedgerClient(
        "ledger.obscura", agent=_FakeAgent(tools, caller_fingerprint=ADMIN),
    )
    tx = admin.mint(to=BOB, amount=500, memo="seed")
    assert tx["from"] is None
    assert state.balance(BOB) == 500
