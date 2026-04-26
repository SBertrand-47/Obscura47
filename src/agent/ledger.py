"""Optional metering / payment primitives for `.obscura` services.

A small in-network token ledger that any operator can publish as a
`.obscura` hidden service. Accounts are keyed by the SHA-256
fingerprint of the caller's service public key, so any client whose
identity has already been surfaced to the application layer (i.e.
``Request.caller_pub`` is populated by the rendezvous handshake) owns
the matching account automatically — no separate enrolment step.

The protocol is intentionally minimal:

* a single fixed-supply token with admin-gated mint;
* signed transfers between accounts, idempotent on a caller-supplied
  nonce so retries are safe;
* JSON history.

Persistence is optional. When a state path is supplied every commit
is atomically rewritten to disk so the ledger survives restarts.

Public framing: this is a reference metering primitive for `.obscura`
apps. Anyone can publish their own ledger; the protocol does not rely
on any blessed central server, and ledger instances do not federate.

Wire surface (mounted via :class:`~src.agent.tools.ToolRegistry`):

* ``balance(account?: string) -> {account, balance}``  — public read.
* ``transfer(to: string, amount: int, memo?: string, nonce: string)``
  — caller pays ``amount`` tokens to ``to``. Caller is the
  authenticated ``caller_fingerprint``; direct local hits without a
  rendezvous identity are rejected.
* ``history(account?: string, limit?: int) -> [tx ...]``  — append-only
  log filtered by ``account`` (defaults to caller).
* ``mint(to: string, amount: int, memo?: string)`` — admin-only.
* Topic ``transactions`` — every commit fans out the canonical tx
  envelope to subscribers, suitable for downstream observability.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from src.agent.app import AgentApp, Request, Response
from src.agent.runtime import AgentRuntime
from src.agent.tools import ParamSpec, ToolError, ToolRegistry, Topic
from src.utils.identity import fingerprint_pubkey
from src.utils.logger import get_logger

if TYPE_CHECKING:
    from src.agent.observatory import Observer

log = get_logger(__name__)


LEDGER_PROTOCOL_VERSION = "obscura.ledger/1"

ACCOUNT_HEX_LEN = 64  # SHA-256 of a PEM
MAX_MEMO_LEN = 200
MAX_AMOUNT = 10**12
MAX_NONCE_LEN = 64
HISTORY_DEFAULT_LIMIT = 50
HISTORY_MAX_LIMIT = 500


@dataclass(frozen=True)
class Transaction:
    """A single committed ledger entry."""

    tx_id: str
    from_account: str | None  # None for mint
    to_account: str
    amount: int
    memo: str
    nonce: str | None
    ts: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "from": self.from_account,
            "to": self.to_account,
            "amount": self.amount,
            "memo": self.memo,
            "nonce": self.nonce,
            "ts": self.ts,
        }


@dataclass
class _StateSnapshot:
    """Serialisable view of the in-memory ledger state."""

    balances: dict[str, int] = field(default_factory=dict)
    transactions: list[dict[str, Any]] = field(default_factory=list)
    nonces: dict[str, str] = field(default_factory=dict)


class LedgerError(Exception):
    """Raised by :class:`LedgerState` on a structured rejection.

    ``code`` and ``message`` map directly onto the tool error envelope
    surfaced over the wire.
    """

    def __init__(self, code: str, message: str, *, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = int(status)


class LedgerState:
    """Thread-safe in-memory ledger with optional JSON persistence.

    Account ids are SHA-256 hex fingerprints (64 lowercase hex chars).
    Amounts are non-negative integers. Idempotency is per
    ``(from_account, nonce)`` — a transfer with the same pair always
    returns the previously committed transaction without re-debiting.

    Parameters
    ----------
    path:
        Optional filesystem path. When set, every commit is atomically
        rewritten to ``<path>.tmp`` and then ``os.replace``-d into
        place, so a crash mid-write cannot corrupt the file.
    admin_fingerprint:
        Account that is allowed to call :meth:`mint`. ``None`` disables
        minting entirely.
    initial_balances:
        Optional bootstrap map. Only applied when no persisted state
        exists at ``path``; loading from disk takes precedence so
        restarts don't reset balances.
    """

    def __init__(
        self,
        path: str | None = None,
        admin_fingerprint: str | None = None,
        initial_balances: dict[str, int] | None = None,
    ):
        self.path = path
        self.admin_fingerprint = admin_fingerprint or None
        self._lock = threading.Lock()
        self._balances: dict[str, int] = {}
        self._txs: list[Transaction] = []
        self._nonces: dict[tuple[str, str], str] = {}

        loaded = False
        if self.path and os.path.isfile(self.path):
            try:
                self._load_from_disk()
                loaded = True
            except Exception as e:
                log.warning("ledger: failed to load %s: %s", self.path, e)

        if not loaded and initial_balances:
            for acct, amount in initial_balances.items():
                _validate_account(acct)
                if not isinstance(amount, int) or amount < 0:
                    raise ValueError(f"initial balance for {acct!r} must be non-negative int")
                self._balances[acct] = amount
            if self.path:
                with self._lock:
                    self._persist_locked()

    @property
    def supply(self) -> int:
        with self._lock:
            return sum(self._balances.values())

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "accounts": len(self._balances),
                "transactions": len(self._txs),
                "supply": sum(self._balances.values()),
                "admin_fingerprint": self.admin_fingerprint,
            }

    def balance(self, account: str) -> int:
        _validate_account(account)
        with self._lock:
            return int(self._balances.get(account, 0))

    def transfer(
        self,
        *,
        from_account: str,
        to_account: str,
        amount: int,
        memo: str = "",
        nonce: str | None = None,
    ) -> Transaction:
        _validate_account(from_account)
        _validate_account(to_account)
        amount = _validate_amount(amount)
        memo = _validate_memo(memo)
        nonce_str = _validate_nonce(nonce, required=True)

        if from_account == to_account:
            raise LedgerError("self_transfer", "cannot transfer to the same account")

        with self._lock:
            existing_tx_id = self._nonces.get((from_account, nonce_str))
            if existing_tx_id is not None:
                tx = self._find_tx(existing_tx_id)
                if tx is None:
                    raise LedgerError(
                        "internal", "nonce index points at missing tx",
                        status=500,
                    )
                if (
                    tx.from_account != from_account
                    or tx.to_account != to_account
                    or tx.amount != amount
                ):
                    raise LedgerError(
                        "nonce_reuse",
                        "nonce already used with different parameters",
                        status=409,
                    )
                return tx

            current = self._balances.get(from_account, 0)
            if current < amount:
                raise LedgerError(
                    "insufficient_funds",
                    f"balance {current} < requested {amount}",
                    status=402,
                )

            tx = self._commit(
                from_account=from_account,
                to_account=to_account,
                amount=amount,
                memo=memo,
                nonce=nonce_str,
            )
        return tx

    def mint(
        self,
        *,
        to_account: str,
        amount: int,
        memo: str = "",
    ) -> Transaction:
        _validate_account(to_account)
        amount = _validate_amount(amount)
        memo = _validate_memo(memo)
        with self._lock:
            tx = self._commit(
                from_account=None,
                to_account=to_account,
                amount=amount,
                memo=memo,
                nonce=None,
            )
        return tx

    def history(
        self,
        account: str | None = None,
        limit: int = HISTORY_DEFAULT_LIMIT,
    ) -> list[Transaction]:
        if account is not None:
            _validate_account(account)
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise LedgerError("bad_limit", "limit must be a positive integer")
        limit = min(limit, HISTORY_MAX_LIMIT)
        with self._lock:
            if account is None:
                rows = list(self._txs)
            else:
                rows = [
                    t for t in self._txs
                    if t.from_account == account or t.to_account == account
                ]
        return rows[-limit:][::-1]

    def replace_state(self, snapshot: _StateSnapshot) -> None:
        """Test/admin helper: blow away in-memory state and reload."""
        with self._lock:
            self._balances = dict(snapshot.balances)
            self._txs = [
                Transaction(
                    tx_id=t["tx_id"],
                    from_account=t.get("from"),
                    to_account=t["to"],
                    amount=int(t["amount"]),
                    memo=t.get("memo", ""),
                    nonce=t.get("nonce"),
                    ts=float(t.get("ts", time.time())),
                )
                for t in snapshot.transactions
            ]
            self._nonces = {}
            for t in self._txs:
                if t.from_account and t.nonce:
                    self._nonces[(t.from_account, t.nonce)] = t.tx_id
            if self.path:
                self._persist_locked()

    def snapshot(self) -> _StateSnapshot:
        with self._lock:
            return _StateSnapshot(
                balances=dict(self._balances),
                transactions=[t.to_dict() for t in self._txs],
                nonces={f"{a}|{n}": tx for (a, n), tx in self._nonces.items()},
            )

    def _commit(
        self,
        *,
        from_account: str | None,
        to_account: str,
        amount: int,
        memo: str,
        nonce: str | None,
    ) -> Transaction:
        if from_account is not None:
            self._balances[from_account] = self._balances.get(from_account, 0) - amount
        self._balances[to_account] = self._balances.get(to_account, 0) + amount
        tx = Transaction(
            tx_id=secrets.token_hex(8),
            from_account=from_account,
            to_account=to_account,
            amount=amount,
            memo=memo,
            nonce=nonce,
            ts=time.time(),
        )
        self._txs.append(tx)
        if from_account is not None and nonce is not None:
            self._nonces[(from_account, nonce)] = tx.tx_id
        if self.path:
            try:
                self._persist_locked()
            except Exception as e:
                log.error("ledger: persistence failed, rolling back: %s", e)
                self._txs.pop()
                if from_account is not None:
                    self._balances[from_account] = self._balances.get(from_account, 0) + amount
                self._balances[to_account] = self._balances.get(to_account, 0) - amount
                if from_account is not None and nonce is not None:
                    self._nonces.pop((from_account, nonce), None)
                raise LedgerError(
                    "persistence_failed",
                    f"could not write ledger state: {e}",
                    status=500,
                ) from e
        return tx

    def _find_tx(self, tx_id: str) -> Transaction | None:
        for t in reversed(self._txs):
            if t.tx_id == tx_id:
                return t
        return None

    def _persist_locked(self) -> None:
        assert self.path is not None
        snapshot = {
            "version": 1,
            "balances": dict(self._balances),
            "transactions": [t.to_dict() for t in self._txs],
            "admin_fingerprint": self.admin_fingerprint,
        }
        directory = os.path.dirname(os.path.abspath(self.path))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, separators=(",", ":"), sort_keys=True)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, self.path)

    def _load_from_disk(self) -> None:
        assert self.path is not None
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("state file is not a JSON object")
        balances = data.get("balances") or {}
        txs = data.get("transactions") or []
        if not isinstance(balances, dict) or not isinstance(txs, list):
            raise ValueError("state file shape invalid")
        admin = data.get("admin_fingerprint")
        if admin and isinstance(admin, str) and not self.admin_fingerprint:
            self.admin_fingerprint = admin
        for acct, amount in balances.items():
            _validate_account(acct)
            if not isinstance(amount, int) or amount < 0:
                raise ValueError(f"balance for {acct!r} invalid")
            self._balances[acct] = amount
        for raw in txs:
            if not isinstance(raw, dict):
                continue
            tx = Transaction(
                tx_id=str(raw["tx_id"]),
                from_account=raw.get("from"),
                to_account=str(raw["to"]),
                amount=int(raw["amount"]),
                memo=str(raw.get("memo", "")),
                nonce=raw.get("nonce"),
                ts=float(raw.get("ts", time.time())),
            )
            self._txs.append(tx)
            if tx.from_account and tx.nonce:
                self._nonces[(tx.from_account, tx.nonce)] = tx.tx_id


def build_ledger_app(
    state: LedgerState,
    *,
    name: str = "ledger",
    observer: "Observer | None" = None,
) -> tuple[AgentApp, ToolRegistry]:
    """Wire a :class:`LedgerState` as a `.obscura` tool surface.

    Returns the ``(app, tools)`` pair ready to hand to
    :class:`AgentRuntime`. The app installs ``/``, ``/health``, and
    ``/info`` routes alongside the standard tool prefix.

    If ``observer`` is supplied it is attached to the underlying app
    and tool registry, and every committed transaction also emits a
    ``tx.commit`` event so downstream collectors get a structured copy
    independent of the local SSE topic.
    """
    app = AgentApp()
    tools = ToolRegistry()
    if observer is not None:
        app.observer = observer
        tools.observer = observer
    transactions_topic: Topic = tools.topic("transactions")

    def _publish(tx: Transaction, req: Request) -> None:
        try:
            transactions_topic.publish(tx.to_dict())
        except Exception:
            log.exception("ledger: failed to publish tx event")
        if observer is not None:
            try:
                observer.emit(
                    "tx.commit",
                    session_id=getattr(req, "session_id", None),
                    tx_id=tx.tx_id,
                    from_account=tx.from_account,
                    to_account=tx.to_account,
                    amount=tx.amount,
                    memo=tx.memo,
                    nonce=tx.nonce,
                )
            except Exception:
                log.exception("ledger: observer emit (tx.commit) failed")

    @app.get("/")
    def _root(_req: Request) -> Response:
        return Response(200, {
            "service": "ledger",
            "name": name,
            "protocol": LEDGER_PROTOCOL_VERSION,
            "endpoints": [
                "/health", "/info",
                "/.well-known/obscura/tools",
            ],
        })

    @app.get("/health")
    def _health(_req: Request) -> Response:
        s = state.stats()
        return Response(200, {"ok": True, **s})

    @app.get("/info")
    def _info(_req: Request) -> Response:
        return Response(200, {
            "service": "ledger",
            "name": name,
            "protocol": LEDGER_PROTOCOL_VERSION,
            **state.stats(),
        })

    @tools.tool(
        "balance",
        description="Return the token balance of an account.",
        params=[ParamSpec("account", type="string", required=False,
                          description="account fingerprint; defaults to caller")],
        returns="object",
    )
    def _balance(args: dict, req: Request) -> dict:
        account = args.get("account") or req.caller_fingerprint
        if not account:
            raise ToolError(
                "missing_account",
                "no account argument supplied and caller is unauthenticated",
            )
        try:
            bal = state.balance(account)
        except LedgerError as e:
            raise ToolError(e.code, e.message, status=e.status)
        return {"account": account, "balance": bal}

    @tools.tool(
        "transfer",
        description="Move tokens from the authenticated caller to another account.",
        params=[
            ParamSpec("to", type="string",
                      description="destination account fingerprint"),
            ParamSpec("amount", type="int",
                      description="positive integer amount of tokens"),
            ParamSpec("memo", type="string", required=False,
                      description="free-text annotation (<= 200 chars)"),
            ParamSpec("nonce", type="string",
                      description="caller-chosen idempotency key"),
        ],
        returns="object",
    )
    def _transfer(args: dict, req: Request) -> dict:
        caller = req.caller_fingerprint
        if not caller:
            raise ToolError(
                "not_authenticated",
                "transfer requires a `.obscura` rendezvous identity",
                status=401,
            )
        try:
            tx = state.transfer(
                from_account=caller,
                to_account=args["to"],
                amount=args["amount"],
                memo=args.get("memo", ""),
                nonce=args["nonce"],
            )
        except LedgerError as e:
            raise ToolError(e.code, e.message, status=e.status)
        _publish(tx, req)
        return {
            **tx.to_dict(),
            "balance_after": state.balance(caller),
        }

    @tools.tool(
        "history",
        description="Return recent transactions involving an account.",
        params=[
            ParamSpec("account", type="string", required=False,
                      description="account fingerprint; defaults to caller"),
            ParamSpec("limit", type="int", required=False,
                      description="max rows to return (1..500)"),
        ],
        returns="array",
    )
    def _history(args: dict, req: Request) -> list[dict]:
        account = args.get("account") or req.caller_fingerprint
        limit = args.get("limit") or HISTORY_DEFAULT_LIMIT
        try:
            rows = state.history(account=account, limit=limit)
        except LedgerError as e:
            raise ToolError(e.code, e.message, status=e.status)
        return [r.to_dict() for r in rows]

    @tools.tool(
        "mint",
        description="Admin-only: create new tokens and credit an account.",
        params=[
            ParamSpec("to", type="string"),
            ParamSpec("amount", type="int"),
            ParamSpec("memo", type="string", required=False),
        ],
        returns="object",
    )
    def _mint(args: dict, req: Request) -> dict:
        if not state.admin_fingerprint:
            raise ToolError(
                "minting_disabled",
                "ledger has no admin configured; minting is disabled",
                status=403,
            )
        caller = req.caller_fingerprint
        if not caller:
            raise ToolError(
                "not_authenticated",
                "mint requires a `.obscura` rendezvous identity",
                status=401,
            )
        if caller != state.admin_fingerprint:
            raise ToolError(
                "forbidden", "caller is not the ledger admin", status=403,
            )
        try:
            tx = state.mint(
                to_account=args["to"],
                amount=args["amount"],
                memo=args.get("memo", ""),
            )
        except LedgerError as e:
            raise ToolError(e.code, e.message, status=e.status)
        _publish(tx, req)
        return tx.to_dict()

    tools.mount(app)
    return app, tools


class LedgerClient:
    """Convenience wrapper around :class:`~src.agent.client.AgentClient`.

    Knows the tool names and unwraps the result envelope into native
    Python values. Reuses an ``AgentClient`` if supplied so a single
    process can talk to multiple ledgers without holding extra proxy
    sockets around.
    """

    def __init__(
        self,
        addr: str,
        *,
        agent: "Any | None" = None,
        port: int = 80,
    ):
        from src.agent.client import AgentClient

        self.addr = addr
        self.port = int(port)
        self.agent = agent or AgentClient()

    def balance(self, account: str | None = None) -> int:
        args: dict[str, Any] = {}
        if account is not None:
            args["account"] = account
        result = self.agent.call_tool(self.addr, "balance", args, port=self.port)
        return int(result["balance"])

    def transfer(
        self,
        *,
        to: str,
        amount: int,
        memo: str = "",
        nonce: str | None = None,
    ) -> dict[str, Any]:
        if nonce is None:
            nonce = secrets.token_hex(8)
        return self.agent.call_tool(
            self.addr, "transfer",
            {"to": to, "amount": int(amount), "memo": memo, "nonce": nonce},
            port=self.port,
        )

    def history(
        self,
        account: str | None = None,
        limit: int = HISTORY_DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        args: dict[str, Any] = {"limit": int(limit)}
        if account is not None:
            args["account"] = account
        return self.agent.call_tool(self.addr, "history", args, port=self.port)

    def mint(
        self,
        *,
        to: str,
        amount: int,
        memo: str = "",
    ) -> dict[str, Any]:
        return self.agent.call_tool(
            self.addr, "mint",
            {"to": to, "amount": int(amount), "memo": memo},
            port=self.port,
        )


def _validate_account(value: Any) -> None:
    if not isinstance(value, str):
        raise LedgerError("bad_account", "account must be a string")
    if len(value) != ACCOUNT_HEX_LEN:
        raise LedgerError(
            "bad_account",
            f"account must be {ACCOUNT_HEX_LEN} hex chars (got {len(value)})",
        )
    try:
        int(value, 16)
    except ValueError:
        raise LedgerError("bad_account", "account must be lowercase hex")
    if value.lower() != value:
        raise LedgerError("bad_account", "account must be lowercase hex")


def _validate_amount(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LedgerError("bad_amount", "amount must be an integer")
    if value <= 0:
        raise LedgerError("bad_amount", "amount must be positive")
    if value > MAX_AMOUNT:
        raise LedgerError("bad_amount", f"amount exceeds {MAX_AMOUNT}")
    return value


def _validate_memo(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise LedgerError("bad_memo", "memo must be a string")
    if len(value) > MAX_MEMO_LEN:
        raise LedgerError("bad_memo", f"memo exceeds {MAX_MEMO_LEN} chars")
    return value


def _validate_nonce(value: Any, *, required: bool) -> str | None:
    if value is None or value == "":
        if required:
            raise LedgerError("missing_nonce", "nonce is required for transfers")
        return None
    if not isinstance(value, str):
        raise LedgerError("bad_nonce", "nonce must be a string")
    if len(value) > MAX_NONCE_LEN:
        raise LedgerError("bad_nonce", f"nonce exceeds {MAX_NONCE_LEN} chars")
    return value


def _resolve_admin_fingerprint(spec: str | None) -> str | None:
    """Accept either an inline PEM, a path to a PEM, or a 64-hex fingerprint."""
    if not spec:
        return None
    raw = spec.strip()
    if "BEGIN PUBLIC KEY" in raw or "BEGIN PRIVATE KEY" in raw:
        return fingerprint_pubkey(_extract_pub_pem(raw))
    if os.path.isfile(raw):
        with open(raw, "r", encoding="utf-8") as f:
            data = f.read()
        return fingerprint_pubkey(_extract_pub_pem(data))
    if len(raw) == ACCOUNT_HEX_LEN:
        try:
            int(raw, 16)
        except ValueError:
            raise SystemExit(f"--admin-key value is neither a PEM, a path, nor a hex fingerprint")
        return raw.lower()
    raise SystemExit(
        "--admin-key must be inline PEM, a PEM file path, or a 64-hex fingerprint"
    )


def _extract_pub_pem(text: str) -> str:
    """If ``text`` is a private-key PEM, derive the corresponding public PEM."""
    if "BEGIN PUBLIC KEY" in text:
        return text
    try:
        from Crypto.PublicKey import ECC
        priv = ECC.import_key(text)
        return priv.public_key().export_key(format="PEM")
    except Exception as e:
        raise SystemExit(f"could not parse admin key material: {e}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.agent.ledger",
        description=(
            "Publish a token ledger as a `.obscura` hidden service. "
            "Reference metering primitive for `.obscura` apps."
        ),
    )
    parser.add_argument(
        "--name", default="ledger",
        help="display name surfaced in /info",
    )
    parser.add_argument(
        "--key", default="ledger_service.pem",
        help="path to the ledger ECC service keypair (PEM); created if missing",
    )
    parser.add_argument(
        "--state", default=None,
        help="path to the JSON state file (omit for ephemeral in-memory ledger)",
    )
    parser.add_argument(
        "--admin-key", default=None,
        help="public-key PEM, path to a PEM, or 64-hex fingerprint of the mint admin",
    )
    parser.add_argument(
        "--bind", default="127.0.0.1",
        help="local interface for the HTTP server (default 127.0.0.1)",
    )
    parser.add_argument(
        "--port", type=int, default=0,
        help="local port for the HTTP server (default: pick a free port)",
    )
    parser.add_argument(
        "--observatory", default=None,
        help=(
            "optional .obscura address of a collector to forward "
            "observability events to"
        ),
    )
    parser.add_argument(
        "--observatory-jsonl", default=None,
        help=(
            "optional local JSONL path that mirrors every observability "
            "event before it leaves the process"
        ),
    )

    from src.agent.sandboxed_runtime import add_sandbox_arguments, policy_from_args

    add_sandbox_arguments(parser)
    args = parser.parse_args(argv)

    admin_fp = _resolve_admin_fingerprint(args.admin_key)
    state = LedgerState(path=args.state, admin_fingerprint=admin_fp)

    from src.agent.observatory import build_observer_from_flags

    observer = build_observer_from_flags(
        actor=args.name,
        remote_addr=args.observatory,
        jsonl_path=args.observatory_jsonl,
    )

    policy = policy_from_args(args)

    app, tools = build_ledger_app(state, name=args.name, observer=observer)

    runtime = AgentRuntime(
        name=args.name, key_path=args.key,
        app=app, tools=tools,
        bind_host=args.bind, bind_port=args.port,
        observer=observer,
        policy=policy,
    )

    if not runtime.start():
        print("[ledger] failed to publish hidden service", file=sys.stderr)
        return 1

    print(
        f"[ledger] {runtime.name} → {runtime.address} "
        f"(admin={admin_fp or 'unset'}, state={args.state or 'in-memory'})"
    )
    try:
        runtime.join()
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
