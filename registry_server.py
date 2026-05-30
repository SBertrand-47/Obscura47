"""
Obscura47 - Bootstrap Registry Server (FastAPI + SQLite)

Drop this single file on any public server (VPS, cloud instance, etc.) and run:

    python registry_server.py

Or with uvicorn directly:

    uvicorn registry_server:app --host 0.0.0.0 --port 8470

Options (env vars or CLI):
    --port PORT    Port to listen on (default: 8470)
    --host HOST    Bind address (default: 0.0.0.0)

Features:
    - SQLite persistence (peers survive restarts)
    - ECDSA challenge-response auth (prevents fake node injection)
    - Per-IP rate limiting
    - Admin API (bearer token for peer management)
"""

import argparse
import asyncio
import ipaddress
import json
import os
import secrets
import threading
import time
import base64
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

import aiosqlite
from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

try:
    from src.utils.audit import write_audit_event
except Exception:
    def write_audit_event(*_args, **_kwargs):
        return

# ── Configuration ────────────────────────────────────────────────
DEFAULT_PORT = int(os.getenv("OBSCURA_REGISTRY_PORT", "8470"))
PEER_TTL = int(os.getenv("OBSCURA_REGISTRY_PEER_TTL", "120"))
DB_PATH = os.getenv("OBSCURA_REGISTRY_DB_PATH", "registry.db")
ADMIN_KEY = os.getenv("OBSCURA_REGISTRY_ADMIN_KEY", "")
RATE_LIMIT = int(os.getenv("OBSCURA_REGISTRY_RATE_LIMIT", "60"))  # requests/min/IP
TLS_CERT = os.getenv("OBSCURA_REGISTRY_TLS_CERT", "")
TLS_KEY = os.getenv("OBSCURA_REGISTRY_TLS_KEY", "")
AUDIT_RETENTION_DAYS = int(os.getenv("OBSCURA_AUDIT_RETENTION_DAYS", "14"))
REGISTRY_ADMIN_AUDIT_ENABLED = os.getenv("OBSCURA_REGISTRY_ADMIN_AUDIT_ENABLED", "true").lower() in ("1", "true", "yes")
REGISTRY_ADMIN_AUDIT_PATH = os.getenv(
    "OBSCURA_REGISTRY_ADMIN_AUDIT_PATH",
    os.path.join(os.path.expanduser("~"), ".obscura47", "audit", "registry_admin.jsonl"),
)
# Diagnostic event collection. Off unless OBSCURA_DIAG_TOKEN is set; nodes
# include the same token in their X-Diag-Token header. The collected events
# go to a rolling JSONL file under ~/.obscura47, separate from audit logs.
DIAG_TOKEN = os.getenv("OBSCURA_DIAG_TOKEN", "")
DIAG_PATH = os.getenv(
    "OBSCURA_DIAG_PATH",
    os.path.join(os.path.expanduser("~"), ".obscura47", "diag.jsonl"),
)
DIAG_MAX_BYTES = int(os.getenv("OBSCURA_DIAG_MAX_BYTES", str(50 * 1024 * 1024)))  # 50MB
DIAG_MAX_BATCH = int(os.getenv("OBSCURA_DIAG_MAX_BATCH", "100"))
DASHBOARD_DIR = Path(__file__).resolve().parent / "dashboard"
DASHBOARD_DIST_DIR = DASHBOARD_DIR / "dist"
# Admin public key: read from inline PEM or file path
_admin_pub_raw = os.getenv("OBSCURA_ADMIN_PUB_PEM", "")
_admin_pub_path = os.getenv("OBSCURA_ADMIN_PUB_PEM_PATH", "")
if _admin_pub_raw and _admin_pub_raw.startswith("-----"):
    ADMIN_PUB_PEM = _admin_pub_raw
elif _admin_pub_path:
    try:
        _p = _admin_pub_path if os.path.isabs(_admin_pub_path) else os.path.join(os.path.dirname(os.path.abspath(__file__)), _admin_pub_path)
        with open(_p, "r") as _f:
            ADMIN_PUB_PEM = _f.read().strip()
    except Exception:
        ADMIN_PUB_PEM = ""
else:
    ADMIN_PUB_PEM = ""

# ── ECDSA verification (inline, no project imports needed) ───────
# This uses pycryptodome which must be installed on the registry server
try:
    from Crypto.PublicKey import ECC
    from Crypto.Signature import DSS
    from Crypto.Hash import SHA256
    _ECDSA_AVAILABLE = True

    def _ecdsa_verify(pub_pem: str, message: bytes, signature_b64: str) -> bool:
        try:
            pub = ECC.import_key(pub_pem)
            h = SHA256.new(message)
            verifier = DSS.new(pub, 'fips-186-3')
            verifier.verify(h, base64.b64decode(signature_b64))
            return True
        except (ValueError, TypeError):
            return False
except ImportError:
    _ECDSA_AVAILABLE = False

    def _ecdsa_verify(pub_pem: str, message: bytes, signature_b64: str) -> bool:
        raise RuntimeError(
            "pycryptodome is not installed - ECDSA verification unavailable. "
            "Install it with: pip install pycryptodome"
        )

# ── Rate limiter (in-memory token bucket per IP) ─────────────────
_rate_buckets: dict[str, list] = {}  # ip -> [timestamps]


def _check_rate_limit(ip: str) -> bool:
    """Returns True if request is allowed, False if rate limited."""
    now = time.time()
    window = 60.0
    if ip not in _rate_buckets:
        _rate_buckets[ip] = []
    bucket = _rate_buckets[ip]
    # Purge old entries
    _rate_buckets[ip] = [t for t in bucket if now - t < window]
    if len(_rate_buckets[ip]) >= RATE_LIMIT:
        return False
    _rate_buckets[ip].append(now)
    return True


# ── WS-port reachability probe (registry-side) ───────────────────
# A peer can heartbeat HTTP just fine while its advertised ws_port is
# blocked by a firewall (corporate network, NAT without forward, etc.).
# Without a probe here, the registry happily advertises that ws_port to
# everyone else, and every circuit/intro that picks the peer eats a
# multi-second timeout. We probe from the registry's vantage at most
# once per WS_PROBE_INTERVAL and mask ws_port to None in /peers responses
# when the probe fails. Heartbeats refresh the verdict; a peer whose
# firewall later opens recovers automatically on the next probe.
_ws_probe_cache: dict[str, tuple[float, bool]] = {}  # peer_id -> (ts, reachable)
WS_PROBE_INTERVAL = 60.0
WS_PROBE_TIMEOUT = 3.0


async def _probe_ws_endpoint(host: str, port: int, timeout: float = WS_PROBE_TIMEOUT) -> bool:
    """Best-effort async TCP probe,does anything accept on host:port?"""
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, OSError, ConnectionError):
        return False
    except Exception:
        return False


async def _verify_ws_reachable(peer_id: str, host: str, ws_port: int) -> bool:
    """Cached probe of ``host:ws_port``. Probes at most once per WS_PROBE_INTERVAL."""
    if not host or not ws_port:
        return True
    now = time.time()
    cached = _ws_probe_cache.get(peer_id)
    if cached and (now - cached[0]) < WS_PROBE_INTERVAL:
        return cached[1]
    ok = await _probe_ws_endpoint(host, int(ws_port))
    _ws_probe_cache[peer_id] = (now, ok)
    if not ok:
        print(f"[registry] ws_port unreachable for {peer_id} (probed {host}:{ws_port}); "
              f"masking from /peers responses")
    return ok


def _ws_recently_unreachable(peer_id: str) -> bool:
    """True if the cached probe verdict for peer_id is recent and False."""
    entry = _ws_probe_cache.get(peer_id)
    if not entry:
        return False
    ts, ok = entry
    if (time.time() - ts) >= WS_PROBE_INTERVAL * 2:
        # Stale verdict,let the next consumer try and let peer_health on
        # their side mark it bad if it really is.
        return False
    return not ok


# ── Pydantic Models ──────────────────────────────────────────────

class PeerRegistration(BaseModel):
    role: Literal["node", "exit", "proxy"]
    port: int = Field(ge=1, le=65535)
    pub: str | None = None
    ws_port: int | None = Field(default=None, ge=1, le=65535)
    ws_tls: bool | None = None  # True if ws_port serves wss://
    advertised_host: str | None = None


class AuthVerification(BaseModel):
    peer_id: str
    signature: str  # base64-encoded ECDSA signature of the challenge nonce


class Deregistration(BaseModel):
    """Signed self-deregister payload. Sig is over ``deregister:{peer_id}:{timestamp}``."""
    peer_id: str
    timestamp: float
    signature: str


class HSDescriptorDelete(BaseModel):
    """Signed HS descriptor deletion. Sig is over ``hs-delete:{addr}:{timestamp}`` by the service key."""
    addr: str
    timestamp: float
    signature: str


# Max clock skew between client and registry for replay protection.
DEREGISTER_MAX_SKEW = 60.0


class PeerInfo(BaseModel):
    host: str
    port: int
    role: str
    pub: str | None = None
    ws_port: int | None = None
    ws_tls: bool | None = None
    last_seen: float


class HealthResponse(BaseModel):
    status: str
    peers: int
    breakdown: dict[str, int]


class KillSwitchRequest(BaseModel):
    reason: str
    signature: str


class PeerHealthInfo(BaseModel):
    peer_id: str
    host: str
    port: int
    role: str
    approved: bool
    last_heartbeat: float
    time_since_heartbeat: float


class AdminHealthResponse(BaseModel):
    total_peers: int
    peers: list[PeerHealthInfo]


class AdminPeerInfo(PeerHealthInfo):
    pub: str | None = None
    ws_port: int | None = None
    ws_tls: bool | None = None


# ── Pending challenges (in-memory, short-lived) ─────────────────
_pending_challenges: dict[str, dict] = {}  # peer_id -> {nonce, peer_data, created_at, ip}


# ── SQLite Database ──────────────────────────────────────────────

DB: aiosqlite.Connection | None = None


async def init_db():
    global DB
    DB = await aiosqlite.connect(DB_PATH)
    await DB.execute("PRAGMA journal_mode=WAL")
    await DB.execute("""
        CREATE TABLE IF NOT EXISTS peers (
            id TEXT PRIMARY KEY,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            role TEXT NOT NULL,
            pub_pem TEXT,
            ws_port INTEGER,
            last_heartbeat REAL NOT NULL,
            metadata TEXT
        )
    """)
    # Additive migration - tolerate existing DBs that pre-date ws_tls
    try:
        await DB.execute("ALTER TABLE peers ADD COLUMN ws_tls INTEGER")
    except Exception:
        pass
    # Additive migration - add approved column for exit node approval system
    try:
        await DB.execute("ALTER TABLE peers ADD COLUMN approved INTEGER DEFAULT 1")
    except Exception:
        pass
    # Additive migration - record the public IP the registry observed at
    # registration. Used to scope private (RFC1918) advertised hosts to peers
    # behind the same NAT, so a LAN-only address is never served to a node
    # that cannot route to it.
    try:
        await DB.execute("ALTER TABLE peers ADD COLUMN source_ip TEXT")
    except Exception:
        pass
    # Network status table for kill switch
    await DB.execute("""
        CREATE TABLE IF NOT EXISTS network_status (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            kill_active INTEGER DEFAULT 0,
            kill_reason TEXT,
            kill_timestamp REAL,
            admin_signature TEXT
        )
    """)
    # Ensure a single row exists in network_status
    await DB.execute("""
        INSERT OR IGNORE INTO network_status (id, kill_active) VALUES (1, 0)
    """)
    # Hidden-service descriptors (plaintext signed blobs)
    await DB.execute("""
        CREATE TABLE IF NOT EXISTS hs_descriptors (
            addr TEXT PRIMARY KEY,
            descriptor TEXT NOT NULL,
            expires REAL NOT NULL,
            updated REAL NOT NULL
        )
    """)
    await DB.commit()
    print(f"[registry] SQLite database initialized at {DB_PATH}")


async def close_db():
    global DB
    if DB:
        await DB.close()
        DB = None


async def upsert_peer(peer_id: str, host: str, port: int, role: str,
                       pub_pem: str | None = None, ws_port: int | None = None,
                       ws_tls: bool | None = None, source_ip: str | None = None):
    ws_tls_int = None if ws_tls is None else (1 if ws_tls else 0)

    # Determine approved status: nodes/proxies auto-approved, exits pending
    approved_val = 1 if role in ("node", "proxy") else 0

    # Check if peer already exists (for heartbeat logic)
    existing = await DB.execute("SELECT role, approved FROM peers WHERE id = ?", (peer_id,))
    existing_row = await existing.fetchone()

    if existing_row:
        # Peer exists: preserve approved status for exits, use auto-approve for role changes
        existing_role, existing_approved = existing_row
        if existing_role == "exit" and role == "exit":
            # Exit re-registering: preserve current approved status
            approved_val = existing_approved
        else:
            # Role changed or wasn't exit: use auto-approval rules
            approved_val = 1 if role in ("node", "proxy") else 0

    await DB.execute("""
        INSERT INTO peers (id, host, port, role, pub_pem, ws_port, ws_tls, approved, last_heartbeat, source_ip)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            host=excluded.host,
            port=excluded.port,
            role=excluded.role,
            pub_pem=COALESCE(excluded.pub_pem, peers.pub_pem),
            ws_port=COALESCE(excluded.ws_port, peers.ws_port),
            ws_tls=COALESCE(excluded.ws_tls, peers.ws_tls),
            approved=CASE
                WHEN excluded.role IN ('node', 'proxy') THEN 1
                WHEN excluded.role = 'exit' AND peers.role = 'exit' THEN peers.approved
                ELSE 0
            END,
            last_heartbeat=excluded.last_heartbeat,
            source_ip=COALESCE(excluded.source_ip, peers.source_ip)
    """, (peer_id, host, port, role, pub_pem, ws_port, ws_tls_int, approved_val, time.time(), source_ip))
    await DB.commit()


async def get_peers(role_filter: str | None = None,
                    requester_ip: str | None = None) -> list[dict]:
    cutoff = time.time() - PEER_TTL
    # Filter: include all approved peers, or unapproved non-exit peers
    # This excludes unapproved exit nodes from being returned to proxies
    if role_filter:
        cursor = await DB.execute(
            "SELECT host, port, role, pub_pem, ws_port, ws_tls, last_heartbeat, source_ip FROM peers WHERE last_heartbeat > ? AND role = ? AND (approved = 1 OR role != 'exit')",
            (cutoff, role_filter)
        )
    else:
        cursor = await DB.execute(
            "SELECT host, port, role, pub_pem, ws_port, ws_tls, last_heartbeat, source_ip FROM peers WHERE last_heartbeat > ? AND (approved = 1 OR role != 'exit')",
            (cutoff,)
        )
    rows = await cursor.fetchall()
    out: list[dict] = []
    for r in rows:
        host, port, role, pub, ws_port, ws_tls, last_seen, source_ip = r
        # NAT-scoped visibility: a peer advertising a private (RFC1918) host is
        # only reachable from inside its own NAT, so serve it only to a
        # requester the registry observed behind that same public IP. Public
        # hosts are served to everyone. When the requester IP is unknown
        # (internal call), don't filter. OBSCURA_ALLOW_LAN_PEERS=1 disables the
        # scoping for fully-private testnets, mirroring the client-side opt-in.
        if requester_ip is not None and _is_private_host(host) and not _allow_lan_peers():
            if not source_ip or source_ip != requester_ip:
                continue
        # Mask ws_port for peers whose registry-side probe recently failed.
        # The peer stays in the listing as a TCP-only candidate, so HTTP
        # heartbeats keep working and they recover the moment their probe
        # succeeds again (on the next heartbeat-triggered re-probe).
        if ws_port is not None:
            peer_id = f"{host}:{port}"
            if _ws_recently_unreachable(peer_id):
                ws_port = None
                ws_tls = None
        out.append({
            "host": host, "port": port, "role": role,
            "pub": pub, "ws_port": ws_port,
            "ws_tls": bool(ws_tls) if ws_tls is not None else None,
            "last_seen": last_seen,
        })
    return out


async def expire_stale():
    cutoff = time.time() - PEER_TTL
    cursor = await DB.execute("DELETE FROM peers WHERE last_heartbeat < ?", (cutoff,))
    await DB.commit()
    return cursor.rowcount


async def delete_peer(peer_id: str) -> bool:
    cursor = await DB.execute("DELETE FROM peers WHERE id = ?", (peer_id,))
    await DB.commit()
    return cursor.rowcount > 0


async def get_peer_by_id(peer_id: str) -> dict | None:
    cursor = await DB.execute(
        "SELECT host, port, role, pub_pem, ws_port, ws_tls, last_heartbeat FROM peers WHERE id = ?",
        (peer_id,)
    )
    row = await cursor.fetchone()
    if not row:
        return None
    return {
        "host": row[0], "port": row[1], "role": row[2],
        "pub": row[3], "ws_port": row[4],
        "ws_tls": bool(row[5]) if row[5] is not None else None,
        "last_seen": row[6],
    }


async def _registration_response(source_ip: str | None, advertised_host: str,
                                  peer_id: str) -> dict:
    """Build a /register response with primary/sibling classification.

    A registration is classified ``sibling`` when its advertised host is a
    private (LAN) address - it can only be reached from inside the same NAT
    and so depends on a public-IP-bound peer as its gateway to the broader
    network. ``primary_peer`` carries that gateway when one is currently
    registered, so the sibling can pin it as a first hop without a separate
    lookup.
    """
    role_kind = "sibling" if _is_private_host(advertised_host) else "primary"
    body: dict = {
        "ok": True,
        "your_ip": source_ip,
        "registered_host": advertised_host,
        "peer_id": peer_id,
        "role_kind": role_kind,
    }
    if role_kind == "sibling":
        primary = await get_primary_node_for_nat(source_ip)
        if primary:
            body["primary_peer"] = primary
    return body


async def get_primary_node_for_nat(source_ip: str | None) -> dict | None:
    """Return the public-IP-bound node registered from *source_ip*, if any.

    The "primary" for a NAT is the relay whose advertised host equals the
    public IP the registry observed for the requester - i.e. the first
    claimant of the (public_ip, port) slot. Other peers from the same
    source_ip that advertise a private (LAN) host are siblings of this
    primary and should route through it as their gateway.
    """
    if not source_ip:
        return None
    cutoff = time.time() - PEER_TTL
    cursor = await DB.execute(
        "SELECT host, port, pub_pem, ws_port, ws_tls FROM peers "
        "WHERE source_ip = ? AND host = ? AND role = 'node' "
        "AND last_heartbeat > ? AND approved = 1 LIMIT 1",
        (source_ip, source_ip, cutoff),
    )
    row = await cursor.fetchone()
    if not row:
        return None
    host, port, pub, ws_port, ws_tls = row
    return {
        "host": host, "port": port, "pub": pub,
        "ws_port": ws_port,
        "ws_tls": bool(ws_tls) if ws_tls is not None else None,
    }


async def get_stats() -> tuple[dict[str, int], int]:
    cursor = await DB.execute("SELECT role, COUNT(*) FROM peers WHERE last_heartbeat > ? GROUP BY role", (time.time() - PEER_TTL,))
    rows = await cursor.fetchall()
    breakdown = {r[0]: r[1] for r in rows}
    total = sum(breakdown.values())
    return breakdown, total


async def get_unapproved_exits() -> list[dict]:
    """Get all pending (unapproved) exit nodes."""
    cursor = await DB.execute(
        "SELECT id, host, port, pub_pem, ws_port, ws_tls, last_heartbeat, approved FROM peers WHERE role = 'exit' AND approved = 0 ORDER BY last_heartbeat DESC"
    )
    rows = await cursor.fetchall()
    now = time.time()
    return [
        {
            "peer_id": r[0],
            "host": r[1],
            "port": r[2],
            "pub": r[3],
            "ws_port": r[4],
            "ws_tls": bool(r[5]) if r[5] is not None else None,
            "last_heartbeat": r[6],
            "time_since_heartbeat": now - r[6],
            "approved": bool(r[7]),
        }
        for r in rows
    ]


async def approve_exit(peer_id: str) -> bool:
    """Approve an exit node. Returns True if successful."""
    cursor = await DB.execute(
        "UPDATE peers SET approved = 1 WHERE id = ? AND role = 'exit'",
        (peer_id,)
    )
    await DB.commit()
    return cursor.rowcount > 0


async def reject_exit(peer_id: str) -> bool:
    """Reject/remove an exit node. Returns True if successful."""
    cursor = await DB.execute(
        "DELETE FROM peers WHERE id = ? AND role = 'exit'",
        (peer_id,)
    )
    await DB.commit()
    return cursor.rowcount > 0


async def get_network_status() -> dict:
    """Get current network status (kill switch state)."""
    cursor = await DB.execute(
        "SELECT kill_active, kill_reason, kill_timestamp, admin_signature FROM network_status WHERE id = 1"
    )
    row = await cursor.fetchone()
    if not row:
        return {"kill_active": False}
    kill_active, reason, timestamp, signature = row
    if not kill_active:
        return {"kill_active": False}
    return {
        "kill_active": True,
        "reason": reason or "",
        "timestamp": timestamp,
        "signature": signature or "",
    }


async def set_kill_active(reason: str, signature: str) -> None:
    """Activate the kill switch."""
    now = time.time()
    await DB.execute(
        "UPDATE network_status SET kill_active = 1, kill_reason = ?, kill_timestamp = ?, admin_signature = ? WHERE id = 1",
        (reason, now, signature)
    )
    await DB.commit()


async def set_kill_inactive() -> None:
    """Deactivate the kill switch."""
    await DB.execute(
        "UPDATE network_status SET kill_active = 0, kill_reason = NULL, kill_timestamp = NULL, admin_signature = NULL WHERE id = 1"
    )
    await DB.commit()


async def get_all_peers_with_details() -> list[dict]:
    """Get all peers (including stale) with detailed info for admin health endpoint."""
    cursor = await DB.execute(
        "SELECT id, host, port, role, approved, pub_pem, ws_port, ws_tls, last_heartbeat FROM peers ORDER BY last_heartbeat DESC"
    )
    rows = await cursor.fetchall()
    now = time.time()
    return [
        {
            "peer_id": r[0],
            "host": r[1],
            "port": r[2],
            "role": r[3],
            "approved": bool(r[4]),
            "pub": r[5],
            "ws_port": r[6],
            "ws_tls": bool(r[7]) if r[7] is not None else None,
            "last_heartbeat": r[8],
            "time_since_heartbeat": now - r[8],
        }
        for r in rows
    ]


async def get_dashboard_summary() -> dict:
    """Return the admin dashboard view backed by the registry SQLite DB."""
    peers = await get_all_peers_with_details()
    status = await get_network_status()
    live_cutoff = PEER_TTL
    pending_exits = [p for p in peers if p["role"] == "exit" and not p["approved"]]
    approved_exits = [p for p in peers if p["role"] == "exit" and p["approved"]]
    live_peers = [p for p in peers if p["time_since_heartbeat"] <= live_cutoff]
    stale_peers = [p for p in peers if p["time_since_heartbeat"] > live_cutoff]
    role_counts: dict[str, int] = {}
    for peer in peers:
        role_counts[peer["role"]] = role_counts.get(peer["role"], 0) + 1
    return {
        "status": "ok",
        "peer_ttl": PEER_TTL,
        "network": status,
        "summary": {
            "total": len(peers),
            "live": len(live_peers),
            "stale": len(stale_peers),
            "pending_exits": len(pending_exits),
            "approved_exits": len(approved_exits),
            "roles": role_counts,
        },
        "pending_exits": pending_exits,
        "peers": peers,
    }


# ── Background tasks ─────────────────────────────────────────────

async def expiry_loop():
    while True:
        await asyncio.sleep(15)
        try:
            count = await expire_stale()
            if count:
                print(f"[registry] Expired {count} stale peer(s)")
        except Exception as e:
            print(f"[registry] Expiry error: {e}")


async def stats_loop():
    while True:
        await asyncio.sleep(60)
        try:
            breakdown, total = await get_stats()
            print(f"[registry] Peers: {total} | {breakdown}")
        except Exception:
            pass


async def challenge_cleanup_loop():
    """Clean up expired pending challenges (older than 30s)."""
    while True:
        await asyncio.sleep(10)
        now = time.time()
        expired = [k for k, v in _pending_challenges.items() if now - v.get("created_at", 0) > 30]
        for k in expired:
            del _pending_challenges[k]


async def rate_bucket_gc_loop():
    """Purge stale rate-limit buckets to prevent unbounded memory growth."""
    while True:
        await asyncio.sleep(120)
        now = time.time()
        stale = [ip for ip, ts_list in _rate_buckets.items() if not ts_list or now - max(ts_list) > 120]
        for ip in stale:
            del _rate_buckets[ip]


# ── FastAPI App ──────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    asyncio.create_task(expiry_loop())
    asyncio.create_task(stats_loop())
    asyncio.create_task(challenge_cleanup_loop())
    asyncio.create_task(rate_bucket_gc_loop())
    print(f"=========================================")
    print(f"  Obscura47 Bootstrap Registry (FastAPI)")
    print(f"  Peer TTL: {PEER_TTL}s")
    print(f"  Database: {DB_PATH}")
    print(f"  Rate limit: {RATE_LIMIT} req/min/IP")
    print(f"  Admin key: {'configured' if ADMIN_KEY else 'NOT SET (admin endpoints disabled)'}")
    print(f"  ECDSA auth: {'enabled' if _ECDSA_AVAILABLE else 'disabled (pycryptodome missing)'}")
    print(f"=========================================")
    yield
    await close_db()


app = FastAPI(title="Obscura47 Registry", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

if (DASHBOARD_DIST_DIR / "assets").exists():
    app.mount("/dashboard/assets", StaticFiles(directory=DASHBOARD_DIST_DIR / "assets"), name="dashboard-assets")


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return _normalise_ip(forwarded.split(",")[0].strip())
    return _normalise_ip(request.client.host)


def _normalise_ip(ip: str) -> str:
    """Normalise an IP address for storage and peer-id construction.

    * Strips IPv6 zone IDs (``%eth0``).
    * Unwraps IPv4-mapped IPv6 addresses (``::ffff:1.2.3.4`` → ``1.2.3.4``).
    * Strips surrounding brackets (``[::1]`` → ``::1``).
    """
    ip = ip.strip()
    if ip.startswith("[") and ip.endswith("]"):
        ip = ip[1:-1]
    # Remove zone ID
    if "%" in ip:
        ip = ip.split("%")[0]
    # Unwrap IPv4-mapped IPv6
    prefixes = ("::ffff:", "0:0:0:0:0:ffff:")
    for prefix in prefixes:
        if ip.lower().startswith(prefix):
            maybe_v4 = ip[len(prefix):]
            if ":" not in maybe_v4:
                return maybe_v4
    return ip


def _allow_lan_peers() -> bool:
    """``OBSCURA_ALLOW_LAN_PEERS=1`` serves private hosts to everyone.

    Mirrors the client-side opt-in so a fully-private testnet can run without
    NAT-scoping. Off by default - private hosts stay scoped to their own NAT.
    """
    return os.environ.get("OBSCURA_ALLOW_LAN_PEERS", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _is_private_host(host: str | None) -> bool:
    """True if ``host`` is a non-routable address literal.

    RFC1918 / loopback / link-local / multicast / unspecified hosts are only
    reachable from the same network, so the registry must not serve them to
    peers behind a different NAT. Hostnames are treated as public - DNS
    resolves them at dial time.
    """
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(str(host).strip())
    except ValueError:
        return False
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_unspecified or ip.is_reserved
    )


def _audit_admin_event(action: str, *, request: Request | None = None, target: str | None = None,
                       allowed: bool, reason: str | None = None) -> None:
    write_audit_event(
        REGISTRY_ADMIN_AUDIT_PATH,
        {
            "component": "registry",
            "event": "admin_action",
            "action": action,
            "allowed": allowed,
            "source_ip": _get_client_ip(request) if request is not None else None,
            "target": target,
            "reason": reason,
        },
        enabled=REGISTRY_ADMIN_AUDIT_ENABLED,
        retention_days=AUDIT_RETENTION_DAYS,
    )


def _require_admin_auth(request: Request, authorization: str | None, action: str, target: str | None = None) -> None:
    if not ADMIN_KEY:
        _audit_admin_event(action, request=request, target=target, allowed=False, reason="admin_not_configured")
        raise HTTPException(403, detail="Admin key not configured")
    if authorization != f"Bearer {ADMIN_KEY}":
        _audit_admin_event(action, request=request, target=target, allowed=False, reason="invalid_admin_key")
        raise HTTPException(403, detail="Invalid admin key")
    _audit_admin_event(action, request=request, target=target, allowed=True)


# ── Endpoints ────────────────────────────────────────────────────

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard():
    """Serve the React admin dashboard when it has been built."""
    index_path = DASHBOARD_DIST_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(
            503,
            detail="Dashboard is not built. Run `npm install && npm run build` in the dashboard directory.",
        )
    return FileResponse(index_path)


@app.post("/register")
async def register_peer(body: PeerRegistration, request: Request):
    """
    Register a peer. If the peer provides a public key, a challenge nonce is
    returned that must be signed and submitted to /register/verify.
    If no public key is provided, the peer is registered immediately (unauthenticated).
    """
    ip = _get_client_ip(request)
    advertised_host = _normalise_ip(body.advertised_host) if body.advertised_host else ip

    if not _check_rate_limit(ip):
        raise HTTPException(429, detail="Rate limit exceeded")

    peer_id = f"{advertised_host}:{body.port}"

    # First-claimant binding (trust-on-first-use): a live slot owned by an
    # established pubkey may only be re-claimed by that same key. This makes
    # the registry first-come-first-served for a given advertised host:port -
    # a second machine behind the same NAT can't silently clobber the first,
    # and an attacker can't overwrite a healthy node's entry with a foreign
    # key. The slot frees once its holder goes stale (no heartbeat within
    # PEER_TTL) or signs a /deregister with the owning key.
    existing = await get_peer_by_id(peer_id)
    if (
        existing
        and existing.get("pub")
        and existing["pub"] != body.pub
        and (time.time() - existing["last_seen"]) <= PEER_TTL
    ):
        age = time.time() - existing["last_seen"]
        print(f"[registry] x rejected takeover of live slot {peer_id} "
              f"(held by another key, {age:.0f}s since heartbeat)")
        raise HTTPException(
            409,
            detail=(
                f"{peer_id} is held by another node's key and is still live "
                f"(heartbeat {age:.0f}s ago); the holder must /deregister or "
                f"expire (TTL {PEER_TTL}s) before another key can claim it"
            ),
        )

    # If peer has a public key, require challenge-response auth
    if body.pub:
        # Known peer heartbeat - same key re-registering, skip re-auth.
        if existing and existing.get("pub") == body.pub:
            # Known peer heartbeat - update timestamp without re-auth.
            # Re-probe ws_port (throttled by WS_PROBE_INTERVAL) so a peer
            # whose firewall opens/closes mid-session recovers/degrades.
            # Skip the probe for private/LAN advertised hosts: the registry's
            # VPS cannot reach them, so the probe would always fail and mask
            # the sibling's ws_port for its LAN peers (who CAN reach it).
            if body.ws_port and not _is_private_host(advertised_host):
                await _verify_ws_reachable(peer_id, advertised_host, body.ws_port)
            await upsert_peer(peer_id, advertised_host, body.port, body.role, body.pub,
                              body.ws_port, body.ws_tls, source_ip=ip)
            return await _registration_response(ip, advertised_host, peer_id)

        # New peer or pubkey change - issue challenge
        nonce = secrets.token_hex(32)
        _pending_challenges[peer_id] = {
            "nonce": nonce,
            "peer_data": {
                "host": advertised_host,
                "port": body.port,
                "role": body.role,
                "pub": body.pub,
                "ws_port": body.ws_port,
                "ws_tls": body.ws_tls,
            },
            "created_at": time.time(),
            "ip": ip,
        }
        print(f"[registry] Challenge issued for {body.role} at {peer_id}")
        return {"ok": False, "challenge": nonce, "peer_id": peer_id, "your_ip": ip, "registered_host": advertised_host}

    # No public key. Relays and exits MUST authenticate - otherwise anyone
    # can flood the pool with self-asserted entries that every consumer then
    # pays a probe/timeout for. Proxies remain allowed unauthenticated so
    # legacy client-only proxies that never minted a long-lived key keep
    # working; they don't get picked as a routing hop.
    if body.role in ("node", "exit"):
        print(f"[registry] x rejected unauthenticated {body.role} registration from {peer_id}")
        raise HTTPException(
            401,
            detail=f"role={body.role!r} requires a public key and challenge-response auth",
        )

    is_new = existing is None
    if body.ws_port and not _is_private_host(advertised_host):
        await _verify_ws_reachable(peer_id, advertised_host, body.ws_port)
    await upsert_peer(peer_id, advertised_host, body.port, body.role,
                      ws_port=body.ws_port, ws_tls=body.ws_tls, source_ip=ip)
    if is_new:
        print(f"[registry] + New {body.role} at {peer_id} (no auth)")
    return await _registration_response(ip, advertised_host, peer_id)


@app.post("/register/verify")
async def verify_registration(body: AuthVerification, request: Request):
    """
    Complete registration by providing the ECDSA signature of the challenge nonce.
    """
    ip = _get_client_ip(request)

    if not _check_rate_limit(ip):
        raise HTTPException(429, detail="Rate limit exceeded")

    challenge = _pending_challenges.get(body.peer_id)
    if not challenge:
        raise HTTPException(400, detail="No pending challenge for this peer_id")

    if challenge["ip"] != ip:
        raise HTTPException(403, detail="IP mismatch")

    # Verify ECDSA signature of the nonce
    pub_pem = challenge["peer_data"]["pub"]
    nonce_bytes = challenge["nonce"].encode()

    if not _ecdsa_verify(pub_pem, nonce_bytes, body.signature):
        del _pending_challenges[body.peer_id]
        raise HTTPException(403, detail="Invalid signature")

    # Auth passed - register the peer
    data = challenge["peer_data"]
    del _pending_challenges[body.peer_id]

    if data.get("ws_port") and not _is_private_host(data["host"]):
        await _verify_ws_reachable(body.peer_id, data["host"], int(data["ws_port"]))
    await upsert_peer(body.peer_id, data["host"], data["port"], data["role"],
                       data["pub"], data.get("ws_port"), data.get("ws_tls"), source_ip=ip)
    print(f"[registry] + Verified {data['role']} at {body.peer_id}")
    return await _registration_response(ip, data["host"], body.peer_id)


# ── Diagnostic event collection ──────────────────────────────────
_diag_file_lock = threading.Lock()


def _diag_roll_if_needed(path: str) -> None:
    try:
        if os.path.getsize(path) >= DIAG_MAX_BYTES:
            rolled = path + ".1"
            if os.path.exists(rolled):
                os.remove(rolled)
            os.rename(path, rolled)
    except OSError:
        pass


def _diag_append(events: list[dict]) -> None:
    """Append validated events to the rolling JSONL diag file."""
    parent = os.path.dirname(DIAG_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with _diag_file_lock:
        _diag_roll_if_needed(DIAG_PATH)
        with open(DIAG_PATH, "a", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev, separators=(",", ":")) + "\n")


@app.post("/diag")
async def submit_diag(request: Request):
    """Receive structured diagnostic events from nodes.

    Disabled unless ``OBSCURA_DIAG_TOKEN`` is set on the registry. Nodes
    authenticate by sending the same value in ``X-Diag-Token``. This is a
    development aid,turning it on tells the registry which peer did what
    when, which is a privacy regression versus the normal opaque-routing
    design. Only run with diag enabled on networks you own.
    """
    if not DIAG_TOKEN:
        raise HTTPException(503, detail="Diagnostic collection not enabled on this registry")

    presented = request.headers.get("x-diag-token", "")
    if presented != DIAG_TOKEN:
        raise HTTPException(401, detail="Invalid diag token")

    ip = _get_client_ip(request)
    if not _check_rate_limit(ip):
        raise HTTPException(429, detail="Rate limit exceeded")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="Invalid JSON")

    # Accept either a single event or {"events": [...]}.
    if isinstance(body, dict) and "events" in body:
        events = body["events"]
    elif isinstance(body, dict):
        events = [body]
    else:
        raise HTTPException(400, detail="Expected an object or {events: [...]}")

    if not isinstance(events, list):
        raise HTTPException(400, detail="events must be a list")
    if len(events) > DIAG_MAX_BATCH:
        raise HTTPException(400, detail=f"Batch exceeds DIAG_MAX_BATCH={DIAG_MAX_BATCH}")

    # Validate each event minimally and stamp registry-side receive time so
    # we can detect clock-skewed nodes.
    now = time.time()
    cleaned: list[dict] = []
    for ev in events:
        if not isinstance(ev, dict):
            raise HTTPException(400, detail="each event must be an object")
        if "event" not in ev:
            raise HTTPException(400, detail="each event must have an 'event' field")
        ev = dict(ev)
        ev.setdefault("ts", now)
        ev["received_at"] = now
        ev["source_ip"] = ip
        cleaned.append(ev)

    _diag_append(cleaned)
    return {"ok": True, "accepted": len(cleaned)}


@app.post("/deregister")
async def deregister_peer(body: Deregistration, request: Request):
    """Authenticated self-removal. Lets a node clear itself from the registry
    on graceful disconnect instead of waiting out PEER_TTL.

    Signature is over ``deregister:{peer_id}:{timestamp}`` with the peer's
    private key; verified against the stored ``pub_pem``. A bounded clock skew
    (DEREGISTER_MAX_SKEW) prevents replay of a captured signature.
    """
    ip = _get_client_ip(request)
    if not _check_rate_limit(ip):
        raise HTTPException(429, detail="Rate limit exceeded")

    now = time.time()
    if abs(now - body.timestamp) > DEREGISTER_MAX_SKEW:
        raise HTTPException(400, detail="Timestamp outside allowed skew window")

    peer = await get_peer_by_id(body.peer_id)
    if not peer:
        # Idempotent: deregistering an already-gone peer is a no-op success.
        return {"ok": True, "deleted": False}

    pub_pem = peer.get("pub")
    if not pub_pem:
        # Unauth-registered peers (legacy proxies) can't be authenticated for
        # deregister. They expire via TTL like before.
        raise HTTPException(403, detail="Peer has no registered public key; cannot authenticate deregister")

    message = f"deregister:{body.peer_id}:{body.timestamp}".encode()
    if not _ecdsa_verify(pub_pem, message, body.signature):
        raise HTTPException(403, detail="Invalid signature")

    deleted = await delete_peer(body.peer_id)
    _ws_probe_cache.pop(body.peer_id, None)
    if deleted:
        print(f"[registry] - {peer.get('role')} at {body.peer_id} deregistered (signed)")
    return {"ok": True, "deleted": deleted}


@app.post("/hs/descriptor/delete")
async def delete_hs_descriptor(body: HSDescriptorDelete, request: Request):
    """Authenticated removal of a hidden-service descriptor.

    A stopped HS otherwise lingers in the registry for DESCRIPTOR_TTL (1 hour),
    causing clients to keep dialing dead intro points. The service signs
    ``hs-delete:{addr}:{timestamp}`` with the service key; the registry
    verifies against the descriptor's stored ``pubkey`` before deleting.
    """
    ip = _get_client_ip(request)
    if not _check_rate_limit(ip):
        raise HTTPException(429, detail="Rate limit exceeded")

    now = time.time()
    if abs(now - body.timestamp) > DEREGISTER_MAX_SKEW:
        raise HTTPException(400, detail="Timestamp outside allowed skew window")

    cursor = await DB.execute(
        "SELECT descriptor FROM hs_descriptors WHERE addr = ?", (body.addr,)
    )
    row = await cursor.fetchone()
    if not row:
        # Idempotent: nothing to delete.
        return {"ok": True, "deleted": False}

    try:
        desc = json.loads(row[0])
        pub_pem = desc.get("pubkey")
    except Exception:
        raise HTTPException(500, detail="Stored descriptor unparseable")
    if not pub_pem:
        raise HTTPException(500, detail="Stored descriptor missing pubkey")

    message = f"hs-delete:{body.addr}:{body.timestamp}".encode()
    if not _ecdsa_verify(pub_pem, message, body.signature):
        raise HTTPException(403, detail="Invalid signature")

    await DB.execute("DELETE FROM hs_descriptors WHERE addr = ?", (body.addr,))
    await DB.commit()
    print(f"[registry] - HS descriptor {body.addr} deleted (signed)")
    return {"ok": True, "deleted": True}


@app.get("/peers")
async def list_peers(role: str | None = None, request: Request = None):
    """Return all live peers, optionally filtered by role."""
    ip = _get_client_ip(request)
    if not _check_rate_limit(ip):
        raise HTTPException(429, detail="Rate limit exceeded")

    peers = await get_peers(role_filter=role, requester_ip=ip)
    return peers


@app.get("/health")
async def health_check():
    """Health check with peer stats."""
    breakdown, total = await get_stats()
    return HealthResponse(status="ok", peers=total, breakdown=breakdown)


@app.get("/whoami")
async def whoami(request: Request):
    """Return the caller's public IP as the registry sees it.

    Lets a process that doesn't otherwise register (e.g. a hidden-service
    host) learn its own WAN IP so it can avoid picking peers that resolve
    to itself - critical when two LAN machines share a NAT and the
    registry's (host, port) primary key collapses their distinct nodes
    into one entry.
    """
    return {"ip": _get_client_ip(request)}


@app.delete("/peers/{peer_id:path}")
async def remove_peer(peer_id: str, request: Request, authorization: str | None = Header(default=None)):
    """Admin-only: remove a specific peer. Requires OBSCURA_REGISTRY_ADMIN_KEY."""
    _require_admin_auth(request, authorization, "remove_peer", peer_id)

    deleted = await delete_peer(peer_id)
    if not deleted:
        raise HTTPException(404, detail="Peer not found")
    print(f"[registry] Admin removed peer {peer_id}")
    return {"ok": True, "deleted": peer_id}


@app.post("/admin/remove/{peer_id:path}")
async def admin_remove_peer(peer_id: str, request: Request, authorization: str | None = Header(default=None)):
    """Admin-only compatibility endpoint: remove a specific peer."""
    _require_admin_auth(request, authorization, "remove_peer", peer_id)

    deleted = await delete_peer(peer_id)
    if not deleted:
        raise HTTPException(404, detail="Peer not found")
    print(f"[registry] Admin removed peer {peer_id}")
    return {"ok": True, "deleted": peer_id}


# ── Exit Node Approval Endpoints ─────────────────────────────────

@app.get("/admin/pending")
async def list_pending_exits(request: Request, authorization: str | None = Header(default=None)):
    """Admin-only: list all unapproved exit nodes."""
    _require_admin_auth(request, authorization, "list_pending_exits")

    pending = await get_unapproved_exits()
    return {"pending_exits": pending, "pending": pending}


@app.post("/admin/approve/{peer_id:path}")
async def approve_exit_node(peer_id: str, request: Request, authorization: str | None = Header(default=None)):
    """Admin-only: approve a pending exit node."""
    _require_admin_auth(request, authorization, "approve_exit", peer_id)

    approved = await approve_exit(peer_id)
    if not approved:
        raise HTTPException(404, detail="Unapproved exit node not found")
    print(f"[registry] Admin approved exit node {peer_id}")
    return {"ok": True, "approved": peer_id}


@app.post("/admin/reject/{peer_id:path}")
async def reject_exit_node(peer_id: str, request: Request, authorization: str | None = Header(default=None)):
    """Admin-only: reject/remove a pending exit node."""
    _require_admin_auth(request, authorization, "reject_exit", peer_id)

    deleted = await reject_exit(peer_id)
    if not deleted:
        raise HTTPException(404, detail="Exit node not found")
    print(f"[registry] Admin rejected exit node {peer_id}")
    return {"ok": True, "rejected": peer_id}


# ── Kill Switch Endpoints ────────────────────────────────────────

@app.get("/network/status")
async def get_kill_status():
    """Public endpoint: return network status (kill switch state)."""
    status = await get_network_status()
    return status


@app.post("/admin/kill")
async def activate_kill_switch(body: KillSwitchRequest, request: Request, authorization: str | None = Header(default=None)):
    """Admin-only: activate the kill switch. Body must include reason and signature."""
    _require_admin_auth(request, authorization, "activate_kill_switch")

    await set_kill_active(body.reason, body.signature)
    print(f"[registry] Admin activated kill switch: {body.reason}")
    return {"ok": True, "kill_active": True, "reason": body.reason}


@app.post("/admin/revive")
async def deactivate_kill_switch(request: Request, authorization: str | None = Header(default=None)):
    """Admin-only: deactivate the kill switch."""
    _require_admin_auth(request, authorization, "deactivate_kill_switch")

    await set_kill_inactive()
    print(f"[registry] Admin deactivated kill switch")
    return {"ok": True, "kill_active": False}


# ── Enhanced Health Endpoint ─────────────────────────────────────

@app.get("/admin/health")
async def admin_health_check(request: Request, authorization: str | None = Header(default=None)):
    """Admin-only: detailed per-node health stats."""
    _require_admin_auth(request, authorization, "admin_health_check")

    all_peers = await get_all_peers_with_details()
    return AdminHealthResponse(
        total_peers=len(all_peers),
        peers=[PeerHealthInfo(**p) for p in all_peers]
    )


@app.get("/admin/peers")
async def admin_list_peers(request: Request, authorization: str | None = Header(default=None)):
    """Admin-only: list all peers with approval and transport details."""
    _require_admin_auth(request, authorization, "list_admin_peers")

    all_peers = await get_all_peers_with_details()
    return {
        "total_peers": len(all_peers),
        "peers": [AdminPeerInfo(**p) for p in all_peers],
    }


# ── Hidden services ──────────────────────────────────────────────

from src.utils.onion_addr import verify_descriptor as _verify_hs_desc


@app.post("/hs/descriptor")
async def publish_hs_descriptor(request: Request):
    """Publish a signed hidden-service descriptor. Body is the descriptor JSON."""
    ip = _get_client_ip(request)
    if not _check_rate_limit(ip):
        raise HTTPException(429, detail="Rate limit exceeded")
    try:
        desc = await request.json()
    except Exception:
        raise HTTPException(400, detail="Invalid JSON")
    if not isinstance(desc, dict):
        raise HTTPException(400, detail="Descriptor must be a JSON object")
    if not _verify_hs_desc(desc):
        raise HTTPException(400, detail="Descriptor failed verification")
    addr = desc["addr"]
    expires = float(desc["expires"])
    now = time.time()
    await DB.execute(
        "INSERT OR REPLACE INTO hs_descriptors (addr, descriptor, expires, updated) VALUES (?, ?, ?, ?)",
        (addr, json.dumps(desc), expires, now),
    )
    await DB.commit()
    return {"ok": True, "addr": addr, "expires": expires}


@app.get("/hs/descriptor/{addr}")
async def fetch_hs_descriptor(addr: str):
    """Fetch the most recent signed descriptor for a `.obscura` address."""
    now = time.time()
    # Opportunistically drop expired entries
    await DB.execute("DELETE FROM hs_descriptors WHERE expires < ?", (now,))
    await DB.commit()
    async with DB.execute(
        "SELECT descriptor FROM hs_descriptors WHERE addr = ? AND expires >= ?",
        (addr, now),
    ) as cursor:
        row = await cursor.fetchone()
    if not row:
        raise HTTPException(404, detail="Descriptor not found")
    return json.loads(row[0])


@app.get("/hs/list")
async def list_hs_descriptors():
    """Lab observability: list all live hidden services."""
    now = time.time()
    async with DB.execute(
        "SELECT addr, expires, updated FROM hs_descriptors WHERE expires >= ? ORDER BY updated DESC",
        (now,),
    ) as cursor:
        rows = await cursor.fetchall()
    return [{"addr": r[0], "expires": r[1], "updated": r[2]} for r in rows]


@app.get("/admin/dashboard/data")
async def admin_dashboard_data(request: Request, authorization: str | None = Header(default=None)):
    """Admin-only: combined data needed by the React dashboard."""
    _require_admin_auth(request, authorization, "view_dashboard")

    return await get_dashboard_summary()


# ── Main ─────────────────────────────────────────────────────────

def main():
    import uvicorn
    parser = argparse.ArgumentParser(description="Obscura47 Bootstrap Registry (FastAPI)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default {DEFAULT_PORT})")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    args = parser.parse_args()

    use_tls = bool(TLS_CERT and TLS_KEY)
    scheme = "https" if use_tls else "http"
    print(f"  Listening on {scheme}://{args.host}:{args.port}")
    print(f"  Clients should set:")
    print(f"  OBSCURA_REGISTRY_URL={scheme}://<this-server-ip>:{args.port}")
    print()

    uvicorn_kwargs = {"host": args.host, "port": args.port, "log_level": "warning"}
    if use_tls:
        uvicorn_kwargs["ssl_certfile"] = TLS_CERT
        uvicorn_kwargs["ssl_keyfile"] = TLS_KEY
    uvicorn.run(app, **uvicorn_kwargs)


if __name__ == "__main__":
    main()
