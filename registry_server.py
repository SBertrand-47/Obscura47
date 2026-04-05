"""
Obscura47 — Bootstrap Registry Server (FastAPI + SQLite)

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
import json
import os
import secrets
import time
import base64
from contextlib import asynccontextmanager
from typing import Literal

import aiosqlite
from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ── Configuration ────────────────────────────────────────────────
DEFAULT_PORT = int(os.getenv("OBSCURA_REGISTRY_PORT", "8470"))
PEER_TTL = int(os.getenv("OBSCURA_REGISTRY_PEER_TTL", "120"))
DB_PATH = os.getenv("OBSCURA_REGISTRY_DB_PATH", "registry.db")
ADMIN_KEY = os.getenv("OBSCURA_REGISTRY_ADMIN_KEY", "")
RATE_LIMIT = int(os.getenv("OBSCURA_REGISTRY_RATE_LIMIT", "60"))  # requests/min/IP
TLS_CERT = os.getenv("OBSCURA_REGISTRY_TLS_CERT", "")
TLS_KEY = os.getenv("OBSCURA_REGISTRY_TLS_KEY", "")

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
        print("[registry] WARNING: pycryptodome not installed, ECDSA verification disabled")
        return True

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


# ── Pydantic Models ──────────────────────────────────────────────

class PeerRegistration(BaseModel):
    role: Literal["node", "exit", "proxy"]
    port: int = Field(ge=1, le=65535)
    pub: str | None = None
    ws_port: int | None = Field(default=None, ge=1, le=65535)
    ws_tls: bool | None = None  # True if ws_port serves wss://


class AuthVerification(BaseModel):
    peer_id: str
    signature: str  # base64-encoded ECDSA signature of the challenge nonce


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
    # Additive migration — tolerate existing DBs that pre-date ws_tls
    try:
        await DB.execute("ALTER TABLE peers ADD COLUMN ws_tls INTEGER")
    except Exception:
        pass
    await DB.commit()
    print(f"[registry] SQLite database initialized at {DB_PATH}")


async def close_db():
    global DB
    if DB:
        await DB.close()
        DB = None


async def upsert_peer(peer_id: str, host: str, port: int, role: str,
                       pub_pem: str | None = None, ws_port: int | None = None,
                       ws_tls: bool | None = None):
    ws_tls_int = None if ws_tls is None else (1 if ws_tls else 0)
    await DB.execute("""
        INSERT INTO peers (id, host, port, role, pub_pem, ws_port, ws_tls, last_heartbeat)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            host=excluded.host,
            port=excluded.port,
            role=excluded.role,
            pub_pem=COALESCE(excluded.pub_pem, peers.pub_pem),
            ws_port=COALESCE(excluded.ws_port, peers.ws_port),
            ws_tls=COALESCE(excluded.ws_tls, peers.ws_tls),
            last_heartbeat=excluded.last_heartbeat
    """, (peer_id, host, port, role, pub_pem, ws_port, ws_tls_int, time.time()))
    await DB.commit()


async def get_peers(role_filter: str | None = None) -> list[dict]:
    cutoff = time.time() - PEER_TTL
    if role_filter:
        cursor = await DB.execute(
            "SELECT host, port, role, pub_pem, ws_port, ws_tls, last_heartbeat FROM peers WHERE last_heartbeat > ? AND role = ?",
            (cutoff, role_filter)
        )
    else:
        cursor = await DB.execute(
            "SELECT host, port, role, pub_pem, ws_port, ws_tls, last_heartbeat FROM peers WHERE last_heartbeat > ?",
            (cutoff,)
        )
    rows = await cursor.fetchall()
    return [
        {
            "host": r[0], "port": r[1], "role": r[2],
            "pub": r[3], "ws_port": r[4],
            "ws_tls": bool(r[5]) if r[5] is not None else None,
            "last_seen": r[6],
        }
        for r in rows
    ]


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


async def get_stats() -> tuple[dict[str, int], int]:
    cursor = await DB.execute("SELECT role, COUNT(*) FROM peers WHERE last_heartbeat > ? GROUP BY role", (time.time() - PEER_TTL,))
    rows = await cursor.fetchall()
    breakdown = {r[0]: r[1] for r in rows}
    total = sum(breakdown.values())
    return breakdown, total


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


# ── FastAPI App ──────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    asyncio.create_task(expiry_loop())
    asyncio.create_task(stats_loop())
    asyncio.create_task(challenge_cleanup_loop())
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


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


# ── Endpoints ────────────────────────────────────────────────────

@app.post("/register")
async def register_peer(body: PeerRegistration, request: Request):
    """
    Register a peer. If the peer provides a public key, a challenge nonce is
    returned that must be signed and submitted to /register/verify.
    If no public key is provided, the peer is registered immediately (unauthenticated).
    """
    ip = _get_client_ip(request)

    if not _check_rate_limit(ip):
        raise HTTPException(429, detail="Rate limit exceeded")

    peer_id = f"{ip}:{body.port}"

    # If peer has a public key, require challenge-response auth
    if body.pub:
        # Check if this peer is already registered with the same pubkey (heartbeat)
        existing = await get_peer_by_id(peer_id)
        if existing and existing.get("pub") == body.pub:
            # Known peer heartbeat — update timestamp without re-auth
            await upsert_peer(peer_id, ip, body.port, body.role, body.pub,
                              body.ws_port, body.ws_tls)
            return {"ok": True, "your_ip": ip, "peer_id": peer_id}

        # New peer or pubkey change — issue challenge
        nonce = secrets.token_hex(32)
        _pending_challenges[peer_id] = {
            "nonce": nonce,
            "peer_data": {
                "host": ip,
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
        return {"ok": False, "challenge": nonce, "peer_id": peer_id, "your_ip": ip}

    # No public key — register immediately (unauthenticated)
    is_new = await get_peer_by_id(peer_id) is None
    await upsert_peer(peer_id, ip, body.port, body.role,
                      ws_port=body.ws_port, ws_tls=body.ws_tls)
    if is_new:
        print(f"[registry] + New {body.role} at {peer_id} (no auth)")
    return {"ok": True, "your_ip": ip, "peer_id": peer_id}


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

    # Auth passed — register the peer
    data = challenge["peer_data"]
    del _pending_challenges[body.peer_id]

    await upsert_peer(body.peer_id, data["host"], data["port"], data["role"],
                       data["pub"], data.get("ws_port"), data.get("ws_tls"))
    print(f"[registry] + Verified {data['role']} at {body.peer_id}")
    return {"ok": True, "your_ip": ip, "peer_id": body.peer_id}


@app.get("/peers")
async def list_peers(role: str | None = None, request: Request = None):
    """Return all live peers, optionally filtered by role."""
    ip = _get_client_ip(request)
    if not _check_rate_limit(ip):
        raise HTTPException(429, detail="Rate limit exceeded")

    peers = await get_peers(role_filter=role)
    return peers


@app.get("/health")
async def health_check():
    """Health check with peer stats."""
    breakdown, total = await get_stats()
    return HealthResponse(status="ok", peers=total, breakdown=breakdown)


@app.delete("/peers/{peer_id:path}")
async def remove_peer(peer_id: str, authorization: str | None = Header(default=None)):
    """Admin-only: remove a specific peer. Requires OBSCURA_REGISTRY_ADMIN_KEY."""
    if not ADMIN_KEY:
        raise HTTPException(403, detail="Admin key not configured")
    if authorization != f"Bearer {ADMIN_KEY}":
        raise HTTPException(403, detail="Invalid admin key")

    deleted = await delete_peer(peer_id)
    if not deleted:
        raise HTTPException(404, detail="Peer not found")
    print(f"[registry] Admin removed peer {peer_id}")
    return {"ok": True, "deleted": peer_id}


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
