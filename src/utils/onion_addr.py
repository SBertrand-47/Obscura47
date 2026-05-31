"""Obscura hidden-service address + descriptor utilities.

An `.obscura` address is a base32-encoded truncated SHA-256 of a service's
P-256 public key (PEM). The service proves ownership by signing descriptors
with the matching private key; anyone can verify because the address is
derived from the public key.

Descriptor format (JSON, stored plaintext in the registry):

    {
      "addr": "<16 char>.obscura",
      "pubkey": "<PEM>",
      "port": 8080,
      "intro_points": [{"node_id": "...", "circuit_id": "..."}, ...],
      "nonce": "<base64 16 bytes>",
      "expires": 1761350400,
      "sig": "<base64 ECDSA over the canonical form without 'sig'>"
    }
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from typing import Any

from Crypto.PublicKey import ECC

from src.core.encryptions import ecdsa_sign, ecdsa_verify


ADDR_LEN = 16  # characters of base32, before the .obscura suffix
ADDR_SUFFIX = ".obscura"


def _env_int(name: str, default: int) -> int:
    """Read a positive integer from the environment, else fall back."""
    try:
        value = int(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


# A live host refreshes its descriptor every DESCRIPTOR_REPUBLISH_INTERVAL
# seconds, so the TTL is really just a *grace period* after republishing
# stops - host offline, registry unreachable, or the node "goes cold" and
# intro re-establishment fails for a while. The old 1h value meant a brief
# cold spell or a stop/restart could expire the entry and make the site 404
# for other hosts. 24h keeps a transiently-offline site discoverable while
# still letting a genuinely-dead site age out within a day. The republish
# interval is deliberately decoupled from the TTL: raising the TTL must not
# slow down how often a running host refreshes (a bug when callers derived
# the loop period from DESCRIPTOR_TTL // 2). Both are env-overridable.
DESCRIPTOR_TTL = _env_int("OBSCURA_DESCRIPTOR_TTL", 86400)  # seconds (24h)
DESCRIPTOR_REPUBLISH_INTERVAL = _env_int(
    "OBSCURA_DESCRIPTOR_REPUBLISH_INTERVAL", 50
)  # seconds


def address_from_pubkey(pub_pem: str) -> str:
    """Derive the `.obscura` hostname from a public key PEM."""
    digest = hashlib.sha256(pub_pem.encode("utf-8")).digest()
    label = base64.b32encode(digest).decode("ascii").lower().rstrip("=")[:ADDR_LEN]
    return f"{label}{ADDR_SUFFIX}"


def is_obscura_address(host: str) -> bool:
    host = (host or "").lower()
    if not host.endswith(ADDR_SUFFIX):
        return False
    label = host[: -len(ADDR_SUFFIX)]
    if len(label) != ADDR_LEN:
        return False
    return all(c in "abcdefghijklmnopqrstuvwxyz234567" for c in label)


def normalize_obscura_input(value: str | None) -> str:
    """Coerce free-form user input into a bare `.obscura` hostname.

    Accepts the same shapes a user might paste from a browser address
    bar (``http://x.obscura/``, ``x.obscura:80``, ``x.obscura/path``)
    and returns just the hostname. Returns the input unchanged if it
    doesn't look URL-shaped, leaving downstream validators to reject it
    with a clear message.
    """
    if not value:
        return ""
    s = value.strip()
    if "://" in s:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(s)
            if parsed.hostname:
                s = parsed.hostname
        except Exception:
            pass
    # Strip any leftover path, query, fragment, port, or trailing slash.
    for sep in ("/", "?", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]
    if ":" in s and not s.startswith("["):
        s = s.split(":", 1)[0]
    return s.lower()


def _canonical(desc: dict[str, Any]) -> bytes:
    """Deterministic byte form of a descriptor (for signing/verifying)."""
    body = {k: v for k, v in desc.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_descriptor(
    priv: ECC.EccKey,
    pub_pem: str,
    port: int,
    intro_points: list[dict[str, str]],
    ttl: int = DESCRIPTOR_TTL,
) -> dict[str, Any]:
    """Assemble and sign a descriptor for publication to the registry."""
    addr = address_from_pubkey(pub_pem)
    desc: dict[str, Any] = {
        "addr": addr,
        "pubkey": pub_pem,
        "port": int(port),
        "intro_points": list(intro_points),
        "nonce": base64.b64encode(os.urandom(16)).decode("ascii"),
        "expires": int(time.time()) + int(ttl),
    }
    desc["sig"] = ecdsa_sign(priv, _canonical(desc))
    return desc


def verify_descriptor(desc: dict[str, Any]) -> bool:
    """Check descriptor structure, signature, address derivation, and expiry."""
    try:
        required = {"addr", "pubkey", "port", "intro_points", "nonce", "expires", "sig"}
        if not required.issubset(desc.keys()):
            return False
        if not isinstance(desc["intro_points"], list):
            return False
        if not isinstance(desc["port"], int) or not (0 < desc["port"] < 65536):
            return False
        if int(desc["expires"]) < int(time.time()):
            return False
        if address_from_pubkey(desc["pubkey"]) != desc["addr"]:
            return False
        return ecdsa_verify(desc["pubkey"], _canonical(desc), desc["sig"])
    except Exception:
        return False
