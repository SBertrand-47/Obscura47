"""Vanity `.obscura` address miner.

Grinds ECC P-256 keypairs until the derived address label matches a
chosen prefix (like Tor's ``mkp224o``).

Usage::

    python -m src.utils.vanity abc
    python -m src.utils.vanity abc --workers 8 --output ~/.obscura47/sites/myblog.pem
"""

from __future__ import annotations

import multiprocessing
import os
import signal
import sys
import time
from dataclasses import dataclass
from typing import Optional

from src.core.encryptions import ecc_generate_keypair
from src.utils.onion_addr import ADDR_LEN, ADDR_SUFFIX, address_from_pubkey


BASE32_CHARSET = set("abcdefghijklmnopqrstuvwxyz234567")


@dataclass
class VanityResult:
    address: str
    private_pem: str
    public_pem: str
    attempts: int
    elapsed: float


def validate_prefix(prefix: str) -> str:
    prefix = prefix.lower()
    if not prefix:
        raise ValueError("prefix must not be empty")
    if len(prefix) > ADDR_LEN:
        raise ValueError(f"prefix too long (max {ADDR_LEN} characters)")
    bad = set(prefix) - BASE32_CHARSET
    if bad:
        raise ValueError(
            f"invalid characters for base32 address: {', '.join(sorted(bad))}. "
            f"Allowed: a-z, 2-7"
        )
    return prefix


def mine_single(prefix: str) -> VanityResult:
    """Grind keypairs in the current thread until one matches *prefix*."""
    prefix = validate_prefix(prefix)
    start = time.monotonic()
    attempts = 0
    while True:
        attempts += 1
        priv, pub_pem = ecc_generate_keypair()
        addr = address_from_pubkey(pub_pem)
        label = addr[: -len(ADDR_SUFFIX)]
        if label.startswith(prefix):
            return VanityResult(
                address=addr,
                private_pem=priv.export_key(format="PEM"),
                public_pem=pub_pem,
                attempts=attempts,
                elapsed=time.monotonic() - start,
            )


def _worker(prefix: str, result_queue, stop_event):
    """Worker process: grind until a match or told to stop."""
    prefix = prefix.lower()
    attempts = 0
    while not stop_event.is_set():
        attempts += 1
        priv, pub_pem = ecc_generate_keypair()
        addr = address_from_pubkey(pub_pem)
        label = addr[: -len(ADDR_SUFFIX)]
        if label.startswith(prefix):
            result_queue.put((addr, priv.export_key(format="PEM"), pub_pem, attempts))
            return


def mine_parallel(
    prefix: str,
    workers: int | None = None,
) -> VanityResult:
    """Grind across *workers* processes. Returns the first match."""
    prefix = validate_prefix(prefix)
    if workers is None:
        workers = max(1, multiprocessing.cpu_count())

    result_queue: multiprocessing.Queue = multiprocessing.Queue()
    stop_event = multiprocessing.Event()
    start = time.monotonic()

    procs = []
    for _ in range(workers):
        p = multiprocessing.Process(
            target=_worker, args=(prefix, result_queue, stop_event), daemon=True,
        )
        p.start()
        procs.append(p)

    addr, priv_pem, pub_pem, attempts = result_queue.get()
    stop_event.set()
    for p in procs:
        p.join(timeout=2)
        if p.is_alive():
            p.terminate()

    return VanityResult(
        address=addr,
        private_pem=priv_pem,
        public_pem=pub_pem,
        attempts=attempts,
        elapsed=time.monotonic() - start,
    )


def save_result(result: VanityResult, path: str) -> str:
    """Persist a vanity key to disk. Returns the resolved path."""
    path = os.path.expanduser(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(result.private_pem)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m src.utils.vanity",
        description="Mine a vanity .obscura address matching a chosen prefix.",
    )
    parser.add_argument("prefix", help="desired address prefix (base32: a-z, 2-7)")
    parser.add_argument(
        "--workers", "-w", type=int, default=None,
        help="number of parallel workers (default: CPU count)",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="save the key to this path (PEM)",
    )
    args = parser.parse_args(argv)

    try:
        prefix = validate_prefix(args.prefix)
    except ValueError as e:
        print(f"  [!] {e}", file=sys.stderr)
        return 1

    est = 32 ** len(prefix)
    print(f"\n  Mining for prefix {prefix!r}... (expected ~{est:,} attempts)")
    print(f"  Workers: {args.workers or multiprocessing.cpu_count()}\n")

    result = mine_parallel(prefix, workers=args.workers)

    print(f"  Found:    {result.address}")
    print(f"  Attempts: {result.attempts:,}")
    print(f"  Time:     {result.elapsed:.2f}s")

    if args.output:
        out = save_result(result, args.output)
        print(f"  Key:      {out}")
    else:
        print(f"\n{result.private_pem}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
