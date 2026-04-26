"""Site management for `.obscura` hidden-service hosting.

Provides helpers for resolving key paths from site names, listing hosted
sites with their derived addresses, and ensuring the sites directory
exists with correct permissions.

Default layout::

    ~/.obscura47/sites/
        default.pem
        default.site.json
        myblog.pem
        myblog.site.json
        shop.pem
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from dataclasses import dataclass
from typing import Iterator

from src.core.encryptions import ecc_load_or_create_keypair, ecc_generate_keypair
from src.utils.onion_addr import address_from_pubkey


SITES_DIR = os.path.join(os.path.expanduser("~"), ".obscura47", "sites")

FIRST_RUN_BANNER = """\

  ┌─────────────────────────────────────────────────────────────────┐
  │  NEW SITE KEY CREATED                                          │
  │                                                                │
  │  Your .pem file IS your .obscura address.                      │
  │  If you lose it, you lose the address forever — there is no    │
  │  recovery. Back it up somewhere safe.                          │
  │                                                                │
  │  Key file:  {key_path:<50s}│
  │                                                                │
  │  Export it with:                                                │
  │    python join_network.py host export-key --name {name:<14s}   │
  └─────────────────────────────────────────────────────────────────┘
"""


@dataclass(frozen=True)
class SiteInfo:
    name: str
    key_path: str
    address: str
    target: str | None = None
    config_path: str | None = None


@dataclass(frozen=True)
class SiteConfig:
    name: str
    key_path: str | None = None
    target: str | None = None
    config_path: str | None = None


def ensure_sites_dir(path: str = SITES_DIR) -> str:
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def key_path_for_name(name: str, sites_dir: str = SITES_DIR) -> str:
    if os.sep in name or (os.altsep and os.altsep in name):
        raise ValueError(f"site name must not contain path separators: {name!r}")
    if not name or name.startswith("."):
        raise ValueError(f"invalid site name: {name!r}")
    return os.path.join(sites_dir, f"{name}.pem")


def config_path_for_name(name: str, sites_dir: str = SITES_DIR) -> str:
    if os.sep in name or (os.altsep and os.altsep in name):
        raise ValueError(f"site name must not contain path separators: {name!r}")
    if not name or name.startswith("."):
        raise ValueError(f"invalid site name: {name!r}")
    return os.path.join(sites_dir, f"{name}.site.json")


def resolve_key_path(
    name: str | None = None,
    key: str | None = None,
    sites_dir: str = SITES_DIR,
) -> str:
    if key:
        return os.path.expanduser(key)
    ensure_sites_dir(sites_dir)
    return key_path_for_name(name or "default", sites_dir)


def save_site_config(
    name: str,
    *,
    key_path: str | None = None,
    target: str | None = None,
    sites_dir: str = SITES_DIR,
) -> str:
    ensure_sites_dir(sites_dir)
    path = config_path_for_name(name, sites_dir)
    existing = load_site_config(name, sites_dir=sites_dir)
    payload = {"name": name}
    resolved_key_path = key_path
    if resolved_key_path is None and existing:
        resolved_key_path = existing.key_path
    resolved_target = target
    if resolved_target is None and existing:
        resolved_target = existing.target
    if resolved_key_path:
        payload["key_path"] = os.path.expanduser(resolved_key_path)
    if resolved_target:
        payload["target"] = resolved_target
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
    set_key_permissions(path)
    return path


def load_site_config(name: str, sites_dir: str = SITES_DIR) -> SiteConfig | None:
    path = config_path_for_name(name, sites_dir)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    key_path = raw.get("key_path")
    if key_path:
        key_path = os.path.expanduser(key_path)
    return SiteConfig(
        name=name,
        key_path=key_path,
        target=raw.get("target"),
        config_path=path,
    )


def delete_site_config(name: str, sites_dir: str = SITES_DIR) -> bool:
    path = config_path_for_name(name, sites_dir)
    if not os.path.isfile(path):
        return False
    os.remove(path)
    return True


def list_sites(sites_dir: str = SITES_DIR) -> Iterator[SiteInfo]:
    if not os.path.isdir(sites_dir):
        return
    names = set()
    for entry in sorted(os.listdir(sites_dir)):
        if entry.endswith(".pem"):
            names.add(entry[:-4])
        elif entry.endswith(".site.json"):
            names.add(entry[:-10])

    for name in sorted(names):
        config = load_site_config(name, sites_dir=sites_dir)
        path = config.key_path if config and config.key_path else None
        if not path:
            default_key_path = key_path_for_name(name, sites_dir)
            if os.path.isfile(default_key_path):
                path = default_key_path
        if not path or not os.path.isfile(path):
            continue
        try:
            _, pub_pem = ecc_load_or_create_keypair(path)
            addr = address_from_pubkey(pub_pem)
        except Exception:
            continue
        yield SiteInfo(
            name=name,
            key_path=path,
            address=addr,
            target=config.target if config else None,
            config_path=config.config_path if config else None,
        )


def set_key_permissions(path: str) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass


def load_or_create_site_key(
    name: str | None = None,
    key: str | None = None,
    sites_dir: str = SITES_DIR,
    quiet: bool = False,
) -> tuple:
    """Resolve, load (or create) a site keypair.

    Returns (priv, pub_pem, key_path, created).
    Prints the first-run banner to stderr when a new key is created.
    """
    path = resolve_key_path(name=name, key=key, sites_dir=sites_dir)
    created = not os.path.isfile(path)
    priv, pub_pem = ecc_load_or_create_keypair(path)
    set_key_permissions(path)
    if name:
        save_site_config(name, key_path=path, sites_dir=sites_dir)
    if created and not quiet:
        label = name or os.path.basename(path).removesuffix(".pem")
        sys.stderr.write(FIRST_RUN_BANNER.format(key_path=path, name=label))
    return priv, pub_pem, path, created


def export_key(name: str, dest: str, sites_dir: str = SITES_DIR) -> str:
    """Copy a site's .pem to *dest*. Returns the destination path."""
    src = key_path_for_name(name, sites_dir)
    if not os.path.isfile(src):
        raise FileNotFoundError(f"no key for site {name!r} at {src}")
    dest = os.path.expanduser(dest)
    if os.path.isdir(dest):
        dest = os.path.join(dest, f"{name}.pem")
    shutil.copy2(src, dest)
    set_key_permissions(dest)
    return dest


def import_key(name: str, src: str, sites_dir: str = SITES_DIR) -> str:
    """Import a .pem file as a named site. Returns the destination path."""
    src = os.path.expanduser(src)
    if not os.path.isfile(src):
        raise FileNotFoundError(f"key file not found: {src}")
    ensure_sites_dir(sites_dir)
    dest = key_path_for_name(name, sites_dir)
    if os.path.isfile(dest):
        raise FileExistsError(f"site {name!r} already exists at {dest}")
    shutil.copy2(src, dest)
    set_key_permissions(dest)
    save_site_config(name, key_path=dest, sites_dir=sites_dir)
    return dest


def rotate_key(name: str, sites_dir: str = SITES_DIR) -> tuple:
    """Generate a fresh keypair for a site, archiving the old key.

    Returns (new_priv, new_pub_pem, new_path, old_backup_path).
    The old key is renamed to <name>.old.pem (overwriting any prior backup).
    """
    ensure_sites_dir(sites_dir)
    path = key_path_for_name(name, sites_dir)
    backup = None
    if os.path.isfile(path):
        backup = path.replace(".pem", ".old.pem")
        shutil.move(path, backup)
    priv = ecc_generate_keypair()[0]
    from Crypto.PublicKey import ECC
    with open(path, "w", encoding="utf-8") as f:
        f.write(priv.export_key(format="PEM"))
    set_key_permissions(path)
    pub_pem = priv.public_key().export_key(format="PEM")
    save_site_config(name, key_path=path, sites_dir=sites_dir)
    return priv, pub_pem, path, backup
