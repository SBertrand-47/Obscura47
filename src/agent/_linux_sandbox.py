"""Linux Layer 2 sandbox: Landlock + ``PR_SET_NO_NEW_PRIVS``.

Restricts the calling process to the FS prefixes named in a
:class:`~src.agent.sandbox.SandboxPolicy` using kernel Landlock when
available. Engaged in-process (no re-exec), unlike the macOS path,
because the kernel APIs apply to the current task and its descendants.

The implementation talks to the kernel directly via ``ctypes`` syscall
numbers: 437 (``prctl``), 444 (``landlock_create_ruleset``), 445
(``landlock_add_rule``), 446 (``landlock_restrict_self``). No
out-of-tree dependencies are required.

Three things are best-effort and degrade quietly:

* If the kernel doesn't expose Landlock at all,
  ``landlock_create_ruleset`` returns ``-1`` with ``errno == ENOSYS``
  and we just set ``PR_SET_NO_NEW_PRIVS`` and return ``True``.
* If the ABI version is older than what we ask for, we trim the
  requested ``handled_access_fs`` mask to what the kernel reports it
  understands.
* If applying the ruleset fails for any other reason, we log and
  return ``False``; the caller falls back to Layer 1 only.

seccomp-bpf is intentionally out of scope for v1: getting a CPython
process to survive a tight syscall filter is its own engineering
project. Tracked as a follow-up.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import sys
from typing import TYPE_CHECKING

from src.utils.logger import get_logger

if TYPE_CHECKING:
    from src.agent.sandbox import SandboxPolicy

log = get_logger(__name__)


_SYS_PRCTL = 157
_SYS_LANDLOCK_CREATE_RULESET = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446

_PR_SET_NO_NEW_PRIVS = 38

_LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
_LANDLOCK_RULE_PATH_BENEATH = 1

_FS_EXECUTE = 1 << 0
_FS_WRITE_FILE = 1 << 1
_FS_READ_FILE = 1 << 2
_FS_READ_DIR = 1 << 3
_FS_REMOVE_DIR = 1 << 4
_FS_REMOVE_FILE = 1 << 5
_FS_MAKE_CHAR = 1 << 6
_FS_MAKE_DIR = 1 << 7
_FS_MAKE_REG = 1 << 8
_FS_MAKE_SOCK = 1 << 9
_FS_MAKE_FIFO = 1 << 10
_FS_MAKE_BLOCK = 1 << 11
_FS_MAKE_SYM = 1 << 12
_FS_REFER = 1 << 13
_FS_TRUNCATE = 1 << 14

_FS_ALL_V1 = (
    _FS_EXECUTE | _FS_WRITE_FILE | _FS_READ_FILE | _FS_READ_DIR
    | _FS_REMOVE_DIR | _FS_REMOVE_FILE | _FS_MAKE_CHAR | _FS_MAKE_DIR
    | _FS_MAKE_REG | _FS_MAKE_SOCK | _FS_MAKE_FIFO | _FS_MAKE_BLOCK
    | _FS_MAKE_SYM
)
_FS_ABI_EXTENSIONS = {2: _FS_REFER, 3: _FS_TRUNCATE}

_FS_READ_MASK = _FS_READ_FILE | _FS_READ_DIR | _FS_EXECUTE
_FS_WRITE_MASK = (
    _FS_WRITE_FILE | _FS_REMOVE_DIR | _FS_REMOVE_FILE | _FS_MAKE_CHAR
    | _FS_MAKE_DIR | _FS_MAKE_REG | _FS_MAKE_SOCK | _FS_MAKE_FIFO
    | _FS_MAKE_BLOCK | _FS_MAKE_SYM
)


class _RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    ]


class _PathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


def is_supported() -> bool:
    """Return True when this is a Linux host (regardless of kernel ABI level)."""
    return sys.platform.startswith("linux")


def _libc() -> ctypes.CDLL | None:
    try:
        path = ctypes.util.find_library("c") or "libc.so.6"
        return ctypes.CDLL(path, use_errno=True)
    except OSError:
        return None


def _syscall(libc: ctypes.CDLL, number: int, *args: int) -> int:
    libc.syscall.restype = ctypes.c_long
    libc.syscall.argtypes = [ctypes.c_long] + [ctypes.c_long] * len(args)
    return int(libc.syscall(ctypes.c_long(number), *(ctypes.c_long(a) for a in args)))


def _set_no_new_privs(libc: ctypes.CDLL) -> bool:
    rc = _syscall(libc, _SYS_PRCTL, _PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if rc != 0:
        e = ctypes.get_errno()
        log.warning("prctl(PR_SET_NO_NEW_PRIVS) failed: %s", os.strerror(e))
        return False
    return True


def _landlock_abi_version(libc: ctypes.CDLL) -> int:
    rc = _syscall(libc, _SYS_LANDLOCK_CREATE_RULESET, 0, 0,
                  _LANDLOCK_CREATE_RULESET_VERSION)
    if rc < 0:
        return 0
    return int(rc)


def _build_handled_mask(abi: int) -> int:
    mask = _FS_ALL_V1
    for ver, extra in _FS_ABI_EXTENSIONS.items():
        if abi >= ver:
            mask |= extra
    return mask


def apply(policy: "SandboxPolicy") -> bool:
    """Apply Landlock + ``PR_SET_NO_NEW_PRIVS`` based on ``policy``.

    Returns ``True`` on best-effort success (including the case where
    the kernel doesn't support Landlock and we only managed to set
    ``no_new_privs``). Returns ``False`` only when even the basic
    hardening failed.
    """
    if not is_supported():
        return False
    libc = _libc()
    if libc is None:
        log.warning("could not load libc; skipping Linux Layer 2")
        return False
    if not _set_no_new_privs(libc):
        return False

    abi = _landlock_abi_version(libc)
    if abi <= 0:
        log.info("kernel does not expose Landlock; Layer 2 is no_new_privs only")
        return True

    handled = _build_handled_mask(abi)
    attr = _RulesetAttr(handled_access_fs=handled, handled_access_net=0, scoped=0)
    ruleset_fd = _syscall(
        libc, _SYS_LANDLOCK_CREATE_RULESET,
        ctypes.addressof(attr), ctypes.sizeof(attr), 0,
    )
    if ruleset_fd < 0:
        e = ctypes.get_errno()
        if e == errno.ENOSYS:
            log.info("Landlock not supported; Layer 2 is no_new_privs only")
            return True
        log.warning("landlock_create_ruleset failed: %s", os.strerror(e))
        return False
    try:
        for prefix in policy.fs_read:
            if not _add_path(libc, ruleset_fd, prefix,
                              _FS_READ_MASK & handled):
                return False
        for prefix in policy.fs_write:
            mask = (_FS_READ_MASK | _FS_WRITE_MASK) & handled
            if not _add_path(libc, ruleset_fd, prefix, mask):
                return False
        rc = _syscall(libc, _SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
        if rc != 0:
            e = ctypes.get_errno()
            log.warning("landlock_restrict_self failed: %s", os.strerror(e))
            return False
    finally:
        try:
            os.close(ruleset_fd)
        except OSError:
            pass
    log.info(
        "Linux Layer 2 active (Landlock ABI v%d, %d read prefixes, %d write prefixes)",
        abi, len(policy.fs_read), len(policy.fs_write),
    )
    return True


def _add_path(libc: ctypes.CDLL, ruleset_fd: int, prefix: str, mask: int) -> bool:
    if mask == 0:
        return True
    try:
        fd = os.open(prefix, os.O_PATH | os.O_CLOEXEC)
    except OSError as e:
        log.warning("Landlock: cannot open prefix %s: %s", prefix, e)
        return False
    try:
        rule = _PathBeneathAttr(allowed_access=mask, parent_fd=fd)
        rc = _syscall(
            libc, _SYS_LANDLOCK_ADD_RULE,
            ruleset_fd, _LANDLOCK_RULE_PATH_BENEATH,
            ctypes.addressof(rule), 0,
        )
        if rc != 0:
            e = ctypes.get_errno()
            log.warning("Landlock add_rule(%s) failed: %s", prefix, os.strerror(e))
            return False
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    return True
