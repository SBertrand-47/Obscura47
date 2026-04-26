"""Pure helper functions for the desktop app — no tkinter dependency."""

from __future__ import annotations


def format_hosted_site_summary(site, *, background_enabled: bool) -> str:
    mode = "background" if background_enabled else "manual"
    target = getattr(site, "target", None) or "(target not saved yet)"
    return (
        f"{site.name}\n"
        f"  Address: {site.address}\n"
        f"  Target: {target}\n"
        f"  Mode: {mode}"
    )


def resolve_hosted_site_selection(selection: str, hosted_sites: list) -> str:
    value = (selection or "").strip()
    if not value:
        raise ValueError("site name or address is required")
    if value.endswith(".obscura"):
        return value
    for site in hosted_sites:
        if getattr(site, "name", None) == value:
            return site.address
    raise ValueError(f"unknown hosted site: {value}")


def build_quick_start_text(*, connected: bool) -> str:
    status = (
        "You are connected. Use the buttons in Quick Actions below."
        if connected else
        "Start by pressing Connect, then use the buttons in Quick Actions below."
    )
    return (
        f"{status}\n\n"
        "Visit a site:\n"
        "  1. Click Open .obscura Address\n"
        "  2. Enter an address like alpha.obscura\n"
        "  3. Obscura47 opens your browser with the right routing\n\n"
        "Browse discovery:\n"
        "  1. Click Browse Directory\n"
        "  2. Enter a directory address\n"
        "  3. Pick a listing to open\n\n"
        "Publish your own site:\n"
        "  1. Click Publish Site\n"
        "  2. Choose a folder or local service\n"
        "  3. Obscura47 saves your address and starts the background host"
    )
