"""Visitor launcher — open `.obscura` addresses in a regular browser.

Generates a PAC (Proxy Auto-Config) file that routes ``*.obscura``
through the local Obscura proxy while sending everything else direct.
Then opens the system browser with the PAC configured.
"""

from __future__ import annotations

import os
import platform
import socket
import subprocess
import sys
import time

from src.utils.config import PROXY_HOST, PROXY_PORT


PAC_TEMPLATE = """\
function FindProxyForURL(url, host) {{
    if (shExpMatch(host, "*.obscura")) {{
        return "PROXY {proxy_host}:{proxy_port}";
    }}
    return "DIRECT";
}}
"""

PAC_DIR = os.path.join(os.path.expanduser("~"), ".obscura47")
PAC_FILENAME = "obscura.pac"
PROXY_START_TIMEOUT_SECONDS = 8.0


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def generate_pac(
    proxy_host: str = PROXY_HOST,
    proxy_port: int = PROXY_PORT,
    output_dir: str = PAC_DIR,
) -> str:
    """Write a PAC file and return its absolute path."""
    os.makedirs(output_dir, exist_ok=True)
    pac_path = os.path.join(output_dir, PAC_FILENAME)
    content = PAC_TEMPLATE.format(proxy_host=proxy_host, proxy_port=proxy_port)
    with open(pac_path, "w", encoding="utf-8") as f:
        f.write(content)
    return pac_path


def pac_file_url(pac_path: str) -> str:
    """Return a file:// URL for the PAC file."""
    return f"file://{os.path.abspath(pac_path)}"


def normalize_browser_url(url: str) -> str:
    """Normalize a user-supplied address into a browser-safe URL."""
    url = (url or "").strip()
    if not url:
        return "about:blank"
    if "://" in url:
        return url
    return f"http://{url}"


def proxy_is_running(
    proxy_host: str = PROXY_HOST,
    proxy_port: int = PROXY_PORT,
    timeout: float = 0.25,
) -> bool:
    try:
        with socket.create_connection((proxy_host, proxy_port), timeout=timeout):
            return True
    except OSError:
        return False


def ensure_proxy_running(
    proxy_host: str = PROXY_HOST,
    proxy_port: int = PROXY_PORT,
    timeout: float = PROXY_START_TIMEOUT_SECONDS,
) -> bool:
    """Start the local proxy if needed and wait for it to listen."""
    if proxy_is_running(proxy_host=proxy_host, proxy_port=proxy_port):
        return True

    kwargs = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "cwd": _project_root(),
    }
    if platform.system() == "Windows":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True

    subprocess.Popen(
        [sys.executable, os.path.join(_project_root(), "join_network.py"), "proxy"],
        **kwargs,
    )

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proxy_is_running(proxy_host=proxy_host, proxy_port=proxy_port):
            return True
        time.sleep(0.1)
    return False


def open_in_browser(
    url: str = "",
    proxy_host: str = PROXY_HOST,
    proxy_port: int = PROXY_PORT,
) -> bool:
    """Open a URL in the system browser, routed through the Obscura proxy.

    Generates a PAC file, then launches the platform's default browser
    with proxy configuration.  Returns True if the browser was launched.
    """
    if not ensure_proxy_running(proxy_host=proxy_host, proxy_port=proxy_port):
        return False

    pac_path = generate_pac(proxy_host=proxy_host, proxy_port=proxy_port)
    pac_url = pac_file_url(pac_path)
    system = platform.system()
    url = normalize_browser_url(url)

    try:
        if system == "Darwin":
            return _open_macos(url, proxy_host, proxy_port, pac_url)
        elif system == "Linux":
            return _open_linux(url, proxy_host, proxy_port, pac_url)
        elif system == "Windows":
            return _open_windows(url, proxy_host, proxy_port, pac_url)
    except Exception:
        pass
    return False


def _open_macos(url: str, host: str, port: int, pac_url: str) -> bool:
    # Try Chromium-based browsers first (they accept --proxy-pac-url).
    for browser in (
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    ):
        if os.path.isfile(browser):
            subprocess.Popen(
                [browser, f"--proxy-pac-url={pac_url}", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
    # Fallback: open with default browser (no PAC flag).
    subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


def _open_linux(url: str, host: str, port: int, pac_url: str) -> bool:
    for browser in ("google-chrome", "chromium-browser", "chromium", "brave-browser"):
        path = _which(browser)
        if path:
            subprocess.Popen(
                [path, f"--proxy-pac-url={pac_url}", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
    for browser in ("firefox", "xdg-open"):
        path = _which(browser)
        if path:
            subprocess.Popen(
                [path, url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
    return False


def _open_windows(url: str, host: str, port: int, pac_url: str) -> bool:
    chrome = os.path.expandvars(
        r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"
    )
    if os.path.isfile(chrome):
        subprocess.Popen(
            [chrome, f"--proxy-pac-url={pac_url}", url],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    subprocess.Popen(["start", url], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


def _which(name: str) -> str | None:
    import shutil
    return shutil.which(name)
