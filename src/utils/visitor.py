"""Visitor launcher - open `.obscura` addresses in a regular browser.

Generates a PAC (Proxy Auto-Config) file that routes ``*.obscura``
through the local Obscura proxy while sending everything else direct,
serves it over a localhost HTTP server (browsers ignore file:// PAC), and
launches a Chromium-based browser configured to use it.
"""

from __future__ import annotations

import http.server
import os
import platform
import socket
import subprocess
import sys
import threading
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


# ── PAC delivery over localhost HTTP ──────────────────────────────────────────
# Chromium-based browsers refuse to load PAC files from file:// URLs (security
# hardening), so `--proxy-pac-url=file://...` is silently ignored and every
# request goes DIRECT - which is why `.obscura` "never loads". Serving the exact
# same PAC from a localhost HTTP server is honored, so routing actually works.

PAC_SERVER_PORT = 9077          # preferred port; falls back to an ephemeral one
PAC_MIME = "application/x-ns-proxy-autoconfig"

_pac_server = None
_pac_server_lock = threading.Lock()


def _make_pac_handler(content: str):
    body = content.encode("utf-8")

    class _PACHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", PAC_MIME)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence default stderr access logging
            pass

    return _PACHandler


def serve_pac(
    proxy_host: str = PROXY_HOST,
    proxy_port: int = PROXY_PORT,
    preferred_port: int = PAC_SERVER_PORT,
) -> str:
    """Serve the PAC from a localhost HTTP server and return its URL.

    Idempotent within a process: the first call starts a daemon HTTP server
    bound to 127.0.0.1; later calls reuse it. Unlike a file:// PAC, this URL
    is actually honored by Chromium-based browsers.
    """
    global _pac_server
    content = PAC_TEMPLATE.format(proxy_host=proxy_host, proxy_port=proxy_port)
    with _pac_server_lock:
        if _pac_server is None:
            handler = _make_pac_handler(content)
            try:
                httpd = http.server.ThreadingHTTPServer(("127.0.0.1", preferred_port), handler)
            except OSError:
                # Port busy (e.g. a stale server from another instance): take any free port.
                httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            _pac_server = httpd
        port = _pac_server.server_address[1]
    return f"http://127.0.0.1:{port}/{PAC_FILENAME}"


def _chromium_profile_dir() -> str:
    """Dedicated Chrome/Chromium profile for Obscura browsing.

    A separate --user-data-dir is what forces a *new* browser instance that
    honors --proxy-pac-url. Without it, launching Chrome while it's already
    running just opens a tab in the existing process and the proxy flag is
    ignored - the second reason `.obscura` "never loads". The isolated profile
    also keeps Obscura browsing free of your normal cookies/identity.
    """
    return os.path.join(PAC_DIR, "browser-profile")


def _chromium_cmd(browser_path: str, pac_url: str, url: str) -> list[str]:
    return [
        browser_path,
        f"--proxy-pac-url={pac_url}",
        f"--user-data-dir={_chromium_profile_dir()}",
        "--no-first-run",
        "--no-default-browser-check",
        url,
    ]


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

    # Keep a PAC file on disk for reference/debugging, but hand the browser the
    # HTTP URL - a file:// PAC is silently ignored by Chromium and breaks routing.
    generate_pac(proxy_host=proxy_host, proxy_port=proxy_port)
    pac_url = serve_pac(proxy_host=proxy_host, proxy_port=proxy_port)
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
    # Chromium-based browsers honor --proxy-pac-url (+ a dedicated profile).
    for browser in (
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ):
        if os.path.isfile(browser):
            subprocess.Popen(
                _chromium_cmd(browser, pac_url, url),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
    # Fallback: default browser without proxy routing - .obscura won't load,
    # but we still surface the page rather than failing silently.
    subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


def _open_linux(url: str, host: str, port: int, pac_url: str) -> bool:
    for browser in ("google-chrome", "google-chrome-stable", "chromium-browser",
                    "chromium", "brave-browser", "microsoft-edge"):
        path = _which(browser)
        if path:
            subprocess.Popen(
                _chromium_cmd(path, pac_url, url),
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
    candidates = [
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
    ]
    for browser in candidates:
        if os.path.isfile(browser):
            subprocess.Popen(
                _chromium_cmd(browser, pac_url, url),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
    subprocess.Popen(["start", url], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


def _which(name: str) -> str | None:
    import shutil
    return shutil.which(name)
