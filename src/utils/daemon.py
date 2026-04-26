"""Daemon template generation for `.obscura` host services.

Generates platform-specific service definitions so a hosted site
persists across reboots without keeping a terminal open.
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path


SYSTEMD_TEMPLATE = textwrap.dedent("""\
    [Unit]
    Description=Obscura47 hidden-service host ({name})
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    ExecStart={python} {script} host {target} --name {name}
    WorkingDirectory={workdir}
    Restart=on-failure
    RestartSec=10
    StandardOutput=journal
    StandardError=journal

    [Install]
    WantedBy=default.target
""")


LAUNCHD_TEMPLATE = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
      "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
      <key>Label</key>
      <string>com.obscura47.host.{name}</string>
      <key>ProgramArguments</key>
      <array>
        <string>{python}</string>
        <string>{script}</string>
        <string>host</string>
        <string>{target}</string>
        <string>--name</string>
        <string>{name}</string>
      </array>
      <key>WorkingDirectory</key>
      <string>{workdir}</string>
      <key>RunAtLoad</key>
      <true/>
      <key>KeepAlive</key>
      <dict>
        <key>NetworkState</key>
        <true/>
      </dict>
      <key>StandardOutPath</key>
      <string>{log_dir}/host-{name}.log</string>
      <key>StandardErrorPath</key>
      <string>{log_dir}/host-{name}.log</string>
    </dict>
    </plist>
""")


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _log_dir() -> str:
    d = os.path.join(os.path.expanduser("~"), ".obscura47", "logs")
    os.makedirs(d, exist_ok=True)
    return d


def generate_systemd_unit(name: str, target: str) -> str:
    return SYSTEMD_TEMPLATE.format(
        name=name,
        target=target,
        python=sys.executable,
        script=os.path.join(_project_root(), "join_network.py"),
        workdir=_project_root(),
    )


def generate_launchd_plist(name: str, target: str) -> str:
    return LAUNCHD_TEMPLATE.format(
        name=name,
        target=target,
        python=sys.executable,
        script=os.path.join(_project_root(), "join_network.py"),
        workdir=_project_root(),
        log_dir=_log_dir(),
    )


def install_daemon(name: str, target: str) -> str:
    """Install a per-site daemon and return the config file path.

    On macOS: writes a launchd plist and loads it via ``launchctl``.
    On Linux: writes a systemd user unit and enables it.
    """
    system = platform.system()
    if system == "Darwin":
        return _install_launchd(name, target)
    elif system == "Linux":
        return _install_systemd(name, target)
    else:
        raise RuntimeError(f"unsupported platform: {system}")


def uninstall_daemon(name: str) -> bool:
    system = platform.system()
    if system == "Darwin":
        return _uninstall_launchd(name)
    elif system == "Linux":
        return _uninstall_systemd(name)
    return False


def _install_launchd(name: str, target: str) -> str:
    agents_dir = os.path.expanduser("~/Library/LaunchAgents")
    os.makedirs(agents_dir, exist_ok=True)
    plist_path = os.path.join(agents_dir, f"com.obscura47.host.{name}.plist")
    with open(plist_path, "w") as f:
        f.write(generate_launchd_plist(name, target))
    subprocess.run(["launchctl", "load", plist_path], check=False)
    return plist_path


def _uninstall_launchd(name: str) -> bool:
    plist_path = os.path.expanduser(
        f"~/Library/LaunchAgents/com.obscura47.host.{name}.plist"
    )
    if not os.path.isfile(plist_path):
        return False
    subprocess.run(["launchctl", "unload", plist_path], check=False)
    os.remove(plist_path)
    return True


def _install_systemd(name: str, target: str) -> str:
    unit_dir = os.path.expanduser("~/.config/systemd/user")
    os.makedirs(unit_dir, exist_ok=True)
    unit_name = f"obscura47-host-{name}.service"
    unit_path = os.path.join(unit_dir, unit_name)
    with open(unit_path, "w") as f:
        f.write(generate_systemd_unit(name, target))
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "--user", "enable", "--now", unit_name], check=False)
    return unit_path


def _uninstall_systemd(name: str) -> bool:
    unit_name = f"obscura47-host-{name}.service"
    unit_path = os.path.expanduser(f"~/.config/systemd/user/{unit_name}")
    if not os.path.isfile(unit_path):
        return False
    subprocess.run(["systemctl", "--user", "disable", "--now", unit_name], check=False)
    os.remove(unit_path)
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    return True
