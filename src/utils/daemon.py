"""Daemon template generation for `.obscura` host services.

Generates platform-specific service definitions so a hosted site
persists across reboots without keeping a terminal open.
"""

from __future__ import annotations

import os
import platform
import shlex
import subprocess
import sys
import textwrap
from xml.sax.saxutils import escape as xml_escape


SYSTEMD_TEMPLATE = textwrap.dedent("""\
    [Unit]
    Description=Obscura47 hidden-service host ({name})
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    ExecStart={exec_start}
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
{program_arguments}
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


WINDOWS_TASK_NAME = "Obscura47 Host {name}"


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _log_dir() -> str:
    d = os.path.join(os.path.expanduser("~"), ".obscura47", "logs")
    os.makedirs(d, exist_ok=True)
    return d


def _host_command_args(
    name: str,
    target: str,
    key_path: str | None = None,
) -> list[str]:
    args = [
        sys.executable,
        os.path.join(_project_root(), "join_network.py"),
        "host",
        target,
        "--name",
        name,
    ]
    if key_path:
        args.extend(["--key", os.path.expanduser(key_path)])
    return args


def generate_systemd_unit(
    name: str,
    target: str,
    key_path: str | None = None,
) -> str:
    return SYSTEMD_TEMPLATE.format(
        name=name,
        exec_start=" ".join(
            shlex.quote(arg) for arg in _host_command_args(name, target, key_path)
        ),
        workdir=_project_root(),
    )


def generate_launchd_plist(
    name: str,
    target: str,
    key_path: str | None = None,
) -> str:
    program_arguments = "\n".join(
        f"    <string>{xml_escape(arg)}</string>"
        for arg in _host_command_args(name, target, key_path)
    )
    return LAUNCHD_TEMPLATE.format(
        name=name,
        program_arguments=program_arguments,
        workdir=_project_root(),
        log_dir=_log_dir(),
    ).lstrip()


def scheduled_task_name(name: str) -> str:
    return WINDOWS_TASK_NAME.format(name=name)


def daemon_reference(name: str, system: str | None = None) -> str:
    system = system or platform.system()
    if system == "Darwin":
        return os.path.expanduser(f"~/Library/LaunchAgents/com.obscura47.host.{name}.plist")
    if system == "Linux":
        return os.path.expanduser(f"~/.config/systemd/user/obscura47-host-{name}.service")
    if system == "Windows":
        return scheduled_task_name(name)
    raise RuntimeError(f"unsupported platform: {system}")


def daemon_installed(name: str, system: str | None = None) -> bool:
    system = system or platform.system()
    if system in ("Darwin", "Linux"):
        return os.path.isfile(daemon_reference(name, system=system))
    if system == "Windows":
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", daemon_reference(name, system=system)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return result.returncode == 0
    return False


def install_daemon(
    name: str,
    target: str,
    key_path: str | None = None,
) -> str:
    """Install a per-site daemon and return the config file path.

    On macOS: writes a launchd plist and loads it via ``launchctl``.
    On Linux: writes a systemd user unit and enables it.
    """
    system = platform.system()
    if system == "Darwin":
        return _install_launchd(name, target, key_path)
    elif system == "Linux":
        return _install_systemd(name, target, key_path)
    elif system == "Windows":
        return _install_windows_task(name, target, key_path)
    else:
        raise RuntimeError(f"unsupported platform: {system}")


def uninstall_daemon(name: str) -> bool:
    system = platform.system()
    if system == "Darwin":
        return _uninstall_launchd(name)
    elif system == "Linux":
        return _uninstall_systemd(name)
    elif system == "Windows":
        return _uninstall_windows_task(name)
    return False


def _install_launchd(name: str, target: str, key_path: str | None = None) -> str:
    plist_path = daemon_reference(name, system="Darwin")
    os.makedirs(os.path.dirname(plist_path), exist_ok=True)
    with open(plist_path, "w", encoding="utf-8") as f:
        f.write(generate_launchd_plist(name, target, key_path))
    subprocess.run(["launchctl", "load", plist_path], check=False)
    return plist_path


def _uninstall_launchd(name: str) -> bool:
    plist_path = daemon_reference(name, system="Darwin")
    if not os.path.isfile(plist_path):
        return False
    subprocess.run(["launchctl", "unload", plist_path], check=False)
    os.remove(plist_path)
    return True


def _install_systemd(name: str, target: str, key_path: str | None = None) -> str:
    unit_path = daemon_reference(name, system="Linux")
    unit_name = os.path.basename(unit_path)
    os.makedirs(os.path.dirname(unit_path), exist_ok=True)
    with open(unit_path, "w", encoding="utf-8") as f:
        f.write(generate_systemd_unit(name, target, key_path))
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "--user", "enable", "--now", unit_name], check=False)
    return unit_path


def _uninstall_systemd(name: str) -> bool:
    unit_path = daemon_reference(name, system="Linux")
    unit_name = os.path.basename(unit_path)
    if not os.path.isfile(unit_path):
        return False
    subprocess.run(["systemctl", "--user", "disable", "--now", unit_name], check=False)
    os.remove(unit_path)
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    return True


def _install_windows_task(
    name: str,
    target: str,
    key_path: str | None = None,
) -> str:
    task_name = daemon_reference(name, system="Windows")
    command = subprocess.list2cmdline(_host_command_args(name, target, key_path))
    subprocess.run(
        [
            "schtasks",
            "/Create",
            "/F",
            "/SC",
            "ONLOGON",
            "/RL",
            "LIMITED",
            "/TN",
            task_name,
            "/TR",
            command,
        ],
        check=False,
    )
    return task_name


def _uninstall_windows_task(name: str) -> bool:
    task_name = daemon_reference(name, system="Windows")
    result = subprocess.run(
        ["schtasks", "/Delete", "/F", "/TN", task_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0
