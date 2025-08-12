import argparse
import threading
import time
import sys

from src.core.proxy import start_proxy
from src.core.node import ObscuraNode
from src.core.exit_node import ExitNode
from src.utils.config import NODE_LISTEN_PORT, EXIT_LISTEN_PORT


def run_proxy():
    start_proxy()


def run_node(port: int):
    node = ObscuraNode(port=port)
    node.run()
    while True:
        time.sleep(1)


def run_exit(port: int):
    exit_node = ExitNode(port=port)
    exit_node.start_server()


def main():
    # Ensure UTF-8 console to avoid UnicodeEncodeError on Windows terminals
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    parser = argparse.ArgumentParser(description="Obscura47 runner")
    parser.add_argument("role", choices=["proxy", "node", "exit"], help="Component to run")
    parser.add_argument("--port", type=int, default=None, help="Listening port for node/exit")
    args = parser.parse_args()

    if args.role == "proxy":
        run_proxy()
    elif args.role == "node":
        run_node(args.port or NODE_LISTEN_PORT)
    elif args.role == "exit":
        run_exit(args.port or EXIT_LISTEN_PORT)


if __name__ == "__main__":
    main()


