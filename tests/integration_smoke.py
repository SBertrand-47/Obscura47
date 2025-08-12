import os
import time
import socket

# Placeholder smoke test scaffolding; to be run manually for now.

def try_connect(host, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass

def test_proxy_up():
    assert try_connect("127.0.0.1", int(os.getenv("OBSCURA_PROXY_PORT", "9047"))), "proxy not up"

