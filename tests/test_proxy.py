import socket

from src.core import proxy as proxy_mod


class _FakeClientSocket:
    def __init__(self, request: bytes):
        self._request = request
        self.sent = []
        self.closed = False

    def recv(self, _size, _flags=0):
        data = self._request
        self._request = b""
        return data

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def close(self):
        self.closed = True


def test_handle_connect_refuses_when_no_relay_route(monkeypatch):
    request = (
        b"CONNECT google.com:443 HTTP/1.1\r\n"
        b"Host: google.com:443\r\n\r\n"
    )
    client = _FakeClientSocket(request)

    proxy_mod.relay_peers[:] = []
    proxy_mod.exit_peers[:] = [{"host": "203.0.113.5", "port": 6000, "pub": "pub"}]

    monkeypatch.setattr(proxy_mod, "choose_best_exit", lambda: dict(proxy_mod.exit_peers[0]))
    monkeypatch.setattr(proxy_mod, "build_route47", lambda peers: [])

    started = {"called": False}

    def _unexpected_start(*args, **kwargs):
        started["called"] = True

    monkeypatch.setattr(proxy_mod, "start_tunnel", _unexpected_start)

    proxy_mod.handle_connect(client)

    assert started["called"] is False
    assert client.closed is True
    assert client.sent == [b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n"]
