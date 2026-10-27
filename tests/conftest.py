import socket

import pytest

from triage.config import Settings
from triage.tools import build_tools


@pytest.fixture(scope="session")
def settings():
    # Hashing embedder: no model download, deterministic, runs in CI.
    return Settings(embedder="hashing")


@pytest.fixture(scope="session")
def tools(settings):
    return build_tools(settings)


class NetworkGuard:
    """What a test tried to reach: one entry per refused connection or name lookup."""

    def __init__(self) -> None:
        self.attempts: list[str] = []


@pytest.fixture
def no_network(monkeypatch):
    """Refuse, and record, every outbound connection and name lookup made through the socket module.

    A triage run may contact only the configured model server (DD-001); with
    the rule-based backend it must contact nothing. Code that opens sockets
    outside Python's socket module (a native extension's own networking) is
    not seen here; offline mode covers that case (DD-027).
    """
    guard = NetworkGuard()

    def refuse(kind):
        def blocked(*args, **kwargs):
            guard.attempts.append(kind)
            raise OSError("network access is disabled in this test")
        return blocked

    monkeypatch.setattr(socket.socket, "connect", refuse("connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", refuse("connect_ex"))
    monkeypatch.setattr(socket, "create_connection", refuse("create_connection"))
    monkeypatch.setattr(socket, "getaddrinfo", refuse("getaddrinfo"))
    return guard
