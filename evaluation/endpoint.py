"""The model endpoint the evaluation may use: a loopback literal and a port, nothing else.

The harness reads OLLAMA_HOST from its own environment and refuses the pass
unless it names the local machine by a literal address. Names are refused
because resolution can be redirected (a hosts file, a resolver), and every
other spelling of a loopback address (octal, decimal, short or mapped forms)
is refused so that one canonical form is all a reviewer has to recognise.
Every child then gets the canonical URL, so no inherited setting can point a
run elsewhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from evaluation.common import EvaluationError

ENDPOINT_RE = re.compile(r"^(?:http://)?(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$")
SERVER_HOST_RE = re.compile(r"^(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$")
MAX_PORT = 65535


class EndpointRefused(EvaluationError):
    """The model endpoint is not a loopback literal and port."""


@dataclass(frozen=True)
class Endpoint:
    host: str   # "127.0.0.1" or "::1"
    port: int


def _match(pattern: re.Pattern, value: object) -> Endpoint | None:
    if not isinstance(value, str):
        return None
    match = pattern.fullmatch(value)
    if match is None:
        return None
    port = int(match.group(2))
    if port > MAX_PORT:
        return None
    host = "::1" if match.group(1) == "[::1]" else "127.0.0.1"
    return Endpoint(host=host, port=port)


def parse_endpoint(value: str | None) -> Endpoint:
    """The endpoint, or EndpointRefused. The message never repeats the value."""
    endpoint = _match(ENDPOINT_RE, value)
    if endpoint is None:
        raise EndpointRefused("model endpoint must be a loopback literal and port")
    return endpoint


def canonical_url(endpoint: Endpoint) -> str:
    host = "[::1]" if endpoint.host == "::1" else "127.0.0.1"
    return f"http://{host}:{endpoint.port}"


def server_host_ok(value: str) -> bool:
    """The server-side OLLAMA_HOST grammar: the same literals, without a scheme."""
    return _match(SERVER_HOST_RE, value) is not None
