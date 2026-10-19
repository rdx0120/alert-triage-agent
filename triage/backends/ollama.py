"""The Ollama backend: the only code that makes a network call at triage time.

A thin, fail-closed client for Ollama's /api/chat. It has no proxy or redirect
handling, every request has a hard deadline, and response bodies are never
stored or logged: a failure is a BackendError with a fixed message.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import ssl
import threading
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from .base import BackendError, ChatReply, ChatRequest, ToolCall

# Fixed for reproducibility; the evaluation host confirms the model and options.
CHAT_PATH = "/api/chat"
TEMPERATURE = 0.0
SEED = 0
MAX_RESPONSE_BYTES = 1_048_576   # far above what MAX_OUTPUT_TOKENS can produce
READ_CHUNK_BYTES = 65_536
MAX_LIVE_WORKERS = 2             # request worker threads alive at once, the current one included
MODEL_NAME_PATTERN = r"^[A-Za-z0-9._:/-]{1,128}$"

# The URL may carry credentials, so the message never repeats it.
_ENDPOINT_ERROR = ("OLLAMA_HOST: must be an http or https URL with a host and no credentials, "
                   "path, query or fragment")

_live_lock = threading.Lock()
_live_workers: set[threading.Thread] = set()


@dataclass(frozen=True)
class Endpoint:
    scheme: str  # "http" | "https"
    host: str
    port: int


def parse_endpoint(url: str) -> Endpoint:
    try:
        parts = urlsplit(url)
        port = parts.port  # raises ValueError on a bad port
    except ValueError:
        raise ValueError(_ENDPOINT_ERROR) from None
    if (parts.scheme not in ("http", "https") or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.path not in ("", "/") or parts.query or parts.fragment):
        raise ValueError(_ENDPOINT_ERROR)
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return Endpoint(parts.scheme, parts.hostname, port)


class Exchange:
    """One request's state, shared by the caller and the worker thread."""

    def __init__(self) -> None:
        self.sock: socket.socket | None = None
        self.aborted = False
        self.released = False
        self.result: tuple[int, bytes] | None = None
        self.error: BaseException | None = None
        self._lock = threading.Lock()

    def attach(self, sock: socket.socket) -> bool:
        with self._lock:
            self.sock = sock
            return not self.aborted

    def abort(self) -> None:
        # The saved socket is a duplicate descriptor owned by the exchange;
        # http.client closes its own socket once the body is read, but the
        # duplicate stays open until release() closes it under the lock, so
        # abort never shuts down a descriptor that has been closed or reused.
        # shutdown() acts on the connection, so it wakes a blocked read
        # whichever descriptor it is called on.
        with self._lock:
            self.aborted = True
            if self.sock is not None and not self.released:
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def release(self, resp, conn) -> None:
        with self._lock:
            self.released = True
            for closable in (resp, conn, self.sock):
                if closable is not None:
                    try:
                        closable.close()
                    except OSError:
                        pass


Transport = Callable[[Endpoint, bytes, float, Exchange], tuple[int, bytes]]


class _Aborted(Exception):
    """The caller gave up before the request was sent; nothing is sent."""


def _http_transport(endpoint: Endpoint, body: bytes, timeout_s: float, exchange: Exchange) -> tuple[int, bytes]:
    # http.client has no proxy or redirect handling, so environment proxy
    # settings are never used and a 3xx is just a status code.
    if endpoint.scheme == "https":
        conn = http.client.HTTPSConnection(endpoint.host, endpoint.port, timeout=timeout_s,
                                           context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=timeout_s)
    resp = None
    try:
        # Name lookup, TCP and, for https, the TLS handshake; all within
        # timeout_s except the name lookup.
        conn.connect()
        saved = socket.socket(fileno=os.dup(conn.sock.fileno()))
        if not exchange.attach(saved):
            raise _Aborted
        conn.request("POST", CHAT_PATH, body=body, headers={
            "Content-Type": "application/json", "Accept": "application/json", "Connection": "close"})
        resp = conn.getresponse()
        if resp.status != 200:
            return resp.status, b""
        chunks, total = [], 0
        # Stops as soon as the cap is passed; the caller rejects what was read.
        while total <= MAX_RESPONSE_BYTES:
            chunk = resp.read(READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return resp.status, b"".join(chunks)
    finally:
        exchange.release(resp, conn)


def live_workers() -> int:
    with _live_lock:
        return len(_live_workers)


def _count(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _malformed() -> BackendError:
    return BackendError("ollama: malformed response")


def _parse(status: int, data: bytes) -> ChatReply:
    # Every failure has a fixed message that never includes response content.
    if status != 200:
        raise BackendError(f"ollama: HTTP {status}")
    if len(data) > MAX_RESPONSE_BYTES:
        raise BackendError("ollama: response too large")
    try:
        body = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):  # includes UnicodeDecodeError
        raise _malformed() from None
    if not isinstance(body, dict):
        raise _malformed()
    if "error" in body:
        raise BackendError("ollama: server reported an error")
    message = body.get("message")
    if body.get("done") is not True or not isinstance(message, dict):
        raise _malformed()
    content = message.get("content")
    tool_calls = message.get("tool_calls")
    if ("content" in message and not isinstance(content, str)) or \
            (tool_calls is not None and not isinstance(tool_calls, list)):
        raise _malformed()
    calls = []
    for entry in tool_calls or []:
        function = entry.get("function") if isinstance(entry, dict) else None
        if not isinstance(function, dict):
            function = {}
        # The loop normalizes bad names and arguments.
        calls.append(ToolCall(name=function.get("name"), arguments=function.get("arguments")))
    # "thinking" and done_reason are ignored: a truncated reply (done_reason
    # "length") goes to validation like any other text.
    return ChatReply(text=content or "", tool_calls=calls,
                     input_tokens=_count(body.get("prompt_eval_count")),
                     output_tokens=_count(body.get("eval_count")))


class OllamaBackend:
    def __init__(self, host: str, model: str, *, think: bool | None = None,
                 transport: Transport | None = None) -> None:
        # Both are checked at construction, before any alert is read.
        self.endpoint = parse_endpoint(host)
        if not isinstance(model, str) or not re.fullmatch(MODEL_NAME_PATTERN, model):
            raise ValueError("OLLAMA_MODEL: missing or not a valid model name")
        self.model = model
        self.think = think
        self.transport = transport or _http_transport
        self.name = f"ollama:{model}"

    def chat(self, request: ChatRequest) -> ChatReply:
        # messages, tools and format are the same objects serialize_request()
        # measured for the context budget; null fields are omitted, never sent.
        payload = {"model": self.model, "messages": request.messages}
        if request.tools is not None:
            payload["tools"] = request.tools
        if request.response_schema is not None:
            payload["format"] = request.response_schema
        payload["stream"] = False
        if self.think is not None:
            payload["think"] = self.think
        payload["options"] = {"num_ctx": request.context_tokens, "num_predict": request.max_output_tokens,
                              "temperature": TEMPERATURE, "seed": SEED}
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

        # The caller returns within the deadline whatever the server does; a
        # worker blocked where shutdown cannot reach (a name lookup) ends when
        # that call returns, and the live-worker cap keeps such workers from
        # accumulating.
        exchange = Exchange()

        def work() -> None:
            try:
                exchange.result = self.transport(self.endpoint, body, request.timeout_s, exchange)
            except BaseException as e:
                exchange.error = e
            finally:
                with _live_lock:
                    _live_workers.discard(threading.current_thread())

        with _live_lock:
            if len(_live_workers) >= MAX_LIVE_WORKERS:
                raise BackendError("ollama: earlier requests still pending")
            worker = threading.Thread(target=work, name="ollama-request", daemon=True)
            _live_workers.add(worker)
        try:
            worker.start()
        except BaseException as e:
            # The slot is freed here because a thread that never started cannot free it.
            with _live_lock:
                _live_workers.discard(worker)
            if isinstance(e, Exception):
                raise BackendError("ollama: could not start a request worker") from None
            raise
        worker.join(request.timeout_s)
        if worker.is_alive():
            exchange.abort()
            # The result is never read after this: a worker woken by shutdown
            # can end with a truncated body that looks like a normal end of file.
            raise BackendError("ollama: request deadline exceeded")

        if isinstance(exchange.error, (OSError, http.client.HTTPException)):
            # OSError includes timeouts and ssl.SSLError.
            raise BackendError("ollama: connection failed") from None
        if exchange.error is not None:
            raise exchange.error  # a bug must not be reported as a backend failure
        return _parse(*exchange.result)
