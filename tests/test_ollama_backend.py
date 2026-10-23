"""The Ollama adapter: request body, reply parsing, fail-closed handling and hard deadlines."""

import ast
import dataclasses
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time

import pytest

from triage.agent import run_agent
from triage.backends import (
    BackendError, ChatRequest, HeuristicBackend, OllamaBackend, ToolCall, make_backend, ollama,
    serialize_request,
)
from triage.backends.ollama import (
    MAX_RESPONSE_BYTES, Endpoint, Exchange, _http_transport, live_workers, parse_endpoint,
)
from triage.config import REPO_ROOT, Settings
from triage.enrich import enrich
from triage.evidence import EvidenceLog
from triage.ingest import load_alert
from triage.prompt import CONTEXT_TOKENS, MAX_OUTPUT_TOKENS, initial_messages, tool_specs
from triage.schemas import DraftSeverity, ModelDraft
from triage.tools import registry

HOST = "http://localhost:11434"
MODEL = "example-model:7b"
MARKER = "ZQXMARKER7731"
POWERSHELL = REPO_ROOT / "samples" / "alerts" / "wazuh" / "encoded_powershell.json"
VALID = ModelDraft(severity=DraftSeverity(value="high", rationale="r", sources=["rule_level"]),
                   next_steps=[], containment=[], missing_data=[]).model_dump_json()


def _wait_until(predicate, timeout_s):
    deadline = time.monotonic() + timeout_s
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


@pytest.fixture(autouse=True)
def release():
    """One event per test; blocking fake transports wait on it, so teardown can release them."""
    event = threading.Event()
    yield event
    event.set()
    assert _wait_until(lambda: live_workers() == 0, 5.0), "a request worker outlived its test"


# --- Helpers -------------------------------------------------------------

@pytest.fixture(scope="module")
def investigate_request(settings, tools):
    alert = load_alert(POWERSHELL.read_text(encoding="utf-8"), fmt="wazuh")
    enrichment = enrich(alert, EvidenceLog(tools), settings)
    return ChatRequest(messages=initial_messages(alert, enrichment), tools=tool_specs(tools),
                       response_schema=None, max_output_tokens=MAX_OUTPUT_TOKENS,
                       context_tokens=CONTEXT_TOKENS, timeout_s=5.0, alert=alert, enrichment=enrichment)


@pytest.fixture(scope="module")
def final_request(investigate_request):
    return dataclasses.replace(investigate_request, tools=None,
                               response_schema=ModelDraft.model_json_schema())


class FakeTransport:
    """Records (endpoint, body, timeout_s) and returns scripted (status, bytes) or raises."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, endpoint, body, timeout_s, exchange):
        self.calls.append((endpoint, body, timeout_s))
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply


def _reply(content="", tool_calls=None, message=None, **fields):
    if message is None:
        message = {"role": "assistant", "content": content}
        if tool_calls is not None:
            message["tool_calls"] = tool_calls
    return 200, json.dumps({"model": MODEL, "message": message, "done": True, **fields}).encode()


def _backend(*replies, **kwargs):
    transport = FakeTransport(*replies)
    return OllamaBackend(HOST, MODEL, transport=transport, **kwargs), transport


def _payload(transport):
    return json.loads(transport.calls[-1][1])


# --- Request body --------------------------------------------------------

def test_investigation_body(investigate_request):
    """An investigation request carries the measured messages and tools, no schema, and fixed options."""
    backend, transport = _backend(_reply())
    backend.chat(investigate_request)
    endpoint, body, timeout_s = transport.calls[0]
    assert endpoint == Endpoint("http", "localhost", 11434) and timeout_s == 5.0
    payload = json.loads(body)
    assert list(payload) == ["model", "messages", "tools", "stream", "options"]
    assert payload["model"] == MODEL
    assert payload["messages"] == investigate_request.messages
    assert payload["tools"] == investigate_request.tools
    assert payload["stream"] is False
    assert payload["options"] == {"num_ctx": 32768, "num_predict": 1024, "temperature": 0.0, "seed": 0}


def test_final_body(final_request):
    """A final request carries the measured schema and no tools."""
    backend, transport = _backend(_reply(VALID))
    backend.chat(final_request)
    payload = _payload(transport)
    assert list(payload) == ["model", "messages", "format", "stream", "options"]
    assert payload["format"] == final_request.response_schema
    assert payload["messages"] == final_request.messages


@pytest.mark.parametrize("which", ["investigate", "final"])
def test_no_null_fields_and_size(which, investigate_request, final_request):
    """Null fields are never sent, and the body adds little to the bytes the budget measured."""
    request = investigate_request if which == "investigate" else final_request
    backend, transport = _backend(_reply())
    backend.chat(request)
    body = transport.calls[0][1]
    payload = json.loads(body)
    assert None not in payload.values() and "think" not in payload
    assert len(body) <= len(serialize_request(request)) + 512


@pytest.mark.parametrize("think", [True, False])
def test_think_sent_only_when_configured(think, investigate_request):
    """The think flag is sent only when it is configured."""
    backend, transport = _backend(_reply(), think=think)
    backend.chat(investigate_request)
    payload = _payload(transport)
    assert payload["think"] is think
    assert list(payload) == ["model", "messages", "tools", "stream", "think", "options"]


# --- Reply parsing -------------------------------------------------------

def test_reply_content(final_request):
    """The reply text is the message content."""
    backend, _ = _backend(_reply(VALID))
    reply = backend.chat(final_request)
    assert reply.text == VALID and reply.tool_calls == []


def test_tool_calls_mapped(investigate_request):
    """Tool calls are passed on as the model sent them; malformed entries become empty calls."""
    calls = [{"function": {"name": "attack_lookup", "arguments": {"technique_id": "T1003"}}},
             "not an object", {"no_function": 1}, {"function": "not an object"}]
    backend, _ = _backend(_reply(tool_calls=calls))
    reply = backend.chat(investigate_request)
    assert reply.tool_calls == [ToolCall("attack_lookup", {"technique_id": "T1003"})] + [ToolCall(None, None)] * 3


@pytest.mark.parametrize("value,expected", [
    (5, 5), (0, 0), (-1, None), (True, None), (1.5, None), ("3", None), (None, None),
])
def test_token_counts(value, expected, investigate_request):
    """Token counts are read only when they are non-negative integers."""
    backend, _ = _backend(_reply(prompt_eval_count=value, eval_count=value))
    reply = backend.chat(investigate_request)
    assert reply.input_tokens == expected and reply.output_tokens == expected


def test_token_counts_missing(investigate_request):
    """A reply without token counts reports none."""
    backend, _ = _backend(_reply())
    reply = backend.chat(investigate_request)
    assert reply.input_tokens is None and reply.output_tokens is None


def test_thinking_ignored(final_request):
    """The model's thinking text never becomes part of the reply."""
    message = {"role": "assistant", "content": VALID, "thinking": MARKER}
    backend, _ = _backend(_reply(message=message))
    reply = backend.chat(final_request)
    assert reply.text == VALID and MARKER not in repr(reply)


def test_truncated_reply_passed_through(final_request):
    """A reply cut off at the output limit goes to validation like any other text."""
    backend, _ = _backend(_reply(VALID[:20], done_reason="length"))
    assert backend.chat(final_request).text == VALID[:20]


# --- Fail closed ---------------------------------------------------------

def _json(obj):
    return json.dumps(obj).encode()


_DEEP = b"[" * 100_000 + f'"{MARKER}"'.encode() + b"]" * 100_000

BAD_REPLIES = {
    "http_301": ((301, MARKER.encode()), "ollama: HTTP 301"),
    "http_400": ((400, MARKER.encode()), "ollama: HTTP 400"),
    "http_404": ((404, MARKER.encode()), "ollama: HTTP 404"),
    "http_500": ((500, MARKER.encode()), "ollama: HTTP 500"),
    "oversized": ((200, _json({"x": MARKER + "a" * MAX_RESPONSE_BYTES})), "ollama: response too large"),
    "not_utf8": ((200, MARKER.encode() + b"\xff"), "ollama: malformed response"),
    "invalid_json": ((200, b"{" + MARKER.encode()), "ollama: malformed response"),
    "deeply_nested": ((200, _DEEP), "ollama: malformed response"),
    "not_object": ((200, _json([MARKER])), "ollama: malformed response"),
    "error_key": ((200, _json({"error": MARKER})), "ollama: server reported an error"),
    "done_false": ((200, _json({"done": False, "message": {"content": MARKER}})), "ollama: malformed response"),
    "done_missing": ((200, _json({"message": {"content": MARKER}})), "ollama: malformed response"),
    "message_missing": ((200, _json({"done": True, "x": MARKER})), "ollama: malformed response"),
    "message_not_object": ((200, _json({"done": True, "message": MARKER})), "ollama: malformed response"),
    "content_not_str": ((200, _json({"done": True, "message": {"content": [MARKER]}})),
                        "ollama: malformed response"),
    "tool_calls_not_list": ((200, _json({"done": True, "message": {"content": "", "tool_calls": {"x": MARKER}}})),
                            "ollama: malformed response"),
}


@pytest.mark.parametrize("case", BAD_REPLIES)
def test_bad_reply_is_backend_error(case, investigate_request):
    """A reply that is not the expected JSON is a backend error whose message carries none of its content."""
    reply, message = BAD_REPLIES[case]
    backend, _ = _backend(reply)
    with pytest.raises(BackendError) as excinfo:
        backend.chat(investigate_request)
    assert str(excinfo.value) == message
    assert MARKER not in str(excinfo.value) and excinfo.value.__cause__ is None


@pytest.mark.parametrize("error", [
    ConnectionRefusedError(MARKER), TimeoutError(MARKER), ssl.SSLError(MARKER), http.client.BadStatusLine(MARKER),
], ids=lambda e: type(e).__name__)
def test_transport_failure_is_connection_failed(error, investigate_request):
    """Network and protocol failures become one fixed error that names no endpoint detail."""
    backend, _ = _backend(error)
    with pytest.raises(BackendError) as excinfo:
        backend.chat(investigate_request)
    assert str(excinfo.value) == "ollama: connection failed" and excinfo.value.__cause__ is None


def test_bug_in_transport_propagates(investigate_request):
    """A bug is re-raised unchanged instead of being reported as a backend failure."""
    error = RuntimeError(MARKER)
    backend, _ = _backend(error)
    with pytest.raises(RuntimeError) as excinfo:
        backend.chat(investigate_request)
    assert excinfo.value is error


# --- Endpoint and model name ---------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("http://localhost:11434", Endpoint("http", "localhost", 11434)),
    ("https://ollama.lan", Endpoint("https", "ollama.lan", 443)),
    ("http://10.0.0.5:11434/", Endpoint("http", "10.0.0.5", 11434)),
    ("http://[::1]:11434", Endpoint("http", "::1", 11434)),
])
def test_valid_endpoints(url, expected):
    """Plain http(s) URLs with a host are accepted, with default ports."""
    assert parse_endpoint(url) == expected


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://host", "http://", "localhost:11434", "http://user:secret@host",
    "http://host/api", "http://host?x=1", "http://host#f", "http://host:99999",
])
def test_invalid_endpoints(url):
    """Alert data cannot be sent to another scheme, path or credentialed URL, and the URL is never echoed."""
    with pytest.raises(ValueError) as excinfo:
        OllamaBackend(url, MODEL)
    message = str(excinfo.value)
    assert message.startswith("OLLAMA_HOST:") and url not in message and "secret" not in message
    assert excinfo.value.__cause__ is None


@pytest.mark.parametrize("model", ["", "bad model", "a" * 129])
def test_invalid_model_names(model):
    """A missing or malformed model name fails at construction, before any alert."""
    with pytest.raises(ValueError, match="^OLLAMA_MODEL:"):
        OllamaBackend(HOST, model)


@pytest.mark.parametrize("model", ["example-model:7b", "org/example-model:latest", "a" * 128])
def test_valid_model_names(model):
    """Ordinary model names are accepted and named in the backend name."""
    assert OllamaBackend(HOST, model).name == f"ollama:{model}"


# --- Factory -------------------------------------------------------------

def test_factory_default_is_heuristic(monkeypatch):
    """Without configuration the rule-based baseline runs, and no network backend is built."""
    monkeypatch.delenv("TRIAGE_BACKEND", raising=False)
    assert isinstance(make_backend(), HeuristicBackend)


def test_factory_ollama_needs_model():
    """The ollama backend has no default model, so a missing one fails at startup."""
    with pytest.raises(ValueError, match="^OLLAMA_MODEL:"):
        make_backend(Settings(backend="ollama", ollama_model=""))


def test_factory_unknown_backend():
    """An unknown backend name fails at startup instead of falling back."""
    with pytest.raises(ValueError, match="^TRIAGE_BACKEND:"):
        make_backend(Settings(backend="claude"))


@pytest.mark.parametrize("value,expected", [("", None), ("true", True), ("false", False)])
def test_factory_think(value, expected):
    """OLLAMA_THINK maps to not sent, true or false."""
    backend = make_backend(Settings(backend="ollama", ollama_host=HOST, ollama_model=MODEL, ollama_think=value))
    assert isinstance(backend, OllamaBackend) and backend.think is expected
    assert backend.name == f"ollama:{MODEL}" and backend.endpoint == Endpoint("http", "localhost", 11434)


def test_factory_invalid_think():
    """An unrecognized OLLAMA_THINK value fails at startup."""
    with pytest.raises(ValueError, match="^OLLAMA_THINK:"):
        make_backend(Settings(backend="ollama", ollama_model=MODEL, ollama_think="yes"))


# --- Watchdog ------------------------------------------------------------

def _blocking(release):
    def transport(endpoint, body, timeout_s, exchange):
        release.wait(10)
        return _reply()
    return transport


def _timed_chat(backend, request):
    t0 = time.monotonic()
    with pytest.raises(BackendError) as excinfo:
        backend.chat(request)
    return str(excinfo.value), time.monotonic() - t0


def test_watchdog_deadline(release, investigate_request):
    """A transport that never returns cannot hold the caller past the request deadline."""
    backend = OllamaBackend(HOST, MODEL, transport=_blocking(release))
    message, elapsed = _timed_chat(backend, dataclasses.replace(investigate_request, timeout_s=0.3))
    assert message == "ollama: request deadline exceeded" and elapsed < 0.3 + 1.0


def test_repeated_timeouts_do_not_accumulate_workers(release, investigate_request):
    """Workers left behind by timed-out requests are capped; further requests fail at once."""
    backend = OllamaBackend(HOST, MODEL, transport=_blocking(release))
    request = dataclasses.replace(investigate_request, timeout_s=0.3)
    for _ in range(2):
        message, elapsed = _timed_chat(backend, request)
        assert message == "ollama: request deadline exceeded" and elapsed < 0.3 + 1.0
    assert live_workers() == 2
    threads = threading.active_count()
    message, elapsed = _timed_chat(backend, request)
    assert message == "ollama: earlier requests still pending" and elapsed < 0.2
    assert threading.active_count() == threads
    release.set()
    assert _wait_until(lambda: live_workers() == 0, 5.0)
    assert backend.chat(request).text == ""


def _unstartable(error):
    class UnstartableThread(threading.Thread):
        def start(self):
            raise error
    return UnstartableThread


def test_failed_thread_start_frees_slot(monkeypatch, investigate_request):
    """A worker that fails to start does not keep its slot and block every later request."""
    backend, _ = _backend(_reply())
    with monkeypatch.context() as m:
        m.setattr(ollama.threading, "Thread", _unstartable(RuntimeError("can't start new thread")))
        for _ in range(3):
            with pytest.raises(BackendError, match="^ollama: could not start a request worker$"):
                backend.chat(investigate_request)
            assert live_workers() == 0
    assert backend.chat(investigate_request).text == ""


def test_interrupted_thread_start_frees_slot(monkeypatch, investigate_request):
    """A KeyboardInterrupt during start propagates unchanged and does not keep the slot."""
    backend, _ = _backend(_reply())
    monkeypatch.setattr(ollama.threading, "Thread", _unstartable(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        backend.chat(investigate_request)
    assert live_workers() == 0


# --- Real http.client over loopback --------------------------------------

def _read_request(conn):
    """Reads one HTTP request; returns False if the client sent none."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return False
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = next((int(line.split(b":", 1)[1]) for line in head.split(b"\r\n")
                   if line.lower().startswith(b"content-length:")), 0)
    while len(body) < length:
        chunk = conn.recv(65536)
        if not chunk:
            return False
        body += chunk
    return True


class LoopbackServer:
    """A TCP server on 127.0.0.1 that hands each connection to handler(server, conn) in its own thread."""

    def __init__(self, handler, tls=None):
        self.handler, self.tls = handler, tls
        self.stop = threading.Event()
        self.requests = 0
        self.connections_done = 0
        self.headers_sent = threading.Event()
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(0.05)
        self.port = self.listener.getsockname()[1]
        self.threads = [threading.Thread(target=self._accept, daemon=True)]
        self.threads[0].start()

    def _accept(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            self.threads.append(thread)
            thread.start()

    def _serve(self, conn):
        try:
            conn.settimeout(2.0)
            if self.tls is not None:
                conn = self.tls.wrap_socket(conn, server_side=True)
            if _read_request(conn):
                self.requests += 1
                self.handler(self, conn)
        except OSError:
            pass  # the client went away
        finally:
            conn.close()
            self.connections_done += 1

    def wait_for_disconnect(self, conn):
        """Holds the connection until the client closes it or the test stops the server."""
        conn.settimeout(0.05)
        while not self.stop.is_set():
            try:
                if not conn.recv(1):
                    return
            except TimeoutError:
                continue

    def dribble(self, conn, data):
        """Sends data one byte every 0.05 s until it ends, the client leaves or the test stops."""
        for i in range(len(data)):
            if self.stop.is_set():
                return
            conn.sendall(data[i:i + 1])
            self.stop.wait(0.05)

    def close(self):
        self.stop.set()
        for thread in list(self.threads):
            thread.join(5.0)
        self.listener.close()
        assert not any(t.is_alive() for t in self.threads), "a server thread outlived its test"


@pytest.fixture
def serve():
    servers = []

    def start(handler, tls=None):
        server = LoopbackServer(handler, tls)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def _ok_response(body: bytes, status="200 OK", extra=""):
    return (f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            f"{extra}Connection: close\r\n\r\n").encode() + body


def _loopback(server, scheme="http", host="127.0.0.1", **kwargs):
    return OllamaBackend(f"{scheme}://{host}:{server.port}", MODEL, **kwargs)


def test_loopback_success(serve, final_request):
    """A valid reply over a real socket is parsed."""
    server = serve(lambda s, conn: conn.sendall(_ok_response(_reply(VALID)[1])))
    assert _loopback(server).chat(final_request).text == VALID
    assert server.requests == 1


def test_redirect_not_followed(serve, investigate_request):
    """A redirect is an error, never followed to another endpoint."""
    def handler(s, conn):
        conn.sendall(_ok_response(b"", "302 Found", f"Location: http://127.0.0.1:{s.port}/elsewhere\r\n"))
    server = serve(handler)
    with pytest.raises(BackendError, match="^ollama: HTTP 302$"):
        _loopback(server).chat(investigate_request)
    assert server.requests == 1


def test_proxy_settings_ignored(serve, monkeypatch, final_request):
    """Proxy environment variables cannot divert alert data to another host."""
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://localhost:9")
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    server = serve(lambda s, conn: conn.sendall(_ok_response(_reply(VALID)[1])))
    assert _loopback(server).chat(final_request).text == VALID
    assert server.requests == 1


def test_error_status_body_not_read(serve, investigate_request):
    """An error status fails at once; its body is not read or reported."""
    def handler(s, conn):
        conn.sendall(_ok_response((MARKER * 400_000).encode(), "500 Internal Server Error"))
    server = serve(handler)
    t0 = time.monotonic()
    with pytest.raises(BackendError) as excinfo:
        _loopback(server).chat(investigate_request)
    assert str(excinfo.value) == "ollama: HTTP 500" and time.monotonic() - t0 < 1.0


def test_oversized_reply(serve, investigate_request):
    """A reply over the cap is rejected after reading just past the cap."""
    server = serve(lambda s, conn: conn.sendall(_ok_response(b" " * (MAX_RESPONSE_BYTES + 100_000))))
    with pytest.raises(BackendError, match="^ollama: response too large$"):
        _loopback(server).chat(investigate_request)


_SLOW_HEADERS = b"HTTP/1.1 200 OK\r\nX-Padding: " + b"a" * 200 + b"\r\n\r\n"
_HEADERS = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"


def _slow_headers(s, conn):
    s.dribble(conn, _SLOW_HEADERS)


def _slow_body(s, conn):
    conn.sendall(_HEADERS)
    s.headers_sent.set()
    s.dribble(conn, b" " * 200)


def _silent(s, conn):
    s.wait_for_disconnect(conn)


@pytest.mark.parametrize("handler", [_slow_headers, _slow_body, _silent], ids=lambda h: h.__name__)
def test_loopback_deadline(handler, serve, investigate_request):
    """A server that trickles bytes or says nothing cannot hold a request past its deadline or keep its worker."""
    # The trickling handlers keep sending for 10 s, far longer than the
    # timeout, so a socket inactivity timeout alone would never fire.
    server = serve(handler)
    message, elapsed = _timed_chat(_loopback(server), dataclasses.replace(investigate_request, timeout_s=0.5))
    returned = time.monotonic()
    assert message == "ollama: request deadline exceeded" and elapsed < 1.5
    assert _wait_until(lambda: live_workers() == 0, 1.0)
    assert time.monotonic() - returned < 1.0
    if handler is _slow_body:
        assert server.headers_sent.is_set()


@pytest.fixture
def tls_files(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("the openssl command is needed to create a test certificate")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
    return cert, key


def test_https_slow_body_deadline(tls_files, serve, monkeypatch, investigate_request):
    """Over TLS too, a body trickled after the headers cannot keep the worker past the deadline."""
    cert, key = tls_files
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    # Certificate and hostname checks stay on; the context trusts only the test certificate.
    real = ssl.create_default_context
    monkeypatch.setattr(ollama.ssl, "create_default_context", lambda: real(cafile=str(cert)))
    server = serve(_slow_body, tls=server_context)
    message, elapsed = _timed_chat(_loopback(server, "https", "localhost"),
                                   dataclasses.replace(investigate_request, timeout_s=0.5))
    returned = time.monotonic()
    assert message == "ollama: request deadline exceeded" and elapsed < 1.5
    assert server.headers_sent.is_set()
    assert _wait_until(lambda: live_workers() == 0, 1.0)
    assert time.monotonic() - returned < 1.0


# --- Exchange ------------------------------------------------------------

class RecordingSocket:
    def __init__(self):
        self.calls = []

    def shutdown(self, how):
        self.calls.append("shutdown")

    def close(self):
        self.calls.append("close")


def test_abort_before_attach_sends_nothing(serve):
    """A request whose caller already gave up is never sent."""
    server = serve(lambda s, conn: None)
    exchange = Exchange()
    exchange.abort()
    assert exchange.attach(RecordingSocket()) is False
    with pytest.raises(ollama._Aborted):
        _http_transport(Endpoint("http", "127.0.0.1", server.port), b"{}", 1.0, exchange)
    assert _wait_until(lambda: server.connections_done == 1, 2.0)
    assert server.requests == 0


def test_abort_before_attach_closes_owned_descriptor(serve):
    """A request cancelled before its socket is attached still has its owned descriptor closed."""
    server = serve(lambda s, conn: None)
    fds = "/proc/self/fd"
    before = len(os.listdir(fds)) if os.path.isdir(fds) else None
    exchange = Exchange()
    exchange.abort()
    with pytest.raises(ollama._Aborted):
        _http_transport(Endpoint("http", "127.0.0.1", server.port), b"{}", 1.0, exchange)
    # These two do not depend on garbage collection, unlike the count below.
    assert exchange.sock is not None and exchange.sock.fileno() == -1
    assert exchange.released is True
    assert _wait_until(lambda: server.connections_done == 1, 2.0)
    assert server.requests == 0
    if before is not None:
        assert len(os.listdir(fds)) == before


def test_abort_after_release_does_not_shut_down():
    """Once the worker has closed its socket, abort cannot touch a descriptor that may be reused."""
    sock, resp, conn = RecordingSocket(), RecordingSocket(), RecordingSocket()
    exchange = Exchange()
    assert exchange.attach(sock) is True
    exchange.release(resp, conn)
    exchange.abort()
    assert sock.calls == ["close"] and resp.calls == ["close"] and conn.calls == ["close"]


def test_abort_never_closes():
    """abort() only shuts the socket down; the worker alone closes it."""
    sock = RecordingSocket()
    exchange = Exchange()
    exchange.attach(sock)
    exchange.abort()
    assert sock.calls == ["shutdown"]


class RecordingExchange(Exchange):
    """Records the saved socket's descriptor at the moment release() starts."""

    def release(self, resp, conn):
        self.fileno_at_release = self.sock.fileno()
        super().release(resp, conn)


def _complete_exchange(serve):
    server = serve(lambda s, conn: conn.sendall(_ok_response(_reply(VALID)[1])))
    exchange = RecordingExchange()
    status, _ = _http_transport(Endpoint("http", "127.0.0.1", server.port), b"{}", 2.0, exchange)
    assert status == 200
    return exchange


def test_saved_socket_open_until_release(serve):
    """http.client closing its socket after the body cannot close the descriptor abort may still use."""
    exchange = _complete_exchange(serve)
    assert exchange.fileno_at_release != -1
    assert exchange.sock.fileno() == -1


def test_abort_after_completed_exchange(serve):
    """An abort that arrives after a completed exchange raises nothing."""
    _complete_exchange(serve).abort()


def test_no_descriptor_leak(serve, final_request, investigate_request):
    """Duplicated descriptors are closed after successful requests and after deadline timeouts alike."""
    if not os.path.isdir("/proc/self/fd"):
        pytest.skip("/proc/self/fd is needed to count open descriptors")
    ok = serve(lambda s, conn: conn.sendall(_ok_response(_reply(VALID)[1])))
    silent = serve(_silent)
    timed = dataclasses.replace(investigate_request, timeout_s=0.2)
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(20):
        assert _loopback(ok).chat(final_request).text == VALID
    for _ in range(5):
        message, _ = _timed_chat(_loopback(silent), timed)
        assert message == "ollama: request deadline exceeded"
        assert _wait_until(lambda: live_workers() == 0, 1.0)
    assert _wait_until(lambda: ok.connections_done == 20 and silent.connections_done == 5, 2.0)
    assert len(os.listdir("/proc/self/fd")) == before


# --- Integration with the agent loop -------------------------------------

def test_agent_run_with_ollama_replies(settings, tools):
    """A run over Ollama-format replies completes, and the lookup the model asked for is marked as its own."""
    alert = load_alert(POWERSHELL.read_text(encoding="utf-8"), fmt="wazuh")
    lookup = {"function": {"name": "attack_lookup", "arguments": {"technique_id": "T1003"}}}
    backend, transport = _backend(_reply(tool_calls=[lookup]), _reply(), _reply(VALID))
    result = run_agent(alert, backend, settings=settings, tools=tools)
    assert result.stop_reason == "completed" and result.backend == f"ollama:{MODEL}"
    assert len(transport.calls) == 3
    new = registry.evidence_id("attack_lookup", {"technique_id": "T1003"})
    assert result.evidence_origin[new] == "model"


def test_agent_run_transport_failure(settings, tools):
    """A connection failure on the first call stops the run as a backend error."""
    alert = load_alert(POWERSHELL.read_text(encoding="utf-8"), fmt="wazuh")
    backend, _ = _backend(ConnectionRefusedError(MARKER))
    result = run_agent(alert, backend, settings=settings, tools=tools)
    assert result.stop_reason == "backend_error" and result.draft is None
    assert MARKER not in result.model_dump_json()


# --- Network code location -----------------------------------------------

_NETWORK_MODULES = {"socket", "ssl", "http", "requests"}


def _imports(path):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module
            yield from (f"{node.module}.{alias.name}" for alias in node.names)


def test_network_code_only_in_adapter():
    """Only the Ollama adapter can make a network call at triage time."""
    adapter = REPO_ROOT / "triage" / "backends" / "ollama.py"
    offenders = []
    for path in sorted((REPO_ROOT / "triage").rglob("*.py")):
        for name in _imports(path):
            if name.split(".")[0] in _NETWORK_MODULES or name == "urllib.request" or name.startswith("urllib.request."):
                offenders.append((path.relative_to(REPO_ROOT).as_posix(), name))
    assert offenders and {path for path, _ in offenders} == {adapter.relative_to(REPO_ROOT).as_posix()}
