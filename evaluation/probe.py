"""The model server's identity, read through three fixed requests to the loopback endpoint.

Only these three requests exist. A request outside the table is refused
before a socket is opened, so no code path in the evaluation can ask the
server to pull, push, create, copy or delete a model. The modelfile and the
model_info block are never read: the modelfile can hold a local path.
"""

from __future__ import annotations

import http.client
import json
import re

from evaluation.common import EvaluationError, SchemaError, sha256_hex, strict_loads
from evaluation.endpoint import Endpoint

REQUESTS = {"version": ("GET", "/api/version"), "tags": ("GET", "/api/tags"), "show": ("POST", "/api/show")}
MAX_BODY = 1 << 20
TIMEOUT_S = 10
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DETAIL_KEYS = ("format", "family", "parameter_size", "quantization_level")


class ProbeRefused(EvaluationError):
    """The request is not in the table, or the server's answer cannot be used."""


def request(endpoint: Endpoint, key: str, model: str | None = None) -> dict:
    if key not in REQUESTS:
        raise ProbeRefused("probe: request not in the table")
    method, path = REQUESTS[key]
    body = None
    headers = {}
    if key == "show":
        if not isinstance(model, str):
            raise ProbeRefused("probe: show needs a model name")
        body = json.dumps({"model": model}).encode("ascii")
        headers["Content-Type"] = "application/json"
    # HTTPConnection never reads proxy settings and never follows a redirect.
    conn = http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=TIMEOUT_S)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read(MAX_BODY + 1)
        status = response.status
    except (OSError, http.client.HTTPException):
        raise ProbeRefused(f"probe: {key} request failed") from None
    finally:
        conn.close()
    if status != 200:
        raise ProbeRefused(f"probe: {key} request was not answered with 200")
    if len(data) > MAX_BODY:
        raise ProbeRefused(f"probe: {key} answer is over 1 MiB")
    try:
        obj = strict_loads(data)
    except SchemaError:
        raise ProbeRefused(f"probe: {key} answer is not JSON") from None
    if not isinstance(obj, dict):
        raise ProbeRefused(f"probe: {key} answer is not an object")
    return obj


def ollama_identity(endpoint: Endpoint, model: str) -> dict:
    """The fields compared with the manifest, in the manifest's key order."""
    version = request(endpoint, "version").get("version")
    if not isinstance(version, str):
        raise ProbeRefused("probe: version missing")
    models = request(endpoint, "tags").get("models")
    if not isinstance(models, list):
        raise ProbeRefused("probe: model list missing")
    named = [m for m in models if isinstance(m, dict) and m.get("name") == model]
    if len(named) != 1:
        raise ProbeRefused("probe: the model is not listed exactly once")
    digest = named[0].get("digest")
    if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
        digest = "sha256:" + digest
    if not isinstance(digest, str) or DIGEST_RE.fullmatch(digest) is None:
        raise ProbeRefused("probe: model digest missing")
    show = request(endpoint, "show", model)
    parameters, template = show.get("parameters"), show.get("template")
    details = show.get("details")
    if not isinstance(parameters, str) or not isinstance(template, str) or not isinstance(details, dict):
        raise ProbeRefused("probe: model details missing")
    out = {"version": version, "model": model, "digest": digest,
           "parameters_sha256": sha256_hex(parameters.encode("utf-8")),
           "template_sha256": sha256_hex(template.encode("utf-8"))}
    for key in DETAIL_KEYS:
        value = details.get(key)
        if not isinstance(value, str):
            raise ProbeRefused("probe: model details missing")
        out[key] = value
    return out
