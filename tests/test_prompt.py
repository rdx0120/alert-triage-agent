"""Prompt views and the context budget: what the model is sent, and that it always fits."""

import json
import sys
import typing

from pydantic_core.core_schema import ErrorType

from pydantic import ValidationError

from triage import agent, prompt
from triage.agent import Limits, run_agent, sanitized_problems
from triage.backends import ChatReply, ChatRequest, ToolCall, serialize_request
from triage.citations import EMPTY_FIELD, UNCITABLE, Citable, generator_schema
from triage.enrich import MAX_CVES, MAX_REPLACEMENT_HOPS, MAX_TECHNIQUES
from triage.prompt import (
    ALERT_METADATA_MAX_BYTES, ARGUMENT_STRING_MAX_BYTES, ASSISTANT_MESSAGE_MAX_BYTES,
    CONTEXT_TOKENS, ENRICHMENT_VIEW_MAX_BYTES, EVENT_KEY_MAX_BYTES, FINAL_INSTRUCTION,
    HINT_EMPTY_FIELD, HINT_KEEP, HINT_SOURCE_FORM, HINT_SOURCES_REQUIRED, HINT_UNCITABLE,
    INVESTIGATION_INSTRUCTION, INVESTIGATION_MAX_OUTPUT_TOKENS, MAX_OUTPUT_TOKENS, REPAIR_TEMPLATE,
    RESULT_STRING_TIERS, SYSTEM_PROMPT, TEMPLATE_TOKENS_BASE, TEMPLATE_TOKENS_PER_MESSAGE,
    TEMPLATE_TOKENS_PER_TOOL, TOOL_RESULT_MAX_BYTES, TRUNCATION_MARKER, UNTRUSTED_VIEW_MAX_BYTES,
    cap_strings, dumps, fits, initial_messages,
    message_bytes, render_assistant, render_result, token_bound, tool_specs, untrusted_view, wire_len,
)
from triage.schemas import (
    MAX_SOURCES, Alert, DraftContainment, DraftMissing, DraftSeverity, DraftSources, DraftStep,
    DraftTechnique, Enrichment, ModelDraft, ToolResult,
)
from triage.tools import registry

MARKER = "ZQXMARKER7731"
FOUR = "\U0001d538"          # a 4-byte UTF-8 character
MIXED = FOUR + '"\\\x01'     # 4-byte, quote, backslash, control: every kind of escaping


def _alert(**overrides):
    base = {"alert_id": "t-1", "source": "synthetic", "rule_id": "r-1", "rule_title": "Test rule",
            "rule_level": "medium"}
    return Alert(**{**base, **overrides})


def _ok(tool, args, data):
    return ToolResult(evidence_id=registry.evidence_id(tool, args), tool=tool, args=args, status="ok", data=data)


def _request(messages, tools=None, schema=None):
    return ChatRequest(messages=messages, tools=tools, response_schema=schema,
                       max_output_tokens=MAX_OUTPUT_TOKENS, context_tokens=CONTEXT_TOKENS,
                       timeout_s=1.0, alert=_alert(), enrichment=_empty_enrichment())


def _empty_enrichment():
    return Enrichment(alert_id="t-1", status="complete", techniques=[], evidence=[])


# --- cap_strings ---------------------------------------------------------

def test_cap_strings_never_splits_a_character():
    """A cut inside a multi-byte character would produce invalid UTF-8."""
    for n in range(20, 40):
        out = cap_strings(FOUR * 100, n)
        assert out.endswith(TRUNCATION_MARKER)
        assert len(out.encode("utf-8")) <= n
        assert set(out.removesuffix(TRUNCATION_MARKER)) <= {FOUR}
    assert cap_strings("short", 10) == "short"


def test_cap_strings_recurses_into_keys_and_keeps_other_scalars():
    """Dict keys are text the model sees too; numbers and booleans are not changed."""
    value = {"k" * 50: ["v" * 50, 7, None, True]}
    out = cap_strings(value, 20)
    (key, items), = out.items()
    assert len(key.encode()) <= 20 and key.endswith(TRUNCATION_MARKER)
    assert items[0].endswith(TRUNCATION_MARKER) and items[1:] == [7, None, True]
    assert value == {"k" * 50: ["v" * 50, 7, None, True]}  # a new object; input unchanged


def test_lone_surrogates_are_replaced():
    """A lone surrogate cannot be encoded as UTF-8 and would crash serialization."""
    out = cap_strings({"a\ud800": "b\udfff"}, 100)
    assert out == {"a�": "b�"}
    serialize_request(_request([{"role": "user", "content": dumps(out)}]))


# --- Packing -------------------------------------------------------------

def test_pack_keeps_order_counts_omissions_and_never_skips_ahead():
    """Nothing is dropped without a count, and a later small item never jumps a big one."""
    items = [("a", "x"), ("b", "y" * 60), ("c", "z")]
    assert prompt._pack(items, 200) == {"a": "x", "b": "y" * 60, "c": "z"}
    packed = prompt._pack(items, 100)
    assert packed == {"a": "x", "_omitted": 2}  # "c" would fit, but is not taken out of order
    assert wire_len(dumps(packed)) <= 100


def test_host_and_cves_survive_long_tags_and_warnings():
    """Long tag and warning lists are cut before the validated host and CVEs."""
    alert = _alert(rule_id="\x01" * 128, rule_tags=["t" * 200] * 20, ingest_warnings=["w" * 200] * 20,
                   host="CLINIC-FRONT01", cves=["CVE-2021-44228"])
    view = prompt.alert_metadata_view(alert)
    assert view["host"] == "CLINIC-FRONT01" and view["cves"] == ["CVE-2021-44228"]
    assert view["_omitted"] >= 1
    assert wire_len(dumps(view)) <= ALERT_METADATA_MAX_BYTES


def test_event_packing_order_and_count():
    """The untrusted view stops at the first event field that does not fit and says how many are left."""
    big = "\x01" * 400      # 384 bytes after capping, each control character 7 bytes on the wire
    event = {"a": "small", "b": big, "c": big, "d": "small"}
    view = untrusted_view(_alert(event=event))
    assert [k for k, _ in view["event"]] == ["a", "b"]
    assert view["_omitted_event_fields"] == 2
    assert wire_len(dumps(view)) <= UNTRUSTED_VIEW_MAX_BYTES


def test_event_view_keeps_keys_that_truncate_to_the_same_prefix():
    """Two different fields must not merge into one after truncation."""
    k1, k2 = "x" * 100 + "1", "x" * 100 + "2"
    view = untrusted_view(_alert(event={k1: "first", k2: "second"}))
    keys = [k for k, _ in view["event"]]
    assert len(keys) == 2 and keys[0] == keys[1]
    assert len(keys[0].encode()) <= EVENT_KEY_MAX_BYTES
    assert [v for _, v in view["event"]] == ["first", "second"]


# --- render_result -------------------------------------------------------

def _runbook_result(tools, query="T1059.001 PowerShell encoded command", top_k=5):
    result = registry.run_tool(tools, "runbook_search", {"query": query, "top_k": top_k})
    assert result.status == "ok"
    return result


def _max_string(value):
    if isinstance(value, str):
        return len(value.encode())
    if isinstance(value, dict):
        return max([0] + [max(_max_string(k), _max_string(v)) for k, v in value.items()])
    if isinstance(value, list):
        return max([0] + [_max_string(v) for v in value])
    return 0


def test_render_result_uses_first_tier_that_fits(tools):
    """A large result is shortened in tiers rather than cut off mid-document."""
    result = _runbook_result(tools, top_k=2)
    rendered = render_result(result, TOOL_RESULT_MAX_BYTES)
    assert wire_len(dumps(rendered)) <= TOOL_RESULT_MAX_BYTES
    fitting = [t for t in RESULT_STRING_TIERS
               if wire_len(dumps({**rendered, "data": cap_strings(result.data, t)})) <= TOOL_RESULT_MAX_BYTES]
    assert fitting and fitting[0] != RESULT_STRING_TIERS[0]  # the first tier is too large here
    assert rendered["data"] == cap_strings(result.data, fitting[0])
    assert _max_string(rendered["data"]) <= fitting[0]
    roomy = render_result(result, 100_000)
    assert roomy["data"] == cap_strings(result.data, RESULT_STRING_TIERS[0])


def test_render_result_falls_back_to_stub(tools):
    """A result too large for any tier is replaced by a stub that still names its evidence ID."""
    result = _runbook_result(tools)
    stub = render_result(result, 200)
    assert stub == {"evidence_id": result.evidence_id, "tool": "runbook_search", "status": "ok",
                    "data_omitted": True}


def test_render_result_error_is_capped():
    """Error text is bounded like any other string."""
    result = ToolResult(evidence_id="attack_lookup:0123456789abcdef", tool="attack_lookup",
                        args={}, status="error", error="E" * 1000)
    rendered = render_result(result, TOOL_RESULT_MAX_BYTES)
    assert len(rendered["error"].encode()) <= 128 and rendered["error"].endswith(TRUNCATION_MARKER)
    assert "data" not in rendered


def test_worst_non_ok_result_fits_tool_result_cap():
    """A non-ok result has no tier fallback, so its worst case must fit by construction."""
    # The gateway echoes no caller-chosen text, but a tool's own error message
    # can be long; the longest tool name with an error of control characters
    # (the worst case for escaping) is the largest a non-ok result can render.
    worst = ToolResult(evidence_id="a" * 64 + ":0123456789abcdef", tool="a" * 64, args={},
                       status="error", error="\x01" * 4096)
    assert wire_len(dumps(render_result(worst, TOOL_RESULT_MAX_BYTES))) <= TOOL_RESULT_MAX_BYTES


def _head(result):
    return {"evidence_id": result.evidence_id, "tool": result.tool, "status": result.status}


def test_render_result_detail_matches_render_result_at_every_tier(tools):
    """render_result_detail() must render exactly what render_result() does and return the tier it used."""
    result = _runbook_result(tools)
    sizes = [wire_len(dumps({**_head(result), "data": cap_strings(result.data, t)})) for t in RESULT_STRING_TIERS]
    assert sizes == sorted(sizes, reverse=True) and len(set(sizes)) == len(sizes)
    for tier, size in zip(RESULT_STRING_TIERS, sizes):
        rendered, cap = prompt.render_result_detail(result, size)
        assert cap == tier and rendered == render_result(result, size)
        assert rendered["data"] == cap_strings(result.data, tier)
    stub, cap = prompt.render_result_detail(result, sizes[-1] - 1)
    assert cap is None and stub == render_result(result, sizes[-1] - 1) and stub["data_omitted"] is True


def test_render_result_detail_non_ok():
    """A non-ok result must render as before, with the error string cap returned."""
    result = ToolResult(evidence_id="attack_lookup:0123456789abcdef", tool="attack_lookup",
                        args={}, status="error", error="E" * 1000)
    rendered, cap = prompt.render_result_detail(result, TOOL_RESULT_MAX_BYTES)
    assert cap == prompt.ERROR_STRING_MAX_BYTES == 120
    assert rendered == render_result(result, TOOL_RESULT_MAX_BYTES)
    assert prompt.strings_cut(result.error, rendered["error"]) == 1


def test_strings_cut_counts_nested_strings():
    """strings_cut() must count every shortened string in nested dicts and lists, and nothing else."""
    original = {"a": "x" * 10, "b": ["short", "y" * 10, {"c": "z" * 10, "d": 5, "e": None}], "f": ("w" * 10,),
                "g": True}
    assert prompt.strings_cut(original, cap_strings(original, 8)) == 4
    assert prompt.strings_cut(original, cap_strings(original, 512)) == 0
    assert prompt.strings_cut(original, original) == 0
    assert prompt.strings_cut({"k": "ok\ud800"}, cap_strings({"k": "ok\ud800"}, 512)) == 1   # clean() counts
    assert prompt.strings_cut(None, "") == 0


def test_render_result_never_contains_arguments(tools):
    """Arguments may hold alert text the model copied; they are never shown back."""
    result = _runbook_result(tools, query=f"powershell encoded {MARKER}")
    for max_bytes in (TOOL_RESULT_MAX_BYTES, 100_000, 200):
        assert MARKER not in dumps(render_result(result, max_bytes))
    failed = registry.run_tool(tools, "attack_lookup", {"technique_id": MARKER})
    assert MARKER not in dumps(render_result(failed, TOOL_RESULT_MAX_BYTES))


# --- render_assistant ----------------------------------------------------

def test_render_assistant_caps_arguments():
    """Copied alert text in arguments is capped like any other string."""
    msg = render_assistant([ToolCall("runbook_search", {"query": "q" * 1000, "top_k": 5}),
                            ToolCall("attack_lookup", ["not", "a", "dict"])])
    first, second = (c["function"]["arguments"] for c in msg["tool_calls"])
    assert len(first["query"].encode()) <= ARGUMENT_STRING_MAX_BYTES and first["top_k"] == 5
    assert second == {"_raw": "['not', 'a', 'dict']"}
    assert msg["role"] == "assistant" and msg["content"] == ""
    assert message_bytes(msg) <= ASSISTANT_MESSAGE_MAX_BYTES


def test_render_assistant_omits_arguments_when_too_large():
    """Many capped arguments can still exceed the message cap; they are then all omitted."""
    args = {f"k{i}" * 30: MIXED * 40 for i in range(10)}
    calls = [ToolCall("a" * 64, args) for _ in range(3)]
    msg = render_assistant(calls)
    assert all(c["function"]["arguments"] == {"_omitted": True} for c in msg["tool_calls"])
    assert [c["function"]["name"] for c in msg["tool_calls"]] == ["a" * 64] * 3
    assert message_bytes(msg) <= ASSISTANT_MESSAGE_MAX_BYTES


# --- Where untrusted text goes -------------------------------------------

def test_untrusted_text_only_in_its_section(settings, tools):
    """Attacker-influenced text is confined to the section the instructions describe as data."""
    from triage.evidence import EvidenceLog
    from triage.enrich import enrich
    alert = _alert(rule_title=f"title {MARKER}", user=f"user{MARKER}", host="CLINIC-BILL01",
                   rule_tags=["attack.t1059.001"], event={"cmd": f"powershell {MARKER}"})
    enrichment = enrich(alert, EvidenceLog(tools), settings)
    system, user = initial_messages(alert, enrichment)
    assert MARKER not in system["content"]
    document = json.loads(user["content"])
    assert set(document) == {"alert_metadata", "untrusted_alert_data", "enrichment"}
    assert MARKER not in dumps(document["alert_metadata"])
    assert MARKER not in dumps(document["enrichment"])
    untrusted = dumps(document["untrusted_alert_data"])
    assert untrusted.count(MARKER) == 3


# --- Worst-case budget ---------------------------------------------------

def _draft_field_names():
    return set().union(*(m.model_fields for m in (ModelDraft, DraftTechnique, DraftSeverity, DraftStep,
                                                  DraftContainment, DraftMissing, DraftSources)))


# The deepest problem path a draft can produce, such as
# missing_data.0.sources.0.<unknown>: the last element is the union member a
# source failed to match. test_deepest_problem_path checks it against real errors.
REPAIR_PATH_DEPTH = 5


def longest_repair_message():
    """The longest repair message the loop can produce.

    Each path element is one of our field names, "<unknown>" or a list index
    (no larger than sys.maxsize), at most REPAIR_PATH_DEPTH deep. The code is
    the longest Pydantic error type or citation code, and every hint is included.
    """
    element = max([*_draft_field_names(), "<unknown>", str(sys.maxsize)], key=len)
    error_type = max([*typing.get_args(ErrorType), UNCITABLE, EMPTY_FIELD], key=len)
    problem = f"{'.'.join([element] * REPAIR_PATH_DEPTH)}: {error_type}"
    problems = [problem] * 10 + [f"and {sys.maxsize} more"]
    hints = [HINT_SOURCES_REQUIRED, HINT_SOURCE_FORM, HINT_UNCITABLE, HINT_EMPTY_FIELD, HINT_KEEP]
    return REPAIR_TEMPLATE.format(problems="; ".join(problems), hints=" ".join(hints))


def test_deepest_problem_path():
    """The repair-message bound must assume the deepest path a real validation error has."""
    bad_sources = {"sources": [7]}
    draft = {
        "technique": {"technique_id": "T1059", **bad_sources},
        "severity": {"value": "low", "rationale": "r", **bad_sources},
        "next_steps": [{"step": "s", **bad_sources}],
        "containment": [{"action": "a", **bad_sources}],
        "missing_data": [{"kind": "other", "description": "d", **bad_sources}],
    }
    try:
        ModelDraft.model_validate(draft)
    except ValidationError as e:
        problems = [p for p in sanitized_problems(e) if not p.startswith("and ")]
    depths = [len(p.rpartition(": ")[0].split(".")) for p in problems]
    assert max(depths) == REPAIR_PATH_DEPTH
    assert "missing_data.0.sources.0.<unknown>: literal_error" in problems


def max_citable_ids():
    """The most evidence IDs one run can hold, from the loop's and enrichment's limits.

    Enrichment: each technique tag's lookup plus its replacement hops, one
    asset, each CVE and one runbook search. Then one per model tool call.
    """
    enrichment = MAX_TECHNIQUES * (1 + MAX_REPLACEMENT_HOPS) + 1 + MAX_CVES + 1
    return enrichment + Limits().max_tool_calls


def worst_case_schema(tools):
    """The largest generator_schema() a run can send.

    Every ID uses the longest allow-listed tool name (only allow-listed tools
    are citable), and every split between SupportSource and AbsenceSource is
    tried, keeping the largest.
    """
    longest = max(tools, key=len)
    ids = [f"{longest}:{i:016x}" for i in range(max_citable_ids())]
    schemas = [generator_schema(Citable(support=tuple(ids[:k]), absence=tuple(ids[k:])))
               for k in range(len(ids) + 1)]
    return max(schemas, key=lambda s: len(dumps(s).encode()))


def test_worst_case_citable_set(tools):
    """The schema bound is computed for the most citable IDs a run can hold, at the longest ID."""
    assert max_citable_ids() == 33
    assert max(tools, key=len) == "kev_epss_lookup"   # tools is build_tools(settings)
    schema = worst_case_schema(tools)
    enums = [schema["$defs"]["SupportSource"]["enum"], schema["$defs"].get("AbsenceSource", {}).get("enum", [])]
    ids = [v for enum in enums for v in enum if ":" in v]
    assert len(ids) == len(set(ids)) == 33
    assert {len(v) for v in ids} == {len("kev_epss_lookup") + 17}


def worst_case_arithmetic(tools):
    """Upper bounds on the requests of a run at the maximum limits, from fixed sizes and caps.

    Returns (investigation bound, final/repair bound, fixed bytes). Investigation
    requests carry the tool specs, no schema and the investigation instruction;
    the final and repair requests carry the largest generator schema and no tools. Each bound counts every message the
    longest run can hold, so it also covers requests made earlier in the run.
    """
    limits = Limits()
    turns, n_tools = limits.max_investigation_turns, limits.max_tool_calls
    schema = worst_case_schema(tools)
    fixed = {
        "system": message_bytes({"role": "system", "content": SYSTEM_PROMPT}),
        # Read from the module so a test can replace it.
        "investigation": message_bytes({"role": "user", "content": prompt.INVESTIGATION_INSTRUCTION}),
        "final": message_bytes({"role": "user", "content": FINAL_INSTRUCTION}),
        "repair": message_bytes({"role": "user", "content": longest_repair_message()}),
        "schema": len(dumps(schema).encode()),
    }
    user_envelope = message_bytes({"role": "user", "content": dumps(
        {"alert_metadata": None, "untrusted_alert_data": None, "enrichment": None})})
    tool_envelope = message_bytes({"role": "tool", "tool_name": "a" * 64, "content": ""})
    history = (fixed["system"]
               + user_envelope + ALERT_METADATA_MAX_BYTES + UNTRUSTED_VIEW_MAX_BYTES + ENRICHMENT_VIEW_MAX_BYTES
               + n_tools * (tool_envelope + TOOL_RESULT_MAX_BYTES)
               + turns * ASSISTANT_MESSAGE_MAX_BYTES)
    history_messages = 2 + turns + n_tools

    def bound(extra_bytes, n_messages, envelope_request, n_specs):
        return (history + extra_bytes + len(serialize_request(envelope_request))  # envelope incl. schema or specs
                + (n_messages - 1)                                                 # commas between messages
                + TEMPLATE_TOKENS_BASE + TEMPLATE_TOKENS_PER_MESSAGE * n_messages
                + TEMPLATE_TOKENS_PER_TOOL * n_specs)

    investigation = bound(fixed["investigation"], history_messages + 1, _request([], tool_specs(tools), None),
                          len(tools))
    final = bound(fixed["final"] + fixed["repair"], history_messages + 2, _request([], None, schema), 0)
    return investigation, final, sum(fixed.values())


def test_worst_case_budget_arithmetic(tools):
    """Every cap at its maximum still leaves room for the reply, so no input can overflow the context."""
    investigation, final, _ = worst_case_arithmetic(tools)
    assert investigation + INVESTIGATION_MAX_OUTPUT_TOKENS <= CONTEXT_TOKENS
    assert final + MAX_OUTPUT_TOKENS <= CONTEXT_TOKENS


def test_investigation_instruction_does_not_move_final_bound(monkeypatch, tools):
    """Investigation-only text must never reach the final and repair requests' budget."""
    investigation, final, _ = worst_case_arithmetic(tools)
    monkeypatch.setattr(prompt, "INVESTIGATION_INSTRUCTION", "")
    without_investigation, without_final, _ = worst_case_arithmetic(tools)
    assert final == without_final
    assert investigation - without_investigation == wire_len(INVESTIGATION_INSTRUCTION) - wire_len("")


def _largest(tools, tool, key, values, n):
    """The n values whose ok lookup results are largest on the wire."""
    sizes = []
    for v in values:
        r = registry.run_tool(tools, tool, {key: v})
        if r.status == "ok":
            sizes.append((wire_len(dumps(r.data)), v))
    return [v for _, v in sorted(sizes, reverse=True)[:n]]


class _WorstCaseBackend:
    """Uses every investigation turn and tool call, then fails the final call so the repair is made."""

    name = "worst-case"

    def __init__(self):
        self.requests = []
        query = lambda i: chr(0x1F600 + i) + FOUR * 299  # noqa: E731 - distinct 300-character queries
        calls = lambda ids: [ToolCall("runbook_search", {"query": query(i), "top_k": 5}) for i in ids]  # noqa: E731
        bad_ids = {"missing_data": [{"kind": "other", "description": "d", "sources": ["X"] * MAX_SOURCES}] * 10}
        self.replies = [ChatReply(tool_calls=calls(range(4))), ChatReply(tool_calls=calls([4])),
                        ChatReply(tool_calls=calls([5])), ChatReply(tool_calls=calls([6])),
                        ChatReply(text=json.dumps(bad_ids)), ChatReply(text="not json")]

    def chat(self, request):
        self.requests.append(request)
        return self.replies[len(self.requests) - 1]


def worst_case_alert(settings, tools):
    data = settings.data_dir
    techniques = _largest(tools, "attack_lookup", "technique_id",
                          json.loads((data / "attack_techniques.json").read_text())["techniques"], 5)
    host = _largest(tools, "asset_context", "host",
                    [a["host"] for a in json.loads((data / "assets.json").read_text())["assets"]], 1)[0]
    cves = _largest(tools, "kev_epss_lookup", "cve",
                    json.loads((data / "kev_epss_snapshot.json").read_text())["cves"], 5)
    long_text = MIXED * 64
    return Alert(
        alert_id="w" * 128, source="synthetic",
        rule_id=FOUR * 128, rule_title=FOUR * 256, rule_level="critical",
        rule_tags=[f"attack.{t.lower()}" for t in techniques] + [long_text] * 15,
        host=host, user=FOUR * 256, timestamp=FOUR * 64,
        cves=cves + [f"CVE-2099-{i:07d}" for i in range(15)],
        event={chr(0x1F600 + i) + FOUR * 127: MIXED * 1024 for i in range(50)},
        ingest_warnings=[long_text] * 20,
    )


def run_worst_case(settings, tools):
    backend = _WorstCaseBackend()
    result = run_agent(worst_case_alert(settings, tools), backend, settings=settings, tools=tools)
    return result, backend


def test_worst_case_budget_constructed(settings, tools):
    """An alert at every schema maximum, with every turn and tool call used, still fits each request."""
    result, backend = run_worst_case(settings, tools)
    assert result.stop_reason == "invalid_output"
    assert [c.phase for c in result.model_calls] == ["investigate"] * 4 + ["final", "repair"]
    assert len(backend.requests) == 6
    assert result.tool_calls == 6
    assert result.model_calls[0].tool_calls_dropped == 1
    for request in backend.requests:
        assert fits(request)
    # The caps were reached, so the case is the worst one, not a small one.
    _, user = backend.requests[0].messages[:2]
    document = json.loads(user["content"])
    assert "_omitted_event_fields" in document["untrusted_alert_data"]
    assert wire_len(dumps(document["untrusted_alert_data"])) <= UNTRUSTED_VIEW_MAX_BYTES
    assert wire_len(dumps(document["alert_metadata"])) <= ALERT_METADATA_MAX_BYTES
    assert wire_len(dumps(document["enrichment"])) <= ENRICHMENT_VIEW_MAX_BYTES
    repair = backend.requests[-1].messages[-1]["content"]
    # 10 findings x MAX_SOURCES sources x 2 union members, plus 3 missing fields, minus the 10 shown.
    assert "and 373 more" in repair
    assert HINT_SOURCE_FORM in repair and HINT_KEEP in repair


def test_worst_case_constructed_within_arithmetic(settings, tools):
    """The arithmetic must cover what the loop sends, the investigation instruction and reservation included."""
    result, backend = run_worst_case(settings, tools)
    investigation, final, _ = worst_case_arithmetic(tools)
    for record, request in zip(result.model_calls, backend.requests):
        if record.phase == "investigate":
            assert request.messages[-1] == {"role": "user", "content": INVESTIGATION_INSTRUCTION}
            assert request.max_output_tokens == INVESTIGATION_MAX_OUTPUT_TOKENS
            assert token_bound(request) <= investigation
        else:
            assert request.max_output_tokens == MAX_OUTPUT_TOKENS
            assert token_bound(request) <= final


def test_worst_case_final_requests_without_instruction(monkeypatch, settings, tools):
    """The worst-case final and repair requests must be byte-identical with or without the instruction."""
    _, shipped = run_worst_case(settings, tools)
    monkeypatch.setattr(agent, "INVESTIGATION_INSTRUCTION", "")
    _, without = run_worst_case(settings, tools)
    assert len(shipped.requests) == len(without.requests) == 6
    for a, b in zip(shipped.requests[4:], without.requests[4:]):
        assert serialize_request(a) == serialize_request(b)
        assert token_bound(a) == token_bound(b)
