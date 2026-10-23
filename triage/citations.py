"""Which evidence a draft may cite, and the check that decides whether it did.

Provenance is decided from what this run actually showed the model, never from
message text: evidence IDs are deterministic, so an attacker can compute one
and plant it in alert text, and an ID that appears only there is not citable.
Existence does not establish relevance: a citable source may still not support
the finding that cites it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import get_args

from .schemas import Alert, AlertField, ModelDraft, ToolResult

ALERT_FIELDS: tuple[str, ...] = get_args(AlertField)

UNCITABLE = "uncitable_evidence_id"
EMPTY_FIELD = "empty_alert_field"


@dataclass(frozen=True)
class Citable:
    """The evidence IDs a draft from this run may cite.

    support: IDs that may back a technique, severity, step or containment
    finding. absence: additional IDs that only a missing_data finding may cite.
    Both are duplicate-free and in evidence-log order, and no ID is in both.
    Ordering always comes from the tuples; membership from the sets.
    """

    support: tuple[str, ...] = ()
    absence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # Fail closed on a malformed set rather than build a schema from it.
        if (len(self.support_set) != len(self.support) or len(self.absence_set) != len(self.absence)
                or self.support_set & self.absence_set):
            raise ValueError("citable IDs must be unique and in only one of support and absence")

    @property
    def support_set(self) -> frozenset[str]:
        return frozenset(self.support)

    @property
    def absence_set(self) -> frozenset[str]:
        return frozenset(self.absence)


def citable_from_views(enrichment_view: dict, tool_renders: list[dict],
                       results: list[ToolResult], allowed_tools: set[str]) -> Citable:
    """The citable IDs of a run, from what it rendered into the prompt.

    Visibility comes only from the rendered objects that were serialized into
    the messages: the enrichment view and each tool message's render_result().
    Identity, tool and status come only from results, the run's evidence log,
    because a rendered dict is a view and its "tool" and "status" keys are not
    trusted for this decision. A result left out by packing is in no view, so
    it is never shown and never citable.
    """
    rendered = list(enrichment_view.get("results", [])) + list(tool_renders)
    shown_with_data = {r["evidence_id"] for r in rendered if "data" in r}
    shown = (shown_with_data
             | {r["evidence_id"] for r in tool_renders}
             | {g["evidence_id"] for g in enrichment_view.get("gaps", []) if g.get("evidence_id") is not None}
             | {eid for res in enrichment_view.get("resolutions", []) for eid in res["evidence_ids"]})
    support: list[str] = []
    absence: list[str] = []
    # results holds each evidence ID once, in call order, so both lists are
    # duplicate-free and in log order. An ID shown but not in results is ignored.
    for r in results:
        if r.tool not in allowed_tools:
            continue  # unknown-tool gateway errors are never citable
        if r.status == "ok" and r.evidence_id in shown_with_data:
            support.append(r.evidence_id)
        elif r.status != "ok" and r.evidence_id in shown:
            absence.append(r.evidence_id)
        # An ok result shown only as data_omitted backs nothing: the model never saw its data.
    return Citable(support=tuple(support), absence=tuple(absence))


def _is_empty(value: object) -> bool:
    return value is None or value == "" or value == [] or value == {}


def check_citations(draft: ModelDraft, citable: Citable, alert: Alert) -> list[str]:
    """Every citation problem in a structurally valid draft, in "path: code" form.

    Problems name only our field names, list indexes and fixed codes, never a
    cited value: a cited value may have been copied from alert text.
    Findings that assert something need evidence the model saw with its data,
    or an alert field that has a value; missing_data may also cite absence.
    """
    findings = [("technique", draft.technique, False), ("severity", draft.severity, False)]
    findings += [(f"next_steps.{i}", f, False) for i, f in enumerate(draft.next_steps)]
    findings += [(f"containment.{i}", f, False) for i, f in enumerate(draft.containment)]
    findings += [(f"missing_data.{i}", f, True) for i, f in enumerate(draft.missing_data)]
    support = citable.support_set
    either = support | citable.absence_set
    problems = []
    for path, finding, may_cite_absence in findings:
        if finding is None:
            continue
        for i, source in enumerate(finding.sources):
            if source in ALERT_FIELDS:
                if not may_cite_absence and _is_empty(getattr(alert, source)):
                    problems.append(f"{path}.sources.{i}: {EMPTY_FIELD}")
            elif source not in (either if may_cite_absence else support):
                problems.append(f"{path}.sources.{i}: {UNCITABLE}")
    return problems


def generator_schema(citable: Citable) -> dict:
    """The draft schema sent with the final and repair requests of one run.

    The generator may only produce eligible sources; check_citations remains
    the authority because a backend may not enforce the schema. Each ID is
    listed once, in the tuples' order, so the schema is deterministic for a
    given run.
    """
    schema = ModelDraft.model_json_schema()  # a new dict on every call
    defs = schema["$defs"]
    defs["SupportSource"] = {"type": "string", "enum": [*ALERT_FIELDS, *citable.support]}
    missing_items: dict = {"$ref": "#/$defs/SupportSource"}
    if citable.absence:
        defs["AbsenceSource"] = {"type": "string", "enum": list(citable.absence)}
        missing_items = {"anyOf": [{"$ref": "#/$defs/SupportSource"}, {"$ref": "#/$defs/AbsenceSource"}]}
    for name, definition in defs.items():
        sources = definition.get("properties", {}).get("sources")
        if sources is not None:
            sources["items"] = missing_items if name == "DraftMissing" else {"$ref": "#/$defs/SupportSource"}
    return schema
