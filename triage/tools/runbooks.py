"""runbook_search: embedding retrieval (RAG) over the Sigma investigation runbooks.

How it works, end to end:
  1. Split each runbook into sections at "## " headings (one chunk per section).
  2. Embed every chunk into a unit-length vector.
  3. Put the vectors in a FAISS IndexFlatIP. Inner product of unit vectors
     is cosine similarity, and "Flat" means exact brute-force search, which
     is the right choice for a few dozen chunks.
  4. At query time, embed the query, take the top-k chunks, and drop any
     below a minimum score. If nothing clears the bar, the tool says
     not_found instead of returning the least-bad irrelevant runbook.

runbook_detail: the "What this means" and "Triage steps" sections of one
runbook, whole, for enrichment only (DD-031). Search ranks a runbook's header
and descriptive sections above its procedure and cuts what it returns, so the
procedure is looked up by heading instead of by similarity.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Protocol

import faiss
import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from ..embedding_model import ModelUnavailable, load_sentence_transformer
from .registry import NotFound

DESCRIPTION = (
    "Search the investigation runbooks for triage steps, known false positives and response "
    "guidance. Query in plain words, e.g. 'encoded powershell parent process'."
)

MAX_CHUNK_CHARS_RETURNED = 800


class RunbookArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=3, max_length=300)
    top_k: int = Field(default=3, ge=1, le=5)


# --- Embedders -----------------------------------------------------------

class Embedder(Protocol):
    name: str
    min_score: float

    def embed(self, texts: list[str]) -> np.ndarray: ...


class HashingEmbedder:
    """Offline stand-in for tests and CI: bag-of-words hashed into a fixed-size vector.

    It only matches shared words, not meaning, so it is not used for real triage.
    """

    name = "hashing-512"
    min_score = 0.15
    dim = 512
    _stop = set("a an and are as at be by for from if in is it of on or that the this to was what when with".split())

    def embed(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), self.dim), dtype="float32")
        for row, text in enumerate(texts):
            for tok in re.findall(r"[a-z0-9]+", text.lower()):
                if tok not in self._stop:
                    idx = int(hashlib.sha1(tok.encode()).hexdigest(), 16) % self.dim
                    out[row, idx] += 1.0
        return _normalize(out)


class MiniLMEmbedder:
    """sentence-transformers all-MiniLM-L6-v2: small (384-dim), CPU-friendly.

    Loaded only from the verified local directory, offline; never downloaded
    here (see triage/embedding_model.py and DD-027).
    """

    name = "all-MiniLM-L6-v2"
    # Starting threshold; calibrate against the eval set before trusting it.
    min_score = 0.30

    def __init__(self, model_dir: Path) -> None:
        self._model = load_sentence_transformer(model_dir)

    def embed(self, texts: list[str]) -> np.ndarray:
        vecs = self._model.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
        return vecs.astype("float32")


def _normalize(m: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(m, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return m / norms


def get_embedder(name: str, model_dir: Path | None = None) -> Embedder:
    if name == "hashing":
        return HashingEmbedder()
    if name == "minilm":
        if model_dir is None:
            raise ModelUnavailable()
        return MiniLMEmbedder(model_dir)
    raise ValueError(f"unknown embedder '{name}' (expected 'minilm' or 'hashing')")


# --- Chunking and index --------------------------------------------------

@dataclass(frozen=True)
class Chunk:
    runbook: str   # file name, e.g. suspicious_encoded_powershell.md
    title: str     # the runbook's "# " heading
    section: str   # the "## " heading this chunk came from
    text: str


def chunk_runbook(path: Path) -> list[Chunk]:
    return _chunk_text(path.name, path.stem, path.read_text(encoding="utf-8"))


def _chunk_text(name: str, stem: str, raw: str) -> list[Chunk]:
    title_match = re.search(r"^# (.+)$", raw, flags=re.M)
    title = title_match.group(1).strip() if title_match else stem
    parts = re.split(r"^## ", raw, flags=re.M)
    chunks = []
    # parts[0] is the header block (title, rule, severity, ATT&CK); keep it as an "Overview" chunk.
    for i, part in enumerate(parts):
        if not part.strip():
            continue
        if i == 0:
            section, body = "Overview", part
        else:
            section, _, body = part.partition("\n")
        # Prefix the title so a section like "Triage steps" still says which runbook it belongs to.
        text = f"{title}\n## {section.strip()}\n{body.strip()}"
        chunks.append(Chunk(name, title, section.strip(), text))
    return chunks


class RunbookIndex:
    def __init__(self, runbook_dir: Path, embedder: Embedder):
        files = sorted(runbook_dir.glob("*.md"))
        self.chunks = [c for f in files for c in chunk_runbook(f)]
        if not self.chunks:
            raise RuntimeError(f"no runbook chunks found in {runbook_dir}")
        self.embedder = embedder
        vecs = embedder.embed([c.text for c in self.chunks])
        self.index = faiss.IndexFlatIP(vecs.shape[1])
        self.index.add(vecs)

    def search(self, query: str, top_k: int) -> list[tuple[float, Chunk]]:
        q = self.embedder.embed([query])
        scores, ids = self.index.search(q, top_k)
        return [(float(s), self.chunks[i]) for s, i in zip(scores[0], ids[0])
                if i != -1 and s >= self.embedder.min_score]


@lru_cache(maxsize=4)
def get_index(runbook_dir: Path, embedder_name: str, model_dir: Path | None = None) -> RunbookIndex:
    # A failed load raises and is not cached, so a later call verifies again.
    return RunbookIndex(runbook_dir, get_embedder(embedder_name, model_dir))


def make_runbook_search(runbook_dir: Path, embedder_name: str, model_dir: Path | None = None):
    def runbook_search(args: RunbookArgs) -> dict:
        idx = get_index(runbook_dir, embedder_name, model_dir)
        hits = idx.search(args.query, args.top_k)
        if not hits:
            raise NotFound(f"no runbook section scored above {idx.embedder.min_score} for this query")
        return {
            "embedder": idx.embedder.name,
            "hits": [
                {"score": round(score, 3), "runbook": c.runbook, "section": c.section,
                 "text": c.text[:MAX_CHUNK_CHARS_RETURNED]}
                for score, c in hits
            ],
        }

    return runbook_search


# --- runbook_detail --------------------------------------------------------

DETAIL_DESCRIPTION = (
    "The 'What this means' and 'Triage steps' sections of one runbook, by file name. "
    "Used by enrichment; not offered to the model."
)
# Returned in this order. "Triage steps" is the reason the lookup exists, so a
# runbook without it is not_found: an ok without the procedure would record
# success while the procedure is missing.
DETAIL_SECTIONS = ("What this means", "Triage steps")
REQUIRED_SECTION = "Triage steps"
# Far above any vendored runbook (under 5 KB); a bound for a custom directory.
MAX_RUNBOOK_BYTES = 64 * 1024
# Fixed: the gateway reports "{type}: {message}", and an OSError's own message
# holds a local path.
READ_ERROR = "the runbook could not be read"
_ITEM_START = re.compile(r"(\d+\.|[-*]) ")


class RunbookDetailArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # A bare file name, used only as a key into the directory's own listing.
    runbook: str = Field(pattern=r"^[a-z0-9_]{1,64}\.md$")


def section_items(body: str) -> list[str]:
    """Paragraphs and list items, each with its line breaks joined by one space.

    Hard-wrapped lines are joined so each item is one string the view can show
    whole; nothing is dropped or reworded.
    """
    items: list[str] = []
    current: list[str] = []
    for line in body.splitlines():
        text = line.strip()
        if current and (not text or _ITEM_START.match(text)):
            items.append(" ".join(current))
            current = []
        if text:
            current.append(text)
    if current:
        items.append(" ".join(current))
    return items


def _read_runbook(path: Path) -> str:
    """The text of one regular file, opened without following a link.

    A runbook directory can be the operator's own (TRIAGE_RUNBOOK_DIR). Only the
    directory itself is trusted: an entry that is a symlink, FIFO, device or
    directory is refused, so a link named like a runbook cannot bring another
    file's content into the prompt, and a FIFO cannot hang the run. Anything
    unexpected is the same fixed error, which degrades enrichment.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        # lstat as well as O_NOFOLLOW, for platforms that do not have the flag.
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise OSError
        fd = os.open(path, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError
            data = b""
            while len(data) <= MAX_RUNBOOK_BYTES and (chunk := os.read(fd, MAX_RUNBOOK_BYTES + 1 - len(data))):
                data += chunk
        finally:
            os.close(fd)
        if len(data) > MAX_RUNBOOK_BYTES:
            raise OSError
        # The same newline handling as Path.read_text(), which the index uses.
        return data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except (OSError, UnicodeDecodeError):
        raise RuntimeError(READ_ERROR) from None


def _section_body(chunk: Chunk) -> str:
    return chunk.text.removeprefix(f"{chunk.title}\n## {chunk.section}\n")


def make_runbook_detail(runbook_dir: Path):
    def runbook_detail(args: RunbookDetailArgs) -> dict:
        try:
            listing = {p.name: p for p in sorted(runbook_dir.glob("*.md"))}
        except OSError:
            raise RuntimeError(READ_ERROR) from None
        # The path comes from the listing, never from the argument.
        path = listing.get(args.runbook)
        if path is None:
            raise NotFound("no such runbook")
        chunks = _chunk_text(path.name, path.stem, _read_runbook(path))
        by_section: dict[str, Chunk] = {}
        for c in chunks:
            by_section.setdefault(c.section, c)   # a repeated heading: the first one
        sections = []
        for heading in DETAIL_SECTIONS:
            items = section_items(_section_body(by_section[heading])) if heading in by_section else []
            if items:
                sections.append({"section": heading, "items": items})
        if not any(s["section"] == REQUIRED_SECTION for s in sections):
            raise NotFound("the runbook has no triage steps")
        return {"runbook": path.name, "title": chunks[0].title, "sections": sections}

    return runbook_detail
