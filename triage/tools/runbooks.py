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
"""

from __future__ import annotations

import hashlib
import re
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
    raw = path.read_text(encoding="utf-8")
    title_match = re.search(r"^# (.+)$", raw, flags=re.M)
    title = title_match.group(1).strip() if title_match else path.stem
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
        chunks.append(Chunk(path.name, title, section.strip(), text))
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
