#!/bin/bash
# Setup script for the Claude Code cloud environment (paste into the environment's
# "Setup script" field at claude.ai/code). It only pre-installs dependencies so they
# are cached in the environment snapshot; the project itself does not need this file.
#
# Needs these domains on the environment's network allowlist (Custom access, with the
# default package-manager list included): download.pytorch.org,
# download-r2.pytorch.org (download.pytorch.org redirects wheel downloads to it),
# huggingface.co, *.huggingface.co, *.hf.co (only for scripts/fetch_embedding_model.py)
# Every step ends in `|| true` so a slow or failed download never blocks a session.

PIP="python3 -m pip install -q --break-system-packages"

$PIP "pydantic>=2.7" "numpy>=1.26" "faiss-cpu>=1.8" "pytest>=8.0" || true
# CPU-only PyTorch: the default PyPI build pulls several GB of CUDA libraries.
$PIP torch --index-url https://download.pytorch.org/whl/cpu || true
# If CPU torch is missing, pip would pull CUDA torch from PyPI as a sentence-transformers dependency.
if python3 -c "import torch" 2>/dev/null; then
  $PIP "sentence-transformers>=3.0" || true
  # The embedding model is not pre-downloaded here: triage loads only the pinned,
  # verified copy that scripts/fetch_embedding_model.py installs (DD-027).
else
  echo "cloud_setup: CPU-only torch not installed; skipping sentence-transformers so pip does not pull the multi-GB CUDA build from PyPI"
fi
exit 0
