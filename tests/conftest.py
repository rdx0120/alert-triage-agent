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
