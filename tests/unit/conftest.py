from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Prevent local .env files and host HIBP_* env vars from bleeding into unit tests."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    monkeypatch.delenv("HIBP_USER_AGENT", raising=False)
