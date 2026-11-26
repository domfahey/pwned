from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Prevent local .env, XDG config/cache, and host HIBP_* env vars from bleeding into tests."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    monkeypatch.delenv("HIBP_USER_AGENT", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
