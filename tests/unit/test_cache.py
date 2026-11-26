from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from pwned.cache import DEFAULT_TTL_SECONDS, ResponseCache, get_cache_dir


def test_default_ttl_seconds() -> None:
    assert DEFAULT_TTL_SECONDS == 3600


def test_get_cache_dir_uses_xdg_cache_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    xdg_dir = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CACHE_HOME", str(xdg_dir))

    assert get_cache_dir() == xdg_dir / "pwned"


def test_get_cache_dir_falls_back_to_home_when_unset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    assert get_cache_dir() == tmp_path / ".cache" / "pwned"


def test_get_cache_dir_falls_back_to_home_when_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", "")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    assert get_cache_dir() == tmp_path / ".cache" / "pwned"


def test_init_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    cache = ResponseCache()

    assert cache.cache_dir == tmp_path / "pwned"
    assert cache.ttl_seconds == DEFAULT_TTL_SECONDS
    assert cache.enabled is True


def test_init_negative_ttl_raises_value_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="ttl_seconds"):
        ResponseCache(cache_dir=tmp_path, ttl_seconds=-1)


def test_key_path_uses_sha256_hex(tmp_path: Path) -> None:
    cache = ResponseCache(cache_dir=tmp_path)
    key = "https://haveibeenpwned.com/api/v3/breaches"
    expected_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()

    assert cache._key_path(key) == tmp_path / f"{expected_digest}.json"


def test_set_and_get_roundtrip(tmp_path: Path) -> None:
    cache = ResponseCache(cache_dir=tmp_path / "nested", ttl_seconds=60)
    payload = b'[{"Name": "Adobe"}]'

    cache.set("breaches", payload)

    assert cache.get("breaches") == payload
    cached_file = cache._key_path("breaches")
    assert cached_file.is_file()
    raw = json.loads(cached_file.read_text(encoding="utf-8"))
    assert raw["payload"] == payload.decode("utf-8")
    assert isinstance(raw["expires_at"], float)


def test_get_missing_key_returns_none(tmp_path: Path) -> None:
    cache = ResponseCache(cache_dir=tmp_path)
    assert cache.get("missing") is None


def test_get_expired_entry_returns_none(tmp_path: Path) -> None:
    cache = ResponseCache(cache_dir=tmp_path, ttl_seconds=10)
    with patch("pwned.cache.time.time", return_value=1000.0):
        cache.set("breaches", b"[]")

    with patch("pwned.cache.time.time", return_value=1010.0):
        assert cache.get("breaches") is None


def test_get_unexpired_entry_returns_bytes(tmp_path: Path) -> None:
    cache = ResponseCache(cache_dir=tmp_path, ttl_seconds=10)
    with patch("pwned.cache.time.time", return_value=1000.0):
        cache.set("breaches", b'["email"]')

    with patch("pwned.cache.time.time", return_value=1009.9):
        assert cache.get("breaches") == b'["email"]'


def test_disabled_cache_skips_get_and_set(tmp_path: Path) -> None:
    cache_dir = tmp_path / "disabled"
    cache = ResponseCache(cache_dir=cache_dir, enabled=False)

    cache.set("breaches", b"[]")
    assert not cache_dir.exists()
    assert cache.get("breaches") is None


def test_zero_ttl_skips_set(tmp_path: Path) -> None:
    cache_dir = tmp_path / "zero_ttl"
    cache = ResponseCache(cache_dir=cache_dir, ttl_seconds=0)

    cache.set("breaches", b"[]")
    assert not cache_dir.exists()
    assert cache.get("breaches") is None


@pytest.mark.parametrize(
    "raw_content",
    [
        "{not-valid-json",
        "[]",
        json.dumps({"expires_at": "invalid", "payload": "[]"}),
        json.dumps({"expires_at": True, "payload": "[]"}),
        json.dumps({"expires_at": 9999999999.0, "payload": 123}),
        json.dumps({"payload": "[]"}),
    ],
)
def test_get_corrupt_or_malformed_json_returns_none(tmp_path: Path, raw_content: str) -> None:
    cache = ResponseCache(cache_dir=tmp_path)
    path = cache._key_path("corrupt")
    path.write_text(raw_content, encoding="utf-8")

    assert cache.get("corrupt") is None


def test_get_oserror_returns_none(tmp_path: Path) -> None:
    cache = ResponseCache(cache_dir=tmp_path)
    path = cache._key_path("unreadable")
    path.write_text("{}", encoding="utf-8")

    with patch.object(Path, "read_text", side_effect=OSError("permission denied")):
        assert cache.get("unreadable") is None


def test_get_invalid_utf8_returns_none(tmp_path: Path) -> None:
    cache = ResponseCache(cache_dir=tmp_path)
    path = cache._key_path("binary")
    path.write_bytes(b"\xff\xfe")

    assert cache.get("binary") is None


def test_set_writes_atomically_via_os_replace(tmp_path: Path) -> None:
    cache = ResponseCache(cache_dir=tmp_path)
    replace_calls: list[tuple[str | os.PathLike[str], str | os.PathLike[str]]] = []
    real_replace = os.replace

    def spy_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        replace_calls.append((src, dst))
        real_replace(src, dst)

    with patch("pwned.cache.os.replace", side_effect=spy_replace):
        cache.set("atomic", b'{"ok": true}')

    assert len(replace_calls) == 1
    src, dst = replace_calls[0]
    assert Path(src) != Path(dst)
    assert Path(dst) == cache._key_path("atomic")
    assert list(tmp_path.glob("*.tmp*")) == []


def test_set_cleans_up_temp_file_and_swallows_oserror(tmp_path: Path) -> None:
    cache = ResponseCache(cache_dir=tmp_path)

    with patch("pwned.cache.os.replace", side_effect=OSError("disk full")):
        cache.set("fail", b"[]")

    assert not cache._key_path("fail").exists()
    assert list(tmp_path.iterdir()) == []


def test_set_swallows_mkdir_oserror(tmp_path: Path) -> None:
    cache = ResponseCache(cache_dir=tmp_path / "unwritable")

    with patch.object(Path, "mkdir", side_effect=OSError("read-only")):
        cache.set("fail", b"[]")

    assert not cache.cache_dir.exists()


def test_clear_deletes_json_files_and_returns_count(tmp_path: Path) -> None:
    cache = ResponseCache(cache_dir=tmp_path)
    cache.set("one", b"1")
    cache.set("two", b"2")
    non_json = tmp_path / "notes.txt"
    non_json.write_text("keep", encoding="utf-8")
    json_dir = tmp_path / "nested.json"
    json_dir.mkdir()

    deleted = cache.clear()

    assert deleted == 2
    assert cache.get("one") is None
    assert cache.get("two") is None
    assert non_json.exists()
    assert json_dir.is_dir()


def test_clear_missing_directory_returns_zero(tmp_path: Path) -> None:
    cache = ResponseCache(cache_dir=tmp_path / "does-not-exist")
    assert cache.clear() == 0
