from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

DEFAULT_TTL_SECONDS = 3600


def get_cache_dir() -> Path:
    """Return the platform cache directory for pwned."""
    xdg_cache_home = os.environ.get("XDG_CACHE_HOME", "")
    if xdg_cache_home:
        return Path(xdg_cache_home) / "pwned"
    return Path.home() / ".cache" / "pwned"


class ResponseCache:
    """Lightweight file-based TTL cache for public HIBP JSON responses."""

    def __init__(
        self,
        cache_dir: Path | None = None,
        *,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        enabled: bool = True,
    ) -> None:
        if ttl_seconds < 0:
            raise ValueError("ttl_seconds must be non-negative")
        self.cache_dir = cache_dir if cache_dir is not None else get_cache_dir()
        self.ttl_seconds = ttl_seconds
        self.enabled = enabled

    def _key_path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def get(self, key: str) -> bytes | None:
        """Return cached UTF-8 payload bytes if present, valid, and unexpired."""
        if not self.enabled:
            return None

        path = self._key_path(key)
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None

        if not isinstance(data, dict):
            return None

        expires_at = data.get("expires_at")
        payload = data.get("payload")
        if (
            isinstance(expires_at, bool)
            or not isinstance(expires_at, (int, float))
            or not isinstance(payload, str)
        ):
            return None

        if time.time() >= expires_at:
            return None

        return payload.encode("utf-8")

    def set(self, key: str, content: bytes) -> None:
        """Store UTF-8 payload bytes atomically with an expiration timestamp."""
        if not self.enabled or self.ttl_seconds == 0:
            return

        target = self._key_path(key)
        wrapper = json.dumps(
            {
                "expires_at": time.time() + self.ttl_seconds,
                "payload": content.decode("utf-8"),
            }
        )
        tmp_path: Path | None = None
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(
                dir=self.cache_dir,
                prefix=".tmp-",
                suffix=".json",
            )
            tmp_path = Path(tmp_name)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(wrapper)
            os.replace(tmp_path, target)
        except OSError:
            if tmp_path is not None:
                with contextlib.suppress(OSError):
                    tmp_path.unlink(missing_ok=True)

    def clear(self) -> int:
        """Delete all cached JSON files in cache_dir and return the number removed."""
        if not self.cache_dir.exists():
            return 0

        removed = 0
        for path in self.cache_dir.glob("*.json"):
            if path.is_file():
                path.unlink()
                removed += 1
        return removed
