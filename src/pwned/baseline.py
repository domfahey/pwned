from __future__ import annotations

import contextlib
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from pwned.batch import AccountBatchItem
from pwned.formatting import serialize
from pwned.models import Breach, Paste, SearchResult


def save_baseline(path: Path, data: Any) -> Path:
    """Serialize data as JSON and write it atomically to path."""
    payload = json.dumps(serialize(data), indent=2)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        raise
    return path


def load_baseline(path: Path) -> Any:
    """Load and parse a JSON baseline snapshot from path."""
    raw = path.read_text(encoding="utf-8")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid baseline JSON in {path}: {exc}") from exc


def diff_breaches(current: Sequence[Breach], previous: Any) -> list[Breach]:
    """Return breaches in current whose Name was not present in previous."""
    if not isinstance(previous, list):
        raise ValueError("Baseline breaches must be a JSON array.")
    seen = {
        item["Name"]
        for item in previous
        if isinstance(item, dict) and isinstance(item.get("Name"), str)
    }
    return [breach for breach in current if breach.name not in seen]


def _diff_pastes(current: Sequence[Paste], previous: Any) -> list[Paste]:
    if not isinstance(previous, list):
        raise ValueError("Baseline pastes must be a JSON array.")
    seen = {
        (item["Source"], item["Id"])
        for item in previous
        if (
            isinstance(item, dict)
            and isinstance(item.get("Source"), str)
            and isinstance(item.get("Id"), str)
        )
    }
    return [paste for paste in current if (paste.source, paste.id) not in seen]


def diff_search_result(current: SearchResult, previous: Any) -> SearchResult:
    """Return a SearchResult with only breaches, pastes, and stealer logs absent from previous."""
    if not isinstance(previous, dict):
        raise ValueError("Baseline search result must be a JSON object.")

    new_breaches = diff_breaches(current.breaches, previous.get("breaches") or [])
    new_pastes = _diff_pastes(current.pastes, previous.get("pastes") or [])

    new_stealer_logs: list[str] | None
    if current.stealer_logs is None:
        new_stealer_logs = None
    else:
        raw_logs = previous.get("stealer_logs") or []
        if not isinstance(raw_logs, list):
            raise ValueError("Baseline stealer_logs must be a JSON array.")
        seen_logs = {entry for entry in raw_logs if isinstance(entry, str)}
        new_stealer_logs = [log for log in current.stealer_logs if log not in seen_logs]

    return SearchResult(
        breaches=new_breaches,
        pastes=new_pastes,
        stealer_logs=new_stealer_logs,
    )


def diff_account_batch(
    current: Sequence[AccountBatchItem], previous: Any
) -> list[AccountBatchItem]:
    """Filter each account's breaches against previous, preserving error items."""
    if not isinstance(previous, list):
        raise ValueError("Baseline account batch must be a JSON array.")

    prev_map: dict[str, set[str]] = {}
    for entry in previous:
        if isinstance(entry, dict) and isinstance(entry.get("account"), str):
            raw_breaches = entry.get("breaches") or []
            if isinstance(raw_breaches, list):
                prev_map.setdefault(entry["account"], set()).update(
                    b for b in raw_breaches if isinstance(b, str)
                )

    results: list[AccountBatchItem] = []
    for item in current:
        if item.status == "error":
            results.append(item)
            continue
        seen = prev_map.get(item.account, set())
        new_breaches = [b for b in item.breaches if b not in seen]
        results.append(
            AccountBatchItem(
                account=item.account,
                breaches=new_breaches,
                status="pwned" if new_breaches else "clean",
            )
        )
    return results


def diff_domain_breaches(current: Mapping[str, list[str]], previous: Any) -> dict[str, list[str]]:
    """Return {alias: new_breaches} for aliases with breaches absent from previous."""
    if not isinstance(previous, dict):
        raise ValueError("Baseline domain breaches must be a JSON object.")

    result: dict[str, list[str]] = {}
    for alias, breaches in current.items():
        raw_prev = previous.get(alias) or []
        if not isinstance(raw_prev, list):
            raise ValueError(f"Baseline breaches for alias {alias!r} must be a JSON array.")
        seen = {b for b in raw_prev if isinstance(b, str)}
        new_breaches = [b for b in breaches if b not in seen]
        if new_breaches:
            result[alias] = new_breaches
    return result
