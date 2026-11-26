from __future__ import annotations

from collections.abc import Sequence
from datetime import date
from typing import Literal

from pwned.models import Breach

BreachSortKey = Literal["pwn-count", "date", "name"]
BREACH_SORT_KEYS: tuple[BreachSortKey, ...] = ("pwn-count", "date", "name")


def filter_breaches(
    breaches: Sequence[Breach],
    *,
    since: str | None = None,
    data_class: str | None = None,
    verified_only: bool = False,
    exclude_retired: bool = False,
    sort_by: BreachSortKey | None = None,
) -> list[Breach]:
    """Filter and optionally sort HIBP breach records."""
    since_date = date.fromisoformat(since) if since is not None else None
    if sort_by is not None and sort_by not in BREACH_SORT_KEYS:
        raise ValueError(f"Unsupported sort key: {sort_by!r}")
    needle = data_class.lower() if data_class is not None else None

    result: list[Breach] = []
    for breach in breaches:
        if since_date is not None and (
            breach.breach_date is None or breach.breach_date < since_date
        ):
            continue
        if needle is not None and not any(needle in dc.lower() for dc in breach.data_classes):
            continue
        if verified_only and not breach.is_verified:
            continue
        if exclude_retired and breach.is_retired:
            continue
        result.append(breach)

    if sort_by == "pwn-count":
        result.sort(key=lambda b: (-b.pwn_count, b.name.lower()))
    elif sort_by == "date":
        result.sort(key=lambda b: b.name.lower())
        result.sort(
            key=lambda b: (b.breach_date is not None, b.breach_date or date.min),
            reverse=True,
        )
    elif sort_by == "name":
        result.sort(key=lambda b: b.name.lower())

    return result
