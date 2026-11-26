from __future__ import annotations

from datetime import date

import pytest

from pwned.filtering import BREACH_SORT_KEYS, filter_breaches
from pwned.models import Breach


def _make_breach(
    name: str,
    *,
    breach_date: date | None = None,
    pwn_count: int = 0,
    data_classes: list[str] | None = None,
    is_verified: bool = True,
    is_retired: bool = False,
) -> Breach:
    return Breach(
        Name=name,
        BreachDate=breach_date,
        PwnCount=pwn_count,
        DataClasses=data_classes or [],
        IsVerified=is_verified,
        IsRetired=is_retired,
    )


class TestConstants:
    def test_breach_sort_keys(self) -> None:
        assert BREACH_SORT_KEYS == ("pwn-count", "date", "name")


class TestFilterBreaches:
    def test_empty_input_returns_empty_list(self) -> None:
        assert filter_breaches([]) == []

    def test_no_filters_preserves_order_and_returns_new_list(self) -> None:
        items = (_make_breach("Zeta"), _make_breach("Alpha"))
        result = filter_breaches(items)
        assert [b.name for b in result] == ["Zeta", "Alpha"]
        assert isinstance(result, list)

    def test_since_inclusive_and_excludes_none_dates(self) -> None:
        items = [
            _make_breach("Old", breach_date=date(2019, 12, 31)),
            _make_breach("Exact", breach_date=date(2020, 1, 1)),
            _make_breach("New", breach_date=date(2022, 6, 15)),
            _make_breach("Undated", breach_date=None),
        ]
        result = filter_breaches(items, since="2020-01-01")
        assert [b.name for b in result] == ["Exact", "New"]

    def test_since_invalid_date_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            filter_breaches([], since="not-a-date")

    def test_data_class_case_insensitive_substring(self) -> None:
        items = [
            _make_breach("One", data_classes=["Email addresses", "Passwords"]),
            _make_breach("Two", data_classes=["Usernames", "IP addresses"]),
            _make_breach("Three", data_classes=[]),
        ]
        assert [b.name for b in filter_breaches(items, data_class="passwords")] == ["One"]
        assert [b.name for b in filter_breaches(items, data_class="EMAIL")] == ["One"]
        assert [b.name for b in filter_breaches(items, data_class="addresses")] == ["One", "Two"]

    def test_verified_only(self) -> None:
        items = [
            _make_breach("Verified", is_verified=True),
            _make_breach("Unverified", is_verified=False),
        ]
        assert [b.name for b in filter_breaches(items, verified_only=True)] == ["Verified"]
        assert [b.name for b in filter_breaches(items, verified_only=False)] == [
            "Verified",
            "Unverified",
        ]

    def test_exclude_retired(self) -> None:
        items = [
            _make_breach("Active", is_retired=False),
            _make_breach("Retired", is_retired=True),
        ]
        assert [b.name for b in filter_breaches(items, exclude_retired=True)] == ["Active"]
        assert [b.name for b in filter_breaches(items, exclude_retired=False)] == [
            "Active",
            "Retired",
        ]

    def test_combined_filters(self) -> None:
        items = [
            _make_breach(
                "Match",
                breach_date=date(2021, 5, 1),
                data_classes=["Passwords"],
                is_verified=True,
                is_retired=False,
            ),
            _make_breach(
                "TooOld",
                breach_date=date(2018, 1, 1),
                data_classes=["Passwords"],
                is_verified=True,
                is_retired=False,
            ),
            _make_breach(
                "Unverified",
                breach_date=date(2022, 1, 1),
                data_classes=["Passwords"],
                is_verified=False,
                is_retired=False,
            ),
            _make_breach(
                "Retired",
                breach_date=date(2022, 1, 1),
                data_classes=["Passwords"],
                is_verified=True,
                is_retired=True,
            ),
            _make_breach(
                "WrongClass",
                breach_date=date(2022, 1, 1),
                data_classes=["Usernames"],
                is_verified=True,
                is_retired=False,
            ),
        ]
        result = filter_breaches(
            items,
            since="2020-01-01",
            data_class="pass",
            verified_only=True,
            exclude_retired=True,
        )
        assert [b.name for b in result] == ["Match"]


class TestSortBreaches:
    def test_sort_by_pwn_count_descending_with_name_tiebreak(self) -> None:
        items = [
            _make_breach("beta", pwn_count=100),
            _make_breach("Big", pwn_count=5000),
            _make_breach("Alpha", pwn_count=100),
            _make_breach("Small", pwn_count=10),
        ]
        result = filter_breaches(items, sort_by="pwn-count")
        assert [b.name for b in result] == ["Big", "Alpha", "beta", "Small"]

    def test_sort_by_date_descending_none_last_with_name_tiebreak(self) -> None:
        items = [
            _make_breach("zeta-none", breach_date=None),
            _make_breach("beta-2020", breach_date=date(2020, 5, 1)),
            _make_breach("Newest", breach_date=date(2023, 1, 1)),
            _make_breach("Alpha-2020", breach_date=date(2020, 5, 1)),
            _make_breach("Alpha-none", breach_date=None),
        ]
        result = filter_breaches(items, sort_by="date")
        assert [b.name for b in result] == [
            "Newest",
            "Alpha-2020",
            "beta-2020",
            "Alpha-none",
            "zeta-none",
        ]

    def test_sort_by_name_ascending_case_insensitive(self) -> None:
        items = [
            _make_breach("charlie"),
            _make_breach("Alpha"),
            _make_breach("bravo"),
        ]
        result = filter_breaches(items, sort_by="name")
        assert [b.name for b in result] == ["Alpha", "bravo", "charlie"]

    def test_invalid_sort_by_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unsupported sort key"):
            filter_breaches([], sort_by="invalid")  # type: ignore[arg-type]
