from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from pwned.baseline import (
    diff_account_batch,
    diff_breaches,
    diff_domain_breaches,
    diff_search_result,
    load_baseline,
    save_baseline,
)
from pwned.batch import AccountBatchItem
from pwned.formatting import serialize
from pwned.models import Breach, Paste, SearchResult


def test_save_baseline_creates_parent_dirs_and_writes_serialized_json(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "dir" / "baseline.json"
    breaches = [Breach(Name="Adobe", PwnCount=152445165)]

    result = save_baseline(target, breaches)

    assert result == target
    assert target.is_file()
    loaded = json.loads(target.read_text(encoding="utf-8"))
    assert loaded == serialize(breaches)
    assert loaded == [{"Name": "Adobe", "PwnCount": 152445165}]


def test_save_baseline_overwrites_atomically_without_leftover_tmp_files(tmp_path: Path) -> None:
    target = tmp_path / "baseline.json"
    save_baseline(target, [{"Name": "Adobe"}])
    save_baseline(target, [{"Name": "LinkedIn"}])

    assert json.loads(target.read_text(encoding="utf-8")) == [{"Name": "LinkedIn"}]
    assert [p.name for p in tmp_path.iterdir()] == ["baseline.json"]


def test_save_baseline_cleans_up_temp_file_on_replace_oserror(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "sub" / "baseline.json"

    def fail_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(OSError, match="disk full"):
        save_baseline(target, {"Name": "Adobe"})

    assert not target.exists()
    assert list((tmp_path / "sub").iterdir()) == []


def test_load_baseline_reads_json(tmp_path: Path) -> None:
    target = tmp_path / "baseline.json"
    payload = [{"Name": "Adobe"}]
    target.write_text(json.dumps(payload), encoding="utf-8")

    assert load_baseline(target) == payload


def test_load_baseline_missing_file_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_baseline(tmp_path / "missing.json")


def test_load_baseline_invalid_json_raises_value_error(tmp_path: Path) -> None:
    target = tmp_path / "broken.json"
    target.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(ValueError):
        load_baseline(target)


def test_diff_breaches_filters_previously_seen() -> None:
    current = [Breach(Name="Adobe"), Breach(Name="LinkedIn"), Breach(Name="Canva")]
    previous = [{"Name": "Adobe"}]

    diff = diff_breaches(current, previous)

    assert [b.name for b in diff] == ["LinkedIn", "Canva"]


def test_diff_breaches_all_seen_returns_empty() -> None:
    current = [Breach(Name="Adobe")]
    previous = [{"Name": "Adobe"}]

    assert diff_breaches(current, previous) == []


def test_diff_breaches_ignores_malformed_previous_entries() -> None:
    current = [Breach(Name="Adobe"), Breach(Name="LinkedIn")]
    previous: list[Any] = ["invalid", {}, {"Name": 123}, {"Name": "Adobe"}]

    diff = diff_breaches(current, previous)

    assert [b.name for b in diff] == ["LinkedIn"]


@pytest.mark.parametrize("previous", [{}, "bad", 42, None])
def test_diff_breaches_invalid_previous_type_raises_value_error(previous: Any) -> None:
    with pytest.raises(ValueError):
        diff_breaches([Breach(Name="Adobe")], previous)


def test_diff_search_result_filters_breaches_pastes_and_stealer_logs() -> None:
    current = SearchResult(
        breaches=[Breach(Name="Adobe"), Breach(Name="LinkedIn")],
        pastes=[
            Paste(Source="Pastebin", Id="1"),
            Paste(Source="Pastebin", Id="2"),
            Paste(Source="Ghostbin", Id="1"),
        ],
        stealer_logs=["a.com", "b.com"],
    )
    previous = {
        "breaches": [{"Name": "Adobe"}],
        "pastes": [{"Source": "Pastebin", "Id": "1"}],
        "stealer_logs": ["a.com"],
    }

    diff = diff_search_result(current, previous)

    assert [b.name for b in diff.breaches] == ["LinkedIn"]
    assert [(p.source, p.id) for p in diff.pastes] == [("Pastebin", "2"), ("Ghostbin", "1")]
    assert diff.stealer_logs == ["b.com"]


def test_diff_search_result_keeps_stealer_logs_none_when_current_is_none() -> None:
    current = SearchResult(breaches=[Breach(Name="Adobe")], pastes=[], stealer_logs=None)
    previous = {"breaches": [], "pastes": [], "stealer_logs": ["a.com"]}

    diff = diff_search_result(current, previous)

    assert [b.name for b in diff.breaches] == ["Adobe"]
    assert diff.pastes == []
    assert diff.stealer_logs is None


def test_diff_search_result_handles_missing_and_none_fields_in_previous() -> None:
    current = SearchResult(
        breaches=[Breach(Name="Adobe")],
        pastes=[Paste(Source="Pastebin", Id="1")],
        stealer_logs=["a.com"],
    )
    previous: dict[str, Any] = {"stealer_logs": None}

    diff = diff_search_result(current, previous)

    assert [b.name for b in diff.breaches] == ["Adobe"]
    assert [(p.source, p.id) for p in diff.pastes] == [("Pastebin", "1")]
    assert diff.stealer_logs == ["a.com"]


def test_diff_search_result_ignores_malformed_paste_and_stealer_entries() -> None:
    current = SearchResult(
        breaches=[],
        pastes=[Paste(Source="Pastebin", Id="1"), Paste(Source="Pastebin", Id="2")],
        stealer_logs=["a.com", "b.com"],
    )
    previous: dict[str, Any] = {
        "breaches": [],
        "pastes": [
            "bad",
            {"Source": "Pastebin"},
            {"Source": 1, "Id": "2"},
            {"Source": "Pastebin", "Id": "1"},
        ],
        "stealer_logs": [123, "a.com"],
    }

    diff = diff_search_result(current, previous)

    assert [(p.source, p.id) for p in diff.pastes] == [("Pastebin", "2")]
    assert diff.stealer_logs == ["b.com"]


@pytest.mark.parametrize("previous", [[], "bad", 42, None])
def test_diff_search_result_invalid_previous_type_raises_value_error(previous: Any) -> None:
    with pytest.raises(ValueError):
        diff_search_result(SearchResult(), previous)


@pytest.mark.parametrize(
    ("previous", "current"),
    [
        ({"pastes": "not-a-list"}, SearchResult()),
        ({"stealer_logs": "not-a-list"}, SearchResult(stealer_logs=["a.com"])),
    ],
)
def test_diff_search_result_invalid_nested_types_raise_value_error(
    previous: dict[str, Any], current: SearchResult
) -> None:
    with pytest.raises(ValueError):
        diff_search_result(current, previous)


def test_diff_account_batch_filters_breaches_and_updates_status() -> None:
    current = [
        AccountBatchItem(account="a@example.com", breaches=["Adobe", "LinkedIn"], status="pwned"),
        AccountBatchItem(account="b@example.com", breaches=["Adobe"], status="pwned"),
        AccountBatchItem(account="c@example.com", breaches=["Canva"], status="pwned"),
        AccountBatchItem(account="d@example.com", breaches=[], status="clean"),
        AccountBatchItem(account="e@example.com", breaches=[], status="error", error="Timeout"),
    ]
    previous = [
        {"account": "a@example.com", "breaches": ["Adobe"], "status": "pwned"},
        {"account": "b@example.com", "breaches": ["Adobe"], "status": "pwned"},
        {"account": "e@example.com", "breaches": ["Adobe"], "status": "pwned"},
    ]

    diff = diff_account_batch(current, previous)

    assert diff == [
        AccountBatchItem(account="a@example.com", breaches=["LinkedIn"], status="pwned"),
        AccountBatchItem(account="b@example.com", breaches=[], status="clean"),
        AccountBatchItem(account="c@example.com", breaches=["Canva"], status="pwned"),
        AccountBatchItem(account="d@example.com", breaches=[], status="clean"),
        AccountBatchItem(account="e@example.com", breaches=[], status="error", error="Timeout"),
    ]


def test_diff_account_batch_ignores_malformed_previous_entries() -> None:
    current = [
        AccountBatchItem(account="a@example.com", breaches=["Adobe", "LinkedIn"], status="pwned"),
    ]
    previous: list[Any] = [
        "bad",
        {"breaches": ["LinkedIn"]},
        {"account": "a@example.com", "breaches": "not-a-list"},
        {"account": "a@example.com", "breaches": [123, "Adobe"]},
    ]

    diff = diff_account_batch(current, previous)

    assert diff == [
        AccountBatchItem(account="a@example.com", breaches=["LinkedIn"], status="pwned"),
    ]


@pytest.mark.parametrize("previous", [{}, "bad", 42, None])
def test_diff_account_batch_invalid_previous_type_raises_value_error(previous: Any) -> None:
    with pytest.raises(ValueError):
        diff_account_batch([], previous)


def test_diff_domain_breaches_filters_seen_and_omits_unchanged_aliases() -> None:
    current = {
        "admin": ["Adobe", "LinkedIn"],
        "info": ["Adobe"],
        "security": ["Canva"],
        "hostmaster": [],
    }
    previous = {
        "admin": ["Adobe"],
        "info": ["Adobe"],
    }

    diff = diff_domain_breaches(current, previous)

    assert diff == {
        "admin": ["LinkedIn"],
        "security": ["Canva"],
    }


def test_diff_domain_breaches_ignores_non_str_entries_in_previous() -> None:
    current = {"admin": ["Adobe", "LinkedIn"]}
    previous: dict[str, Any] = {"admin": [123, "Adobe"]}

    assert diff_domain_breaches(current, previous) == {"admin": ["LinkedIn"]}


@pytest.mark.parametrize("previous", [[], "bad", 42, None])
def test_diff_domain_breaches_invalid_previous_type_raises_value_error(previous: Any) -> None:
    with pytest.raises(ValueError):
        diff_domain_breaches({"admin": ["Adobe"]}, previous)


def test_diff_domain_breaches_invalid_alias_value_raises_value_error() -> None:
    with pytest.raises(ValueError):
        diff_domain_breaches({"admin": ["Adobe"]}, {"admin": "not-a-list"})
