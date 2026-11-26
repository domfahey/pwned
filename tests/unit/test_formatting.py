from __future__ import annotations

import csv
import io
import json
from typing import Any

import pytest

from pwned.formatting import (
    OUTPUT_FORMATS,
    format_output,
    serialize,
    should_use_color,
    strip_html,
)
from pwned.models import Breach, Paste, SearchResult


class TestConstants:
    def test_output_formats(self) -> None:
        assert OUTPUT_FORMATS == ("text", "json", "jsonl", "csv", "table")


class TestStripHtml:
    def test_strips_tags_and_decodes_entities(self) -> None:
        raw = '<em>Encrypted</em> &amp; <a href="https://x.test">details</a> &#39;ok&#39;.'
        assert strip_html(raw) == "Encrypted & details 'ok'."

    def test_empty_tag_returns_empty(self) -> None:
        assert strip_html("<br/>") == ""

    def test_plain_text_unchanged(self) -> None:
        assert strip_html("plain text") == "plain text"


class TestSerialize:
    def test_single_model_uses_aliases_and_excludes_unset(self) -> None:
        breach = Breach(Name="Adobe", Title="Adobe")
        assert serialize(breach) == {"Name": "Adobe", "Title": "Adobe"}

    def test_list_of_models(self) -> None:
        items = [Breach(Name="Adobe"), Breach(Name="Gawker")]
        assert serialize(items) == [{"Name": "Adobe"}, {"Name": "Gawker"}]

    def test_nested_search_result_model(self) -> None:
        sr = SearchResult(
            breaches=[Breach(Name="Adobe", PwnCount=10)],
            pastes=[Paste(Source="Pastebin", Id="abc123")],
            stealer_logs=["example.com"],
        )
        assert serialize(sr) == {
            "breaches": [{"Name": "Adobe", "PwnCount": 10}],
            "pastes": [{"Source": "Pastebin", "Id": "abc123"}],
            "stealer_logs": ["example.com"],
        }

    def test_dict_with_nested_models(self) -> None:
        payload: dict[str, Any] = {
            "breaches": [Breach(Name="Adobe")],
            "paste": Paste(Source="Pastebin", Id="1"),
            "plain": "ok",
        }
        assert serialize(payload) == {
            "breaches": [{"Name": "Adobe"}],
            "paste": {"Source": "Pastebin", "Id": "1"},
            "plain": "ok",
        }

    def test_primitives_unchanged(self) -> None:
        assert serialize("hello") == "hello"
        assert serialize(42) == 42


class TestFormatJson:
    def test_json_dict_preserves_html(self) -> None:
        raw_html = "<b>Bold</b> &amp; raw"
        breach = Breach(Name="Adobe", Description=raw_html)
        out = format_output(breach, fmt="json")
        assert json.loads(out) == {"Name": "Adobe", "Description": raw_html}
        assert "\n" in out  # indented

    def test_json_empty_list_and_dict(self) -> None:
        assert format_output([], fmt="json") == "[]"
        assert format_output({}, fmt="json") == "{}"


class TestFormatJsonl:
    def test_jsonl_list_of_models(self) -> None:
        items = [Breach(Name="Adobe"), Breach(Name="Gawker")]
        out = format_output(items, fmt="jsonl")
        lines = out.splitlines()
        assert len(lines) == 2
        assert [json.loads(line) for line in lines] == [
            {"Name": "Adobe"},
            {"Name": "Gawker"},
        ]

    def test_jsonl_list_of_scalars(self) -> None:
        out = format_output(["a", "b"], fmt="jsonl")
        assert out == '"a"\n"b"'

    def test_jsonl_empty_list(self) -> None:
        assert format_output([], fmt="jsonl") == ""

    def test_jsonl_single_dict_and_empty_dict(self) -> None:
        assert json.loads(format_output({"Name": "Adobe"}, fmt="jsonl")) == {"Name": "Adobe"}
        assert format_output({}, fmt="jsonl") == "{}"

    def test_jsonl_scalar(self) -> None:
        assert format_output(123, fmt="jsonl") == "123"


class TestFormatText:
    def test_default_format_is_text(self) -> None:
        assert format_output({"Name": "Adobe"}) == "  Name: Adobe"

    def test_empty_list_and_dict(self) -> None:
        assert format_output([], fmt="text") == "No results found."
        assert format_output({}, fmt="text") == "No results found."

    def test_single_dict_strips_description_html_and_joins_lists(self) -> None:
        data = {
            "Name": "Adobe",
            "Description": "<em>Encrypted</em> &amp; leaked.",
            "DataClasses": ["Email addresses", "Passwords"],
            "Empty": [],
        }
        out = format_output(data, fmt="text")
        assert out == (
            "  Name: Adobe\n"
            "  Description: Encrypted & leaked.\n"
            "  DataClasses: Email addresses, Passwords\n"
            "  Empty: "
        )

    def test_list_of_dicts_separated_by_blank_line(self) -> None:
        items = [{"Name": "Adobe", "Domain": "adobe.com"}, {"Name": "Gawker"}]
        out = format_output(items, fmt="text")
        assert out == "  Name: Adobe\n  Domain: adobe.com\n\n  Name: Gawker"

    def test_list_of_scalars(self) -> None:
        out = format_output(["Email addresses", "Passwords"], fmt="text")
        assert out == "Email addresses\nPasswords"

    def test_nested_search_result_subsections(self) -> None:
        sr = SearchResult(
            breaches=[
                Breach(Name="Adobe", Description="<b>First</b>"),
                Breach(Name="Gawker"),
            ],
            pastes=[Paste(Source="Pastebin", Id="xyz")],
            stealer_logs=["example.com"],
        )
        out = format_output(sr, fmt="text")
        expected = (
            "  breaches:\n"
            "    Name: Adobe\n"
            "    Description: First\n"
            "\n"
            "    Name: Gawker\n"
            "  pastes:\n"
            "    Source: Pastebin\n"
            "    Id: xyz\n"
            "  stealer_logs: example.com"
        )
        assert out == expected

    def test_nested_dict_value(self) -> None:
        data = {"meta": {"count": 2, "Description": "<i>Info</i>"}}
        out = format_output(data, fmt="text")
        assert out == "  meta:\n    count: 2\n    Description: Info"

    def test_scalar(self) -> None:
        assert format_output(42, fmt="text") == "42"


class TestFormatCsv:
    def _parse_csv(self, text: str) -> list[list[str]]:
        return list(csv.reader(io.StringIO(text)))

    def test_csv_empty(self) -> None:
        assert format_output([], fmt="csv") == ""
        assert format_output({}, fmt="csv") == ""

    def test_csv_list_of_dicts_union_keys_and_formatting(self) -> None:
        items = [
            {
                "Name": "Adobe",
                "Description": "<em>Encrypted</em>, bad",
                "DataClasses": ["Email", "Passwords"],
                "PwnCount": 0,
            },
            {
                "Name": "Gawker",
                "Domain": "gawker.com",
                "Attribution": None,
                "IsVerified": False,
            },
        ]
        out = format_output(items, fmt="csv")
        assert "\r\n" not in out
        rows = self._parse_csv(out)
        assert rows[0] == [
            "Name",
            "Description",
            "DataClasses",
            "PwnCount",
            "Domain",
            "Attribution",
            "IsVerified",
        ]
        assert rows[1] == ["Adobe", "Encrypted, bad", "Email; Passwords", "0", "", "", ""]
        assert rows[2] == ["Gawker", "", "", "", "gawker.com", "", "False"]

    def test_csv_list_of_scalars(self) -> None:
        out = format_output(["Email addresses", "Passwords"], fmt="csv")
        assert self._parse_csv(out) == [
            ["value"],
            ["Email addresses"],
            ["Passwords"],
        ]

    def test_csv_dict_of_str_to_list_of_str(self) -> None:
        data = {"alice": ["Adobe", "LinkedIn"], "bob": []}
        out = format_output(data, fmt="csv")
        assert self._parse_csv(out) == [
            ["key", "values"],
            ["alice", "Adobe, LinkedIn"],
            ["bob", ""],
        ]

    def test_csv_single_dict(self) -> None:
        data = {
            "Name": "Adobe",
            "Description": "<b>Test</b>",
            "DataClasses": ["Email", "Passwords"],
            "PwnCount": 152445165,
            "Attribution": None,
        }
        out = format_output(data, fmt="csv")
        assert self._parse_csv(out) == [
            ["Name", "Description", "DataClasses", "PwnCount", "Attribution"],
            ["Adobe", "Test", "Email; Passwords", "152445165", ""],
        ]

    def test_csv_single_dict_with_nested_models(self) -> None:
        sr = SearchResult(breaches=[Breach(Name="Adobe")], pastes=[])
        out = format_output(sr, fmt="csv")
        rows = self._parse_csv(out)
        assert rows[0] == ["breaches", "pastes"]
        assert json.loads(rows[1][0]) == [{"Name": "Adobe"}]
        assert rows[1][1] == ""

    def test_csv_scalar(self) -> None:
        out = format_output("ok", fmt="csv")
        assert self._parse_csv(out) == [["value"], ["ok"]]


class TestFormatTable:
    def test_table_empty(self) -> None:
        assert format_output([], fmt="table") == "No results found."
        assert format_output({}, fmt="table") == "No results found."

    def test_table_list_of_dicts_aligns_and_truncates(self) -> None:
        long_desc = "<p>" + ("x" * 70) + "</p>\nline2"
        items = [
            {
                "Name": "Adobe",
                "Description": long_desc,
                "DataClasses": ["Email", "Passwords"],
            },
            {
                "Name": "Gawker",
                "Domain": "gawker.com",
                "Description": "<b>Short</b>",
                "Attribution": None,
            },
        ]
        out = format_output(items, fmt="table")
        lines = out.splitlines()
        assert len(lines) == 4
        assert "Name" in lines[0]
        assert "Description" in lines[0]
        assert "Domain" in lines[0]
        assert set(lines[1].replace(" | ", "").replace("-", "")) == set()
        # Truncated to 60 chars ending in ellipsis
        truncated = ("x" * 59) + "…"
        assert len(truncated) == 60
        assert truncated in lines[2]
        assert "Email, Passwords" in lines[2]
        assert "Short" in lines[3]
        assert "gawker.com" in lines[3]

    def test_table_single_dict(self) -> None:
        data = {
            "Name": "Adobe",
            "Description": "<em>Encrypted</em> &amp; leaked.",
            "DataClasses": ["Email", "Passwords"],
            "Attribution": None,
        }
        out = format_output(data, fmt="table")
        lines = out.splitlines()
        assert lines[0].startswith("Field")
        assert "Value" in lines[0]
        assert lines[1].startswith("-----")
        assert "Name" in lines[2] and "Adobe" in lines[2]
        assert "Description" in lines[3] and "Encrypted & leaked." in lines[3]
        assert "DataClasses" in lines[4] and "Email, Passwords" in lines[4]
        assert "Attribution" in lines[5]

    def test_table_single_dict_nested_dict_and_list_of_dicts(self) -> None:
        sr = SearchResult(breaches=[Breach(Name="Adobe")], stealer_logs=["a.com"])
        out = format_output(sr, fmt="table")
        lines = out.splitlines()
        assert "breaches" in lines[2]
        assert '"Name": "Adobe"' in lines[2]
        assert "stealer_logs" in lines[3]
        assert "a.com" in lines[3]

    def test_table_single_dict_with_nested_dict_value(self) -> None:
        out = format_output({"meta": {"count": 2}}, fmt="table")
        assert '{"count": 2}' in out

    def test_table_list_of_scalars(self) -> None:
        out = format_output(["Email addresses", "Passwords"], fmt="table")
        lines = out.splitlines()
        assert lines == [
            "Value",
            "---------------",
            "Email addresses",
            "Passwords",
        ]

    def test_table_scalar(self) -> None:
        out = format_output(42, fmt="table")
        assert out.splitlines() == ["Value", "-----", "42"]


class TestFormatErrors:
    def test_unsupported_format_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unsupported output format"):
            format_output({"a": 1}, fmt="xml")  # type: ignore[arg-type]


class TestShouldUseColor:
    def test_tty_no_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        assert should_use_color(is_tty=True) is True
        assert should_use_color(is_tty=False) is False

    def test_no_color_empty_string_allows_color(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "")
        assert should_use_color(is_tty=True) is True

    def test_no_color_non_empty_disables_color(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        assert should_use_color(is_tty=True) is False
        assert should_use_color(is_tty=False) is False
