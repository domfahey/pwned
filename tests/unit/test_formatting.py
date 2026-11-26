from __future__ import annotations

import csv
import io
import json
from datetime import date
from typing import Any

import pytest

from pwned.audit import AuditFinding, AuditSummary, ReuseGroup
from pwned.batch import AccountBatchItem, PasswordBatchItem
from pwned.formatting import (
    OUTPUT_FORMATS,
    format_output,
    serialize,
    should_use_color,
    strip_html,
)
from pwned.models import Breach, Paste, SearchResult
from pwned.reporting import BreachExposureSummary, DataClassExposure, DomainReport


class TestConstants:
    def test_output_formats(self) -> None:
        assert OUTPUT_FORMATS == (
            "text",
            "json",
            "jsonl",
            "csv",
            "table",
            "sarif",
            "markdown",
            "html",
        )


class TestStripHtml:
    def test_strips_tags_and_decodes_entities(self) -> None:
        raw = '<em>Encrypted</em> &amp; <a href="https://x.test">details</a> &#39;ok&#39;.'
        assert strip_html(raw) == "Encrypted & details 'ok'."

    def test_empty_tag_returns_empty(self) -> None:
        assert strip_html("<br/>") == ""

    def test_plain_text_unchanged(self) -> None:
        assert strip_html("plain text") == "plain text"

    def test_malformed_marked_section_does_not_raise(self) -> None:
        assert isinstance(strip_html("<![*\x175~:"), str)

    def test_falls_back_on_htmlparser_assertion_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom(self: object, data: str) -> None:
            raise AssertionError("expected name token")

        monkeypatch.setattr("pwned._parsers._HTMLStripper.feed", _boom)
        assert strip_html("<b>Hello</b> &amp; <![*bad") == "Hello & <![*bad"


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


class TestFormatSarif:
    def _assert_valid_sarif_envelope(self, raw: str) -> dict[str, Any]:
        assert "\n" in raw  # indented JSON
        doc = json.loads(raw)
        assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"]) == 1
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "pwned"
        assert driver["informationUri"] == "https://github.com/domfahey/pwned"
        assert isinstance(driver["rules"], list)
        assert {r["id"] for r in driver["rules"]} >= {"HIBP001", "HIBP002", "HIBP003", "HIBP004"}
        assert isinstance(doc["runs"][0]["results"], list)
        return doc  # type: ignore[no-any-return]

    def test_sarif_empty_list_and_dict_and_other(self) -> None:
        for payload in ([], {}, ["a", "b"], 42, {"unrelated": "value"}):
            doc = self._assert_valid_sarif_envelope(format_output(payload, fmt="sarif"))
            assert doc["runs"][0]["results"] == []

    def test_sarif_unrelated_list_of_dicts(self) -> None:
        doc = self._assert_valid_sarif_envelope(format_output([{"foo": "bar"}], fmt="sarif"))
        assert doc["runs"][0]["results"] == []

    def test_sarif_audit_summary(self) -> None:
        summary = AuditSummary(
            total_entries=5,
            unique_passwords=4,
            compromised_entries=2,
            findings=[
                AuditFinding(name="GitHub", username="alice", pwn_count=42),
                AuditFinding(name="Email", username="bob", pwn_count=7),
            ],
        )
        raw = format_output(summary, fmt="sarif")
        doc = self._assert_valid_sarif_envelope(raw)
        results = doc["runs"][0]["results"]
        assert len(results) == 2
        assert results[0]["ruleId"] == "HIBP002"
        assert results[0]["level"] == "error"
        assert "GitHub" in results[0]["message"]["text"]
        assert "alice" in results[0]["message"]["text"]
        assert "42" in results[0]["message"]["text"]
        assert results[1]["ruleId"] == "HIBP002"
        assert "Email" in results[1]["message"]["text"]

    def test_sarif_audit_summary_empty_findings(self) -> None:
        summary = AuditSummary(
            total_entries=3,
            unique_passwords=3,
            compromised_entries=0,
            findings=[],
        )
        doc = self._assert_valid_sarif_envelope(format_output(summary, fmt="sarif"))
        assert doc["runs"][0]["results"] == []

    def test_sarif_search_result_full(self) -> None:
        sr = SearchResult(
            breaches=[Breach(Name="Adobe", Domain="adobe.com", PwnCount=152445165)],
            pastes=[Paste(Source="Pastebin", Id="abc123")],
            stealer_logs=["evil.example"],
        )
        doc = self._assert_valid_sarif_envelope(format_output(sr, fmt="sarif"))
        results = doc["runs"][0]["results"]
        assert len(results) == 3
        assert all(r["ruleId"] == "HIBP001" for r in results)
        assert all(r["level"] == "error" for r in results)
        assert "Adobe" in results[0]["message"]["text"]
        assert "Pastebin" in results[1]["message"]["text"]
        assert "abc123" in results[1]["message"]["text"]
        assert "evil.example" in results[2]["message"]["text"]

    def test_sarif_search_result_partial_without_pastes(self) -> None:
        sr = SearchResult(breaches=[Breach(Name="Adobe", Domain="adobe.com", PwnCount=10)])
        doc = self._assert_valid_sarif_envelope(format_output(sr, fmt="sarif"))
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "HIBP001"
        assert "Adobe" in results[0]["message"]["text"]

    def test_sarif_account_batch_items(self) -> None:
        items = [
            AccountBatchItem(account="a@example.com", breaches=["Adobe", "Gawker"], status="pwned"),
            AccountBatchItem(account="b@example.com", breaches=[], status="clean"),
            AccountBatchItem(account="c@example.com", breaches=[], status="error", error="boom"),
        ]
        doc = self._assert_valid_sarif_envelope(format_output(items, fmt="sarif"))
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "HIBP001"
        assert results[0]["level"] == "error"
        assert "a@example.com" in results[0]["message"]["text"]
        assert "Adobe" in results[0]["message"]["text"]
        assert "Gawker" in results[0]["message"]["text"]

    def test_sarif_password_batch_items(self) -> None:
        items = [
            PasswordBatchItem(index=0, pwn_count=99, status="pwned"),
            PasswordBatchItem(index=1, pwn_count=0, status="clean"),
            PasswordBatchItem(index=2, pwn_count=0, status="error", error="fail"),
        ]
        doc = self._assert_valid_sarif_envelope(format_output(items, fmt="sarif"))
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "HIBP002"
        assert results[0]["level"] == "error"
        assert "#0" in results[0]["message"]["text"]
        assert "99" in results[0]["message"]["text"]

    def test_sarif_list_of_breaches(self) -> None:
        breaches = [
            Breach(Name="Adobe", Domain="adobe.com", PwnCount=152445165),
            Breach(Name="Gawker", Domain="gawker.com", PwnCount=1300000),
        ]
        doc = self._assert_valid_sarif_envelope(format_output(breaches, fmt="sarif"))
        results = doc["runs"][0]["results"]
        assert len(results) == 2
        assert all(r["ruleId"] == "HIBP004" for r in results)
        assert all(r["level"] == "warning" for r in results)
        assert "Adobe" in results[0]["message"]["text"]
        assert "adobe.com" in results[0]["message"]["text"]
        assert "152445165" in results[0]["message"]["text"]
        assert "Gawker" in results[1]["message"]["text"]

    def test_sarif_single_breach(self) -> None:
        breach = Breach(Name="Adobe", Domain="adobe.com", PwnCount=152445165)
        doc = self._assert_valid_sarif_envelope(format_output(breach, fmt="sarif"))
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "HIBP004"
        assert results[0]["level"] == "warning"
        assert "Adobe" in results[0]["message"]["text"]
        assert "adobe.com" in results[0]["message"]["text"]
        assert "152445165" in results[0]["message"]["text"]

    def test_sarif_domain_breaches_mapping(self) -> None:
        data = {"alice": ["Adobe", "LinkedIn"], "bob": ["Gawker"]}
        doc = self._assert_valid_sarif_envelope(format_output(data, fmt="sarif"))
        results = doc["runs"][0]["results"]
        assert len(results) == 2
        assert all(r["ruleId"] == "HIBP003" for r in results)
        assert all(r["level"] == "warning" for r in results)
        assert "alice" in results[0]["message"]["text"]
        assert "Adobe" in results[0]["message"]["text"]
        assert "LinkedIn" in results[0]["message"]["text"]
        assert "bob" in results[1]["message"]["text"]
        assert "Gawker" in results[1]["message"]["text"]


class TestFormatMarkdown:
    def test_markdown_empty(self) -> None:
        assert format_output([], fmt="markdown") == "No results found."
        assert format_output({}, fmt="markdown") == "No results found."

    def test_markdown_escapes_pipes_and_linebreaks_in_table_and_scalar(self) -> None:
        items = [
            {"Col|1": "val|one\r\nline2", "Description": "<b>Hi</b>\nfoo|bar\rline3"},
        ]
        out = format_output(items, fmt="markdown")
        lines = out.splitlines()
        assert lines[0] == "| Col\\|1 | Description |"
        assert lines[1] == "| --- | --- |"
        assert lines[2] == "| val\\|one line2 | Hi foo\\|bar line3 |"

        assert format_output("a|b\nc\r\nd\re", fmt="markdown") == "a\\|b c d e"

    def test_markdown_audit_summary_full(self) -> None:
        summary = AuditSummary(
            total_entries=10,
            unique_passwords=8,
            compromised_entries=2,
            findings=[
                AuditFinding(name="GitHub|Prod", username="alice\nbob", pwn_count=42),
            ],
            reused_groups=[
                ReuseGroup(entries=["GitHub", "GitLab"], count=2, pwn_count=42),
            ],
        )
        payload = serialize(summary)
        payload["strength_findings"] = [
            {"name": "Router", "username": "admin", "score": 1, "reason": "Too short"},
        ]
        out = format_output(payload, fmt="markdown")
        assert "## Vault Audit Summary" in out
        assert "| Total Entries | 10 |" in out
        assert "| Unique Passwords | 8 |" in out
        assert "| Compromised Entries | 2 |" in out
        assert "### Compromised Credentials" in out
        assert "| GitHub\\|Prod | alice bob | 42 |" in out
        assert "### Reused Passwords" in out
        assert "| GitHub, GitLab | 2 | 42 |" in out
        assert "### Weak Passwords" in out
        assert "| Router | admin | 1 | Too short |" in out

    def test_markdown_audit_summary_clean(self) -> None:
        summary = AuditSummary(
            total_entries=5,
            unique_passwords=5,
            compromised_entries=0,
            findings=[],
        )
        out = format_output(summary, fmt="markdown")
        assert "## Vault Audit Summary" in out
        assert "| Total Entries | 5 |" in out
        assert "### Compromised Credentials" not in out
        assert "### Reused Passwords" not in out
        assert "### Weak Passwords" not in out

        minimal_out = format_output({"total_entries": 1, "findings": []}, fmt="markdown")
        assert "## Vault Audit Summary" in minimal_out
        assert "| Total Entries | 1 |" in minimal_out
        assert "Unique Passwords" not in minimal_out

    def test_markdown_domain_report_full(self) -> None:
        report = DomainReport(
            domain="example.com",
            total_exposed_aliases=12,
            total_exposures=20,
            unique_breaches=2,
            most_recent_breach_date=date(2023, 5, 1),
            sensitive_breach_count=1,
            stealer_log_aliases=3,
            top_breaches=[
                BreachExposureSummary(
                    name="Adobe",
                    title="Adobe",
                    breach_date=date(2013, 10, 4),
                    exposed_aliases=10,
                    is_verified=True,
                    is_sensitive=False,
                    is_spam_list=False,
                    data_classes=["Email addresses", "Passwords"],
                ),
            ],
            data_classes=[
                DataClassExposure(
                    data_class="Email addresses",
                    exposed_aliases=12,
                    breach_count=2,
                ),
            ],
        )
        out = format_output(report, fmt="markdown")
        assert "## Domain Exposure Report: example.com" in out
        assert "| Domain | example.com |" in out
        assert "| Total Exposed Aliases | 12 |" in out
        assert "| Most Recent Breach Date | 2023-05-01 |" in out
        assert "| Stealer Log Aliases | 3 |" in out
        assert "### Top Breaches" in out
        assert "| Adobe | Adobe | 2013-10-04 | 10 |" in out
        assert "### Compromised Data Classes" in out
        assert "| Email addresses | 12 | 2 |" in out

    def test_markdown_domain_report_empty_sections(self) -> None:
        report = DomainReport(
            domain="clean.example",
            total_exposed_aliases=0,
            total_exposures=0,
            unique_breaches=0,
            most_recent_breach_date=None,
            sensitive_breach_count=0,
            stealer_log_aliases=None,
            top_breaches=[],
            data_classes=[],
        )
        out = format_output(report, fmt="markdown")
        assert "## Domain Exposure Report: clean.example" in out
        assert "| Most Recent Breach Date | N/A |" in out
        assert "| Stealer Log Aliases | N/A |" in out
        assert "### Top Breaches" not in out
        assert "### Compromised Data Classes" not in out

    def test_markdown_search_result_full(self) -> None:
        sr = SearchResult(
            breaches=[
                Breach(
                    Name="Adobe",
                    Domain="adobe.com",
                    PwnCount=152445165,
                    Description="<b>Encrypted</b> &amp; leaked.",
                ),
            ],
            pastes=[Paste(Source="Pastebin", Id="abc123", EmailCount=42)],
            stealer_logs=["evil.example", "bad|site.example"],
        )
        out = format_output(sr, fmt="markdown")
        assert "## Account Search Results" in out
        assert "### Breaches" in out
        assert "Encrypted & leaked." in out
        assert "### Pastes" in out
        assert "| Pastebin | abc123 | 42 |" in out
        assert "### Stealer Logs" in out
        assert "- evil.example" in out
        assert "- bad\\|site.example" in out

    def test_markdown_search_result_empty_and_no_stealer_logs(self) -> None:
        sr_empty = SearchResult(breaches=[], pastes=[], stealer_logs=[])
        out_empty = format_output(sr_empty, fmt="markdown")
        assert "## Account Search Results" in out_empty
        assert "### Breaches\n\nNo breaches found." in out_empty
        assert "### Pastes\n\nNo pastes found." in out_empty
        assert "### Stealer Logs\n\nNo stealer logs found." in out_empty

        sr_no_stealer = SearchResult(breaches=[], pastes=[])
        out_no_stealer = format_output(sr_no_stealer, fmt="markdown")
        assert "### Stealer Logs" not in out_no_stealer

    def test_markdown_monitor_report(self) -> None:
        payload: dict[str, Any] = {
            "accounts_checked": 3,
            "domains_checked": 2,
            "new_exposures": 1,
            "accounts": [
                {"account": "a@example.com", "status": "pwned", "breaches": ["Adobe"]},
            ],
            "domains": [
                {"domain": "example.com", "exposed_aliases": 5},
            ],
            "alerts": ["New breach detected|today"],
            "empty_items": [],
        }
        out = format_output(payload, fmt="markdown")
        assert "## Monitor Report" in out
        assert "| accounts_checked | 3 |" in out
        assert "| domains_checked | 2 |" in out
        assert "### Accounts" in out
        assert "| a@example.com | pwned | Adobe |" in out
        assert "### Domains" in out
        assert "| example.com | 5 |" in out
        assert "### Alerts" in out
        assert "- New breach detected\\|today" in out
        assert "### Empty Items\n\nNo empty items found." in out

    def test_markdown_monitor_report_variant_keys_and_no_scalars(self) -> None:
        payload = {
            "accounts_checked": [],
            "domains_checked": [],
            "account_results": [{"account": "b@example.com", "status": "clean"}],
            "domain_results": [{"domain": "org.example", "exposed_aliases": 0}],
        }
        out = format_output(payload, fmt="markdown")
        assert "## Monitor Report" in out
        assert "### Accounts" in out
        assert "| b@example.com | clean |" in out
        assert "### Domains" in out
        assert "| org.example | 0 |" in out

    def test_markdown_generic_shapes(self) -> None:
        # List of scalars
        assert format_output(["Email|addresses", "Pass\nwords"], fmt="markdown") == (
            "- Email\\|addresses\n- Pass words"
        )
        # String-list mapping
        mapping_out = format_output({"alice": ["Adobe", "LinkedIn"], "bob": []}, fmt="markdown")
        assert "| Key | Values |" in mapping_out
        assert "| alice | Adobe, LinkedIn |" in mapping_out
        assert "| bob |  |" in mapping_out
        # Generic dict
        dict_out = format_output({"Name": "Adobe", "Count": 5}, fmt="markdown")
        assert "| Field | Value |" in dict_out
        assert "| Name | Adobe |" in dict_out
        assert "| Count | 5 |" in dict_out


class TestFormatHtml:
    def _assert_html_envelope(self, raw: str) -> None:
        assert raw.startswith("<!DOCTYPE html>")
        assert '<meta charset="utf-8">' in raw
        assert "<style>" in raw
        assert "prefers-color-scheme: dark" in raw
        assert "<main>" in raw
        assert "</main>" in raw
        assert "<footer>" in raw
        assert '<a href="https://haveibeenpwned.com/">Have I Been Pwned</a>' in raw
        assert "CC BY 4.0" in raw

    def test_html_empty(self) -> None:
        empty_payloads: tuple[Any, ...] = ([], {})
        for payload in empty_payloads:
            out = format_output(payload, fmt="html")
            self._assert_html_envelope(out)
            assert "<p>No results found.</p>" in out

    def test_html_xss_strict_escaping_across_all_shapes(self) -> None:
        xss = '<script>alert(1)</script><img src=x onerror="alert(2)">'
        encoded_xss = (
            "&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=&quot;alert(2)&quot;&gt;"
        )

        # 1. Generic list of dicts (including Description raw & entity-encoded script)
        list_out = format_output(
            [
                {
                    "Name": xss,
                    "Description": "<b>Bold</b> &lt;script&gt;alert(1)&lt;/script&gt;",
                }
            ],
            fmt="html",
        )
        self._assert_html_envelope(list_out)
        assert "<script>" not in list_out
        assert "onerror=" not in list_out or "onerror=&quot;" in list_out
        assert encoded_xss in list_out
        assert "Bold &lt;script&gt;alert(1)&lt;/script&gt;" in list_out

        # 2. AuditSummary
        audit_payload = serialize(
            AuditSummary(
                total_entries=2,
                unique_passwords=1,
                compromised_entries=1,
                findings=[AuditFinding(name=xss, username=xss, pwn_count=5)],
                reused_groups=[ReuseGroup(entries=[xss], count=2, pwn_count=5)],
            )
        )
        audit_payload["strength_findings"] = [{"name": xss, "reason": xss}]
        audit_out = format_output(audit_payload, fmt="html")
        self._assert_html_envelope(audit_out)
        assert "<script>" not in audit_out
        assert encoded_xss in audit_out

        # 3. DomainReport
        domain_report = DomainReport(
            domain=f"{xss}.example",
            total_exposed_aliases=1,
            total_exposures=1,
            unique_breaches=1,
            top_breaches=[
                BreachExposureSummary(
                    name=xss,
                    title=xss,
                    exposed_aliases=1,
                    data_classes=[xss],
                )
            ],
            data_classes=[DataClassExposure(data_class=xss, exposed_aliases=1, breach_count=1)],
        )
        domain_out = format_output(domain_report, fmt="html")
        self._assert_html_envelope(domain_out)
        assert "<script>" not in domain_out
        assert encoded_xss in domain_out

        # 4. SearchResult
        sr = SearchResult(
            breaches=[Breach(Name=xss, Description="<em>Info</em> &lt;script&gt;x&lt;/script&gt;")],
            pastes=[Paste(Source=xss, Id=xss)],
            stealer_logs=[xss],
        )
        sr_out = format_output(sr, fmt="html")
        self._assert_html_envelope(sr_out)
        assert "<script>" not in sr_out
        assert encoded_xss in sr_out
        assert "Info &lt;script&gt;x&lt;/script&gt;" in sr_out

        # 5. Scalar, list of scalars, str-list mapping, generic dict
        for payload in (xss, [xss], {xss: [xss]}, {xss: xss}):
            out = format_output(payload, fmt="html")
            self._assert_html_envelope(out)
            assert "<script>" not in out
            assert encoded_xss in out

    def test_html_structured_shapes(self) -> None:
        # AuditSummary
        summary = AuditSummary(
            total_entries=5,
            unique_passwords=4,
            compromised_entries=1,
            findings=[AuditFinding(name="GitHub", username="alice", pwn_count=10)],
        )
        audit_out = format_output(summary, fmt="html")
        self._assert_html_envelope(audit_out)
        assert "<h1>Vault Audit Summary</h1>" in audit_out
        assert "<h2>Compromised Credentials</h2>" in audit_out
        assert "<td>GitHub</td>" in audit_out

        # DomainReport
        report = DomainReport(
            domain="example.com",
            total_exposed_aliases=3,
            total_exposures=4,
            unique_breaches=1,
            top_breaches=[BreachExposureSummary(name="Adobe", title="Adobe", exposed_aliases=3)],
            data_classes=[
                DataClassExposure(data_class="Passwords", exposed_aliases=3, breach_count=1),
            ],
        )
        domain_out = format_output(report, fmt="html")
        self._assert_html_envelope(domain_out)
        assert "<h1>Domain Exposure Report: example.com</h1>" in domain_out
        assert "<h2>Top Breaches</h2>" in domain_out
        assert "<h2>Compromised Data Classes</h2>" in domain_out

        # SearchResult empty
        sr_out = format_output(SearchResult(breaches=[], pastes=[]), fmt="html")
        self._assert_html_envelope(sr_out)
        assert "<h1>Account Search Results</h1>" in sr_out
        assert "<p>No breaches found.</p>" in sr_out
        assert "<p>No pastes found.</p>" in sr_out

        # MonitorReport
        mon_out = format_output(
            {
                "accounts_checked": 2,
                "domains_checked": 1,
                "accounts": [{"account": "a@example.com", "status": "clean"}],
                "domains": [{"domain": "example.com", "exposed_aliases": 0}],
            },
            fmt="html",
        )
        self._assert_html_envelope(mon_out)
        assert "<h1>Monitor Report</h1>" in mon_out
        assert "<h2>Accounts</h2>" in mon_out
        assert "<h2>Domains</h2>" in mon_out

    def test_html_generic_shapes(self) -> None:
        list_out = format_output(["Email addresses", "Passwords"], fmt="html")
        self._assert_html_envelope(list_out)
        assert "<ul><li>Email addresses</li><li>Passwords</li></ul>" in list_out

        map_out = format_output({"alice": ["Adobe"]}, fmt="html")
        self._assert_html_envelope(map_out)
        assert "<th>Key</th><th>Values</th>" in map_out
        assert "<td>alice</td><td>Adobe</td>" in map_out

        dict_out = format_output({"Name": "Adobe"}, fmt="html")
        self._assert_html_envelope(dict_out)
        assert "<th>Field</th><th>Value</th>" in dict_out
        assert "<td>Name</td><td>Adobe</td>" in dict_out

        scalar_out = format_output(42, fmt="html")
        self._assert_html_envelope(scalar_out)
        assert "<p>42</p>" in scalar_out


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
