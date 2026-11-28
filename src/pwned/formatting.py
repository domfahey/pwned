from __future__ import annotations

import csv
import html
import io
import json
import os
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel

from pwned._parsers import strip_html as strip_html

OutputFormat = Literal["text", "json", "jsonl", "csv", "table", "sarif", "markdown", "html"]
OUTPUT_FORMATS: tuple[OutputFormat, ...] = (
    "text",
    "json",
    "jsonl",
    "csv",
    "table",
    "sarif",
    "markdown",
    "html",
)

_TABLE_MAX_CELL = 60
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_INFO_URI = "https://github.com/domfahey/pwned"
_SARIF_RULES: list[dict[str, Any]] = [
    {
        "id": "HIBP001",
        "name": "AccountBreachExposure",
        "shortDescription": {"text": "Account found in a data breach, paste, or stealer log."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "HIBP002",
        "name": "CompromisedPassword",
        "shortDescription": {"text": "Password found in the Pwned Passwords corpus."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "HIBP003",
        "name": "DomainAliasBreach",
        "shortDescription": {"text": "Domain email alias exposed in a data breach."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "HIBP004",
        "name": "BreachRecord",
        "shortDescription": {"text": "Known data breach record from Have I Been Pwned."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "HIBP005",
        "name": "ADCredentialHygiene",
        "shortDescription": {
            "text": (
                "Active Directory credential hygiene issue "
                "(empty NTLM hash, legacy LM hash, or username-as-password)."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "HIBP006",
        "name": "BannedWordlistPassword",
        "shortDescription": {
            "text": "Password matches an entry in the custom organizational banned wordlist."
        },
        "defaultConfiguration": {"level": "error"},
    },
]


def serialize(data: Any) -> Any:
    """Convert Pydantic models to JSON-safe dicts recursively, preserving field aliases."""
    if isinstance(data, BaseModel):
        return data.model_dump(by_alias=True, exclude_unset=True, mode="json")
    if isinstance(data, list):
        return [serialize(item) for item in data]
    if isinstance(data, dict):
        return {k: serialize(v) for k, v in data.items()}
    return data


def _collect_keys(items: list[dict[str, Any]]) -> list[str]:
    """Collect unique dict keys in first-seen order."""
    keys: list[str] = []
    seen: set[str] = set()
    for item in items:
        for key in item:
            if key not in seen:
                seen.add(key)
                keys.append(key)
    return keys


def _format_cell(
    key: str,
    value: Any,
    *,
    list_sep: str = ", ",
    none_str: str = "",
) -> str:
    if value is None:
        return none_str
    if isinstance(value, list):
        if any(isinstance(v, (dict, list)) for v in value):
            return json.dumps(value)
        return list_sep.join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value)
    if key == "Description" and isinstance(value, str):
        return strip_html(value)
    return str(value)


def _format_dict_lines(d: dict[str, Any], *, indent: str = "  ") -> list[str]:
    lines: list[str] = []
    for key, value in d.items():
        if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            lines.append(f"{indent}{key}:")
            for idx, item in enumerate(value):
                if idx > 0:
                    lines.append("")
                lines.extend(_format_dict_lines(item, indent=f"{indent}  "))
        elif isinstance(value, dict):
            lines.append(f"{indent}{key}:")
            lines.extend(_format_dict_lines(value, indent=f"{indent}  "))
        else:
            formatted = _format_cell(key, value, list_sep=", ", none_str="None")
            lines.append(f"{indent}{key}: {formatted}")
    return lines


def _format_text(serialized: Any) -> str:
    if isinstance(serialized, list):
        if not serialized:
            return "No results found."
        lines: list[str] = []
        for i, item in enumerate(serialized):
            if isinstance(item, dict):
                if i > 0:
                    lines.append("")
                lines.extend(_format_dict_lines(item))
            else:
                lines.append(str(item))
        return "\n".join(lines)
    if isinstance(serialized, dict):
        if not serialized:
            return "No results found."
        return "\n".join(_format_dict_lines(serialized))
    return str(serialized)


def _format_jsonl(serialized: Any) -> str:
    if isinstance(serialized, list):
        return "\n".join(json.dumps(item) for item in serialized)
    return json.dumps(serialized)


def _is_str_list_mapping(d: dict[str, Any]) -> bool:
    return all(isinstance(v, list) and all(isinstance(x, str) for x in v) for v in d.values())


def _format_csv(serialized: Any) -> str:
    if isinstance(serialized, (list, dict)) and not serialized:
        return ""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    if isinstance(serialized, list):
        if all(isinstance(item, dict) for item in serialized):
            headers = _collect_keys(serialized)
            writer.writerow(headers)
            for row in serialized:
                writer.writerow([_format_cell(k, row.get(k), list_sep="; ") for k in headers])
        else:
            writer.writerow(["value"])
            for item in serialized:
                writer.writerow([_format_cell("value", item, list_sep="; ")])
    elif isinstance(serialized, dict):
        if _is_str_list_mapping(serialized):
            writer.writerow(["key", "values"])
            for key, values in serialized.items():
                writer.writerow([str(key), ", ".join(values)])
        else:
            headers = list(serialized.keys())
            writer.writerow(headers)
            writer.writerow([_format_cell(k, serialized[k], list_sep="; ") for k in headers])
    else:
        writer.writerow(["value"])
        writer.writerow([_format_cell("value", serialized, list_sep="; ")])
    return buf.getvalue().removesuffix("\n")


def _normalize_linebreaks(text: str) -> str:
    return text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def _truncate_cell(text: str, max_len: int = _TABLE_MAX_CELL) -> str:
    normalized = _normalize_linebreaks(text)
    if len(normalized) > max_len:
        return normalized[: max_len - 1] + "…"
    return normalized


def _render_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [max([len(h), *(len(row[i]) for row in rows)]) for i, h in enumerate(headers)]

    def _join(cells: list[str]) -> str:
        return " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells)).rstrip()

    header_line = _join(headers)
    sep_line = " | ".join("-" * w for w in widths)
    data_lines = [_join(row) for row in rows]
    return "\n".join([header_line, sep_line, *data_lines])


def _format_table(serialized: Any) -> str:
    if isinstance(serialized, (list, dict)) and not serialized:
        return "No results found."
    if isinstance(serialized, list):
        if all(isinstance(item, dict) for item in serialized):
            headers = _collect_keys(serialized)
            rows = [
                [_truncate_cell(_format_cell(k, row.get(k))) for k in headers] for row in serialized
            ]
            return _render_table(headers, rows)
        rows = [[_truncate_cell(_format_cell("value", item))] for item in serialized]
        return _render_table(["Value"], rows)
    if isinstance(serialized, dict):
        rows = [
            [str(k), _normalize_linebreaks(_format_cell(str(k), v))] for k, v in serialized.items()
        ]
        return _render_table(["Field", "Value"], rows)
    return _render_table(["Value"], [[_truncate_cell(_format_cell("value", serialized))]])


def _sarif_result(rule_id: str, level: str, text: str) -> dict[str, Any]:
    return {"ruleId": rule_id, "level": level, "message": {"text": text}}


def _sarif_breach_result(
    breach: dict[str, Any],
    *,
    rule_id: str,
    level: str,
    prefix: str,
) -> dict[str, Any]:
    name = breach.get("Name", "")
    domain = breach.get("Domain", "")
    pwn_count = breach.get("PwnCount", 0)
    return _sarif_result(
        rule_id,
        level,
        f"{prefix}{name} (domain: {domain}, pwn count: {pwn_count}).",
    )


def _sarif_dict_results(serialized: dict[str, Any]) -> list[dict[str, Any]]:
    if "findings" in serialized and isinstance(serialized["findings"], list):
        results = [
            _sarif_result(
                "HIBP002",
                "error",
                f"Compromised password for {f.get('name', '')} "
                f"({f.get('username', '')}): "
                f"seen {f.get('pwn_count', 0)} times in breaches.",
            )
            for f in serialized["findings"]
        ]
        results.extend(
            _sarif_result(
                "HIBP005",
                "error",
                f"AD credential hygiene issue ({f.get('issue', '')}) for "
                f"{f.get('name', '')} ({f.get('username', '')}): {f.get('detail', '')}",
            )
            for f in serialized.get("ad_findings") or []
        )
        results.extend(
            _sarif_result(
                "HIBP006",
                "error",
                f"Password matches custom wordlist ({f.get('match_type', '')}) for "
                f"{f.get('name', '')} ({f.get('username', '')}).",
            )
            for f in serialized.get("wordlist_findings") or []
        )
        return results
    if "breaches" in serialized or "pastes" in serialized or "stealer_logs" in serialized:
        results = [
            _sarif_breach_result(
                b,
                rule_id="HIBP001",
                level="error",
                prefix="Account found in breach ",
            )
            for b in serialized.get("breaches") or []
        ]
        results.extend(
            _sarif_result(
                "HIBP001",
                "error",
                f"Account found in paste {p.get('Source', '')} (id: {p.get('Id', '')}).",
            )
            for p in serialized.get("pastes") or []
        )
        results.extend(
            _sarif_result("HIBP001", "error", f"Account found in stealer log for {domain}.")
            for domain in serialized.get("stealer_logs") or []
        )
        return results
    if "Name" in serialized:
        return [
            _sarif_breach_result(
                serialized,
                rule_id="HIBP004",
                level="warning",
                prefix="Breach ",
            )
        ]
    if serialized and _is_str_list_mapping(serialized):
        return [
            _sarif_result(
                "HIBP003",
                "warning",
                f"Domain alias {alias} exposed in breaches: {', '.join(breaches)}.",
            )
            for alias, breaches in serialized.items()
        ]
    return []


def _sarif_list_results(serialized: list[Any]) -> list[dict[str, Any]]:
    if not serialized or not all(isinstance(item, dict) for item in serialized):
        return []
    if all("account" in item and "status" in item for item in serialized):
        return [
            _sarif_result(
                "HIBP001",
                "error",
                f"Account {item['account']} found in breaches: "
                f"{', '.join(item.get('breaches', []))}.",
            )
            for item in serialized
            if item.get("status") == "pwned"
        ]
    if all("index" in item and "status" in item for item in serialized):
        return [
            _sarif_result(
                "HIBP002",
                "error",
                f"Password #{item['index']} seen {item.get('pwn_count', 0)} times in breaches.",
            )
            for item in serialized
            if item.get("status") == "pwned"
        ]
    if all("Name" in item for item in serialized):
        return [
            _sarif_breach_result(
                item,
                rule_id="HIBP004",
                level="warning",
                prefix="Breach ",
            )
            for item in serialized
        ]
    return []


def _format_sarif(serialized: Any) -> str:
    results: list[dict[str, Any]] = []
    if isinstance(serialized, dict):
        results = _sarif_dict_results(serialized)
    elif isinstance(serialized, list):
        results = _sarif_list_results(serialized)

    doc = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pwned",
                        "informationUri": _SARIF_INFO_URI,
                        "rules": _SARIF_RULES,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


@dataclass(frozen=True)
class _Heading:
    level: int
    text: str


@dataclass(frozen=True)
class _Table:
    headers: list[str]
    rows: list[list[str]]


@dataclass(frozen=True)
class _BulletList:
    items: list[str]


@dataclass(frozen=True)
class _Paragraph:
    text: str


_Block = _Heading | _Table | _BulletList | _Paragraph

_DOMAIN_METRICS: tuple[tuple[str, str], ...] = (
    ("domain", "Domain"),
    ("total_exposed_aliases", "Total Exposed Aliases"),
    ("total_exposures", "Total Exposures"),
    ("unique_breaches", "Unique Breaches"),
    ("most_recent_breach_date", "Most Recent Breach Date"),
    ("sensitive_breach_count", "Sensitive Breach Count"),
    ("stealer_log_aliases", "Stealer Log Aliases"),
)

_HTML_CSS = """\
  :root { color-scheme: light dark; }
  body {
    font-family: system-ui, -apple-system, sans-serif;
    line-height: 1.5;
    margin: 0;
    padding: 2rem 1rem;
    background: #ffffff;
    color: #1f2328;
  }
  main { max-width: 64rem; margin: 0 auto; }
  h1, h2 { margin-top: 1.5rem; margin-bottom: 0.75rem; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  th, td {
    border: 1px solid #d0d7de;
    padding: 0.5rem 0.75rem;
    text-align: left;
    vertical-align: top;
  }
  th { background: #f6f8fa; font-weight: 600; }
  footer {
    max-width: 64rem;
    margin: 2rem auto 0;
    padding-top: 1rem;
    border-top: 1px solid #d0d7de;
    font-size: 0.875rem;
    color: #59636e;
  }
  @media (prefers-color-scheme: dark) {
    body { background: #0d1117; color: #e6edf3; }
    th, td { border-color: #30363d; }
    th { background: #161b22; }
    footer { border-top-color: #30363d; color: #8b949e; }
    a { color: #58a6ff; }
  }"""


def _dict_list_table(items: list[dict[str, Any]]) -> _Table:
    headers = _collect_keys(items)
    rows = [[_format_cell(k, row.get(k)) for k in headers] for row in items]
    return _Table(headers=headers, rows=rows)


def _audit_blocks(serialized: dict[str, Any]) -> list[_Block]:
    summary_rows: list[list[str]] = [["Total Entries", str(serialized["total_entries"])]]
    for key, label in (
        ("unique_passwords", "Unique Passwords"),
        ("compromised_entries", "Compromised Entries"),
    ):
        if key in serialized:
            summary_rows.append([label, str(serialized[key])])
    reused_groups = serialized.get("reused_groups")
    if isinstance(reused_groups, list):
        summary_rows.append(["Reused Password Groups", str(len(reused_groups))])
    strength_findings = serialized.get("strength_findings")
    if isinstance(strength_findings, list):
        summary_rows.append(["Weak Passwords", str(len(strength_findings))])
    ad_findings = serialized.get("ad_findings")
    if isinstance(ad_findings, list):
        summary_rows.append(["AD Hygiene Findings", str(len(ad_findings))])
    wordlist_findings = serialized.get("wordlist_findings")
    if isinstance(wordlist_findings, list):
        summary_rows.append(["Custom Wordlist Matches", str(len(wordlist_findings))])

    blocks: list[_Block] = [
        _Heading(2, "Vault Audit Summary"),
        _Table(["Metric", "Value"], summary_rows),
    ]
    findings = serialized.get("findings")
    if isinstance(findings, list) and findings:
        blocks.append(_Heading(3, "Compromised Credentials"))
        blocks.append(
            _Table(
                ["Name", "Username", "Pwn Count"],
                [
                    [
                        str(f.get("name", "")),
                        str(f.get("username", "")),
                        str(f.get("pwn_count", 0)),
                    ]
                    for f in findings
                ],
            )
        )
    if isinstance(reused_groups, list) and reused_groups:
        blocks.append(_Heading(3, "Reused Passwords"))
        blocks.append(
            _Table(
                ["Entries", "Count", "Pwn Count"],
                [
                    [
                        _format_cell("entries", g.get("entries", [])),
                        str(g.get("count", 0)),
                        str(g.get("pwn_count", 0)),
                    ]
                    for g in reused_groups
                ],
            )
        )
    if isinstance(strength_findings, list) and strength_findings:
        blocks.append(_Heading(3, "Weak Passwords"))
        blocks.append(_dict_list_table(strength_findings))
    if isinstance(ad_findings, list) and ad_findings:
        blocks.append(_Heading(3, "AD Hygiene Findings"))
        blocks.append(
            _Table(
                ["Name", "Username", "Issue", "Detail"],
                [
                    [
                        str(f.get("name", "")),
                        str(f.get("username", "")),
                        str(f.get("issue", "")),
                        str(f.get("detail", "")),
                    ]
                    for f in ad_findings
                ],
            )
        )
    if isinstance(wordlist_findings, list) and wordlist_findings:
        blocks.append(_Heading(3, "Custom Wordlist Matches"))
        blocks.append(
            _Table(
                ["Name", "Username", "Match Type"],
                [
                    [
                        str(f.get("name", "")),
                        str(f.get("username", "")),
                        str(f.get("match_type", "")),
                    ]
                    for f in wordlist_findings
                ],
            )
        )
    return blocks


def _domain_report_blocks(serialized: dict[str, Any]) -> list[_Block]:
    overview_rows = [
        [label, _format_cell(key, serialized[key], none_str="N/A")]
        for key, label in _DOMAIN_METRICS
        if key in serialized
    ]
    blocks: list[_Block] = [
        _Heading(2, f"Domain Exposure Report: {serialized['domain']}"),
        _Table(["Metric", "Value"], overview_rows),
    ]
    top_breaches = serialized.get("top_breaches")
    if isinstance(top_breaches, list) and top_breaches:
        blocks.append(_Heading(3, "Top Breaches"))
        blocks.append(_dict_list_table(top_breaches))
    data_classes = serialized.get("data_classes")
    if isinstance(data_classes, list) and data_classes:
        blocks.append(_Heading(3, "Compromised Data Classes"))
        blocks.append(_dict_list_table(data_classes))
    return blocks


def _search_result_blocks(serialized: dict[str, Any]) -> list[_Block]:
    blocks: list[_Block] = [_Heading(2, "Account Search Results")]
    breaches = serialized.get("breaches")
    blocks.append(_Heading(3, "Breaches"))
    if isinstance(breaches, list) and breaches:
        blocks.append(_dict_list_table(breaches))
    else:
        blocks.append(_Paragraph("No breaches found."))

    pastes = serialized.get("pastes")
    blocks.append(_Heading(3, "Pastes"))
    if isinstance(pastes, list) and pastes:
        blocks.append(_dict_list_table(pastes))
    else:
        blocks.append(_Paragraph("No pastes found."))

    stealer_logs = serialized.get("stealer_logs")
    if isinstance(stealer_logs, list):
        blocks.append(_Heading(3, "Stealer Logs"))
        if stealer_logs:
            blocks.append(_BulletList([str(item) for item in stealer_logs]))
        else:
            blocks.append(_Paragraph("No stealer logs found."))
    return blocks


def _monitor_section_title(key: str) -> str:
    if key in ("accounts", "account_results"):
        return "Accounts"
    if key in ("domains", "domain_results"):
        return "Domains"
    return key.replace("_", " ").title()


def _monitor_report_blocks(serialized: dict[str, Any]) -> list[_Block]:
    blocks: list[_Block] = [_Heading(2, "Monitor Report")]
    summary_rows = [
        [str(k), _format_cell(str(k), v, none_str="N/A")]
        for k, v in serialized.items()
        if not isinstance(v, (list, dict))
    ]
    if summary_rows:
        blocks.append(_Table(["Metric", "Value"], summary_rows))

    for key, value in serialized.items():
        if not isinstance(value, list):
            continue
        title = _monitor_section_title(str(key))
        blocks.append(_Heading(3, title))
        if not value:
            blocks.append(_Paragraph(f"No {title.lower()} found."))
        elif all(isinstance(item, dict) for item in value):
            blocks.append(_dict_list_table(value))
        else:
            blocks.append(_BulletList([_format_cell("value", item) for item in value]))
    return blocks


def _build_blocks(serialized: Any) -> list[_Block]:
    if isinstance(serialized, (list, dict)) and not serialized:
        return [_Paragraph("No results found.")]
    if isinstance(serialized, dict):
        if "total_entries" in serialized and "findings" in serialized:
            return _audit_blocks(serialized)
        if "domain" in serialized and "top_breaches" in serialized and "data_classes" in serialized:
            return _domain_report_blocks(serialized)
        if "breaches" in serialized and "pastes" in serialized:
            return _search_result_blocks(serialized)
        if "accounts_checked" in serialized and "domains_checked" in serialized:
            return _monitor_report_blocks(serialized)
        if _is_str_list_mapping(serialized):
            return [
                _Table(
                    ["Key", "Values"],
                    [[str(k), ", ".join(v)] for k, v in serialized.items()],
                )
            ]
        return [
            _Table(
                ["Field", "Value"],
                [[str(k), _format_cell(str(k), v)] for k, v in serialized.items()],
            )
        ]
    if isinstance(serialized, list):
        if all(isinstance(item, dict) for item in serialized):
            return [_dict_list_table(serialized)]
        return [_BulletList([_format_cell("value", item) for item in serialized])]
    return [_Paragraph(str(serialized))]


def _md_escape(text: str) -> str:
    """Escape pipe characters and normalize linebreaks for GitHub-Flavored Markdown."""
    return _normalize_linebreaks(text).replace("|", "\\|")


def _render_md_table(headers: list[str], rows: list[list[str]]) -> str:
    header_line = "| " + " | ".join(_md_escape(h) for h in headers) + " |"
    sep_line = "| " + " | ".join("---" for _ in headers) + " |"
    data_lines = ["| " + " | ".join(_md_escape(cell) for cell in row) + " |" for row in rows]
    return "\n".join([header_line, sep_line, *data_lines])


_MARKDOWN_ATTRIBUTION = (
    "---\n\n*Data sourced from [Have I Been Pwned](https://haveibeenpwned.com/) (CC BY 4.0).*"
)


def _needs_markdown_attribution(serialized: Any) -> bool:
    """Return True for HIBP breach, paste, domain, audit, or monitoring payloads."""
    if isinstance(serialized, dict):
        if not serialized:
            return False
        if (
            ("total_entries" in serialized and "findings" in serialized)
            or ("domain" in serialized and "total_exposed_aliases" in serialized)
            or ("breaches" in serialized and "pastes" in serialized)
            or ("accounts_checked" in serialized and "domains_checked" in serialized)
            or "Name" in serialized
            or ("Source" in serialized and "Id" in serialized)
        ):
            return True
        return _is_str_list_mapping(serialized)
    if isinstance(serialized, list) and serialized:
        return all(
            isinstance(item, dict)
            and (
                "Name" in item
                or ("Source" in item and "Id" in item)
                or ("account" in item and "breaches" in item)
            )
            for item in serialized
        )
    return False


def _format_markdown(serialized: Any) -> str:
    parts: list[str] = []
    for block in _build_blocks(serialized):
        if isinstance(block, _Heading):
            prefix = "#" * block.level
            parts.append(f"{prefix} {_md_escape(block.text)}")
        elif isinstance(block, _Table):
            parts.append(_render_md_table(block.headers, block.rows))
        elif isinstance(block, _BulletList):
            parts.append("\n".join(f"- {_md_escape(item)}" for item in block.items))
        else:
            parts.append(_md_escape(block.text))
    if _needs_markdown_attribution(serialized):
        parts.append(_MARKDOWN_ATTRIBUTION)
    return "\n\n".join(parts)


def _html_escape(text: str) -> str:
    return html.escape(text, quote=True)


def _render_html_table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{_html_escape(h)}</th>" for h in headers)
    body_rows = [
        "<tr>" + "".join(f"<td>{_html_escape(cell)}</td>" for cell in row) + "</tr>" for row in rows
    ]
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"


def _format_html(serialized: Any) -> str:
    title = "pwned Report"
    parts: list[str] = []
    for block in _build_blocks(serialized):
        if isinstance(block, _Heading):
            if block.level == 2:
                title = block.text
                tag = "h1"
            else:
                tag = "h2"
            parts.append(f"<{tag}>{_html_escape(block.text)}</{tag}>")
        elif isinstance(block, _Table):
            parts.append(_render_html_table(block.headers, block.rows))
        elif isinstance(block, _BulletList):
            items_html = "".join(f"<li>{_html_escape(item)}</li>" for item in block.items)
            parts.append(f"<ul>{items_html}</ul>")
        else:
            parts.append(f"<p>{_html_escape(block.text)}</p>")

    body = "\n".join(parts)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_html_escape(title)}</title>\n"
        "<style>\n"
        f"{_HTML_CSS}\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<main>\n"
        f"{body}\n"
        "</main>\n"
        "<footer>\n"
        'Data sourced from <a href="https://haveibeenpwned.com/">Have I Been Pwned</a> '
        "(CC BY 4.0).\n"
        "</footer>\n"
        "</body>\n"
        "</html>"
    )


def format_output(data: Any, *, fmt: OutputFormat = "text") -> str:
    """Format API response data according to the requested output format."""
    serialized = serialize(data)
    if fmt == "text":
        return _format_text(serialized)
    if fmt == "json":
        return json.dumps(serialized, indent=2)
    if fmt == "jsonl":
        return _format_jsonl(serialized)
    if fmt == "csv":
        return _format_csv(serialized)
    if fmt == "table":
        return _format_table(serialized)
    if fmt == "sarif":
        return _format_sarif(serialized)
    if fmt == "markdown":
        return _format_markdown(serialized)
    if fmt == "html":
        return _format_html(serialized)
    raise ValueError(f"Unsupported output format: {fmt!r}")


def should_use_color(*, is_tty: bool) -> bool:
    """Return whether ANSI color output should be enabled."""
    if os.environ.get("NO_COLOR"):
        return False
    return is_tty
