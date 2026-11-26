from __future__ import annotations

import csv
import io
import json
import os
from typing import Any, Literal

from pydantic import BaseModel

from pwned._parsers import strip_html as strip_html

OutputFormat = Literal["text", "json", "jsonl", "csv", "table", "sarif"]
OUTPUT_FORMATS: tuple[OutputFormat, ...] = ("text", "json", "jsonl", "csv", "table", "sarif")

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
        return [
            _sarif_result(
                "HIBP002",
                "error",
                f"Compromised password for {f.get('name', '')} "
                f"({f.get('username', '')}): "
                f"seen {f.get('pwn_count', 0)} times in breaches.",
            )
            for f in serialized["findings"]
        ]
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
    raise ValueError(f"Unsupported output format: {fmt!r}")


def should_use_color(*, is_tty: bool) -> bool:
    """Return whether ANSI color output should be enabled."""
    if os.environ.get("NO_COLOR"):
        return False
    return is_tty
