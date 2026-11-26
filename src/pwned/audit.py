from __future__ import annotations

import csv
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pwned.models import NonNegativeInt, _HIBPBase
from pwned.passwords import PwnedPasswordsClient

ExportSource = Literal["bitwarden-json", "bitwarden-csv", "csv", "keepass"]


@dataclass(frozen=True)
class AuditEntry:
    """Internal credential record parsed from a password-manager export."""

    name: str
    username: str
    password: str = field(repr=False)


class AuditFinding(_HIBPBase):
    """Compromised credential finding without any plaintext password."""

    name: str
    username: str
    pwn_count: NonNegativeInt


class AuditSummary(_HIBPBase):
    """Summary of an audited password-manager export."""

    total_entries: NonNegativeInt
    unique_passwords: NonNegativeInt
    compromised_entries: NonNegativeInt
    findings: list[AuditFinding]


def parse_bitwarden_json(path: Path) -> list[AuditEntry]:
    """Parse a Bitwarden JSON export into credential audit entries."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise ValueError("Bitwarden JSON export must be an object with an 'items' list.")

    entries: list[AuditEntry] = []
    for item in data["items"]:
        if not isinstance(item, dict):
            continue
        login = item.get("login")
        if not isinstance(login, dict):
            continue
        password = login.get("password")
        if not isinstance(password, str) or not password:
            continue
        raw_name = item.get("name")
        raw_username = login.get("username")
        entries.append(
            AuditEntry(
                name=raw_name if isinstance(raw_name, str) else "",
                username=raw_username if isinstance(raw_username, str) else "",
                password=password,
            )
        )
    return entries


def parse_bitwarden_csv(path: Path) -> list[AuditEntry]:
    """Parse a Bitwarden CSV export into credential audit entries."""
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        fieldnames = reader.fieldnames or []
        if "login_password" not in fieldnames:
            raise ValueError("Bitwarden CSV export is missing the 'login_password' column.")
        entries: list[AuditEntry] = []
        for row in reader:
            password = row.get("login_password") or ""
            if not password:
                continue
            entries.append(
                AuditEntry(
                    name=row.get("name") or "",
                    username=row.get("login_username") or "",
                    password=password,
                )
            )
    return entries


def _first_non_empty(row: Mapping[str, str | None], header_map: dict[str, str], *keys: str) -> str:
    for key in keys:
        column = header_map.get(key)
        if column is not None:
            value = row.get(column)
            if value:
                return value
    return ""


def parse_generic_csv(path: Path) -> list[AuditEntry]:
    """Parse a generic CSV export with case-insensitive columns into audit entries."""
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        fieldnames = reader.fieldnames or []
        header_map = {col.strip().lower(): col for col in fieldnames}
        password_col = header_map.get("password")
        if password_col is None:
            raise ValueError("CSV export is missing a 'password' column.")
        entries: list[AuditEntry] = []
        for row in reader:
            password = row.get(password_col) or ""
            if not password:
                continue
            entries.append(
                AuditEntry(
                    name=_first_non_empty(row, header_map, "name", "title"),
                    username=_first_non_empty(row, header_map, "username", "email"),
                    password=password,
                )
            )
    return entries


def parse_keepass(path: Path, *, master_password: str) -> list[AuditEntry]:
    """Parse a KeePass (.kdbx) database into credential audit entries."""
    try:
        from pykeepass import PyKeePass  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "KeePass support requires the optional 'keepass' dependency: "
            "uv pip install 'pwned[keepass]'"
        ) from exc

    kp = PyKeePass(str(path), password=master_password)
    entries: list[AuditEntry] = []
    for entry in kp.entries:
        password = entry.password
        if not isinstance(password, str) or not password:
            continue
        entries.append(
            AuditEntry(
                name=entry.title or "",
                username=entry.username or "",
                password=password,
            )
        )
    return entries


def load_export(
    path: Path,
    *,
    source: ExportSource,
    master_password: str | None = None,
) -> list[AuditEntry]:
    """Load credential entries from a supported password-manager export file."""
    if source == "bitwarden-json":
        return parse_bitwarden_json(path)
    if source == "bitwarden-csv":
        return parse_bitwarden_csv(path)
    if source == "csv":
        return parse_generic_csv(path)
    if source == "keepass":
        if master_password is None:
            raise ValueError("master_password is required for KeePass exports.")
        return parse_keepass(path, master_password=master_password)
    raise ValueError(f"Unsupported export source: {source!r}")


def audit_entries(
    entries: Sequence[AuditEntry],
    client: PwnedPasswordsClient,
    *,
    threshold: int = 1,
    ntlm: bool = False,
    pad: bool = True,
) -> AuditSummary:
    """Check unique entry passwords against Pwned Passwords via k-anonymity."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1.")

    counts: dict[str, int] = {}
    for entry in entries:
        if entry.password not in counts:
            counts[entry.password] = client.check_password(
                entry.password,
                ntlm=ntlm,
                pad=pad,
            )

    findings = [
        AuditFinding(
            name=entry.name,
            username=entry.username,
            pwn_count=counts[entry.password],
        )
        for entry in entries
        if counts[entry.password] >= threshold
    ]
    findings.sort(key=lambda finding: (-finding.pwn_count, finding.name))

    return AuditSummary(
        total_entries=len(entries),
        unique_passwords=len(counts),
        compromised_entries=len(findings),
        findings=findings,
    )
