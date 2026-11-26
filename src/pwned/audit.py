from __future__ import annotations

import asyncio
import base64
import binascii
import csv
import json
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import Field

from pwned.models import NonNegativeInt, PasswordChecker, _HIBPBase
from pwned.passwords import AsyncPwnedPasswordsClient

ExportSource = Literal[
    "bitwarden-json",
    "bitwarden-encrypted-json",
    "bitwarden-csv",
    "1password-csv",
    "1password-1pux",
    "chrome-csv",
    "firefox-csv",
    "apple-csv",
    "csv",
    "keepass",
]


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


class ReuseGroup(_HIBPBase):
    """Group of entries sharing the same password without exposing plaintext."""

    entries: list[str]
    count: NonNegativeInt
    pwn_count: NonNegativeInt = 0


class AuditSummary(_HIBPBase):
    """Summary of an audited password-manager export."""

    total_entries: NonNegativeInt
    unique_passwords: NonNegativeInt
    compromised_entries: NonNegativeInt
    findings: list[AuditFinding]
    reused_groups: list[ReuseGroup] = Field(default_factory=list)


def _extract_bitwarden_entries(data: object) -> list[AuditEntry]:
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


def parse_bitwarden_json(path: Path) -> list[AuditEntry]:
    """Parse a Bitwarden JSON export into credential audit entries."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    return _extract_bitwarden_entries(data)


def _decode_bw_cipher_parts(cipher_string: str) -> tuple[bytes, bytes, bytes]:
    if "." not in cipher_string:
        raise ValueError("Malformed Bitwarden cipher string.")
    enc_type, rest = cipher_string.split(".", 1)
    if enc_type != "2":
        raise ValueError(f"Unsupported Bitwarden cipher type: {enc_type!r}.")
    parts = rest.split("|")
    if len(parts) != 3:
        raise ValueError("Malformed Bitwarden cipher string parts.")
    try:
        iv = base64.b64decode(parts[0], validate=True)
        ct = base64.b64decode(parts[1], validate=True)
        mac = base64.b64decode(parts[2], validate=True)
    except binascii.Error as exc:
        raise ValueError("Invalid base64 in Bitwarden cipher string.") from exc
    if not iv or not ct or not mac:
        raise ValueError("Empty component in Bitwarden cipher string.")
    return iv, ct, mac


def parse_bitwarden_encrypted_json(path: Path, *, master_password: str) -> list[AuditEntry]:
    """Parse a password-protected Bitwarden encrypted JSON export."""
    try:
        from cryptography.hazmat.primitives import (  # type: ignore[import-not-found]
            hashes,
            hmac,
        )
        from cryptography.hazmat.primitives.ciphers import (  # type: ignore[import-not-found]
            Cipher,
            algorithms,
            modes,
        )
        from cryptography.hazmat.primitives.kdf.hkdf import (  # type: ignore[import-not-found]
            HKDFExpand,
        )
        from cryptography.hazmat.primitives.kdf.pbkdf2 import (  # type: ignore[import-not-found]
            PBKDF2HMAC,
        )
        from cryptography.hazmat.primitives.padding import (  # type: ignore[import-not-found]
            PKCS7,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Encrypted Bitwarden JSON support requires the optional 'crypto' dependency: "
            "uv pip install 'pwned[crypto]'"
        ) from exc

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError("Bitwarden encrypted JSON export must be a JSON object.")
    if payload.get("encrypted") is not True or payload.get("passwordProtected") is not True:
        raise ValueError("Bitwarden export must be encrypted and password-protected.")

    kdf_type = payload.get("kdfType")
    if isinstance(kdf_type, bool) or kdf_type != 0:
        raise ValueError(
            f"Unsupported Bitwarden KDF type: {kdf_type!r} (only PBKDF2 kdfType=0 is supported)."
        )

    salt = payload.get("salt")
    if not isinstance(salt, str) or not salt:
        raise ValueError("Bitwarden encrypted JSON export is missing a valid 'salt'.")

    kdf_iterations = payload.get("kdfIterations")
    if (
        isinstance(kdf_iterations, bool)
        or not isinstance(kdf_iterations, int)
        or kdf_iterations <= 0
    ):
        raise ValueError("Bitwarden encrypted JSON export is missing a valid 'kdfIterations'.")

    enc_validation = payload.get("encKeyValidation_DO_NOT_EDIT")
    if not isinstance(enc_validation, str) or not enc_validation:
        raise ValueError(
            "Bitwarden encrypted JSON export is missing 'encKeyValidation_DO_NOT_EDIT'."
        )

    encrypted_data = payload.get("data")
    if not isinstance(encrypted_data, str) or not encrypted_data:
        raise ValueError("Bitwarden encrypted JSON export is missing 'data'.")

    master_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode("utf-8"),
        iterations=kdf_iterations,
    ).derive(master_password.encode("utf-8"))
    enc_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc").derive(master_key)
    mac_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac").derive(master_key)

    def _decrypt(cipher_string: str) -> bytes:
        iv, ct, mac = _decode_bw_cipher_parts(cipher_string)
        mac_verifier = hmac.HMAC(mac_key, hashes.SHA256())
        mac_verifier.update(iv + ct)
        try:
            mac_verifier.verify(mac)
            decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
            padded = decryptor.update(ct) + decryptor.finalize()
            unpadder = PKCS7(128).unpadder()
            return bytes(unpadder.update(padded) + unpadder.finalize())
        except Exception as exc:
            raise ValueError(
                "Invalid master password or corrupted Bitwarden encrypted export."
            ) from exc

    _decrypt(enc_validation)
    decrypted_raw = _decrypt(encrypted_data)
    try:
        decrypted_data = json.loads(decrypted_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid JSON in decrypted Bitwarden export: {exc}") from exc

    return _extract_bitwarden_entries(decrypted_data)


def _first_non_empty(row: Mapping[str, str | None], header_map: dict[str, str], *keys: str) -> str:
    for key in keys:
        column = header_map.get(key)
        if column is not None:
            value = row.get(column)
            if value:
                return value
    return ""


def _parse_csv_columns(
    path: Path,
    *,
    required_col_key: str,
    name_keys: tuple[str, ...],
    username_keys: tuple[str, ...],
    missing_col_message: str,
) -> list[AuditEntry]:
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        fieldnames = reader.fieldnames or []
        header_map = {col.strip().lower(): col for col in fieldnames}
        password_col = header_map.get(required_col_key)
        if password_col is None:
            raise ValueError(missing_col_message)
        entries: list[AuditEntry] = []
        for row in reader:
            password = row.get(password_col) or ""
            if not password:
                continue
            entries.append(
                AuditEntry(
                    name=_first_non_empty(row, header_map, *name_keys),
                    username=_first_non_empty(row, header_map, *username_keys),
                    password=password,
                )
            )
    return entries


def parse_bitwarden_csv(path: Path) -> list[AuditEntry]:
    """Parse a Bitwarden CSV export into credential audit entries."""
    return _parse_csv_columns(
        path,
        required_col_key="login_password",
        name_keys=("name",),
        username_keys=("login_username",),
        missing_col_message="Bitwarden CSV export is missing the 'login_password' column.",
    )


def parse_1password_csv(path: Path) -> list[AuditEntry]:
    """Parse a 1Password CSV export into credential audit entries."""
    return _parse_csv_columns(
        path,
        required_col_key="password",
        name_keys=("title", "url"),
        username_keys=("username",),
        missing_col_message="1Password CSV export is missing a 'Password' column.",
    )


def _extract_1pux_item(item: object) -> AuditEntry | None:
    if not isinstance(item, dict):
        return None
    details = item.get("details")
    if not isinstance(details, dict):
        return None
    login_fields = details.get("loginFields")
    if not isinstance(login_fields, list):
        return None

    username = ""
    password = ""
    for field_obj in login_fields:
        if not isinstance(field_obj, dict):
            continue
        designation = field_obj.get("designation")
        value = field_obj.get("value")
        if not isinstance(value, str):
            continue
        if designation == "username" and not username:
            username = value
        elif designation == "password" and not password:
            password = value

    if not password:
        return None
    overview = item.get("overview")
    raw_title = overview.get("title") if isinstance(overview, dict) else None
    return AuditEntry(
        name=raw_title if isinstance(raw_title, str) else "",
        username=username,
        password=password,
    )


def parse_1password_1pux(path: Path) -> list[AuditEntry]:
    """Parse a 1Password 1PUX ZIP export into credential audit entries."""
    try:
        with zipfile.ZipFile(path) as zf:
            raw_bytes = zf.read("export.data")
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Invalid 1PUX ZIP archive in {path}: {exc}") from exc
    except KeyError as exc:
        raise ValueError(f"1PUX archive {path} is missing 'export.data'.") from exc

    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid 1PUX JSON in {path}: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("accounts"), list):
        raise ValueError("1PUX export.data must be an object with an 'accounts' list.")

    entries: list[AuditEntry] = []
    for account in data["accounts"]:
        if not isinstance(account, dict) or not isinstance(account.get("vaults"), list):
            raise ValueError("1PUX account must be an object with a 'vaults' list.")
        for vault in account["vaults"]:
            if not isinstance(vault, dict) or not isinstance(vault.get("items"), list):
                raise ValueError("1PUX vault must be an object with an 'items' list.")
            for item in vault["items"]:
                entry = _extract_1pux_item(item)
                if entry is not None:
                    entries.append(entry)
    return entries


def parse_chrome_csv(path: Path) -> list[AuditEntry]:
    """Parse a Google Chrome password CSV export into credential audit entries."""
    return _parse_csv_columns(
        path,
        required_col_key="password",
        name_keys=("name", "url"),
        username_keys=("username",),
        missing_col_message="Chrome CSV export is missing a 'password' column.",
    )


def parse_firefox_csv(path: Path) -> list[AuditEntry]:
    """Parse a Mozilla Firefox password CSV export into credential audit entries."""
    return _parse_csv_columns(
        path,
        required_col_key="password",
        name_keys=("url",),
        username_keys=("username",),
        missing_col_message="Firefox CSV export is missing a 'password' column.",
    )


def parse_apple_csv(path: Path) -> list[AuditEntry]:
    """Parse an Apple Passwords CSV export into credential audit entries."""
    return _parse_csv_columns(
        path,
        required_col_key="password",
        name_keys=("title", "url"),
        username_keys=("username",),
        missing_col_message="Apple Passwords CSV export is missing a 'Password' column.",
    )


def parse_generic_csv(path: Path) -> list[AuditEntry]:
    """Parse a generic CSV export with case-insensitive columns into audit entries."""
    return _parse_csv_columns(
        path,
        required_col_key="password",
        name_keys=("name", "title"),
        username_keys=("username", "email"),
        missing_col_message="CSV export is missing a 'password' column.",
    )


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


_SIMPLE_PARSERS: dict[str, Callable[[Path], list[AuditEntry]]] = {
    "bitwarden-json": parse_bitwarden_json,
    "bitwarden-csv": parse_bitwarden_csv,
    "1password-csv": parse_1password_csv,
    "1password-1pux": parse_1password_1pux,
    "chrome-csv": parse_chrome_csv,
    "firefox-csv": parse_firefox_csv,
    "apple-csv": parse_apple_csv,
    "csv": parse_generic_csv,
}


def load_export(
    path: Path,
    *,
    source: ExportSource,
    master_password: str | None = None,
) -> list[AuditEntry]:
    """Load credential entries from a supported password-manager export file."""
    if source == "keepass":
        if master_password is None:
            raise ValueError("master_password is required for KeePass exports.")
        return parse_keepass(path, master_password=master_password)
    if source == "bitwarden-encrypted-json":
        if master_password is None:
            raise ValueError("master_password is required for encrypted Bitwarden JSON exports.")
        return parse_bitwarden_encrypted_json(path, master_password=master_password)
    parser = _SIMPLE_PARSERS.get(source)
    if parser is not None:
        return parser(path)
    raise ValueError(f"Unsupported export source: {source!r}")


def _format_entry_label(entry: AuditEntry) -> str:
    if entry.name and entry.username:
        return f"{entry.name} ({entry.username})"
    if entry.name:
        return entry.name
    if entry.username:
        return entry.username
    return "<unnamed>"


def _build_audit_summary(
    entries: Sequence[AuditEntry],
    counts: Mapping[str, int],
    *,
    threshold: int,
    check_reuse: bool,
) -> AuditSummary:
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

    if check_reuse:
        by_password: dict[str, list[str]] = {}
        for entry in entries:
            by_password.setdefault(entry.password, []).append(_format_entry_label(entry))
        reused_groups = [
            ReuseGroup(
                entries=labels,
                count=len(labels),
                pwn_count=counts[password],
            )
            for password, labels in by_password.items()
            if len(labels) >= 2
        ]
        reused_groups.sort(key=lambda group: (-group.count, -group.pwn_count, group.entries))
        return AuditSummary(
            total_entries=len(entries),
            unique_passwords=len(counts),
            compromised_entries=len(findings),
            findings=findings,
            reused_groups=reused_groups,
        )

    return AuditSummary(
        total_entries=len(entries),
        unique_passwords=len(counts),
        compromised_entries=len(findings),
        findings=findings,
    )


def audit_entries(
    entries: Sequence[AuditEntry],
    client: PasswordChecker,
    *,
    threshold: int = 1,
    ntlm: bool = False,
    pad: bool = True,
    check_reuse: bool = False,
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

    return _build_audit_summary(
        entries,
        counts,
        threshold=threshold,
        check_reuse=check_reuse,
    )


async def async_audit_entries(
    entries: Sequence[AuditEntry],
    client: AsyncPwnedPasswordsClient,
    *,
    threshold: int = 1,
    ntlm: bool = False,
    pad: bool = True,
    check_reuse: bool = False,
    concurrency: int = 10,
) -> AuditSummary:
    """Concurrently check unique entry passwords against Pwned Passwords."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1.")
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1.")

    unique_passwords = list(dict.fromkeys(entry.password for entry in entries))
    semaphore = asyncio.Semaphore(concurrency)

    async def _check_one(password: str) -> tuple[str, int]:
        async with semaphore:
            count = await client.check_password(password, ntlm=ntlm, pad=pad)
            return password, count

    results = await asyncio.gather(*(_check_one(pw) for pw in unique_passwords))
    counts = dict(results)

    return _build_audit_summary(
        entries,
        counts,
        threshold=threshold,
        check_reuse=check_reuse,
    )
