from __future__ import annotations

import asyncio
import base64
import binascii
import csv
import hashlib
import json
import os
import shutil
import subprocess  # noqa: S404
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TypedDict

from pydantic import Field

from pwned._parsers import parse_pwdump_lines
from pwned.models import NonNegativeInt, PasswordChecker, _HIBPBase
from pwned.passwords import AsyncPwnedPasswordsClient
from pwned.strength import compute_vault_risk_score, evaluate_password_strength

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
    "pwdump",
    "lastpass-csv",
    "dashlane-csv",
    "protonpass-csv",
    "pass",
    "gopass",
]


@dataclass(frozen=True)
class AuditEntry:
    """Internal credential record parsed from a password-manager export."""

    name: str
    username: str
    password: str = field(repr=False)
    is_hash: bool = False
    hash_type: Literal["sha1", "ntlm"] | None = None


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


class StrengthFinding(_HIBPBase):
    """Weak password finding without exposing plaintext."""

    name: str
    username: str
    score: int = Field(ge=0, le=4)
    reasons: list[str] = Field(default_factory=list)


class AuditSummary(_HIBPBase):
    """Summary of an audited password-manager export."""

    total_entries: NonNegativeInt
    unique_passwords: NonNegativeInt
    compromised_entries: NonNegativeInt
    findings: list[AuditFinding]
    reused_groups: list[ReuseGroup] = Field(default_factory=list)
    weak_entries: NonNegativeInt = 0
    strength_findings: list[StrengthFinding] = Field(default_factory=list)
    risk_score: int | None = Field(default=None, ge=0, le=100)


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
        from cryptography.hazmat.primitives.kdf.argon2 import (  # type: ignore[import-not-found]
            Argon2id,
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
    if isinstance(kdf_type, bool) or kdf_type not in (0, 1):
        raise ValueError(
            f"Unsupported Bitwarden KDF type: {kdf_type!r} "
            "(only PBKDF2 kdfType=0 and Argon2id kdfType=1 are supported)."
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

    if kdf_type == 1:
        kdf_memory = payload.get("kdfMemory")
        if isinstance(kdf_memory, bool) or not isinstance(kdf_memory, int) or kdf_memory <= 0:
            raise ValueError("Bitwarden encrypted JSON export is missing a valid 'kdfMemory'.")
        kdf_parallelism = payload.get("kdfParallelism")
        if (
            isinstance(kdf_parallelism, bool)
            or not isinstance(kdf_parallelism, int)
            or kdf_parallelism <= 0
        ):
            raise ValueError("Bitwarden encrypted JSON export is missing a valid 'kdfParallelism'.")
    else:
        kdf_memory = 0
        kdf_parallelism = 0

    enc_validation = payload.get("encKeyValidation_DO_NOT_EDIT")
    if not isinstance(enc_validation, str) or not enc_validation:
        raise ValueError(
            "Bitwarden encrypted JSON export is missing 'encKeyValidation_DO_NOT_EDIT'."
        )

    encrypted_data = payload.get("data")
    if not isinstance(encrypted_data, str) or not encrypted_data:
        raise ValueError("Bitwarden encrypted JSON export is missing 'data'.")

    if kdf_type == 0:
        master_key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode("utf-8"),
            iterations=kdf_iterations,
        ).derive(master_password.encode("utf-8"))
    else:
        salt_bytes = hashlib.sha256(salt.encode("utf-8")).digest()
        master_key = Argon2id(
            salt=salt_bytes,
            length=32,
            iterations=kdf_iterations,
            lanes=kdf_parallelism,
            memory_cost=kdf_memory * 1024,
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


def parse_pwdump(path: Path) -> list[AuditEntry]:
    """Parse an impacket secretsdump / pwdump file into pre-hashed NTLM audit entries."""
    with path.open(encoding="utf-8") as fh:
        return [
            AuditEntry(
                name=domain,
                username=user,
                password=nt_hash,
                is_hash=True,
                hash_type="ntlm",
            )
            for domain, user, nt_hash in parse_pwdump_lines(fh)
        ]


def parse_lastpass_csv(path: Path) -> list[AuditEntry]:
    """Parse a LastPass CSV export into credential audit entries."""
    return _parse_csv_columns(
        path,
        required_col_key="password",
        name_keys=("name", "url"),
        username_keys=("username",),
        missing_col_message="LastPass CSV export is missing a 'password' column.",
    )


def parse_dashlane_csv(path: Path) -> list[AuditEntry]:
    """Parse a Dashlane CSV export into credential audit entries."""
    return _parse_csv_columns(
        path,
        required_col_key="password",
        name_keys=("title", "domain", "url"),
        username_keys=("username", "login", "username2"),
        missing_col_message="Dashlane CSV export is missing a 'password' column.",
    )


def parse_protonpass_csv(path: Path) -> list[AuditEntry]:
    """Parse a Proton Pass CSV export into credential audit entries."""
    return _parse_csv_columns(
        path,
        required_col_key="password",
        name_keys=("name", "url"),
        username_keys=("username", "email"),
        missing_col_message="Proton Pass CSV export is missing a 'password' column.",
    )


def _parse_pass_entry_output(entry_name: str, output: str) -> AuditEntry | None:
    raw_lines = output.split("\n")
    password = raw_lines[0].rstrip("\r")
    if not password:
        return None

    username = ""
    for raw_line in raw_lines[1:]:
        stripped = raw_line.rstrip("\r").lstrip()
        lowered = stripped.lower()
        for prefix in ("username:", "login:", "user:"):
            if lowered.startswith(prefix):
                _, _, value = stripped.partition(":")
                candidate = value.strip()
                if candidate:
                    username = candidate
                    break
        if username:
            break

    return AuditEntry(name=entry_name, username=username, password=password)


def _run_store_cli(cmd: list[str], *, env: dict[str, str], label: str) -> str:
    proc = subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if proc.returncode != 0:
        detail = " ".join((proc.stderr or "").split())
        if detail:
            raise RuntimeError(f"{label} failed: {detail}")
        raise RuntimeError(f"{label} failed with exit code {proc.returncode}.")
    return proc.stdout


def parse_pass_store(store_dir: Path | None = None) -> list[AuditEntry]:
    """Parse entries from a Unix pass (password-store) directory without temp files."""
    exe = shutil.which("pass")
    if exe is None:
        raise RuntimeError("The 'pass' CLI is not installed or not on PATH.")

    if store_dir is not None:
        resolved_dir = store_dir
    else:
        env_dir = os.environ.get("PASSWORD_STORE_DIR")
        resolved_dir = Path(env_dir) if env_dir else Path.home() / ".password-store"

    if not resolved_dir.is_dir():
        raise ValueError(f"Password store directory does not exist: {resolved_dir}")

    entry_names: list[str] = []
    for gpg_file in sorted(resolved_dir.rglob("*.gpg")):
        rel = gpg_file.relative_to(resolved_dir)
        if any(part.startswith(".") for part in rel.parts):
            continue
        entry_name = rel.with_suffix("").as_posix()
        if entry_name.startswith("-"):
            continue
        entry_names.append(entry_name)
    entry_names.sort()

    env = os.environ.copy()
    env["PASSWORD_STORE_DIR"] = str(resolved_dir)

    entries: list[AuditEntry] = []
    for entry_name in entry_names:
        stdout = _run_store_cli([exe, "show", entry_name], env=env, label=f"pass show {entry_name}")
        entry = _parse_pass_entry_output(entry_name, stdout)
        if entry is not None:
            entries.append(entry)
    return entries


def parse_gopass_store(store_dir: Path | None = None) -> list[AuditEntry]:
    """Parse entries from a gopass store without creating plaintext temporary files."""
    exe = shutil.which("gopass")
    if exe is None:
        raise RuntimeError("The 'gopass' CLI is not installed or not on PATH.")

    env = os.environ.copy()
    if store_dir is not None:
        env["PASSWORD_STORE_DIR"] = str(store_dir)

    ls_stdout = _run_store_cli([exe, "ls", "--flat"], env=env, label="gopass ls")
    entry_names = sorted(
        name for raw in ls_stdout.splitlines() if (name := raw.strip()) and not name.startswith("-")
    )

    entries: list[AuditEntry] = []
    for entry_name in entry_names:
        stdout = _run_store_cli(
            [exe, "show", entry_name],
            env=env,
            label=f"gopass show {entry_name}",
        )
        entry = _parse_pass_entry_output(entry_name, stdout)
        if entry is not None:
            entries.append(entry)
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
    "pwdump": parse_pwdump,
    "lastpass-csv": parse_lastpass_csv,
    "dashlane-csv": parse_dashlane_csv,
    "protonpass-csv": parse_protonpass_csv,
}


def load_export(
    path: Path | None,
    *,
    source: ExportSource,
    master_password: str | None = None,
) -> list[AuditEntry]:
    """Load credential entries from a supported password-manager export file or store."""
    if source == "pass":
        return parse_pass_store(path)
    if source == "gopass":
        return parse_gopass_store(path)
    if source not in ("keepass", "bitwarden-encrypted-json") and source not in _SIMPLE_PARSERS:
        raise ValueError(f"Unsupported export source: {source!r}")
    if path is None:
        raise ValueError(f"A file path is required for source {source!r}.")
    if source == "keepass":
        if master_password is None:
            raise ValueError("master_password is required for KeePass exports.")
        return parse_keepass(path, master_password=master_password)
    if source == "bitwarden-encrypted-json":
        if master_password is None:
            raise ValueError("master_password is required for encrypted Bitwarden JSON exports.")
        return parse_bitwarden_encrypted_json(path, master_password=master_password)
    return _SIMPLE_PARSERS[source](path)


_CheckKey = tuple[bool, Literal["sha1", "ntlm"] | None, str]


class _OptionalSummaryFields(TypedDict, total=False):
    reused_groups: list[ReuseGroup]
    weak_entries: int
    strength_findings: list[StrengthFinding]
    risk_score: int


def _entry_check_key(entry: AuditEntry) -> _CheckKey:
    return (entry.is_hash, entry.hash_type, entry.password)


def _format_entry_label(entry: AuditEntry) -> str:
    if entry.name and entry.username:
        return f"{entry.name} ({entry.username})"
    if entry.name:
        return entry.name
    if entry.username:
        return entry.username
    return "<unnamed>"


def _validate_audit_options(threshold: int, min_strength_score: int) -> None:
    if threshold < 1:
        raise ValueError("threshold must be at least 1.")
    if isinstance(min_strength_score, bool) or not (0 <= min_strength_score <= 4):
        raise ValueError("min_strength_score must be between 0 and 4.")


def _build_audit_summary(
    entries: Sequence[AuditEntry],
    counts: Mapping[_CheckKey, int],
    *,
    threshold: int,
    check_reuse: bool,
    check_strength: bool,
    min_strength_score: int,
) -> AuditSummary:
    findings = [
        AuditFinding(
            name=entry.name,
            username=entry.username,
            pwn_count=counts[_entry_check_key(entry)],
        )
        for entry in entries
        if counts[_entry_check_key(entry)] >= threshold
    ]
    findings.sort(key=lambda finding: (-finding.pwn_count, finding.name))

    extra: _OptionalSummaryFields = {}
    reused_count = 0
    if check_reuse:
        by_secret: dict[tuple[bool, str], list[AuditEntry]] = {}
        for entry in entries:
            by_secret.setdefault((entry.is_hash, entry.password), []).append(entry)
        reused_groups = [
            ReuseGroup(
                entries=[_format_entry_label(e) for e in group_entries],
                count=len(group_entries),
                pwn_count=max(counts[_entry_check_key(e)] for e in group_entries),
            )
            for group_entries in by_secret.values()
            if len(group_entries) >= 2
        ]
        reused_groups.sort(key=lambda group: (-group.count, -group.pwn_count, group.entries))
        extra["reused_groups"] = reused_groups
        reused_count = sum(group.count for group in reused_groups)

    if check_strength:
        strength_findings: list[StrengthFinding] = []
        for entry in entries:
            if entry.is_hash:
                continue
            result = evaluate_password_strength(
                entry.password,
                context_terms=(entry.name, entry.username),
            )
            if result.score <= min_strength_score:
                strength_findings.append(
                    StrengthFinding(
                        name=entry.name,
                        username=entry.username,
                        score=result.score,
                        reasons=result.reasons,
                    )
                )
        strength_findings.sort(key=lambda finding: (finding.score, finding.name))
        risk_score = compute_vault_risk_score(
            total_entries=len(entries),
            compromised_entries=len(findings),
            reused_entries=reused_count,
            weak_entries=len(strength_findings),
        )
        extra["weak_entries"] = len(strength_findings)
        extra["strength_findings"] = strength_findings
        extra["risk_score"] = risk_score

    return AuditSummary(
        total_entries=len(entries),
        unique_passwords=len(counts),
        compromised_entries=len(findings),
        findings=findings,
        **extra,
    )


def audit_entries(
    entries: Sequence[AuditEntry],
    client: PasswordChecker,
    *,
    threshold: int = 1,
    ntlm: bool = False,
    pad: bool = True,
    check_reuse: bool = False,
    check_strength: bool = False,
    min_strength_score: int = 2,
) -> AuditSummary:
    """Check unique entry passwords against Pwned Passwords via k-anonymity."""
    _validate_audit_options(threshold, min_strength_score)

    counts: dict[_CheckKey, int] = {}
    for entry in entries:
        key = _entry_check_key(entry)
        if key not in counts:
            if entry.is_hash:
                counts[key] = client.check_hash(
                    entry.password,
                    ntlm=(entry.hash_type == "ntlm" or ntlm),
                    pad=pad,
                )
            else:
                counts[key] = client.check_password(
                    entry.password,
                    ntlm=ntlm,
                    pad=pad,
                )

    return _build_audit_summary(
        entries,
        counts,
        threshold=threshold,
        check_reuse=check_reuse,
        check_strength=check_strength,
        min_strength_score=min_strength_score,
    )


async def async_audit_entries(
    entries: Sequence[AuditEntry],
    client: AsyncPwnedPasswordsClient,
    *,
    threshold: int = 1,
    ntlm: bool = False,
    pad: bool = True,
    check_reuse: bool = False,
    check_strength: bool = False,
    min_strength_score: int = 2,
    concurrency: int = 10,
) -> AuditSummary:
    """Concurrently check unique entry passwords against Pwned Passwords."""
    _validate_audit_options(threshold, min_strength_score)
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1.")

    unique_keys = list(dict.fromkeys(_entry_check_key(entry) for entry in entries))
    semaphore = asyncio.Semaphore(concurrency)

    async def _check_one(key: _CheckKey) -> tuple[_CheckKey, int]:
        is_hash, hash_type, secret = key
        async with semaphore:
            if is_hash:
                count = await client.check_hash(
                    secret,
                    ntlm=(hash_type == "ntlm" or ntlm),
                    pad=pad,
                )
            else:
                count = await client.check_password(secret, ntlm=ntlm, pad=pad)
            return key, count

    results = await asyncio.gather(*(_check_one(key) for key in unique_keys))
    counts = dict(results)

    return _build_audit_summary(
        entries,
        counts,
        threshold=threshold,
        check_reuse=check_reuse,
        check_strength=check_strength,
        min_strength_score=min_strength_score,
    )
