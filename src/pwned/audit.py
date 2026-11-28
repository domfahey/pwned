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
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Literal, TypedDict
from urllib.parse import urlparse

from pydantic import Field

from pwned._parsers import (
    EMPTY_LM_HASH as EMPTY_LM_HASH,
)
from pwned._parsers import (
    EMPTY_NTLM_HASH as EMPTY_NTLM_HASH,
)
from pwned._parsers import (
    parse_input_lines,
    parse_pwdump_records,
)
from pwned.async_client import AsyncHIBPClient
from pwned.client import HIBPClient, HIBPError, NotFoundError
from pwned.models import Breach, NonNegativeInt, PasswordChecker, _HIBPBase
from pwned.passwords import AsyncPwnedPasswordsClient, _hash_password
from pwned.strength import compute_vault_risk_score, evaluate_password_strength

ExportSource = Literal[
    "bitwarden-json",
    "bitwarden-encrypted-json",
    "bitwarden-csv",
    "bitwarden-cli",
    "1password-csv",
    "1password-1pux",
    "1password-cli",
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


ADHygieneIssue = Literal["empty_ntlm", "lm_hash_present", "username_as_password"]
WordlistMatchType = Literal["exact", "case_insensitive", "case_variant"]
BreachCorrelationSource = Literal["site_domain", "account_breach", "stealer_log"]


@dataclass(frozen=True)
class AuditEntry:
    """Internal credential record parsed from a password-manager export."""

    name: str
    username: str
    password: str = field(repr=False)
    is_hash: bool = False
    hash_type: Literal["sha1", "ntlm"] | None = None
    has_lm_hash: bool = False
    domains: tuple[str, ...] = field(default=(), compare=False)


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


class ADHygieneFinding(_HIBPBase):
    """Active Directory credential hygiene finding without exposing secrets."""

    name: str
    username: str
    issue: ADHygieneIssue
    detail: str


class WordlistFinding(_HIBPBase):
    """Custom organizational wordlist match without exposing secrets."""

    name: str
    username: str
    match_type: WordlistMatchType


class BreachCorrelationFinding(_HIBPBase):
    """Breach or stealer-log correlation finding without exposing secrets."""

    name: str
    username: str
    source: BreachCorrelationSource
    domain: str = ""
    breaches: list[str] = Field(default_factory=list)


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
    ad_findings: list[ADHygieneFinding] = Field(default_factory=list)
    wordlist_matches: NonNegativeInt = 0
    wordlist_findings: list[WordlistFinding] = Field(default_factory=list)
    breach_findings: list[BreachCorrelationFinding] = Field(default_factory=list)
    breach_correlated_entries: NonNegativeInt = 0


def extract_domain(raw_url: str) -> str | None:
    """Extract a normalized domain name from a URL or bare hostname."""
    cleaned = raw_url.strip()
    if not cleaned:
        return None
    try:
        parsed = urlparse(cleaned)
        if not parsed.scheme and "." in cleaned and not any(ch.isspace() for ch in cleaned):
            parsed = urlparse(f"https://{cleaned}")
    except ValueError:
        return None
    host = parsed.hostname
    if not host:
        return None
    normalized = host.lower().rstrip(".").removeprefix("www.")
    if "." not in normalized:
        return None
    return normalized


def _collect_domains(raw_urls: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(domain for raw in raw_urls if (domain := extract_domain(raw)) is not None)
    )


def _extract_uri_domains(raw_uris: object) -> tuple[str, ...]:
    if not isinstance(raw_uris, list):
        return ()
    values: list[str] = []
    for item in raw_uris:
        if isinstance(item, str):
            values.append(item)
        elif isinstance(item, dict):
            uri = item.get("uri")
            if isinstance(uri, str):
                values.append(uri)
    return _collect_domains(values)


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
                domains=_extract_uri_domains(login.get("uris")),
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


def _extract_row_domains(
    row: Mapping[str, str | None],
    header_map: dict[str, str],
    url_keys: tuple[str, ...],
) -> tuple[str, ...]:
    raw_urls: list[str] = []
    for key in url_keys:
        column = header_map.get(key)
        if column is not None:
            value = row.get(column)
            if value:
                raw_urls.append(value)
    return _collect_domains(raw_urls)


def _parse_csv_columns(
    path: Path,
    *,
    required_col_key: str,
    name_keys: tuple[str, ...],
    username_keys: tuple[str, ...],
    missing_col_message: str,
    url_keys: tuple[str, ...] = ("url", "domain"),
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
                    domains=_extract_row_domains(row, header_map, url_keys),
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
        url_keys=("login_uri",),
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
    raw_title: object = None
    raw_urls: list[str] = []
    if isinstance(overview, dict):
        raw_title = overview.get("title")
        primary_url = overview.get("url")
        if isinstance(primary_url, str):
            raw_urls.append(primary_url)
        extra_urls = overview.get("urls")
        if isinstance(extra_urls, list):
            for url_obj in extra_urls:
                if isinstance(url_obj, dict):
                    url_val = url_obj.get("url")
                    if isinstance(url_val, str):
                        raw_urls.append(url_val)
    return AuditEntry(
        name=raw_title if isinstance(raw_title, str) else "",
        username=username,
        password=password,
        domains=_collect_domains(raw_urls),
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
        raw_url = getattr(entry, "url", None)
        entries.append(
            AuditEntry(
                name=entry.title or "",
                username=entry.username or "",
                password=password,
                domains=_collect_domains((raw_url,)) if isinstance(raw_url, str) else (),
            )
        )
    return entries


def parse_pwdump(path: Path, *, exclude_machines: bool = False) -> list[AuditEntry]:
    """Parse an impacket secretsdump / pwdump file into pre-hashed NTLM audit entries."""
    with path.open(encoding="utf-8") as fh:
        return [
            AuditEntry(
                name=domain,
                username=user,
                password=nt_hash,
                is_hash=True,
                hash_type="ntlm",
                has_lm_hash=bool(lm_hash and lm_hash != EMPTY_LM_HASH),
            )
            for domain, user, lm_hash, nt_hash in parse_pwdump_records(fh)
            if not (exclude_machines and user.endswith("$"))
        ]


def load_custom_wordlist(path: Path, *, ignore_comments: bool = True) -> list[str]:
    """Load deduplicated banned password terms from a UTF-8 newline-delimited file."""
    with path.open(encoding="utf-8-sig") as fh:
        return parse_input_lines(
            fh,
            strip=True,
            ignore_comments=ignore_comments,
            deduplicate=True,
            skip_empty=True,
        )


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
    raw_urls: list[str] = []
    for raw_line in raw_lines[1:]:
        stripped = raw_line.rstrip("\r").lstrip()
        lowered = stripped.lower()
        if not username and any(
            lowered.startswith(prefix) for prefix in ("username:", "login:", "user:")
        ):
            _, _, value = stripped.partition(":")
            candidate = value.strip()
            if candidate:
                username = candidate
        elif any(lowered.startswith(prefix) for prefix in ("url:", "website:", "site:")):
            _, _, value = stripped.partition(":")
            candidate = value.strip()
            if candidate:
                raw_urls.append(candidate)

    return AuditEntry(
        name=entry_name,
        username=username,
        password=password,
        domains=_collect_domains(raw_urls),
    )


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


def parse_bitwarden_cli(target: Path | str | None = None) -> list[AuditEntry]:
    """Parse unlocked Bitwarden entries directly in memory via 'bw' or 'rbw' CLI."""
    filter_term = str(target).strip() if target is not None else ""
    if filter_term.startswith("-"):
        raise ValueError("Invalid target filter starting with '-'.")

    bw_exe = shutil.which("bw")
    if bw_exe is not None:
        cmd = [bw_exe, "list", "items"]
        if filter_term:
            cmd.extend(["--search", filter_term])
        stdout = _run_store_cli(cmd, env=os.environ.copy(), label="bw list items")
        try:
            items = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON from bw list items: {exc}") from exc
        if not isinstance(items, list):
            raise ValueError("Bitwarden CLI 'bw list items' must return a JSON list.")
        return _extract_bitwarden_entries({"items": items})

    rbw_exe = shutil.which("rbw")
    if rbw_exe is None:
        raise RuntimeError("Neither 'bw' nor 'rbw' CLI is installed or on PATH.")

    env = os.environ.copy()
    list_stdout = _run_store_cli(
        [rbw_exe, "list", "--fields", "id,name,user"],
        env=env,
        label="rbw list",
    )
    needle = filter_term.casefold()
    item_ids: list[str] = []
    for raw_line in list_stdout.splitlines():
        if not raw_line.strip():
            continue
        parts = raw_line.split("\t")
        item_id = parts[0].strip()
        if not item_id or item_id.startswith("-"):
            continue
        if needle:
            name_field = parts[1] if len(parts) > 1 else ""
            user_field = parts[2] if len(parts) > 2 else ""
            if needle not in name_field.casefold() and needle not in user_field.casefold():
                continue
        item_ids.append(item_id)

    entries: list[AuditEntry] = []
    for item_id in item_ids:
        raw_json = _run_store_cli(
            [rbw_exe, "get", "--raw", item_id],
            env=env,
            label=f"rbw get {item_id}",
        )
        try:
            item = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON from rbw get {item_id}: {exc}") from exc
        if not isinstance(item, dict):
            continue
        data = item.get("data")
        if not isinstance(data, dict):
            continue
        password = data.get("password")
        if not isinstance(password, str) or not password:
            continue
        raw_name = item.get("name")
        raw_username = data.get("username")
        entries.append(
            AuditEntry(
                name=raw_name if isinstance(raw_name, str) else "",
                username=raw_username if isinstance(raw_username, str) else "",
                password=password,
                domains=_extract_uri_domains(data.get("uris")),
            )
        )
    return entries


def parse_1password_cli(vault: Path | str | None = None) -> list[AuditEntry]:
    """Parse unlocked 1Password Login items directly in memory via the 'op' CLI."""
    vault_name = str(vault).strip() if vault is not None else ""
    if vault_name.startswith("-"):
        raise ValueError("Invalid 1Password vault name starting with '-'.")

    op_exe = shutil.which("op")
    if op_exe is None:
        raise RuntimeError("The 'op' (1Password) CLI is not installed or not on PATH.")

    env = os.environ.copy()
    list_cmd = [op_exe, "item", "list", "--categories", "Login", "--format", "json"]
    if vault_name:
        list_cmd.extend(["--vault", vault_name])
    list_stdout = _run_store_cli(list_cmd, env=env, label="op item list")
    try:
        items = json.loads(list_stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON from op item list: {exc}") from exc
    if not isinstance(items, list):
        raise ValueError("1Password CLI 'op item list' must return a JSON list.")

    entries: list[AuditEntry] = []
    for summary_item in items:
        if not isinstance(summary_item, dict):
            continue
        raw_id = summary_item.get("id")
        if not isinstance(raw_id, str):
            continue
        item_id = raw_id.strip()
        if not item_id or item_id.startswith("-"):
            continue

        get_cmd = [op_exe, "item", "get", item_id, "--format", "json"]
        if vault_name:
            get_cmd.extend(["--vault", vault_name])
        item_stdout = _run_store_cli(get_cmd, env=env, label=f"op item get {item_id}")
        try:
            detail = json.loads(item_stdout)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON from op item get {item_id}: {exc}") from exc
        if not isinstance(detail, dict):
            continue

        raw_fields = detail.get("fields")
        if not isinstance(raw_fields, list):
            continue
        username = ""
        password = ""
        for field_obj in raw_fields:
            if not isinstance(field_obj, dict):
                continue
            value = field_obj.get("value")
            if not isinstance(value, str):
                continue
            purpose = field_obj.get("purpose")
            field_id = field_obj.get("id")
            if (purpose == "USERNAME" or field_id == "username") and not username:
                username = value
            elif (purpose == "PASSWORD" or field_id == "password") and not password:
                password = value
        if not password:
            continue

        raw_title = detail.get("title")
        raw_urls = detail.get("urls")
        url_values: list[str] = []
        if isinstance(raw_urls, list):
            for url_obj in raw_urls:
                if isinstance(url_obj, dict):
                    href = url_obj.get("href")
                    if isinstance(href, str):
                        url_values.append(href)
        entries.append(
            AuditEntry(
                name=raw_title if isinstance(raw_title, str) else "",
                username=username,
                password=password,
                domains=_collect_domains(url_values),
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
    exclude_machines: bool = False,
) -> list[AuditEntry]:
    """Load credential entries from a supported password-manager export file or store."""
    if source == "pass":
        entries = parse_pass_store(path)
    elif source == "gopass":
        entries = parse_gopass_store(path)
    elif source == "bitwarden-cli":
        entries = parse_bitwarden_cli(path)
    elif source == "1password-cli":
        entries = parse_1password_cli(path)
    else:
        if source not in ("keepass", "bitwarden-encrypted-json") and source not in _SIMPLE_PARSERS:
            raise ValueError(f"Unsupported export source: {source!r}")
        if path is None:
            raise ValueError(f"A file path is required for source {source!r}.")
        if source == "keepass":
            if master_password is None:
                raise ValueError("master_password is required for KeePass exports.")
            entries = parse_keepass(path, master_password=master_password)
        elif source == "bitwarden-encrypted-json":
            if master_password is None:
                raise ValueError(
                    "master_password is required for encrypted Bitwarden JSON exports."
                )
            entries = parse_bitwarden_encrypted_json(path, master_password=master_password)
        else:
            entries = _SIMPLE_PARSERS[source](path)
    if exclude_machines:
        return [entry for entry in entries if not entry.username.endswith("$")]
    return entries


_CheckKey = tuple[bool, Literal["sha1", "ntlm"] | None, str]


class _OptionalSummaryFields(TypedDict, total=False):
    reused_groups: list[ReuseGroup]
    weak_entries: int
    strength_findings: list[StrengthFinding]
    risk_score: int
    ad_findings: list[ADHygieneFinding]
    wordlist_matches: int
    wordlist_findings: list[WordlistFinding]
    breach_findings: list[BreachCorrelationFinding]
    breach_correlated_entries: int


_MISSING = object()


def _client_has_api_key(hibp_client: object) -> bool:
    api_key = getattr(hibp_client, "api_key", _MISSING)
    if api_key is not _MISSING:
        return bool(api_key)
    inner_client = getattr(hibp_client, "_client", None)
    headers = getattr(inner_client, "headers", None)
    if isinstance(headers, Mapping):
        return bool(headers.get("hibp-api-key"))
    return True


def _normalize_email(username: str) -> str | None:
    cleaned = username.strip().lower()
    if "@" not in cleaned or any(ch.isspace() for ch in cleaned):
        return None
    local, _, domain = cleaned.partition("@")
    if not local or not domain:
        return None
    return cleaned


def _domain_candidates(domain: str) -> tuple[str, ...]:
    parts = domain.split(".")
    return tuple(".".join(parts[idx:]) for idx in range(len(parts) - 1))


def _index_breach_catalog(catalog: Sequence[Breach]) -> dict[str, list[str]]:
    by_domain: dict[str, set[str]] = {}
    for breach in catalog:
        domain = extract_domain(breach.domain)
        if domain is not None:
            by_domain.setdefault(domain, set()).add(breach.name)
    return {domain: sorted(names) for domain, names in by_domain.items()}


def _collect_breach_findings(
    entries: Sequence[AuditEntry],
    *,
    catalog: Sequence[Breach],
    account_breaches_by_email: Mapping[str, list[str]],
    stealer_logs_by_email: Mapping[str, list[str]],
) -> tuple[list[BreachCorrelationFinding], int]:
    catalog_index = _index_breach_catalog(catalog)
    findings: list[BreachCorrelationFinding] = []
    correlated_indices: set[int] = set()

    for idx, entry in enumerate(entries):
        matched_domains: set[str] = set()
        for raw_domain in entry.domains:
            normalized = extract_domain(raw_domain)
            if normalized is None:
                continue
            for candidate in _domain_candidates(normalized):
                breach_names = catalog_index.get(candidate)
                if breach_names is not None:
                    if candidate not in matched_domains:
                        matched_domains.add(candidate)
                        findings.append(
                            BreachCorrelationFinding(
                                name=entry.name,
                                username=entry.username,
                                source="site_domain",
                                domain=candidate,
                                breaches=list(breach_names),
                            )
                        )
                        correlated_indices.add(idx)
                    break

        email = _normalize_email(entry.username)
        if email is not None:
            acct_breaches = account_breaches_by_email.get(email)
            if acct_breaches:
                findings.append(
                    BreachCorrelationFinding(
                        name=entry.name,
                        username=entry.username,
                        source="account_breach",
                        domain="",
                        breaches=list(acct_breaches),
                    )
                )
                correlated_indices.add(idx)
            stealer_domains = stealer_logs_by_email.get(email)
            if stealer_domains:
                findings.append(
                    BreachCorrelationFinding(
                        name=entry.name,
                        username=entry.username,
                        source="stealer_log",
                        domain="",
                        breaches=list(stealer_domains),
                    )
                )
                correlated_indices.add(idx)

    findings.sort(
        key=lambda finding: (finding.source, finding.name, finding.username, finding.domain)
    )
    return findings, len(correlated_indices)


def _correlate_breaches_sync(
    entries: Sequence[AuditEntry],
    *,
    breach_catalog: Sequence[Breach] | None,
    hibp_client: HIBPClient | None,
    include_stealer_logs: bool,
) -> tuple[list[BreachCorrelationFinding], int]:
    catalog: Sequence[Breach]
    if breach_catalog is not None:
        catalog = breach_catalog
    elif hibp_client is not None and any(entry.domains for entry in entries):
        try:
            catalog = hibp_client.get_breaches()
        except HIBPError:
            catalog = []
    else:
        catalog = []

    account_breaches_by_email: dict[str, list[str]] = {}
    stealer_logs_by_email: dict[str, list[str]] = {}
    if hibp_client is not None and _client_has_api_key(hibp_client):
        unique_emails = list(
            dict.fromkeys(
                email
                for entry in entries
                if (email := _normalize_email(entry.username)) is not None
            )
        )
        for email in unique_emails:
            try:
                breaches = hibp_client.get_account_breaches(email, truncate=True)
            except NotFoundError:
                breaches = []
            if breaches:
                account_breaches_by_email[email] = sorted({b.name for b in breaches})
            if include_stealer_logs:
                try:
                    stealer_domains = hibp_client.get_stealer_logs_by_email(email)
                except NotFoundError:
                    stealer_domains = []
                if stealer_domains:
                    stealer_logs_by_email[email] = sorted(set(stealer_domains))

    return _collect_breach_findings(
        entries,
        catalog=catalog,
        account_breaches_by_email=account_breaches_by_email,
        stealer_logs_by_email=stealer_logs_by_email,
    )


async def _correlate_breaches_async(
    entries: Sequence[AuditEntry],
    *,
    breach_catalog: Sequence[Breach] | None,
    hibp_client: AsyncHIBPClient | None,
    include_stealer_logs: bool,
    semaphore: asyncio.Semaphore,
) -> tuple[list[BreachCorrelationFinding], int]:
    catalog: Sequence[Breach]
    if breach_catalog is not None:
        catalog = breach_catalog
    elif hibp_client is not None and any(entry.domains for entry in entries):
        try:
            catalog = await hibp_client.get_breaches()
        except HIBPError:
            catalog = []
    else:
        catalog = []

    account_breaches_by_email: dict[str, list[str]] = {}
    stealer_logs_by_email: dict[str, list[str]] = {}
    if hibp_client is not None and _client_has_api_key(hibp_client):
        unique_emails = list(
            dict.fromkeys(
                email
                for entry in entries
                if (email := _normalize_email(entry.username)) is not None
            )
        )
        active_client = hibp_client

        async def _fetch_email(email: str) -> tuple[str, list[str], list[str]]:
            async with semaphore:
                try:
                    breaches = await active_client.get_account_breaches(email, truncate=True)
                except NotFoundError:
                    breaches = []
                stealer_domains: list[str] = []
                if include_stealer_logs:
                    try:
                        stealer_domains = await active_client.get_stealer_logs_by_email(email)
                    except NotFoundError:
                        stealer_domains = []
                return (
                    email,
                    sorted({b.name for b in breaches}),
                    sorted(set(stealer_domains)),
                )

        email_results = await asyncio.gather(*(_fetch_email(email) for email in unique_emails))
        for email, breach_names, stealer_domains in email_results:
            if breach_names:
                account_breaches_by_email[email] = breach_names
            if stealer_domains:
                stealer_logs_by_email[email] = stealer_domains

    return _collect_breach_findings(
        entries,
        catalog=catalog,
        account_breaches_by_email=account_breaches_by_email,
        stealer_logs_by_email=stealer_logs_by_email,
    )


def _case_variants(value: str) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            (
                value,
                value.lower(),
                value.upper(),
                value.capitalize(),
                value.title(),
            )
        )
    )


def _username_candidates(username: str) -> tuple[str, ...]:
    if not username:
        return ()
    bases = [username]
    if username.endswith("$"):
        stripped = username.rstrip("$")
        if stripped:
            bases.append(stripped)
    if "@" in username:
        local = username.split("@", 1)[0]
        if local:
            bases.append(local)
    return tuple(dict.fromkeys(variant for base in bases for variant in _case_variants(base)))


def _entry_is_ntlm(entry: AuditEntry, ntlm: bool) -> bool:
    return entry.hash_type == "ntlm" or (entry.hash_type is None and ntlm)


def _matches_username_password(entry: AuditEntry, *, ntlm: bool = False) -> bool:
    candidates = _username_candidates(entry.username)
    if not candidates:
        return False
    if entry.is_hash:
        target = entry.password.upper()
        use_ntlm = _entry_is_ntlm(entry, ntlm)
        return any(_hash_password(candidate, ntlm=use_ntlm) == target for candidate in candidates)
    target_folded = entry.password.casefold()
    return any(candidate.casefold() == target_folded for candidate in candidates)


def _collect_ad_hygiene_findings(
    entries: Sequence[AuditEntry],
    *,
    ntlm: bool = False,
) -> list[ADHygieneFinding]:
    findings: list[ADHygieneFinding] = []
    for entry in entries:
        if (
            entry.is_hash
            and _entry_is_ntlm(entry, ntlm)
            and entry.password.upper() == EMPTY_NTLM_HASH
        ):
            findings.append(
                ADHygieneFinding(
                    name=entry.name,
                    username=entry.username,
                    issue="empty_ntlm",
                    detail="Account has an empty NTLM password hash.",
                )
            )
        if entry.has_lm_hash:
            findings.append(
                ADHygieneFinding(
                    name=entry.name,
                    username=entry.username,
                    issue="lm_hash_present",
                    detail="Legacy LM hash is stored for this account.",
                )
            )
        if _matches_username_password(entry, ntlm=ntlm):
            findings.append(
                ADHygieneFinding(
                    name=entry.name,
                    username=entry.username,
                    issue="username_as_password",
                    detail="Password matches account username.",
                )
            )
    findings.sort(key=lambda finding: (finding.issue, finding.name, finding.username))
    return findings


def _build_hash_wordlist_sets(
    terms: Sequence[str],
    hasher: Callable[[str], str],
) -> tuple[set[str], set[str]]:
    exact: set[str] = set()
    case_insensitive: set[str] = set()
    for term in terms:
        exact.add(hasher(term))
        for variant in _case_variants(term):
            case_insensitive.add(hasher(variant))
    case_insensitive -= exact
    return exact, case_insensitive


def _collect_wordlist_findings(
    entries: Sequence[AuditEntry],
    custom_wordlist: Sequence[str] | AbstractSet[str],
    *,
    ntlm: bool = False,
) -> list[WordlistFinding]:
    """Match entries against a custom banned wordlist without exposing secrets.

    Plaintext entries support exact (``"exact"``) and full case-folded
    (``"case_insensitive"``) matching. Irreversible pre-hashed NTLM/SHA-1 entries
    cannot be case-folded directly, so they are matched against exact digests
    (``"exact"``) and common capitalization variants (``lower``, ``upper``,
    ``capitalize``, ``title``) reported explicitly as ``"case_variant"``.
    """
    terms = list(dict.fromkeys(term for term in custom_wordlist if term))
    if not terms or not entries:
        return []

    exact_plain = set(terms)
    ci_plain = {term.casefold() for term in terms}
    ntlm_sets: tuple[set[str], set[str]] | None = None
    sha1_sets: tuple[set[str], set[str]] | None = None

    findings: list[WordlistFinding] = []
    for entry in entries:
        match_type: WordlistMatchType | None = None
        if entry.is_hash:
            digest = entry.password.upper()
            if _entry_is_ntlm(entry, ntlm):
                if ntlm_sets is None:
                    ntlm_sets = _build_hash_wordlist_sets(terms, partial(_hash_password, ntlm=True))
                exact_hashes, variant_hashes = ntlm_sets
            else:
                if sha1_sets is None:
                    sha1_sets = _build_hash_wordlist_sets(
                        terms, partial(_hash_password, ntlm=False)
                    )
                exact_hashes, variant_hashes = sha1_sets
            if digest in exact_hashes:
                match_type = "exact"
            elif digest in variant_hashes:
                match_type = "case_variant"
        elif entry.password in exact_plain:
            match_type = "exact"
        elif entry.password.casefold() in ci_plain:
            match_type = "case_insensitive"

        if match_type is not None:
            findings.append(
                WordlistFinding(
                    name=entry.name,
                    username=entry.username,
                    match_type=match_type,
                )
            )

    findings.sort(key=lambda finding: (finding.name, finding.username, finding.match_type))
    return findings


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
    ntlm: bool,
    check_reuse: bool,
    check_strength: bool,
    min_strength_score: int,
    check_ad_hygiene: bool,
    custom_wordlist: Sequence[str] | AbstractSet[str] | None,
    breach_correlation: tuple[list[BreachCorrelationFinding], int] | None = None,
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

    if check_ad_hygiene:
        extra["ad_findings"] = _collect_ad_hygiene_findings(entries, ntlm=ntlm)

    if custom_wordlist is not None:
        wordlist_findings = _collect_wordlist_findings(entries, custom_wordlist, ntlm=ntlm)
        extra["wordlist_matches"] = len(wordlist_findings)
        extra["wordlist_findings"] = wordlist_findings

    if breach_correlation is not None:
        breach_findings, breach_correlated_entries = breach_correlation
        extra["breach_findings"] = breach_findings
        extra["breach_correlated_entries"] = breach_correlated_entries

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
    check_ad_hygiene: bool = False,
    custom_wordlist: Sequence[str] | AbstractSet[str] | None = None,
    check_breaches: bool = False,
    breach_catalog: Sequence[Breach] | None = None,
    hibp_client: HIBPClient | None = None,
    include_stealer_logs: bool = False,
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

    breach_correlation = (
        _correlate_breaches_sync(
            entries,
            breach_catalog=breach_catalog,
            hibp_client=hibp_client,
            include_stealer_logs=include_stealer_logs,
        )
        if check_breaches
        else None
    )

    return _build_audit_summary(
        entries,
        counts,
        threshold=threshold,
        ntlm=ntlm,
        check_reuse=check_reuse,
        check_strength=check_strength,
        min_strength_score=min_strength_score,
        check_ad_hygiene=check_ad_hygiene,
        custom_wordlist=custom_wordlist,
        breach_correlation=breach_correlation,
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
    check_ad_hygiene: bool = False,
    custom_wordlist: Sequence[str] | AbstractSet[str] | None = None,
    check_breaches: bool = False,
    breach_catalog: Sequence[Breach] | None = None,
    hibp_client: AsyncHIBPClient | None = None,
    include_stealer_logs: bool = False,
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

    breach_correlation = (
        await _correlate_breaches_async(
            entries,
            breach_catalog=breach_catalog,
            hibp_client=hibp_client,
            include_stealer_logs=include_stealer_logs,
            semaphore=semaphore,
        )
        if check_breaches
        else None
    )

    return _build_audit_summary(
        entries,
        counts,
        threshold=threshold,
        ntlm=ntlm,
        check_reuse=check_reuse,
        check_strength=check_strength,
        min_strength_score=min_strength_score,
        check_ad_hygiene=check_ad_hygiene,
        custom_wordlist=custom_wordlist,
        breach_correlation=breach_correlation,
    )
