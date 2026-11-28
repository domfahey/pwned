from __future__ import annotations

import platform
import re
from contextlib import nullcontext
from pathlib import Path
from typing import BinaryIO, Literal, cast

from pydantic import Field

from pwned.cache import get_cache_dir
from pwned.client import HIBPClient, HIBPError
from pwned.config import (
    DEFAULT_USER_AGENT,
    get_api_key_source,
    keyring_available,
    mask_api_key,
)
from pwned.models import NonNegativeInt, _HIBPBase
from pwned.offline import OfflinePasswordsClient, _find_line_start, _read_directory_mode
from pwned.passwords import PwnedPasswordsClient

_PREFIX_FILE_RE = re.compile(r"^[0-9A-Fa-f]{5}\.txt$")
_DUMP_LINE_RE = re.compile(rb"^([0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}):([0-9]+)$")
_DUMP_SAMPLE_POINTS = 16


class DoctorCheck(_HIBPBase):
    """Individual diagnostic check emitted by :func:`run_doctor`."""

    name: str
    status: Literal["ok", "warn", "error", "skipped"]
    detail: str


class DoctorReport(_HIBPBase):
    """Aggregate environment, credential, cache, offline DB, and API diagnostics."""

    version: str
    python_version: str
    api_key_source: str
    api_key_masked: str
    keyring_available: bool
    cache_dir: str
    cache_entries: NonNegativeInt
    cache_bytes: NonNegativeInt
    subscription_name: str | None = None
    subscription_rpm: NonNegativeInt | None = None
    offline_db_path: str | None = None
    offline_db_kind: Literal["file", "directory"] | None = None
    offline_db_mode: Literal["sha1", "ntlm"] | None = None
    offline_db_entries: NonNegativeInt | None = None
    checks: list[DoctorCheck] = Field(default_factory=list)
    healthy: bool = True


def _package_version() -> str:
    from pwned import __version__

    return __version__


def _inspect_cache(cache_dir: Path) -> tuple[int, int]:
    if not cache_dir.is_dir():
        return 0, 0
    entries = 0
    total_bytes = 0
    for path in cache_dir.glob("*.json"):
        if path.is_file():
            entries += 1
            total_bytes += path.stat().st_size
    return entries, total_bytes


def _sample_line_offsets(handle: BinaryIO, size: int) -> list[int]:
    """Return deduplicated ascending line-start offsets sampled across the dump file."""
    handle.seek(max(0, size - 2))
    tail = handle.read(2)
    trimmed = len(tail) - len(tail.rstrip(b"\r\n"))
    last_pos = max(0, size - trimmed - 1)
    offsets: list[int] = []
    seen: set[int] = set()
    for step in range(_DUMP_SAMPLE_POINTS + 1):
        probe = (last_pos * step) // _DUMP_SAMPLE_POINTS
        start = _find_line_start(handle, probe)
        if start not in seen:
            seen.add(start)
            offsets.append(start)
    return offsets


def _inspect_offline_db(
    offline_db: Path, *, ntlm: bool | None
) -> tuple[
    Literal["file", "directory"] | None,
    Literal["sha1", "ntlm"] | None,
    int | None,
    DoctorCheck,
]:
    if not offline_db.exists():
        return (
            None,
            None,
            None,
            DoctorCheck(
                name="offline_db",
                status="error",
                detail=f"Path not found: {offline_db}",
            ),
        )

    if offline_db.is_dir():
        raw_mode = _read_directory_mode(offline_db)
        detected_mode = cast(Literal["sha1", "ntlm"] | None, raw_mode)
        effective_ntlm = ntlm if ntlm is not None else (detected_mode == "ntlm")
        try:
            with OfflinePasswordsClient(offline_db, ntlm=effective_ntlm):
                pass
        except ValueError as exc:
            return (
                "directory",
                detected_mode,
                None,
                DoctorCheck(name="offline_db", status="error", detail=str(exc)),
            )
        prefix_files = sum(
            1
            for item in offline_db.iterdir()
            if item.is_file() and _PREFIX_FILE_RE.fullmatch(item.name)
        )
        resolved_mode: Literal["sha1", "ntlm"] = "ntlm" if effective_ntlm else "sha1"
        if prefix_files == 0:
            return (
                "directory",
                resolved_mode,
                0,
                DoctorCheck(
                    name="offline_db",
                    status="warn",
                    detail=f"Directory contains 0 prefix range files: {offline_db}",
                ),
            )
        return (
            "directory",
            resolved_mode,
            prefix_files,
            DoctorCheck(
                name="offline_db",
                status="ok",
                detail=f"Directory ({resolved_mode.upper()}): {prefix_files:,} prefix files",
            ),
        )

    try:
        size = offline_db.stat().st_size
        if size == 0:
            return (
                "file",
                None,
                0,
                DoctorCheck(
                    name="offline_db",
                    status="warn",
                    detail=f"Dump file is empty (0 bytes): {offline_db}",
                ),
            )
        with offline_db.open("rb") as handle:
            offsets = _sample_line_offsets(handle, size)
            prev_hash: bytes | None = None
            expected_len: int | None = None
            samples: list[str] = []
            for offset in offsets:
                handle.seek(offset)
                raw_line = handle.readline().rstrip(b"\r\n")
                match = _DUMP_LINE_RE.match(raw_line)
                if match is None:
                    return (
                        "file",
                        None,
                        None,
                        DoctorCheck(
                            name="offline_db",
                            status="error",
                            detail=(
                                f"Unrecognized dump format (expected HASH:COUNT lines): "
                                f"{offline_db}"
                            ),
                        ),
                    )
                digest = match.group(1).upper()
                if expected_len is None:
                    expected_len = len(digest)
                elif len(digest) != expected_len:
                    return (
                        "file",
                        None,
                        None,
                        DoctorCheck(
                            name="offline_db",
                            status="error",
                            detail=f"Inconsistent hash lengths in dump file: {offline_db}",
                        ),
                    )
                if prev_hash is not None and digest <= prev_hash:
                    return (
                        "file",
                        "ntlm" if expected_len == 32 else "sha1",
                        None,
                        DoctorCheck(
                            name="offline_db",
                            status="error",
                            detail=(
                                f"Dump file is not sorted in strictly ascending hash order: "
                                f"{offline_db}"
                            ),
                        ),
                    )
                prev_hash = digest
                samples.append(digest.decode("ascii"))
        file_mode: Literal["sha1", "ntlm"] = "ntlm" if expected_len == 32 else "sha1"
        if ntlm is not None and (("ntlm" if ntlm else "sha1") != file_mode):
            requested = "NTLM" if ntlm else "SHA1"
            return (
                "file",
                file_mode,
                None,
                DoctorCheck(
                    name="offline_db",
                    status="error",
                    detail=(
                        f"Offline file {offline_db} contains {file_mode.upper()} hashes, "
                        f"but {requested} mode was requested"
                    ),
                ),
            )
        with OfflinePasswordsClient(offline_db, ntlm=(file_mode == "ntlm")) as client:
            client.check_hash(samples[0])
            client.check_hash(samples[-1])
        return (
            "file",
            file_mode,
            None,
            DoctorCheck(
                name="offline_db",
                status="ok",
                detail=(
                    f"Sorted dump file ({file_mode.upper()}, {size:,} bytes, "
                    f"{len(samples)} sampled records verified)"
                ),
            ),
        )
    except OSError as exc:
        return (
            "file",
            None,
            None,
            DoctorCheck(name="offline_db", status="error", detail=str(exc)),
        )


def run_doctor(
    *,
    api_key: str | None = None,
    api_key_source: str | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    cache_dir: Path | None = None,
    offline_db: Path | None = None,
    ntlm: bool | None = None,
    check_network: bool = True,
    hibp_client: HIBPClient | None = None,
    passwords_client: PwnedPasswordsClient | None = None,
) -> DoctorReport:
    """Verify credentials, keyring, cache, optional offline DB, and HIBP connectivity."""
    source = api_key_source if api_key_source is not None else get_api_key_source()
    masked = mask_api_key(api_key)
    has_keyring = keyring_available()
    resolved_cache_dir = cache_dir if cache_dir is not None else get_cache_dir()
    cache_entries, cache_bytes = _inspect_cache(resolved_cache_dir)

    checks: list[DoctorCheck] = [
        DoctorCheck(
            name="credentials",
            status="ok" if api_key else "warn",
            detail=(
                f"Configured via {source} ({masked})"
                if api_key
                else "No API key configured (free endpoints & Pwned Passwords still work)"
            ),
        ),
        DoctorCheck(
            name="keyring",
            status="ok" if has_keyring else "warn",
            detail=(
                "Installed (pwned[keyring])"
                if has_keyring
                else "Not installed (optional; install with pwned[keyring])"
            ),
        ),
        DoctorCheck(
            name="cache",
            status="ok",
            detail=f"{cache_entries} entries ({cache_bytes:,} bytes) in {resolved_cache_dir}",
        ),
    ]

    offline_db_kind: Literal["file", "directory"] | None = None
    offline_db_mode: Literal["sha1", "ntlm"] | None = None
    offline_db_entries: int | None = None
    if offline_db is not None:
        offline_db_kind, offline_db_mode, offline_db_entries, db_check = _inspect_offline_db(
            offline_db, ntlm=ntlm
        )
        checks.append(db_check)

    subscription_name: str | None = None
    subscription_rpm: int | None = None
    if check_network:
        pw_cm = (
            nullcontext(passwords_client)
            if passwords_client is not None
            else PwnedPasswordsClient(user_agent=user_agent)
        )
        with pw_cm as active_pw:
            try:
                suffixes = active_pw.get_password_range("5BAA6", pad=True)
            except HIBPError as exc:
                checks.append(
                    DoctorCheck(name="pwned_passwords_api", status="error", detail=str(exc))
                )
            else:
                checks.append(
                    DoctorCheck(
                        name="pwned_passwords_api",
                        status="ok",
                        detail=f"Reachable ({len(suffixes)} suffixes in range 5BAA6)",
                    )
                )

        hibp_cm = (
            nullcontext(hibp_client)
            if hibp_client is not None
            else HIBPClient(api_key=api_key, user_agent=user_agent)
        )
        with hibp_cm as active_hibp:
            try:
                latest = active_hibp.get_latest_breach()
            except HIBPError as exc:
                checks.append(DoctorCheck(name="hibp_api", status="error", detail=str(exc)))
            else:
                checks.append(
                    DoctorCheck(
                        name="hibp_api",
                        status="ok",
                        detail=f"Reachable (latest breach: {latest.name})",
                    )
                )

            if api_key:
                try:
                    sub = active_hibp.get_subscription_status()
                except HIBPError as exc:
                    checks.append(DoctorCheck(name="subscription", status="error", detail=str(exc)))
                else:
                    subscription_name = sub.subscription_name
                    subscription_rpm = sub.rpm
                    checks.append(
                        DoctorCheck(
                            name="subscription",
                            status="ok",
                            detail=f"{sub.subscription_name} ({sub.rpm} RPM)",
                        )
                    )
            else:
                checks.append(
                    DoctorCheck(
                        name="subscription",
                        status="skipped",
                        detail="No API key configured",
                    )
                )
    else:
        checks.append(
            DoctorCheck(
                name="network",
                status="skipped",
                detail="Skipped (--no-network)",
            )
        )

    return DoctorReport(
        version=_package_version(),
        python_version=platform.python_version(),
        api_key_source=source,
        api_key_masked=masked,
        keyring_available=has_keyring,
        cache_dir=str(resolved_cache_dir),
        cache_entries=cache_entries,
        cache_bytes=cache_bytes,
        subscription_name=subscription_name,
        subscription_rpm=subscription_rpm,
        offline_db_path=str(offline_db) if offline_db is not None else None,
        offline_db_kind=offline_db_kind,
        offline_db_mode=offline_db_mode,
        offline_db_entries=offline_db_entries,
        checks=checks,
        healthy=all(check.status != "error" for check in checks),
    )
