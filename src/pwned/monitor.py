from __future__ import annotations

import hashlib
import os
import re
import time
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import Field, field_validator

from pwned.baseline import (
    diff_domain_breaches,
    diff_search_result,
    load_baseline,
    save_baseline,
)
from pwned.client import HIBPClient, HIBPError, NotFoundError
from pwned.filtering import filter_breaches
from pwned.formatting import OutputFormat
from pwned.models import NonNegativeInt, SearchResult, _HIBPBase
from pwned.notify import WebhookFormat, send_webhook_notification

_ENV_VAR_RE = re.compile(r"\$\{([^}]+)\}")


def _validate_non_empty(value: str, *, field_name: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} must not be empty.")
    return cleaned


class MonitorAccountTarget(_HIBPBase):
    """Account monitoring target parsed from pwned.toml."""

    email: str
    domain: str | None = None
    include_unverified: bool = True
    include_stealer_logs: bool = False
    truncate: bool = True
    since: str | None = None
    data_class: str | None = None
    verified_only: bool = False
    exclude_retired: bool = False

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        return _validate_non_empty(value, field_name="email")


class MonitorDomainTarget(_HIBPBase):
    """Domain monitoring target parsed from pwned.toml."""

    domain: str
    include_stealer_logs: bool = False

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        return _validate_non_empty(value, field_name="domain")


class MonitorNotifyConfig(_HIBPBase):
    """Notification configuration for monitor alerts."""

    webhook_url: str | None = None
    format: WebhookFormat = "auto"


class MonitorConfig(_HIBPBase):
    """Declarative monitoring configuration loaded from pwned.toml."""

    baseline_dir: Path | None = None
    cache: bool = False
    format: OutputFormat | None = None
    fail_if_pwned: bool = False
    rpm: int | None = Field(default=None, ge=1)
    notify: MonitorNotifyConfig = Field(default_factory=MonitorNotifyConfig)
    accounts: list[MonitorAccountTarget] = Field(default_factory=list)
    domains: list[MonitorDomainTarget] = Field(default_factory=list)


class MonitorAccountResult(_HIBPBase):
    """Per-account monitoring outcome."""

    email: str
    new_breaches: list[str] = Field(default_factory=list)
    new_pastes: list[str] = Field(default_factory=list)
    new_stealer_logs: list[str] = Field(default_factory=list)
    status: Literal["pwned", "clean", "error"]
    error: str | None = None


class MonitorDomainResult(_HIBPBase):
    """Per-domain monitoring outcome."""

    domain: str
    new_aliases: dict[str, list[str]] = Field(default_factory=dict)
    new_stealer_logs: dict[str, list[str]] = Field(default_factory=dict)
    status: Literal["pwned", "clean", "error"]
    error: str | None = None


class MonitorReport(_HIBPBase):
    """Aggregate report emitted by run_monitor."""

    accounts_checked: NonNegativeInt
    domains_checked: NonNegativeInt
    new_exposures: NonNegativeInt
    accounts: list[MonitorAccountResult] = Field(default_factory=list)
    domains: list[MonitorDomainResult] = Field(default_factory=list)
    webhook_sent: bool = False


def _expand_env_vars(value: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        env_val = os.environ.get(name)
        if not env_val:
            raise ValueError(f"Environment variable {name!r} referenced in webhook_url is not set.")
        return env_val

    return _ENV_VAR_RE.sub(_replace, value)


def load_monitor_config(path: Path) -> MonitorConfig:
    """Load and validate a declarative TOML monitoring configuration."""
    raw_text = path.read_text(encoding="utf-8")
    try:
        raw = tomllib.loads(raw_text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML in {path}: {exc}") from exc

    monitor_raw = raw.get("monitor", {})
    if not isinstance(monitor_raw, dict):
        raise ValueError("TOML section [monitor] must be a table.")

    notify_raw = raw.get("notify", {})
    if not isinstance(notify_raw, dict):
        raise ValueError("TOML section [notify] must be a table.")

    accounts_raw = raw.get("accounts", [])
    if not isinstance(accounts_raw, list):
        raise ValueError("TOML section [[accounts]] must be an array of tables.")

    domains_raw = raw.get("domains", [])
    if not isinstance(domains_raw, list):
        raise ValueError("TOML section [[domains]] must be an array of tables.")

    notify_data = dict(notify_raw)
    raw_url = notify_data.get("webhook_url")
    if raw_url is not None:
        if not isinstance(raw_url, str):
            raise ValueError("notify.webhook_url must be a string.")
        notify_data["webhook_url"] = _expand_env_vars(raw_url)

    monitor_data: dict[str, Any] = dict(monitor_raw)
    raw_baseline_dir = monitor_data.get("baseline_dir")
    if raw_baseline_dir is not None:
        if not isinstance(raw_baseline_dir, (str, Path)):
            raise ValueError("monitor.baseline_dir must be a string path.")
        baseline_path = Path(raw_baseline_dir)
        if not baseline_path.is_absolute():
            baseline_path = path.parent / baseline_path
        monitor_data["baseline_dir"] = baseline_path

    config = MonitorConfig.model_validate(
        {
            **monitor_data,
            "notify": notify_data,
            "accounts": accounts_raw,
            "domains": domains_raw,
        }
    )
    if not config.accounts and not config.domains:
        raise ValueError("Monitor config must define at least one account or domain target.")
    return config


def _baseline_path(baseline_dir: Path, kind: Literal["account", "domain"], identifier: str) -> Path:
    digest = hashlib.sha256(identifier.lower().encode("utf-8")).hexdigest()[:16]
    return baseline_dir / f"{kind}_{digest}.json"


def _apply_account_filters(result: SearchResult, target: MonitorAccountTarget) -> SearchResult:
    if (
        target.since is None
        and target.data_class is None
        and not target.verified_only
        and not target.exclude_retired
    ):
        return result
    filtered_breaches = filter_breaches(
        result.breaches,
        since=target.since,
        data_class=target.data_class,
        verified_only=target.verified_only,
        exclude_retired=target.exclude_retired,
    )
    return SearchResult(
        breaches=filtered_breaches,
        pastes=result.pastes,
        stealer_logs=result.stealer_logs,
    )


def _check_account_target(
    target: MonitorAccountTarget,
    client: HIBPClient,
    *,
    baseline_dir: Path | None,
    save_baselines: bool,
) -> tuple[MonitorAccountResult, int]:
    try:
        result = client.search_account(
            target.email,
            truncate=target.truncate,
            domain=target.domain,
            include_unverified=target.include_unverified,
            include_stealer_logs=target.include_stealer_logs,
        )
    except HIBPError as exc:
        return (
            MonitorAccountResult(
                email=target.email,
                new_breaches=[],
                new_pastes=[],
                new_stealer_logs=[],
                status="error",
                error=str(exc),
            ),
            0,
        )

    result = _apply_account_filters(result, target)
    if baseline_dir is not None:
        path = _baseline_path(baseline_dir, "account", target.email)
        previous = load_baseline(path) if path.is_file() else None
        if save_baselines:
            save_baseline(path, result)
        diffed = diff_search_result(result, previous) if previous is not None else result
    else:
        diffed = result

    new_breaches = [breach.name for breach in diffed.breaches]
    new_pastes = [f"{paste.source}:{paste.id}" for paste in diffed.pastes]
    new_stealer_logs = list(diffed.stealer_logs or [])
    count = len(new_breaches) + len(new_pastes) + len(new_stealer_logs)
    status: Literal["pwned", "clean"] = "pwned" if count > 0 else "clean"
    return (
        MonitorAccountResult(
            email=target.email,
            new_breaches=new_breaches,
            new_pastes=new_pastes,
            new_stealer_logs=new_stealer_logs,
            status=status,
        ),
        count,
    )


def _check_domain_target(
    target: MonitorDomainTarget,
    client: HIBPClient,
    *,
    baseline_dir: Path | None,
    save_baselines: bool,
) -> tuple[MonitorDomainResult, int]:
    try:
        domain_breaches = client.get_domain_breaches(target.domain)
    except NotFoundError:
        domain_breaches = {}
    except HIBPError as exc:
        return (
            MonitorDomainResult(
                domain=target.domain,
                new_aliases={},
                new_stealer_logs={},
                status="error",
                error=str(exc),
            ),
            0,
        )

    stealer_logs: dict[str, list[str]] = {}
    if target.include_stealer_logs:
        try:
            stealer_logs = client.get_stealer_logs_by_email_domain(target.domain)
        except NotFoundError:
            stealer_logs = {}
        except HIBPError as exc:
            return (
                MonitorDomainResult(
                    domain=target.domain,
                    new_aliases={},
                    new_stealer_logs={},
                    status="error",
                    error=str(exc),
                ),
                0,
            )

    if baseline_dir is not None:
        path = _baseline_path(baseline_dir, "domain", target.domain)
        previous = load_baseline(path) if path.is_file() else None
        if save_baselines:
            save_baseline(path, {"breaches": domain_breaches, "stealer_logs": stealer_logs})
        if previous is not None:
            if not isinstance(previous, dict):
                raise ValueError("Baseline domain snapshot must be a JSON object.")
            prev_breaches = previous.get("breaches")
            prev_logs = previous.get("stealer_logs")
            new_aliases = diff_domain_breaches(
                domain_breaches, {} if prev_breaches is None else prev_breaches
            )
            new_stealer_logs = diff_domain_breaches(
                stealer_logs, {} if prev_logs is None else prev_logs
            )
        else:
            new_aliases = domain_breaches
            new_stealer_logs = stealer_logs
    else:
        new_aliases = domain_breaches
        new_stealer_logs = stealer_logs

    count = sum(len(v) for v in new_aliases.values()) + sum(
        len(v) for v in new_stealer_logs.values()
    )
    status: Literal["pwned", "clean"] = "pwned" if count > 0 else "clean"
    return (
        MonitorDomainResult(
            domain=target.domain,
            new_aliases=new_aliases,
            new_stealer_logs=new_stealer_logs,
            status=status,
        ),
        count,
    )


def run_monitor(
    config: MonitorConfig,
    client: HIBPClient,
    *,
    save_baselines: bool = False,
    webhook_url_override: str | None = None,
    webhook_format_override: WebhookFormat | None = None,
    sleep: Callable[[float], None] = time.sleep,
    webhook_client: httpx.Client | None = None,
) -> MonitorReport:
    """Execute account and domain checks defined in a MonitorConfig."""
    delay = 60.0 / config.rpm if config.rpm is not None else 0.0
    account_results: list[MonitorAccountResult] = []
    domain_results: list[MonitorDomainResult] = []
    total_exposures = 0

    for idx, account_target in enumerate(config.accounts, start=1):
        if idx > 1 and delay > 0.0:
            sleep(delay)
        result, count = _check_account_target(
            account_target,
            client,
            baseline_dir=config.baseline_dir,
            save_baselines=save_baselines,
        )
        account_results.append(result)
        total_exposures += count

    for domain_target in config.domains:
        dom_result, count = _check_domain_target(
            domain_target,
            client,
            baseline_dir=config.baseline_dir,
            save_baselines=save_baselines,
        )
        domain_results.append(dom_result)
        total_exposures += count

    report = MonitorReport(
        accounts_checked=len(config.accounts),
        domains_checked=len(config.domains),
        new_exposures=total_exposures,
        accounts=account_results,
        domains=domain_results,
        webhook_sent=False,
    )

    effective_url = webhook_url_override or config.notify.webhook_url
    if effective_url:
        effective_fmt: WebhookFormat = (
            webhook_format_override if webhook_format_override is not None else config.notify.format
        )
        sent = send_webhook_notification(
            effective_url,
            report,
            fmt=effective_fmt,
            title="pwned Monitor Alert",
            client=webhook_client,
        )
        if sent:
            report = report.model_copy(update={"webhook_sent": True})

    return report
