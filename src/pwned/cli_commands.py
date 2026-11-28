from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, cast

import click
import click.shell_completion

from pwned.audit import (
    AuditSummary,
    ExportSource,
    async_audit_entries,
    audit_entries,
    load_export,
)
from pwned.baseline import diff_search_result, load_baseline, save_baseline
from pwned.cache import ResponseCache
from pwned.cli_helpers import (
    ExitCode,
    FileOrStoreError,
    get_cache,
    get_output_format,
    handle_errors,
    render_output,
    require_api_key,
)
from pwned.client import HIBPClient, NotFoundError
from pwned.config import (
    clear_api_key,
    clear_api_key_keyring,
    get_api_key_source,
    get_config_file,
    keyring_available,
    mask_api_key,
    save_api_key,
    save_api_key_keyring,
)
from pwned.doctor import run_doctor
from pwned.formatting import format_output
from pwned.mcp_server import MCPServer, serve_stdio
from pwned.models import BreachedAccountRangeResult, EmailAlias
from pwned.monitor import load_monitor_config, run_monitor
from pwned.notify import WEBHOOK_FORMATS, WebhookFormat, send_webhook_notification
from pwned.offline import OfflinePasswordsClient
from pwned.offline_download import download_offline_db
from pwned.passwords import AsyncPwnedPasswordsClient, PwnedPasswordsClient
from pwned.reporting import generate_domain_report

_EMAIL_ALIASES = ("admin", "hostmaster", "info", "security", "webmaster")
_AUDIT_SOURCES = (
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
)
_AUTH_BACKENDS = ("auto", "file", "keyring")
_COMPLETION_SHELLS = ("bash", "zsh", "fish")
_HASH_MODES = ("sha1", "ntlm")


def _authed_client(ctx: click.Context) -> HIBPClient:
    settings = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    return HIBPClient(api_key=api_key, user_agent=settings.user_agent)


def _maybe_notify(
    webhook_url: str | None,
    webhook_format: WebhookFormat,
    data: Any,
    *,
    title: str,
) -> None:
    if webhook_url is None:
        return
    try:
        send_webhook_notification(webhook_url, data, fmt=webhook_format, title=title)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc


def _finish_keyring_save() -> None:
    if clear_api_key():
        click.echo("Saved API key to OS keyring (removed previous key from config file).")
    else:
        click.echo("Saved API key to OS keyring.")


@click.group()
def auth() -> None:
    """Manage stored HIBP API key credentials."""


@auth.command("set")
@click.argument("api_key", required=False)
@click.option("--stdin", "from_stdin", is_flag=True, help="Read API key from stdin.")
@click.option(
    "--backend",
    type=click.Choice(_AUTH_BACKENDS),
    default="auto",
    show_default=True,
    help="Credential storage backend (auto prefers OS keyring when installed).",
)
@handle_errors
def auth_set(api_key: str | None, from_stdin: bool, backend: str) -> None:
    """Store the HIBP API key in the OS keyring or user config file."""
    if api_key is not None and from_stdin:
        raise click.UsageError("Cannot specify both API_KEY and --stdin.")
    if from_stdin:
        key = sys.stdin.readline().rstrip("\r\n")
        if not key:
            raise click.UsageError("No API key provided on stdin.")
    elif api_key is not None:
        key = api_key
    else:
        key = click.prompt("HIBP API key", hide_input=True, err=True)

    if backend == "keyring":
        try:
            save_api_key_keyring(key)
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
        except Exception as exc:
            raise FileOrStoreError(str(exc)) from exc
        _finish_keyring_save()
        return

    if backend == "auto" and keyring_available():
        try:
            save_api_key_keyring(key)
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
        except Exception as exc:
            click.echo(
                f"OS keyring unavailable ({exc}); falling back to file storage.",
                err=True,
            )
        else:
            _finish_keyring_save()
            return

    try:
        path = save_api_key(key)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    click.echo(f"Saved API key to {path}")


@auth.command("show")
@click.pass_context
def auth_show(ctx: click.Context) -> None:
    """Show the currently configured API key status."""
    key: str | None = ctx.obj["settings"].get_api_key()
    config_file: str | None
    try:
        config_file = str(get_config_file())
    except RuntimeError:
        config_file = None
    data = {
        "api_key": mask_api_key(key),
        "config_file": config_file,
        "configured": bool(key),
        "source": get_api_key_source(api_key=ctx.obj.get("cli_api_key")),
        "keyring_available": keyring_available(),
    }
    click.echo(format_output(data, fmt=get_output_format(ctx)))


@auth.command("clear")
@click.option(
    "--backend",
    type=click.Choice(_AUTH_BACKENDS),
    default="auto",
    show_default=True,
    help="Credential storage backend (auto clears OS keyring and config file).",
)
@handle_errors
def auth_clear(backend: str) -> None:
    """Remove the stored API key from the OS keyring and/or user config file."""
    if backend == "keyring":
        try:
            removed = clear_api_key_keyring()
        except Exception as exc:
            raise FileOrStoreError(str(exc)) from exc
        if removed:
            click.echo("API key removed from OS keyring.")
        else:
            click.echo("No stored API key found in OS keyring.")
        return

    if backend == "auto":
        removed_keyring = False
        keyring_error: Exception | None = None
        if keyring_available():
            try:
                removed_keyring = clear_api_key_keyring()
            except Exception as exc:
                keyring_error = exc
        removed_file = clear_api_key()
        if keyring_error is not None:
            if removed_file:
                click.echo("API key removed from config file.")
            raise FileOrStoreError(
                f"Failed to clear OS keyring: {keyring_error}"
            ) from keyring_error
        if removed_keyring and removed_file:
            click.echo("API key removed from OS keyring and config file.")
        elif removed_keyring:
            click.echo("API key removed from OS keyring.")
        elif removed_file:
            click.echo("API key removed.")
        else:
            click.echo("No stored API key found.")
        return

    if clear_api_key():
        click.echo("API key removed.")
    else:
        click.echo("No stored API key found.")


@click.command()
@click.argument("account")
@click.option(
    "--no-truncate", "--full", "no_truncate", is_flag=True, help="Return full breach model."
)
@click.option("--domain", default=None, help="Filter by domain.")
@click.option("--no-include-unverified", is_flag=True, help="Exclude unverified breaches.")
@click.option("--include-stealer-logs", is_flag=True, help="Include stealer log domains.")
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a previous search baseline JSON file to diff against.",
)
@click.option(
    "--save-baseline",
    "save_baseline_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Save full search results as a JSON baseline snapshot.",
)
@click.option(
    "--notify-webhook",
    default=None,
    help="HTTPS webhook URL to notify on exposures.",
)
@click.option(
    "--webhook-format",
    type=click.Choice(WEBHOOK_FORMATS),
    default="auto",
    help="Webhook payload format.",
)
@click.option(
    "--fail-if-pwned",
    "--fail-if-found",
    "fail_if_pwned",
    is_flag=True,
    help="Exit with code 8 if exposed.",
)
@click.pass_context
@handle_errors
def search(
    ctx: click.Context,
    account: str,
    no_truncate: bool,
    domain: str | None,
    no_include_unverified: bool,
    include_stealer_logs: bool,
    baseline_path: Path | None,
    save_baseline_path: Path | None,
    notify_webhook: str | None,
    webhook_format: str,
    fail_if_pwned: bool,
) -> None:
    """Search breaches, pastes, and optionally stealer logs for an account."""
    with _authed_client(ctx) as client:
        result = client.search_account(
            account,
            truncate=not no_truncate,
            domain=domain,
            include_unverified=not no_include_unverified,
            include_stealer_logs=include_stealer_logs,
        )
    if save_baseline_path is not None:
        save_baseline(save_baseline_path, result)
    if baseline_path is not None:
        try:
            prev = load_baseline(baseline_path)
            result = diff_search_result(result, prev)
        except ValueError as exc:
            raise FileOrStoreError(str(exc)) from exc
    render_output(ctx, result)
    _maybe_notify(
        notify_webhook,
        cast(WebhookFormat, webhook_format),
        result,
        title=f"pwned Search Alert: {account}",
    )
    if fail_if_pwned and (result.breaches or result.pastes or result.stealer_logs):
        sys.exit(int(ExitCode.FINDINGS))


@click.command("account-range")
@click.argument("target")
@click.option(
    "--fail-if-pwned",
    "--fail-if-found",
    "fail_if_pwned",
    is_flag=True,
    help="Exit with code 8 if breached.",
)
@click.pass_context
@handle_errors
def account_range(ctx: click.Context, target: str, fail_if_pwned: bool) -> None:
    """Check breached sites for an email address or 6-char SHA-1 hex prefix."""
    results: list[str] | list[BreachedAccountRangeResult]
    with _authed_client(ctx) as client:
        if "@" in target:
            results = client.check_account_range(target)
        else:
            try:
                results = client.get_account_range(target)
            except ValueError as exc:
                raise click.UsageError(str(exc)) from exc
            except NotFoundError:
                results = []
    render_output(ctx, results)
    if fail_if_pwned and results:
        sys.exit(int(ExitCode.FINDINGS))


@click.command("password-range")
@click.argument("prefix")
@click.option(
    "--mode",
    type=click.Choice(_HASH_MODES),
    default="sha1",
    show_default=True,
    help="Hash algorithm: sha1 or ntlm.",
)
@click.option(
    "--ntlm",
    "-n",
    is_flag=True,
    help="Use NTLM hash mode instead of SHA-1 (overrides --mode).",
)
@click.option(
    "--pad/--no-pad",
    default=True,
    show_default=True,
    help="Request padded responses to hide response length.",
)
@click.option(
    "--fail-if-pwned",
    "--fail-if-found",
    "fail_if_pwned",
    is_flag=True,
    help="Exit with code 8 if any hashes are found in the range.",
)
@click.pass_context
@handle_errors
def password_range(
    ctx: click.Context,
    prefix: str,
    mode: str,
    ntlm: bool,
    pad: bool,
    fail_if_pwned: bool,
) -> None:
    """Fetch compromised password hash suffixes for a 5-character hex prefix."""
    settings = ctx.obj["settings"]
    effective_ntlm = ntlm or mode == "ntlm"
    with PwnedPasswordsClient(user_agent=settings.user_agent, cache=get_cache(ctx)) as client:
        try:
            results = client.get_password_range(prefix, ntlm=effective_ntlm, pad=pad)
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
    render_output(ctx, results)
    if fail_if_pwned and results:
        sys.exit(int(ExitCode.FINDINGS))


@click.group("domain-verify")
def domain_verify() -> None:
    """Manage HIBP domain ownership verification."""


@domain_verify.command("dns-token")
@click.argument("domain")
@click.pass_context
@handle_errors
def domain_verify_dns_token(ctx: click.Context, domain: str) -> None:
    """Generate a DNS TXT verification token for a domain."""
    with _authed_client(ctx) as client:
        token = client.generate_dns_token(domain)
    render_output(ctx, token)


@domain_verify.command("dns-check")
@click.argument("domain")
@click.pass_context
@handle_errors
def domain_verify_dns_check(ctx: click.Context, domain: str) -> None:
    """Verify a domain's DNS TXT verification record."""
    with _authed_client(ctx) as client:
        client.verify_dns_token(domain)
    render_output(ctx, {"domain": domain, "verified": True})


@domain_verify.command("email")
@click.argument("domain")
@click.argument("alias", type=click.Choice(_EMAIL_ALIASES))
@click.pass_context
@handle_errors
def domain_verify_email(ctx: click.Context, domain: str, alias: str) -> None:
    """Send a domain verification email to a standard administrative alias."""
    with _authed_client(ctx) as client:
        client.send_verification_email(domain, cast(EmailAlias, alias))
    render_output(ctx, {"domain": domain, "alias": alias, "sent": True})


@domain_verify.command("meta-tag")
@click.argument("domain")
@click.pass_context
@handle_errors
def domain_verify_meta_tag(ctx: click.Context, domain: str) -> None:
    """Generate an HTML meta tag for domain verification."""
    with _authed_client(ctx) as client:
        meta_tag = client.generate_meta_tag(domain)
    render_output(ctx, meta_tag)


@domain_verify.command("meta-check")
@click.argument("domain")
@click.pass_context
@handle_errors
def domain_verify_meta_check(ctx: click.Context, domain: str) -> None:
    """Verify a domain's HTML meta tag."""
    with _authed_client(ctx) as client:
        client.verify_meta_tag(domain)
    render_output(ctx, {"domain": domain, "verified": True})


@click.command()
@click.argument("path", required=False, type=click.Path(exists=True, dir_okay=True, path_type=Path))
@click.option(
    "--source",
    type=click.Choice(_AUDIT_SOURCES),
    default="bitwarden-json",
    show_default=True,
    help="Password manager export format.",
)
@click.option(
    "--mode",
    type=click.Choice(_HASH_MODES),
    default="sha1",
    show_default=True,
    help="Hash algorithm: sha1 or ntlm.",
)
@click.option(
    "--ntlm",
    "-n",
    is_flag=True,
    help="Use NTLM hashes instead of SHA-1 (overrides --mode).",
)
@click.option(
    "--pad/--no-pad",
    default=True,
    show_default=True,
    help="Request padded responses to hide response length.",
)
@click.option(
    "--threshold",
    type=click.IntRange(min=1),
    default=1,
    show_default=True,
    help="Minimum breach count to report.",
)
@click.option(
    "--check-reuse",
    is_flag=True,
    help="Report passwords reused across multiple entries.",
)
@click.option(
    "--check-strength",
    is_flag=True,
    help="Flag weak passwords and compute vault risk score.",
)
@click.option(
    "--concurrency",
    "--parallelism",
    "-p",
    "concurrency",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Maximum concurrent Pwned Passwords requests.",
)
@click.option(
    "--offline-db",
    type=click.Path(exists=True, dir_okay=True, path_type=Path),
    default=None,
    help="Path to a local HIBP password dump file or per-prefix directory for offline checking.",
)
@click.option(
    "--notify-webhook",
    default=None,
    help="HTTPS webhook URL to notify on exposures.",
)
@click.option(
    "--webhook-format",
    type=click.Choice(WEBHOOK_FORMATS),
    default="auto",
    help="Webhook payload format.",
)
@click.option(
    "--fail-if-pwned",
    "--fail-if-found",
    "fail_if_pwned",
    is_flag=True,
    help="Exit with code 8 if compromised.",
)
@click.pass_context
@handle_errors
def audit(
    ctx: click.Context,
    path: Path | None,
    source: str,
    mode: str,
    ntlm: bool,
    pad: bool,
    threshold: int,
    check_reuse: bool,
    check_strength: bool,
    concurrency: int,
    offline_db: Path | None,
    notify_webhook: str | None,
    webhook_format: str,
    fail_if_pwned: bool,
) -> None:
    """Audit a password-manager export locally via k-anonymity."""
    if source not in ("pass", "gopass"):
        if path is None:
            raise click.UsageError(f"PATH is required for --source {source}.")
        if path.is_dir():
            raise click.UsageError(f"PATH must be a file for --source {source}.")

    master_password: str | None = None
    if source == "keepass":
        master_password = click.prompt("KeePass master password", hide_input=True, err=True)
    elif source == "bitwarden-encrypted-json":
        master_password = click.prompt("Bitwarden export password", hide_input=True, err=True)
    try:
        entries = load_export(
            path,
            source=cast(ExportSource, source),
            master_password=master_password,
        )
    except (ValueError, RuntimeError) as exc:
        raise FileOrStoreError(str(exc)) from exc

    settings = ctx.obj["settings"]
    effective_ntlm = ntlm or mode == "ntlm" or source == "pwdump"
    if offline_db is not None:
        try:
            offline_cm = OfflinePasswordsClient(offline_db, ntlm=effective_ntlm)
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
        with offline_cm as offline_client:
            summary = audit_entries(
                entries,
                offline_client,
                threshold=threshold,
                ntlm=effective_ntlm,
                pad=pad,
                check_reuse=check_reuse,
                check_strength=check_strength,
            )
    else:

        async def _run_online_audit() -> AuditSummary:
            async with AsyncPwnedPasswordsClient(
                user_agent=settings.user_agent,
                cache=get_cache(ctx),
            ) as pw_client:
                return await async_audit_entries(
                    entries,
                    pw_client,
                    threshold=threshold,
                    ntlm=effective_ntlm,
                    pad=pad,
                    check_reuse=check_reuse,
                    check_strength=check_strength,
                    concurrency=concurrency,
                )

        summary = asyncio.run(_run_online_audit())
    render_output(ctx, summary)
    _maybe_notify(
        notify_webhook,
        cast(WebhookFormat, webhook_format),
        summary,
        title="pwned Vault Audit Alert",
    )
    if fail_if_pwned and summary.compromised_entries > 0:
        sys.exit(int(ExitCode.FINDINGS))


def _is_stderr_tty() -> bool:
    return sys.stderr.isatty()


def _offline_progress(completed: int, total: int) -> None:
    if completed == total or completed % max(1, total // 100) == 0:
        click.echo(f"[{completed:,}/{total:,}] ranges downloaded", err=True)


@click.group()
def offline() -> None:
    """Manage local offline Pwned Passwords hash dumps."""


@offline.command("download")
@click.argument("output", type=click.Path(dir_okay=True, path_type=Path))
@click.option(
    "--single",
    "-s",
    is_flag=True,
    default=False,
    help="Write ordered HASH:COUNT lines to one merged file instead of a per-prefix directory.",
)
@click.option(
    "--mode",
    type=click.Choice(_HASH_MODES),
    default="sha1",
    show_default=True,
    help="Hash algorithm: sha1 or ntlm.",
)
@click.option(
    "--ntlm",
    "-n",
    is_flag=True,
    help="Download NTLM hashes instead of SHA-1 (overrides --mode).",
)
@click.option(
    "--concurrency",
    "--parallelism",
    "-p",
    "concurrency",
    type=click.IntRange(min=1),
    default=32,
    show_default=True,
    help="Maximum concurrent prefix downloads.",
)
@click.option(
    "--resume/--no-resume",
    default=True,
    show_default=True,
    help="Resume an interrupted download if partial shards exist.",
)
@click.option(
    "--etag-cache",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="JSON file storing ETags for conditional HTTP 304 updates.",
)
@click.option(
    "--max-retries",
    type=click.IntRange(min=0),
    default=None,
    help="Maximum retries per range prefix (omit for unlimited, 0 to disable).",
)
@click.option(
    "--overwrite",
    "-o",
    is_flag=True,
    default=False,
    help="Permit replacing an existing single file or non-empty directory without an index.",
)
@click.option(
    "--force-refresh",
    is_flag=True,
    default=False,
    help="Ignore cached shards and saved ETags, forcing a full re-download.",
)
@click.pass_context
@handle_errors
def offline_download(
    ctx: click.Context,
    output: Path,
    single: bool,
    mode: str,
    ntlm: bool,
    concurrency: int,
    resume: bool,
    etag_cache: Path | None,
    max_retries: int | None,
    overwrite: bool,
    force_refresh: bool,
) -> None:
    """Download an offline Pwned Passwords hash dump (per-prefix directory by default,
    or --single file; pass --force-refresh to ignore saved ETags).
    """
    settings = ctx.obj["settings"]
    effective_ntlm = ntlm or mode == "ntlm"
    try:
        stats = asyncio.run(
            download_offline_db(
                output,
                ntlm=effective_ntlm,
                directory=not single,
                concurrency=concurrency,
                resume=resume,
                force=force_refresh,
                overwrite=overwrite,
                etag_cache_path=etag_cache,
                user_agent=settings.user_agent,
                max_retries=max_retries,
                on_progress=_offline_progress if _is_stderr_tty() else None,
            )
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    render_output(ctx, stats)


@click.command("domain-report")
@click.argument("domain")
@click.option(
    "--include-stealer-logs",
    is_flag=True,
    help="Include stealer log alias exposure counts.",
)
@click.option(
    "--notify-webhook",
    default=None,
    help="HTTPS webhook URL to notify on exposures.",
)
@click.option(
    "--webhook-format",
    type=click.Choice(WEBHOOK_FORMATS),
    default="auto",
    help="Webhook payload format.",
)
@click.option(
    "--fail-if-pwned",
    "--fail-if-found",
    "fail_if_pwned",
    is_flag=True,
    help="Exit with code 8 if any exposures are found.",
)
@click.pass_context
@handle_errors
def domain_report(
    ctx: click.Context,
    domain: str,
    include_stealer_logs: bool,
    notify_webhook: str | None,
    webhook_format: str,
    fail_if_pwned: bool,
) -> None:
    """Generate an aggregated breach exposure report for a verified domain."""
    settings = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    with HIBPClient(
        api_key=api_key,
        user_agent=settings.user_agent,
        cache=get_cache(ctx),
    ) as client:
        report = generate_domain_report(
            client,
            domain,
            include_stealer_logs=include_stealer_logs,
        )
    render_output(ctx, report)
    _maybe_notify(
        notify_webhook,
        cast(WebhookFormat, webhook_format),
        report,
        title=f"pwned Domain Report Alert: {domain}",
    )
    if fail_if_pwned and (report.total_exposed_aliases > 0 or bool(report.stealer_log_aliases)):
        sys.exit(int(ExitCode.FINDINGS))


@click.command("monitor")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("pwned.toml"),
    show_default=True,
    help="Path to declarative monitor TOML config.",
)
@click.option(
    "--save-baselines",
    is_flag=True,
    help="Save updated snapshots to baseline_dir.",
)
@click.option(
    "--smart-precheck",
    is_flag=True,
    help="Poll /latestBreach first and skip domain breach queries when unchanged.",
)
@click.option(
    "--notify-webhook",
    default=None,
    help="Override webhook URL from config.",
)
@click.option(
    "--webhook-format",
    type=click.Choice(WEBHOOK_FORMATS),
    default=None,
    help="Override webhook format from config.",
)
@click.option(
    "--fail-if-pwned",
    "--fail-if-found",
    "fail_if_pwned",
    is_flag=True,
    help="Exit with code 8 if new exposures are detected.",
)
@click.pass_context
@handle_errors
def monitor(
    ctx: click.Context,
    config_path: Path,
    save_baselines: bool,
    smart_precheck: bool,
    notify_webhook: str | None,
    webhook_format: str | None,
    fail_if_pwned: bool,
) -> None:
    """Run declarative account and domain monitoring from a TOML config."""
    try:
        config = load_monitor_config(config_path)
    except ValueError as exc:
        raise FileOrStoreError(str(exc)) from exc

    settings = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    cache_backend = ResponseCache() if (config.cache or ctx.obj.get("use_cache")) else None
    with HIBPClient(
        api_key=api_key,
        user_agent=settings.user_agent,
        cache=cache_backend,
        retry_jitter=0.25,
    ) as client:
        try:
            report = run_monitor(
                config,
                client,
                save_baselines=save_baselines,
                smart_precheck_override=smart_precheck,
                webhook_url_override=notify_webhook,
                webhook_format_override=(
                    cast(WebhookFormat, webhook_format) if webhook_format is not None else None
                ),
            )
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc

    if config.format is not None and ctx.obj.get("fmt") == "text" and not ctx.obj.get("use_json"):
        click.echo(format_output(report, fmt=config.format))
    else:
        render_output(ctx, report)

    if (fail_if_pwned or config.fail_if_pwned) and report.new_exposures > 0:
        sys.exit(int(ExitCode.FINDINGS))


@click.command("mcp")
@click.option(
    "--offline-db",
    type=click.Path(exists=True, dir_okay=True, path_type=Path),
    default=None,
    help="Local HIBP password dump file or per-prefix directory for offline MCP lookups.",
)
@click.option(
    "--mode",
    type=click.Choice(_HASH_MODES),
    default="sha1",
    show_default=True,
    help="Default hash algorithm for MCP lookups: sha1 or ntlm.",
)
@click.option(
    "--ntlm",
    "-n",
    is_flag=True,
    help="Default to NTLM hash mode for MCP lookups (overrides --mode).",
)
@click.pass_context
@handle_errors
def mcp(ctx: click.Context, offline_db: Path | None, mode: str, ntlm: bool) -> None:
    """Run the local stdio MCP server for AI assistants."""
    settings = ctx.obj["settings"]
    effective_ntlm = ntlm or mode == "ntlm"
    server = MCPServer(
        api_key=settings.get_api_key(),
        user_agent=settings.user_agent,
        offline_db=offline_db,
        ntlm=effective_ntlm,
        cache=get_cache(ctx),
    )
    serve_stdio(server)


@click.group()
def cache() -> None:
    """Manage the local response cache."""


@cache.command("clear")
@click.pass_context
@handle_errors
def cache_clear(ctx: click.Context) -> None:
    """Delete all cached HIBP responses."""
    count = ResponseCache().clear()
    if get_output_format(ctx) != "text":
        render_output(ctx, {"cleared": count})
        return
    click.echo(f"Cleared {count} cached entries.")


@click.command()
@click.argument("shell", type=click.Choice(_COMPLETION_SHELLS))
@click.pass_context
def completion(ctx: click.Context, shell: str) -> None:
    """Output shell completion script for bash, zsh, or fish."""
    comp_cls = cast(
        type[click.shell_completion.ShellComplete],
        click.shell_completion.get_completion_class(shell),
    )
    root = ctx.find_root()
    comp = comp_cls(root.command, {}, "pwned", "_PWNED_COMPLETE")
    click.echo(comp.source())


@click.command("doctor")
@click.option(
    "--offline-db",
    type=click.Path(exists=False, path_type=Path),
    default=None,
    help="Optional local HIBP password dump file or per-prefix directory to verify.",
)
@click.option(
    "--mode",
    type=click.Choice(_HASH_MODES),
    default=None,
    help="Expected offline DB hash algorithm (sha1 or ntlm); auto-detected if omitted.",
)
@click.option(
    "--ntlm",
    "-n",
    is_flag=True,
    help="Expect NTLM hashes in --offline-db (overrides --mode).",
)
@click.option(
    "--no-network",
    is_flag=True,
    help="Skip live HIBP HTTP connectivity and subscription checks.",
)
@click.pass_context
@handle_errors
def doctor(
    ctx: click.Context,
    offline_db: Path | None,
    mode: str | None,
    ntlm: bool,
    no_network: bool,
) -> None:
    """Verify HIBP API connectivity, subscription, credentials, cache, and offline DB."""
    settings = ctx.obj["settings"]
    cli_api_key: str | None = ctx.obj.get("cli_api_key")
    expected_ntlm: bool | None = True if ntlm else (None if mode is None else mode == "ntlm")
    report = run_doctor(
        api_key=settings.get_api_key(),
        api_key_source=get_api_key_source(api_key=cli_api_key),
        user_agent=settings.user_agent,
        offline_db=offline_db,
        ntlm=expected_ntlm,
        check_network=not no_network,
    )
    render_output(ctx, report)
    if not report.healthy:
        sys.exit(int(ExitCode.ERROR))


def register_extra_commands(cli_group: click.Group) -> None:
    """Register additional CLI commands and command groups on a Click group."""
    cli_group.add_command(auth)
    cli_group.add_command(search)
    cli_group.add_command(account_range)
    cli_group.add_command(password_range)
    cli_group.add_command(domain_verify)
    cli_group.add_command(audit)
    cli_group.add_command(offline)
    cli_group.add_command(domain_report)
    cli_group.add_command(monitor)
    cli_group.add_command(mcp)
    cli_group.add_command(cache)
    cli_group.add_command(completion)
    cli_group.add_command(doctor)
