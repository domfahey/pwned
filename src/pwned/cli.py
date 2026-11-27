from __future__ import annotations

import asyncio
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click

from pwned import __version__
from pwned.baseline import (
    diff_account_batch,
    diff_breaches,
    diff_domain_breaches,
    load_baseline,
    save_baseline,
)
from pwned.batch import (
    AccountBatchItem,
    PasswordBatchItem,
    async_batch_check_passwords,
    batch_check_accounts,
    batch_check_passwords,
    compute_batch_stats,
    format_batch_stats,
    load_input_file,
    parse_input_lines,
)
from pwned.cache import ResponseCache
from pwned.cli_commands import register_extra_commands
from pwned.cli_helpers import (
    ExitCode,
    FileOrStoreError,
    get_cache,
    get_output_format,
    render_output,
    require_api_key,
)
from pwned.cli_helpers import (
    handle_errors as handle_errors,
)
from pwned.client import HIBPClient, NotFoundError
from pwned.config import load_settings
from pwned.filtering import BREACH_SORT_KEYS, BreachSortKey, filter_breaches
from pwned.formatting import OUTPUT_FORMATS, OutputFormat, should_use_color
from pwned.models import Breach, DataClassDescription
from pwned.notify import WEBHOOK_FORMATS, WebhookFormat, send_webhook_notification
from pwned.offline import OfflinePasswordsClient
from pwned.passwords import AsyncPwnedPasswordsClient, PwnedPasswordsClient


class _GlobalOptionGroup(click.Group):
    """Allow global options to appear after subcommands and resolve short aliases."""

    _VALUE_OPTIONS = ("--api-key", "--user-agent", "--format")
    _FLAG_OPTIONS = ("--json", "--cache", "--no-cache")
    _ALIASES: dict[str, str] = {
        "pw": "password",
        "ba": "account",
        "bar": "account-range",
        "pa": "pastes",
        "bd": "domain",
        "sd": "subscribed-domains",
        "lb": "latest-breach",
        "dc": "dataclasses",
    }

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        return super().get_command(ctx, self._ALIASES.get(cmd_name, cmd_name))

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        reordered: list[str] = []
        rest: list[str] = []
        it = iter(args)
        for arg in it:
            if arg == "--":
                rest.append(arg)
                rest.extend(it)
                break
            if arg in self._FLAG_OPTIONS:
                reordered.append(arg)
            elif arg in self._VALUE_OPTIONS:
                val = next(it, None)
                if val is None:
                    raise click.UsageError(f"Option '{arg}' requires an argument.", ctx=ctx)
                reordered.extend((arg, val))
            elif any(arg.startswith(f"{opt}=") for opt in self._VALUE_OPTIONS):
                reordered.append(arg)
            else:
                rest.append(arg)
        return super().parse_args(ctx, reordered + rest)


@click.group(cls=_GlobalOptionGroup)
@click.version_option(version=__version__, prog_name="pwned")
@click.option(
    "--api-key",
    default=None,
    help=(
        "HIBP API key [env: HIBP_API_KEY]. Prefer env var or .env to avoid process-table exposure."
    ),
)
@click.option(
    "--user-agent",
    default=None,
    help="User-Agent string [env: HIBP_USER_AGENT].",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(OUTPUT_FORMATS),
    default=None,
    help="Output format: text, json, jsonl, csv, table, sarif, markdown, or html.",
)
@click.option(
    "--json",
    "use_json",
    is_flag=True,
    help="Output raw JSON (shorthand for --format json).",
)
@click.option(
    "--cache/--no-cache",
    "use_cache",
    default=False,
    help="Cache public endpoint responses locally.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    api_key: str | None,
    user_agent: str | None,
    output_format: OutputFormat | None,
    use_json: bool,
    use_cache: bool,
) -> None:
    """CLI for the Have I Been Pwned API v3."""
    if output_format is not None and use_json and output_format != "json":
        raise click.UsageError("Cannot combine --json with a non-json --format.")
    fmt: OutputFormat = "json" if use_json else (output_format or "text")
    settings = load_settings(api_key=api_key, user_agent=user_agent)
    ctx.ensure_object(dict)
    ctx.obj["settings"] = settings
    ctx.obj["cli_api_key"] = api_key
    ctx.obj["fmt"] = fmt
    ctx.obj["use_json"] = fmt == "json"
    ctx.obj["use_cache"] = use_cache


def _apply_breach_filters(
    breaches_list: list[Breach],
    *,
    since: str | None,
    data_class: str | None,
    verified_only: bool,
    exclude_retired: bool,
    sort_by: BreachSortKey | None,
) -> list[Breach]:
    try:
        return filter_breaches(
            breaches_list,
            since=since,
            data_class=data_class,
            verified_only=verified_only,
            exclude_retired=exclude_retired,
            sort_by=sort_by,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc


def _apply_baseline_diff[T](
    current: T,
    baseline_path: Path | None,
    diff_fn: Callable[[T, Any], T],
) -> T:
    if baseline_path is None:
        return current
    try:
        previous = load_baseline(baseline_path)
        return diff_fn(current, previous)
    except ValueError as exc:
        raise FileOrStoreError(str(exc)) from exc


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


# --- Breach commands ---


@cli.command()
@click.argument("name")
@click.pass_context
@handle_errors
def breach(ctx: click.Context, name: str) -> None:
    """Get a single breach by name."""
    s = ctx.obj["settings"]
    with HIBPClient(user_agent=s.user_agent) as client:
        data = client.get_breach(name)
    render_output(ctx, data)


@cli.command()
@click.option("--domain", default=None, help="Filter by domain.")
@click.option(
    "--spam-list/--no-spam-list",
    default=None,
    help="Filter to only spam lists (--spam-list) or exclude them (--no-spam-list).",
)
@click.option("--no-include-unverified", is_flag=True, help="Exclude unverified breaches.")
@click.option("--since", default=None, help="Filter breaches on or after YYYY-MM-DD.")
@click.option(
    "--data-class",
    default=None,
    help="Filter breaches containing a data class (case-insensitive substring).",
)
@click.option("--verified-only", is_flag=True, help="Only include verified breaches.")
@click.option("--exclude-retired", is_flag=True, help="Exclude retired breaches.")
@click.option(
    "--sort",
    "sort_by",
    type=click.Choice(BREACH_SORT_KEYS),
    default=None,
    help="Sort breaches by pwn-count, date, or name.",
)
@click.pass_context
@handle_errors
def breaches(
    ctx: click.Context,
    domain: str | None,
    spam_list: bool | None,
    no_include_unverified: bool,
    since: str | None,
    data_class: str | None,
    verified_only: bool,
    exclude_retired: bool,
    sort_by: BreachSortKey | None,
) -> None:
    """Get all breaches in the system."""
    s = ctx.obj["settings"]
    with HIBPClient(user_agent=s.user_agent, cache=get_cache(ctx)) as client:
        data = client.get_breaches(
            domain=domain,
            is_spam_list=spam_list,
            include_unverified=not no_include_unverified,
        )
    data = _apply_breach_filters(
        data,
        since=since,
        data_class=data_class,
        verified_only=verified_only,
        exclude_retired=exclude_retired,
        sort_by=sort_by,
    )
    render_output(ctx, data)


@cli.command("latest-breach")
@click.pass_context
@handle_errors
def latest_breach(ctx: click.Context) -> None:
    """Get the most recently added breach."""
    s = ctx.obj["settings"]
    with HIBPClient(user_agent=s.user_agent) as client:
        data = client.get_latest_breach()
    render_output(ctx, data)


@cli.command()
@click.option("--descriptions", is_flag=True, help="Include data class descriptions.")
@click.pass_context
@handle_errors
def dataclasses(ctx: click.Context, descriptions: bool) -> None:
    """Get all data classes in the system."""
    s = ctx.obj["settings"]
    with HIBPClient(user_agent=s.user_agent, cache=get_cache(ctx)) as client:
        data: list[str] | list[DataClassDescription] = (
            client.get_data_class_descriptions() if descriptions else client.get_data_classes()
        )
    render_output(ctx, data)


# --- Account commands ---


def _is_stdout_tty() -> bool:
    return sys.stdout.isatty()


def _is_stderr_tty() -> bool:
    return sys.stderr.isatty()


def _echo_status(message: str, *, fg: str) -> None:
    if should_use_color(is_tty=_is_stdout_tty()):
        click.echo(click.style(message, fg=fg))
    else:
        click.echo(message)


def _render_search_result(
    ctx: click.Context,
    data: Any,
    *,
    was_not_found: bool,
    clean_message: str,
    allow_clean_text: bool = True,
) -> None:
    if was_not_found and allow_clean_text and get_output_format(ctx) == "text":
        _echo_status(clean_message, fg="green")
    else:
        render_output(ctx, data)


def _account_progress(idx: int, total: int, item: AccountBatchItem) -> None:
    click.echo(f"[{idx}/{total}] {item.account}: {item.status}", err=True)


def _password_progress(idx: int, total: int, item: PasswordBatchItem) -> None:
    click.echo(f"[{idx}/{total}] #{item.index}: {item.status}", err=True)


def _run_account_single(
    ctx: click.Context,
    account: str,
    *,
    no_truncate: bool,
    domain: str | None,
    no_include_unverified: bool,
    since: str | None,
    data_class: str | None,
    verified_only: bool,
    exclude_retired: bool,
    sort_by: BreachSortKey | None,
    baseline: Path | None,
    save_baseline_path: Path | None,
    fail_if_pwned: bool,
    notify_webhook: str | None = None,
    webhook_format: WebhookFormat = "auto",
) -> None:
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    was_not_found = False
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        try:
            data = client.get_account_breaches(
                account,
                truncate=not no_truncate,
                domain=domain,
                include_unverified=not no_include_unverified,
            )
        except NotFoundError:
            data = []
            was_not_found = True

    data = _apply_breach_filters(
        data,
        since=since,
        data_class=data_class,
        verified_only=verified_only,
        exclude_retired=exclude_retired,
        sort_by=sort_by,
    )
    if save_baseline_path is not None:
        save_baseline(save_baseline_path, data)
    data = _apply_baseline_diff(data, baseline, diff_breaches)

    _render_search_result(
        ctx,
        data,
        was_not_found=was_not_found,
        clean_message="Clean (not found in any breaches).",
        allow_clean_text=baseline is None,
    )
    _maybe_notify(
        notify_webhook,
        webhook_format,
        data,
        title=f"pwned Account Alert: {account}",
    )
    if fail_if_pwned and data:
        sys.exit(int(ExitCode.FINDINGS))


@cli.command()
@click.argument("account", required=False)
@click.option("--no-truncate", is_flag=True, help="Return full breach model.")
@click.option("--domain", default=None, help="Filter by domain.")
@click.option("--no-include-unverified", is_flag=True, help="Exclude unverified breaches.")
@click.option("--since", default=None, help="Filter breaches on or after YYYY-MM-DD.")
@click.option(
    "--data-class",
    default=None,
    help="Filter breaches containing a data class (case-insensitive substring).",
)
@click.option("--verified-only", is_flag=True, help="Only include verified breaches.")
@click.option("--exclude-retired", is_flag=True, help="Exclude retired breaches.")
@click.option(
    "--sort",
    "sort_by",
    type=click.Choice(BREACH_SORT_KEYS),
    default=None,
    help="Sort breaches by pwn-count, date, or name.",
)
@click.option(
    "--file",
    "input_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Read accounts (one per line) from a file.",
)
@click.option(
    "--stdin",
    "from_stdin",
    is_flag=True,
    help="Read accounts (one per line) from stdin.",
)
@click.option(
    "--rpm",
    type=click.IntRange(min=1),
    default=None,
    help="Rate limit in requests per minute for batch mode.",
)
@click.option(
    "--baseline",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Compare results against a saved JSON baseline file.",
)
@click.option(
    "--save-baseline",
    "save_baseline_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Save results to a JSON baseline file.",
)
@click.option(
    "--stats",
    is_flag=True,
    help="Print batch summary statistics to stderr in batch mode.",
)
@click.option(
    "--fail-if-pwned",
    is_flag=True,
    help="Exit with code 8 if any account is found in breaches.",
)
@click.option(
    "--notify-webhook",
    default=None,
    help="HTTPS webhook URL (Slack, Discord, or generic) to notify on exposures.",
)
@click.option(
    "--webhook-format",
    type=click.Choice(WEBHOOK_FORMATS),
    default="auto",
    help="Webhook payload format: auto, slack, discord, or generic.",
)
@click.pass_context
@handle_errors
def account(
    ctx: click.Context,
    account: str | None,
    no_truncate: bool,
    domain: str | None,
    no_include_unverified: bool,
    since: str | None,
    data_class: str | None,
    verified_only: bool,
    exclude_retired: bool,
    sort_by: BreachSortKey | None,
    input_file: Path | None,
    from_stdin: bool,
    rpm: int | None,
    baseline: Path | None,
    save_baseline_path: Path | None,
    stats: bool,
    fail_if_pwned: bool,
    notify_webhook: str | None,
    webhook_format: WebhookFormat,
) -> None:
    """Get breaches for an account (email or username). Requires API key."""
    sources = sum([account is not None, input_file is not None, from_stdin])
    if sources == 0:
        raise click.UsageError("Must provide ACCOUNT, --file, or --stdin.")
    if sources > 1:
        raise click.UsageError("Cannot combine ACCOUNT, --file, and --stdin.")

    if account is not None:
        _run_account_single(
            ctx,
            account,
            no_truncate=no_truncate,
            domain=domain,
            no_include_unverified=no_include_unverified,
            since=since,
            data_class=data_class,
            verified_only=verified_only,
            exclude_retired=exclude_retired,
            sort_by=sort_by,
            baseline=baseline,
            save_baseline_path=save_baseline_path,
            fail_if_pwned=fail_if_pwned,
            notify_webhook=notify_webhook,
            webhook_format=webhook_format,
        )
        return

    if no_truncate:
        raise click.UsageError("Cannot combine --no-truncate with --file or --stdin.")
    if (
        since is not None
        or data_class is not None
        or verified_only
        or exclude_retired
        or sort_by is not None
    ):
        raise click.UsageError("Cannot combine breach filter/sort options with --file or --stdin.")

    accounts = (
        load_input_file(input_file) if input_file is not None else parse_input_lines(sys.stdin)
    )
    if not accounts:
        raise click.UsageError("No accounts provided.")

    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    start = time.monotonic()
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        results = batch_check_accounts(
            accounts,
            client,
            rpm=rpm,
            auto_rpm=rpm is None,
            domain=domain,
            include_unverified=not no_include_unverified,
            on_progress=_account_progress if _is_stderr_tty() else None,
        )
    if save_baseline_path is not None:
        save_baseline(save_baseline_path, results)
    results = _apply_baseline_diff(results, baseline, diff_account_batch)
    if stats:
        elapsed = time.monotonic() - start
        click.echo(
            format_batch_stats(compute_batch_stats(results, elapsed_seconds=elapsed)),
            err=True,
        )
    render_output(ctx, results)
    _maybe_notify(
        notify_webhook,
        webhook_format,
        results,
        title="pwned Batch Account Alert",
    )
    if fail_if_pwned and any(r.status == "pwned" for r in results):
        sys.exit(int(ExitCode.FINDINGS))


@cli.command("domain")
@click.argument("domain")
@click.option(
    "--baseline",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Compare results against a saved JSON baseline file.",
)
@click.option(
    "--save-baseline",
    "save_baseline_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Save results to a JSON baseline file.",
)
@click.option(
    "--fail-if-pwned",
    is_flag=True,
    help="Exit with code 8 if any domain aliases are found in breaches.",
)
@click.option(
    "--notify-webhook",
    default=None,
    help="HTTPS webhook URL (Slack, Discord, or generic) to notify on exposures.",
)
@click.option(
    "--webhook-format",
    type=click.Choice(WEBHOOK_FORMATS),
    default="auto",
    help="Webhook payload format: auto, slack, discord, or generic.",
)
@click.pass_context
@handle_errors
def domain_cmd(
    ctx: click.Context,
    domain: str,
    baseline: Path | None,
    save_baseline_path: Path | None,
    fail_if_pwned: bool,
    notify_webhook: str | None,
    webhook_format: WebhookFormat,
) -> None:
    """Get breached email addresses for a domain. Requires API key."""
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    was_not_found = False
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        try:
            data = client.get_domain_breaches(domain)
        except NotFoundError:
            data = {}
            was_not_found = True
    if save_baseline_path is not None:
        save_baseline(save_baseline_path, data)
    data = _apply_baseline_diff(data, baseline, diff_domain_breaches)
    _render_search_result(
        ctx,
        data,
        was_not_found=was_not_found,
        clean_message="Clean (no breached accounts found).",
        allow_clean_text=baseline is None,
    )
    _maybe_notify(
        notify_webhook,
        webhook_format,
        data,
        title=f"pwned Domain Alert: {domain}",
    )
    if fail_if_pwned and data:
        sys.exit(int(ExitCode.FINDINGS))


def _list_subscribed_domains(ctx: click.Context) -> None:
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_subscribed_domains()
    render_output(ctx, data)


@cli.group("subscribed-domains", invoke_without_command=True)
@click.pass_context
@handle_errors
def subscribed_domains(ctx: click.Context) -> None:
    """List or manage subscribed domains. Requires API key."""
    if ctx.invoked_subcommand is None:
        _list_subscribed_domains(ctx)


@subscribed_domains.command("list")
@click.pass_context
@handle_errors
def subscribed_domains_list(ctx: click.Context) -> None:
    """List all subscribed domains."""
    _list_subscribed_domains(ctx)


@subscribed_domains.command("remove")
@click.argument("domain")
@click.pass_context
@handle_errors
def subscribed_domains_remove(ctx: click.Context, domain: str) -> None:
    """Remove a subscribed domain from your account (Pro tier)."""
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        client.remove_subscribed_domain(domain)
    render_output(ctx, {"domain": domain, "removed": True})


@cli.command()
@click.argument("email")
@click.option(
    "--fail-if-pwned",
    is_flag=True,
    help="Exit with code 8 if any pastes are found.",
)
@click.pass_context
@handle_errors
def pastes(ctx: click.Context, email: str, fail_if_pwned: bool) -> None:
    """Get pastes for an email address. Requires API key."""
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    was_not_found = False
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        try:
            data = client.get_pastes(email)
        except NotFoundError:
            data = []
            was_not_found = True
    _render_search_result(
        ctx,
        data,
        was_not_found=was_not_found,
        clean_message="Clean (not found in any pastes).",
    )
    if fail_if_pwned and data:
        sys.exit(int(ExitCode.FINDINGS))


# --- Stealer log commands ---


@cli.group()
def stealer() -> None:
    """Stealer log searches. Requires API key."""


@stealer.command("email")
@click.argument("email")
@click.option(
    "--fail-if-pwned",
    is_flag=True,
    help="Exit with code 8 if any stealer logs are found.",
)
@click.pass_context
@handle_errors
def stealer_email(ctx: click.Context, email: str, fail_if_pwned: bool) -> None:
    """Get stealer log domains for an email address."""
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    was_not_found = False
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        try:
            data = client.get_stealer_logs_by_email(email)
        except NotFoundError:
            data = []
            was_not_found = True
    _render_search_result(
        ctx,
        data,
        was_not_found=was_not_found,
        clean_message="Clean (no stealer log records found).",
    )
    if fail_if_pwned and data:
        sys.exit(int(ExitCode.FINDINGS))


@stealer.command("website")
@click.argument("domain")
@click.option(
    "--fail-if-pwned",
    is_flag=True,
    help="Exit with code 8 if any stealer logs are found.",
)
@click.pass_context
@handle_errors
def stealer_website(ctx: click.Context, domain: str, fail_if_pwned: bool) -> None:
    """Get stealer log email addresses for a website domain."""
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    was_not_found = False
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        try:
            data = client.get_stealer_logs_by_website_domain(domain)
        except NotFoundError:
            data = []
            was_not_found = True
    _render_search_result(
        ctx,
        data,
        was_not_found=was_not_found,
        clean_message="Clean (no stealer log records found).",
    )
    if fail_if_pwned and data:
        sys.exit(int(ExitCode.FINDINGS))


@stealer.command("domain")
@click.argument("domain")
@click.option(
    "--fail-if-pwned",
    is_flag=True,
    help="Exit with code 8 if any stealer logs are found.",
)
@click.pass_context
@handle_errors
def stealer_domain(ctx: click.Context, domain: str, fail_if_pwned: bool) -> None:
    """Get stealer log email aliases for an email domain."""
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    was_not_found = False
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        try:
            data = client.get_stealer_logs_by_email_domain(domain)
        except NotFoundError:
            data = {}
            was_not_found = True
    _render_search_result(
        ctx,
        data,
        was_not_found=was_not_found,
        clean_message="Clean (no stealer log records found).",
    )
    if fail_if_pwned and data:
        sys.exit(int(ExitCode.FINDINGS))


# --- Password command ---


def _check_single_password(
    ctx: click.Context,
    single_password: str,
    *,
    ntlm: bool,
    pad: bool,
    threshold: int,
    fail_if_pwned: bool,
    hashed: bool,
    offline_db: Path | None,
) -> None:
    s = ctx.obj["settings"]
    client_cm: OfflinePasswordsClient | PwnedPasswordsClient = (
        OfflinePasswordsClient(offline_db, ntlm=ntlm)
        if offline_db is not None
        else PwnedPasswordsClient(user_agent=s.user_agent, cache=get_cache(ctx))
    )
    with client_cm as client:
        try:
            count = (
                client.check_hash(single_password, ntlm=ntlm, pad=pad)
                if hashed
                else client.check_password(single_password, ntlm=ntlm, pad=pad)
            )
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
    if get_output_format(ctx) == "text":
        if count > 0:
            _echo_status(f"Password found {count:,} times in data breaches!", fg="red")
        else:
            _echo_status("Password not found in any data breaches.", fg="green")
    else:
        render_output(ctx, {"count": count})
    if fail_if_pwned and count >= threshold:
        sys.exit(int(ExitCode.FINDINGS))


async def _run_async_password_batch(
    passwords: list[str],
    *,
    user_agent: str,
    threshold: int,
    ntlm: bool,
    pad: bool,
    hashed: bool,
    concurrency: int,
    on_progress: Callable[[int, int, PasswordBatchItem], None] | None,
    cache: ResponseCache | None = None,
) -> list[PasswordBatchItem]:
    async with AsyncPwnedPasswordsClient(user_agent=user_agent, cache=cache) as client:
        return await async_batch_check_passwords(
            passwords,
            client,
            threshold=threshold,
            ntlm=ntlm,
            pad=pad,
            hashed=hashed,
            concurrency=concurrency,
            on_progress=on_progress,
        )


def _check_batch_passwords(
    ctx: click.Context,
    passwords: list[str],
    *,
    ntlm: bool,
    pad: bool,
    threshold: int,
    fail_if_pwned: bool,
    hashed: bool,
    offline_db: Path | None,
    concurrency: int,
    stats: bool,
    cache: ResponseCache | None = None,
) -> None:
    s = ctx.obj["settings"]
    on_progress = _password_progress if _is_stderr_tty() else None
    start = time.monotonic()
    if offline_db is not None:
        with OfflinePasswordsClient(offline_db, ntlm=ntlm) as client:
            results = batch_check_passwords(
                passwords,
                client,
                threshold=threshold,
                ntlm=ntlm,
                pad=pad,
                hashed=hashed,
                on_progress=on_progress,
            )
    else:
        results = asyncio.run(
            _run_async_password_batch(
                passwords,
                user_agent=s.user_agent,
                threshold=threshold,
                ntlm=ntlm,
                pad=pad,
                hashed=hashed,
                concurrency=concurrency,
                on_progress=on_progress,
                cache=cache,
            )
        )
    if stats:
        elapsed = time.monotonic() - start
        click.echo(
            format_batch_stats(compute_batch_stats(results, elapsed_seconds=elapsed)),
            err=True,
        )
    render_output(ctx, results)
    if fail_if_pwned and any(r.status == "pwned" for r in results):
        sys.exit(int(ExitCode.FINDINGS))


@cli.command()
@click.argument("password", required=False)
@click.option("--stdin", "from_stdin", is_flag=True, help="Read password from stdin.")
@click.option(
    "--file",
    "input_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Check passwords (one per line) from a file.",
)
@click.option("--ntlm", is_flag=True, help="Use NTLM hash instead of SHA-1.")
@click.option(
    "--pad/--no-pad",
    default=True,
    show_default=True,
    help="Request padded responses to hide response length.",
)
@click.option(
    "--hashed",
    is_flag=True,
    help="Treat input(s) as pre-computed SHA-1 (40 hex) or NTLM (32 hex) hashes.",
)
@click.option(
    "--offline-db",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Query a local sorted HIBP password hash dump instead of the network API.",
)
@click.option(
    "--concurrency",
    type=click.IntRange(min=1),
    default=10,
    help="Maximum concurrent requests in online batch mode.",
)
@click.option(
    "--stats",
    is_flag=True,
    help="Print batch summary statistics to stderr in batch mode.",
)
@click.option(
    "--threshold",
    type=click.IntRange(min=1),
    default=1,
    help="Minimum breach count to treat a password as pwned.",
)
@click.option(
    "--fail-if-pwned",
    is_flag=True,
    help="Exit with code 8 if password count meets threshold.",
)
@click.pass_context
@handle_errors
def password(
    ctx: click.Context,
    password: str | None,
    from_stdin: bool,
    input_file: Path | None,
    ntlm: bool,
    pad: bool,
    hashed: bool,
    offline_db: Path | None,
    concurrency: int,
    stats: bool,
    threshold: int,
    fail_if_pwned: bool,
) -> None:
    """Check if a password has been exposed in data breaches.

    Accepts PASSWORD as an argument, via --stdin, via --file, or prompts interactively.
    Using --stdin, --file, or the interactive prompt avoids exposing the password in the
    process table.
    """
    sources: list[str] = []
    if password is not None:
        sources.append("PASSWORD argument")
    if from_stdin:
        sources.append("--stdin")
    if input_file is not None:
        sources.append("--file")
    if len(sources) > 1:
        raise click.UsageError(f"Cannot specify both {' and '.join(sources)}.")

    if input_file is not None:
        passwords = load_input_file(
            input_file, strip=False, ignore_comments=False, deduplicate=False
        )
        if not passwords:
            raise click.UsageError("No passwords provided.")
        _check_batch_passwords(
            ctx,
            passwords,
            ntlm=ntlm,
            pad=pad,
            threshold=threshold,
            fail_if_pwned=fail_if_pwned,
            hashed=hashed,
            offline_db=offline_db,
            concurrency=concurrency,
            stats=stats,
            cache=get_cache(ctx),
        )
        return

    if from_stdin:
        lines = parse_input_lines(sys.stdin, strip=False, ignore_comments=False, deduplicate=False)
        if not lines:
            raise click.UsageError("No password provided on stdin.")
        if len(lines) > 1:
            _check_batch_passwords(
                ctx,
                lines,
                ntlm=ntlm,
                pad=pad,
                threshold=threshold,
                fail_if_pwned=fail_if_pwned,
                hashed=hashed,
                offline_db=offline_db,
                concurrency=concurrency,
                stats=stats,
                cache=get_cache(ctx),
            )
            return
        single_password = lines[0]
    elif password is None:
        single_password = (
            click.prompt("Hash", hide_input=False, err=True)
            if hashed
            else click.prompt("Password", hide_input=True, err=True)
        )
    else:
        single_password = password

    _check_single_password(
        ctx,
        single_password,
        ntlm=ntlm,
        pad=pad,
        threshold=threshold,
        fail_if_pwned=fail_if_pwned,
        hashed=hashed,
        offline_db=offline_db,
    )


# --- Subscription command ---


@cli.command()
@click.pass_context
@handle_errors
def subscription(ctx: click.Context) -> None:
    """Get current subscription status. Requires API key."""
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_subscription_status()
    render_output(ctx, data)


register_extra_commands(cli)
