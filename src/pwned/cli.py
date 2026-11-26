from __future__ import annotations

import sys
from pathlib import Path

import click

from pwned import __version__
from pwned.batch import (
    batch_check_accounts,
    batch_check_passwords,
    load_input_file,
    parse_input_lines,
)
from pwned.cli_commands import register_extra_commands
from pwned.cli_helpers import (
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
from pwned.formatting import OUTPUT_FORMATS, OutputFormat
from pwned.models import DataClassDescription
from pwned.passwords import PwnedPasswordsClient


class _GlobalOptionGroup(click.Group):
    """Allow global options to appear after subcommands."""

    _VALUE_OPTIONS = ("--api-key", "--user-agent", "--format")
    _FLAG_OPTIONS = ("--json", "--cache", "--no-cache")

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
    help="Output format: text, json, jsonl, csv, or table.",
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
    ctx.obj["fmt"] = fmt
    ctx.obj["use_json"] = fmt == "json"
    ctx.obj["use_cache"] = use_cache


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
@click.pass_context
@handle_errors
def breaches(ctx: click.Context, domain: str | None, spam_list: bool | None) -> None:
    """Get all breaches in the system."""
    s = ctx.obj["settings"]
    with HIBPClient(user_agent=s.user_agent, cache=get_cache(ctx)) as client:
        data = client.get_breaches(domain=domain, is_spam_list=spam_list)
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


def _run_account_single(
    ctx: click.Context,
    account: str,
    *,
    no_truncate: bool,
    domain: str | None,
    no_include_unverified: bool,
    fail_if_pwned: bool,
) -> None:
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        try:
            data = client.get_account_breaches(
                account,
                truncate=not no_truncate,
                domain=domain,
                include_unverified=not no_include_unverified,
            )
        except NotFoundError:
            if not fail_if_pwned:
                raise
            if get_output_format(ctx) == "text":
                click.echo("Clean (not found in any breaches).")
            else:
                render_output(ctx, [])
            return
    render_output(ctx, data)
    if fail_if_pwned and data:
        sys.exit(1)


@cli.command()
@click.argument("account", required=False)
@click.option("--no-truncate", is_flag=True, help="Return full breach model.")
@click.option("--domain", default=None, help="Filter by domain.")
@click.option("--no-include-unverified", is_flag=True, help="Exclude unverified breaches.")
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
    "--fail-if-pwned",
    is_flag=True,
    help="Exit with code 1 if any account is found in breaches.",
)
@click.pass_context
@handle_errors
def account(
    ctx: click.Context,
    account: str | None,
    no_truncate: bool,
    domain: str | None,
    no_include_unverified: bool,
    input_file: Path | None,
    from_stdin: bool,
    rpm: int | None,
    fail_if_pwned: bool,
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
            fail_if_pwned=fail_if_pwned,
        )
        return

    accounts = (
        load_input_file(input_file) if input_file is not None else parse_input_lines(sys.stdin)
    )
    if not accounts:
        raise click.UsageError("No accounts provided.")

    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        results = batch_check_accounts(
            accounts,
            client,
            rpm=rpm,
            domain=domain,
            include_unverified=not no_include_unverified,
        )
    render_output(ctx, results)
    if fail_if_pwned and any(r.status == "pwned" for r in results):
        sys.exit(1)


@cli.command("domain")
@click.argument("domain")
@click.pass_context
@handle_errors
def domain_cmd(ctx: click.Context, domain: str) -> None:
    """Get breached email addresses for a domain. Requires API key."""
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_domain_breaches(domain)
    render_output(ctx, data)


@cli.command("subscribed-domains")
@click.pass_context
@handle_errors
def subscribed_domains(ctx: click.Context) -> None:
    """List subscribed domains. Requires API key."""
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_subscribed_domains()
    render_output(ctx, data)


@cli.command()
@click.argument("email")
@click.pass_context
@handle_errors
def pastes(ctx: click.Context, email: str) -> None:
    """Get pastes for an email address. Requires API key."""
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_pastes(email)
    render_output(ctx, data)


# --- Stealer log commands ---


@cli.group()
def stealer() -> None:
    """Stealer log searches. Requires API key."""


@stealer.command("email")
@click.argument("email")
@click.pass_context
@handle_errors
def stealer_email(ctx: click.Context, email: str) -> None:
    """Get stealer log domains for an email address."""
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_stealer_logs_by_email(email)
    render_output(ctx, data)


@stealer.command("website")
@click.argument("domain")
@click.pass_context
@handle_errors
def stealer_website(ctx: click.Context, domain: str) -> None:
    """Get stealer log email addresses for a website domain."""
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_stealer_logs_by_website_domain(domain)
    render_output(ctx, data)


@stealer.command("domain")
@click.argument("domain")
@click.pass_context
@handle_errors
def stealer_domain(ctx: click.Context, domain: str) -> None:
    """Get stealer log email aliases for an email domain."""
    s = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_stealer_logs_by_email_domain(domain)
    render_output(ctx, data)


# --- Password command ---


def _check_single_password(
    ctx: click.Context,
    single_password: str,
    *,
    ntlm: bool,
    pad: bool,
    threshold: int,
    fail_if_pwned: bool,
) -> None:
    s = ctx.obj["settings"]
    with PwnedPasswordsClient(user_agent=s.user_agent) as client:
        count = client.check_password(single_password, ntlm=ntlm, pad=pad)
    if get_output_format(ctx) == "text":
        if count > 0:
            click.echo(f"Password found {count:,} times in data breaches!")
        else:
            click.echo("Password not found in any data breaches.")
    else:
        render_output(ctx, {"count": count})
    if fail_if_pwned and count >= threshold:
        sys.exit(1)


def _check_batch_passwords(
    ctx: click.Context,
    passwords: list[str],
    *,
    ntlm: bool,
    pad: bool,
    threshold: int,
    fail_if_pwned: bool,
) -> None:
    s = ctx.obj["settings"]
    with PwnedPasswordsClient(user_agent=s.user_agent) as client:
        results = batch_check_passwords(
            passwords,
            client,
            threshold=threshold,
            ntlm=ntlm,
            pad=pad,
        )
    render_output(ctx, results)
    if fail_if_pwned and any(r.status == "pwned" for r in results):
        sys.exit(1)


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
@click.option("--pad", is_flag=True, help="Request padded responses.")
@click.option(
    "--threshold",
    type=click.IntRange(min=1),
    default=1,
    help="Minimum breach count to treat a password as pwned.",
)
@click.option(
    "--fail-if-pwned",
    is_flag=True,
    help="Exit with code 1 if password count meets threshold.",
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
        passwords = load_input_file(input_file, strip=False, ignore_comments=False)
        if not passwords:
            raise click.UsageError("No passwords provided.")
        _check_batch_passwords(
            ctx,
            passwords,
            ntlm=ntlm,
            pad=pad,
            threshold=threshold,
            fail_if_pwned=fail_if_pwned,
        )
        return

    if from_stdin:
        lines = parse_input_lines(sys.stdin, strip=False, ignore_comments=False)
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
            )
            return
        single_password = lines[0]
    elif password is None:
        single_password = click.prompt("Password", hide_input=True)
    else:
        single_password = password

    _check_single_password(
        ctx,
        single_password,
        ntlm=ntlm,
        pad=pad,
        threshold=threshold,
        fail_if_pwned=fail_if_pwned,
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
