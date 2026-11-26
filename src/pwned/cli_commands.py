from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import cast

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
from pwned.cli_helpers import get_output_format, handle_errors, render_output, require_api_key
from pwned.client import HIBPClient
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
from pwned.models import EmailAlias
from pwned.offline import OfflinePasswordsClient
from pwned.passwords import AsyncPwnedPasswordsClient

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
)
_AUTH_BACKENDS = ("file", "keyring")
_COMPLETION_SHELLS = ("bash", "zsh", "fish")


def _authed_client(ctx: click.Context) -> HIBPClient:
    settings = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    return HIBPClient(api_key=api_key, user_agent=settings.user_agent)


@click.group()
def auth() -> None:
    """Manage stored HIBP API key credentials."""


@auth.command("set")
@click.argument("api_key", required=False)
@click.option(
    "--backend",
    type=click.Choice(_AUTH_BACKENDS),
    default="file",
    show_default=True,
    help="Credential storage backend.",
)
def auth_set(api_key: str | None, backend: str) -> None:
    """Store the HIBP API key in the user config file or OS keyring."""
    key = api_key if api_key is not None else click.prompt("HIBP API key", hide_input=True)
    if backend == "keyring":
        try:
            save_api_key_keyring(key)
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
        except RuntimeError as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo("Saved API key to OS keyring.")
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
    render_output(
        ctx,
        {
            "api_key": mask_api_key(key),
            "config_file": config_file,
            "configured": bool(key),
            "source": get_api_key_source(api_key=ctx.obj.get("cli_api_key")),
            "keyring_available": keyring_available(),
        },
    )


@auth.command("clear")
@click.option(
    "--backend",
    type=click.Choice(_AUTH_BACKENDS),
    default="file",
    show_default=True,
    help="Credential storage backend.",
)
def auth_clear(backend: str) -> None:
    """Remove the stored API key from the user config file or OS keyring."""
    if backend == "keyring":
        try:
            removed = clear_api_key_keyring()
        except RuntimeError as exc:
            raise click.ClickException(str(exc)) from exc
        if removed:
            click.echo("API key removed from OS keyring.")
        else:
            click.echo("No stored API key found in OS keyring.")
        return

    if clear_api_key():
        click.echo("API key removed.")
    else:
        click.echo("No stored API key found.")


@click.command()
@click.argument("account")
@click.option("--no-truncate", is_flag=True, help="Return full breach model.")
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
@click.option("--fail-if-pwned", is_flag=True, help="Exit with code 1 if exposed.")
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
            raise click.ClickException(str(exc)) from exc
    render_output(ctx, result)
    if fail_if_pwned and (result.breaches or result.pastes or result.stealer_logs):
        sys.exit(1)


@click.command("account-range")
@click.argument("email")
@click.option("--fail-if-pwned", is_flag=True, help="Exit with code 1 if breached.")
@click.pass_context
@handle_errors
def account_range(ctx: click.Context, email: str, fail_if_pwned: bool) -> None:
    """Check breached sites for an email using k-anonymity range search."""
    with _authed_client(ctx) as client:
        breaches = client.check_account_range(email)
    render_output(ctx, breaches)
    if fail_if_pwned and breaches:
        sys.exit(1)


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
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--source",
    type=click.Choice(_AUDIT_SOURCES),
    default="bitwarden-json",
    show_default=True,
    help="Password manager export format.",
)
@click.option("--ntlm", is_flag=True, help="Use NTLM hashes instead of SHA-1.")
@click.option("--no-pad", is_flag=True, default=False, help="Disable response padding.")
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
    "--concurrency",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Maximum concurrent Pwned Passwords requests.",
)
@click.option(
    "--offline-db",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a local HIBP password dump file for offline checking.",
)
@click.option("--fail-if-pwned", is_flag=True, help="Exit with code 1 if compromised.")
@click.pass_context
@handle_errors
def audit(
    ctx: click.Context,
    path: Path,
    source: str,
    ntlm: bool,
    no_pad: bool,
    threshold: int,
    check_reuse: bool,
    concurrency: int,
    offline_db: Path | None,
    fail_if_pwned: bool,
) -> None:
    """Audit a password-manager export locally via k-anonymity."""
    master_password: str | None = None
    if source == "keepass":
        master_password = click.prompt("KeePass master password", hide_input=True)
    elif source == "bitwarden-encrypted-json":
        master_password = click.prompt("Bitwarden export password", hide_input=True)
    try:
        entries = load_export(
            path,
            source=cast(ExportSource, source),
            master_password=master_password,
        )
    except (ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc

    settings = ctx.obj["settings"]
    if offline_db is not None:
        with OfflinePasswordsClient(offline_db, ntlm=ntlm) as offline_client:
            summary = audit_entries(
                entries,
                offline_client,
                threshold=threshold,
                ntlm=ntlm,
                pad=not no_pad,
                check_reuse=check_reuse,
            )
    else:

        async def _run_online_audit() -> AuditSummary:
            async with AsyncPwnedPasswordsClient(user_agent=settings.user_agent) as pw_client:
                return await async_audit_entries(
                    entries,
                    pw_client,
                    threshold=threshold,
                    ntlm=ntlm,
                    pad=not no_pad,
                    check_reuse=check_reuse,
                    concurrency=concurrency,
                )

        summary = asyncio.run(_run_online_audit())
    render_output(ctx, summary)
    if fail_if_pwned and summary.compromised_entries > 0:
        sys.exit(1)


@click.group()
def cache() -> None:
    """Manage the local response cache."""


@cache.command("clear")
@click.pass_context
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


def register_extra_commands(cli_group: click.Group) -> None:
    """Register additional CLI commands and command groups on a Click group."""
    cli_group.add_command(auth)
    cli_group.add_command(search)
    cli_group.add_command(account_range)
    cli_group.add_command(domain_verify)
    cli_group.add_command(audit)
    cli_group.add_command(cache)
    cli_group.add_command(completion)
