from __future__ import annotations

import sys
from pathlib import Path
from typing import cast

import click

from pwned.audit import ExportSource, audit_entries, load_export
from pwned.cache import ResponseCache
from pwned.cli_helpers import get_output_format, handle_errors, render_output, require_api_key
from pwned.client import HIBPClient
from pwned.config import clear_api_key, get_config_file, mask_api_key, save_api_key
from pwned.models import EmailAlias
from pwned.passwords import PwnedPasswordsClient

_EMAIL_ALIASES = ("admin", "hostmaster", "info", "security", "webmaster")
_AUDIT_SOURCES = ("bitwarden-json", "bitwarden-csv", "csv", "keepass")


def _authed_client(ctx: click.Context) -> HIBPClient:
    settings = ctx.obj["settings"]
    api_key = require_api_key(ctx)
    return HIBPClient(api_key=api_key, user_agent=settings.user_agent)


@click.group()
def auth() -> None:
    """Manage stored HIBP API key credentials."""


@auth.command("set")
@click.argument("api_key", required=False)
def auth_set(api_key: str | None) -> None:
    """Store the HIBP API key in the user config file."""
    key = api_key if api_key is not None else click.prompt("HIBP API key", hide_input=True)
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
        },
    )


@auth.command("clear")
def auth_clear() -> None:
    """Remove the stored API key from the user config file."""
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
    fail_if_pwned: bool,
) -> None:
    """Audit a password-manager export locally via k-anonymity."""
    master_password: str | None = None
    if source == "keepass":
        master_password = click.prompt("KeePass master password", hide_input=True)
    try:
        entries = load_export(
            path,
            source=cast(ExportSource, source),
            master_password=master_password,
        )
    except (ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc

    settings = ctx.obj["settings"]
    with PwnedPasswordsClient(user_agent=settings.user_agent) as pw_client:
        summary = audit_entries(
            entries,
            pw_client,
            threshold=threshold,
            ntlm=ntlm,
            pad=not no_pad,
        )
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


def register_extra_commands(cli_group: click.Group) -> None:
    """Register additional CLI commands and command groups on a Click group."""
    cli_group.add_command(auth)
    cli_group.add_command(search)
    cli_group.add_command(account_range)
    cli_group.add_command(domain_verify)
    cli_group.add_command(audit)
    cli_group.add_command(cache)
