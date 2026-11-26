from __future__ import annotations

import json
import sys
from collections.abc import Callable
from functools import wraps
from html.parser import HTMLParser
from typing import Any

import click
from pydantic import BaseModel, ValidationError

from pwned import __version__
from pwned.client import HIBPClient, HIBPError, NotFoundError, UnauthorizedError
from pwned.config import load_settings
from pwned.passwords import PwnedPasswordsClient


class _HTMLStripper(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self._parts.append(data)

    def get_text(self) -> str:
        return "".join(self._parts)


def _strip_html(text: str) -> str:
    stripper = _HTMLStripper()
    stripper.feed(text)
    stripper.close()
    return stripper.get_text()


def handle_errors[**P, R](f: Callable[P, R]) -> Callable[P, R]:
    @wraps(f)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return f(*args, **kwargs)
        except NotFoundError:
            click.echo("Not found.", err=True)
            sys.exit(1)
        except UnauthorizedError:
            click.echo("Error: Invalid or missing API key.", err=True)
            sys.exit(1)
        except HIBPError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        except ValidationError as e:
            click.echo(f"Error: API response did not match expected schema: {e}", err=True)
            sys.exit(1)

    return wrapper


def _require_api_key(ctx: click.Context) -> str:
    api_key: str | None = ctx.obj["settings"].get_api_key()
    if not api_key:
        raise UnauthorizedError("Invalid or missing API key")
    return api_key


def _serialize(data: Any) -> Any:
    """Convert Pydantic models to JSON-safe dicts, using field aliases as keys."""
    if isinstance(data, BaseModel):
        return data.model_dump(by_alias=True, exclude_unset=True, mode="json")
    if isinstance(data, list):
        return [_serialize(item) for item in data]
    return data


def _output(data: BaseModel | list[Any] | dict[str, Any], *, use_json: bool) -> None:
    serialized = _serialize(data)
    if use_json:
        click.echo(json.dumps(serialized, indent=2))
    elif isinstance(serialized, list):
        if not serialized:
            click.echo("No results found.")
            return
        for i, item in enumerate(serialized):
            if isinstance(item, dict):
                if i > 0:
                    click.echo()
                _print_dict(item)
            else:
                click.echo(item)
    else:
        if not serialized:
            click.echo("No results found.")
            return
        _print_dict(serialized)


def _print_dict(d: dict[str, Any]) -> None:
    for key, value in d.items():
        if isinstance(value, list):
            click.echo(f"  {key}: {', '.join(str(v) for v in value)}")
        elif key == "Description" and isinstance(value, str):
            click.echo(f"  {key}: {_strip_html(value)}")
        else:
            click.echo(f"  {key}: {value}")


class _GlobalOptionGroup(click.Group):
    """Allow global options (--api-key, --user-agent, --json) to appear after subcommands."""

    _VALUE_OPTIONS = ("--api-key", "--user-agent")
    _FLAG_OPTIONS = ("--json",)

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
@click.option("--json", "use_json", is_flag=True, help="Output raw JSON.")
@click.pass_context
def cli(ctx: click.Context, api_key: str | None, user_agent: str | None, use_json: bool) -> None:
    """CLI for the Have I Been Pwned API v3."""
    settings = load_settings(api_key=api_key, user_agent=user_agent)
    ctx.ensure_object(dict)
    ctx.obj["settings"] = settings
    ctx.obj["use_json"] = use_json


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
    _output(data, use_json=ctx.obj["use_json"])


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
    with HIBPClient(user_agent=s.user_agent) as client:
        data = client.get_breaches(domain=domain, is_spam_list=spam_list)
    _output(data, use_json=ctx.obj["use_json"])


@cli.command("latest-breach")
@click.pass_context
@handle_errors
def latest_breach(ctx: click.Context) -> None:
    """Get the most recently added breach."""
    s = ctx.obj["settings"]
    with HIBPClient(user_agent=s.user_agent) as client:
        data = client.get_latest_breach()
    _output(data, use_json=ctx.obj["use_json"])


@cli.command()
@click.pass_context
@handle_errors
def dataclasses(ctx: click.Context) -> None:
    """Get all data classes in the system."""
    s = ctx.obj["settings"]
    with HIBPClient(user_agent=s.user_agent) as client:
        data = client.get_data_classes()
    _output(data, use_json=ctx.obj["use_json"])


# --- Account commands ---


@cli.command()
@click.argument("account")
@click.option("--no-truncate", is_flag=True, help="Return full breach model.")
@click.option("--domain", default=None, help="Filter by domain.")
@click.option("--no-include-unverified", is_flag=True, help="Exclude unverified breaches.")
@click.pass_context
@handle_errors
def account(
    ctx: click.Context,
    account: str,
    no_truncate: bool,
    domain: str | None,
    no_include_unverified: bool,
) -> None:
    """Get breaches for an account (email or username). Requires API key."""
    s = ctx.obj["settings"]
    api_key = _require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_account_breaches(
            account,
            truncate=not no_truncate,
            domain=domain,
            include_unverified=not no_include_unverified,
        )
    _output(data, use_json=ctx.obj["use_json"])


@cli.command("domain")
@click.argument("domain")
@click.pass_context
@handle_errors
def domain_cmd(ctx: click.Context, domain: str) -> None:
    """Get breached email addresses for a domain. Requires API key."""
    s = ctx.obj["settings"]
    api_key = _require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_domain_breaches(domain)
    _output(data, use_json=ctx.obj["use_json"])


@cli.command("subscribed-domains")
@click.pass_context
@handle_errors
def subscribed_domains(ctx: click.Context) -> None:
    """List subscribed domains. Requires API key."""
    s = ctx.obj["settings"]
    api_key = _require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_subscribed_domains()
    _output(data, use_json=ctx.obj["use_json"])


@cli.command()
@click.argument("email")
@click.pass_context
@handle_errors
def pastes(ctx: click.Context, email: str) -> None:
    """Get pastes for an email address. Requires API key."""
    s = ctx.obj["settings"]
    api_key = _require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_pastes(email)
    _output(data, use_json=ctx.obj["use_json"])


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
    api_key = _require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_stealer_logs_by_email(email)
    _output(data, use_json=ctx.obj["use_json"])


@stealer.command("website")
@click.argument("domain")
@click.pass_context
@handle_errors
def stealer_website(ctx: click.Context, domain: str) -> None:
    """Get stealer log email addresses for a website domain."""
    s = ctx.obj["settings"]
    api_key = _require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_stealer_logs_by_website_domain(domain)
    _output(data, use_json=ctx.obj["use_json"])


@stealer.command("domain")
@click.argument("domain")
@click.pass_context
@handle_errors
def stealer_domain(ctx: click.Context, domain: str) -> None:
    """Get stealer log email aliases for an email domain."""
    s = ctx.obj["settings"]
    api_key = _require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_stealer_logs_by_email_domain(domain)
    _output(data, use_json=ctx.obj["use_json"])


# --- Password command ---


@cli.command()
@click.argument("password", required=False)
@click.option("--stdin", "from_stdin", is_flag=True, help="Read password from stdin.")
@click.option("--ntlm", is_flag=True, help="Use NTLM hash instead of SHA-1.")
@click.option("--pad", is_flag=True, help="Request padded responses.")
@click.pass_context
@handle_errors
def password(
    ctx: click.Context,
    password: str | None,
    from_stdin: bool,
    ntlm: bool,
    pad: bool,
) -> None:
    """Check if a password has been exposed in data breaches.

    Accepts PASSWORD as an argument, via --stdin, or prompts interactively.
    Using --stdin or the interactive prompt avoids exposing the password in the
    process table.
    """
    if from_stdin and password is not None:
        raise click.UsageError("Cannot specify both PASSWORD argument and --stdin.")
    if from_stdin:
        password = click.get_text_stream("stdin").readline().removesuffix("\n").removesuffix("\r")
        if not password:
            raise click.UsageError("No password provided on stdin.")
    elif password is None:
        password = click.prompt("Password", hide_input=True)
    s = ctx.obj["settings"]
    with PwnedPasswordsClient(user_agent=s.user_agent) as client:
        count = client.check_password(password, ntlm=ntlm, pad=pad)
    if ctx.obj["use_json"]:
        click.echo(json.dumps({"count": count}, indent=2))
    elif count > 0:
        click.echo(f"Password found {count:,} times in data breaches!")
    else:
        click.echo("Password not found in any data breaches.")


# --- Subscription command ---


@cli.command()
@click.pass_context
@handle_errors
def subscription(ctx: click.Context) -> None:
    """Get current subscription status. Requires API key."""
    s = ctx.obj["settings"]
    api_key = _require_api_key(ctx)
    with HIBPClient(api_key=api_key, user_agent=s.user_agent) as client:
        data = client.get_subscription_status()
    _output(data, use_json=ctx.obj["use_json"])
