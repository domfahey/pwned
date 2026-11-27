from __future__ import annotations

import sys
from collections.abc import Callable
from enum import IntEnum
from functools import wraps
from typing import Any

import click
from pydantic import ValidationError

from pwned.cache import ResponseCache
from pwned.client import (
    BadRequestError,
    ForbiddenError,
    HIBPError,
    NotFoundError,
    RateLimitError,
    UnauthorizedError,
)
from pwned.formatting import OutputFormat, format_output


class ExitCode(IntEnum):
    """Semantic CLI exit codes mirroring the official Have I Been Pwned CLI."""

    OK = 0
    ERROR = 1
    INVALID_USAGE = 2
    AUTH_ERROR = 3
    FORBIDDEN = 4
    RATE_LIMITED = 5
    NETWORK_ERROR = 6
    FILE_OR_STORE_ERROR = 7
    FINDINGS = 8
    NOT_FOUND = 9
    CANCELLED = 130


class FileOrStoreError(click.ClickException):
    """Click exception for local file, config, vault, or credential-store failures."""

    exit_code = int(ExitCode.FILE_OR_STORE_ERROR)


def handle_errors[**P, R](f: Callable[P, R]) -> Callable[P, R]:
    @wraps(f)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return f(*args, **kwargs)
        except (KeyboardInterrupt, click.Abort):
            click.echo("Cancelled.", err=True)
            sys.exit(int(ExitCode.CANCELLED))
        except NotFoundError as e:
            detail = str(e)
            msg = "Not found." if detail in ("", "Not found") else f"Not found: {detail}"
            click.echo(msg, err=True)
            sys.exit(int(ExitCode.NOT_FOUND))
        except BadRequestError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(int(ExitCode.INVALID_USAGE))
        except UnauthorizedError as e:
            detail = str(e) or "Invalid or missing API key"
            suffix = "" if detail.endswith(".") else "."
            click.echo(f"Error: {detail}{suffix}", err=True)
            sys.exit(int(ExitCode.AUTH_ERROR))
        except ForbiddenError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(int(ExitCode.FORBIDDEN))
        except RateLimitError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(int(ExitCode.RATE_LIMITED))
        except HIBPError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(int(ExitCode.NETWORK_ERROR))
        except OSError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(int(ExitCode.FILE_OR_STORE_ERROR))
        except ValidationError as e:
            click.echo(f"Error: API response did not match expected schema: {e}", err=True)
            sys.exit(int(ExitCode.ERROR))

    return wrapper


def require_api_key(ctx: click.Context) -> str:
    api_key: str | None = ctx.obj["settings"].get_api_key()
    if not api_key:
        raise UnauthorizedError("Invalid or missing API key")
    return api_key


def get_output_format(ctx: click.Context) -> OutputFormat:
    fmt: OutputFormat = ctx.obj.get("fmt", "json" if ctx.obj.get("use_json") else "text")
    return fmt


def render_output(ctx: click.Context, data: Any) -> None:
    formatted = format_output(data, fmt=get_output_format(ctx))
    if formatted or get_output_format(ctx) in ("json", "text", "table"):
        click.echo(formatted)


def get_cache(ctx: click.Context) -> ResponseCache | None:
    if ctx.obj.get("use_cache", False):
        return ResponseCache()
    return None
