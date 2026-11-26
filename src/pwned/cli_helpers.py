from __future__ import annotations

import sys
from collections.abc import Callable
from functools import wraps
from typing import Any

import click
from pydantic import ValidationError

from pwned.cache import ResponseCache
from pwned.client import HIBPError, NotFoundError, UnauthorizedError
from pwned.formatting import OutputFormat, format_output


def handle_errors[**P, R](f: Callable[P, R]) -> Callable[P, R]:
    @wraps(f)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return f(*args, **kwargs)
        except NotFoundError as e:
            detail = str(e)
            msg = "Not found." if detail in ("", "Not found") else f"Not found: {detail}"
            click.echo(msg, err=True)
            sys.exit(1)
        except UnauthorizedError as e:
            detail = str(e) or "Invalid or missing API key"
            suffix = "" if detail.endswith(".") else "."
            click.echo(f"Error: {detail}{suffix}", err=True)
            sys.exit(1)
        except HIBPError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        except ValidationError as e:
            click.echo(f"Error: API response did not match expected schema: {e}", err=True)
            sys.exit(1)

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
