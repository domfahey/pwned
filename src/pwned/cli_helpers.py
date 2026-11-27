from __future__ import annotations

import contextlib
import os
import sys
import tempfile
from collections.abc import Callable
from enum import IntEnum
from functools import wraps
from pathlib import Path
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
from pwned.formatting import OutputFormat, format_output, should_use_color


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
        except BrokenPipeError:
            raise
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


def write_output_file(path: Path, content: str, *, force: bool = False) -> None:
    """Atomically write UTF-8 text to *path*, refusing to clobber unless *force* is set."""
    if path.is_dir():
        raise FileOrStoreError(f"Output path is a directory: {path}")
    if not path.parent.exists():
        raise FileOrStoreError(f"Output directory does not exist: {path.parent}")
    if path.exists() and not force:
        raise FileOrStoreError(f"Output file already exists: {path} (use --force to overwrite)")
    payload = f"{content}\n" if content and not content.endswith("\n") else content
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def render_output(ctx: click.Context, data: Any) -> None:
    fmt = get_output_format(ctx)
    formatted = format_output(data, fmt=fmt)
    outfile: Path | None = ctx.obj.get("outfile")
    if outfile is not None:
        write_output_file(outfile, formatted, force=bool(ctx.obj.get("force", False)))
        return
    if formatted or fmt in ("json", "text", "table"):
        click.echo(formatted)


def emit_text(
    ctx: click.Context,
    message: str,
    *,
    fg: str | None = None,
    is_tty: bool = False,
) -> None:
    outfile: Path | None = ctx.obj.get("outfile")
    if outfile is not None:
        write_output_file(outfile, message, force=bool(ctx.obj.get("force", False)))
        return
    if fg is not None and should_use_color(is_tty=is_tty):
        click.echo(click.style(message, fg=fg))
    else:
        click.echo(message)


def get_cache(ctx: click.Context) -> ResponseCache | None:
    if ctx.obj.get("use_cache", False):
        return ResponseCache()
    return None
