from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner
from pydantic import BaseModel

from pwned.cache import ResponseCache
from pwned.cli_helpers import (
    ExitCode,
    FileOrStoreError,
    emit_text,
    get_cache,
    get_output_format,
    handle_errors,
    render_output,
    require_api_key,
    write_output_file,
)
from pwned.client import (
    BadRequestError,
    ForbiddenError,
    HIBPError,
    NotFoundError,
    RateLimitError,
    UnauthorizedError,
)


def _make_ctx(obj: dict[str, Any] | None = None) -> click.Context:
    cmd = click.Command("test")
    return click.Context(cmd, obj={} if obj is None else obj)


class _DummySettings:
    def __init__(self, api_key: str | None) -> None:
        self._api_key = api_key

    def get_api_key(self) -> str | None:
        return self._api_key


class _SampleSchema(BaseModel):
    count: int


class TestExitCodeAndFileOrStoreError:
    def test_exit_codes_match_contract(self) -> None:
        assert int(ExitCode.OK) == 0
        assert int(ExitCode.ERROR) == 1
        assert int(ExitCode.INVALID_USAGE) == 2
        assert int(ExitCode.AUTH_ERROR) == 3
        assert int(ExitCode.FORBIDDEN) == 4
        assert int(ExitCode.RATE_LIMITED) == 5
        assert int(ExitCode.NETWORK_ERROR) == 6
        assert int(ExitCode.FILE_OR_STORE_ERROR) == 7
        assert int(ExitCode.FINDINGS) == 8
        assert int(ExitCode.NOT_FOUND) == 9
        assert int(ExitCode.CANCELLED) == 130

    def test_file_or_store_error_has_exit_code_7(self) -> None:
        err = FileOrStoreError("store failure")
        assert isinstance(err, click.ClickException)
        assert err.exit_code == int(ExitCode.FILE_OR_STORE_ERROR)
        assert err.message == "store failure"


class TestHandleErrors:
    def test_returns_value_and_preserves_metadata(self) -> None:
        @handle_errors
        def add(a: int, *, b: int) -> int:
            return a + b

        assert add.__name__ == "add"
        assert add(2, b=3) == 5

    @pytest.mark.parametrize("exc", [KeyboardInterrupt(), click.Abort()])
    def test_cancel_exceptions_exit_130(
        self,
        exc: BaseException,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        @handle_errors
        def failing() -> None:
            raise exc

        with pytest.raises(SystemExit) as exc_info:
            failing()

        assert exc_info.value.code == int(ExitCode.CANCELLED)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "Cancelled.\n"

    @pytest.mark.parametrize("detail", ["", "Not found"])
    def test_not_found_default_messages_exit_9(
        self,
        detail: str,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        @handle_errors
        def failing() -> None:
            raise NotFoundError(detail)

        with pytest.raises(SystemExit) as exc_info:
            failing()

        assert exc_info.value.code == int(ExitCode.NOT_FOUND)
        assert capsys.readouterr().err == "Not found.\n"

    def test_not_found_custom_detail_exits_9(self, capsys: pytest.CaptureFixture[str]) -> None:
        @handle_errors
        def failing() -> None:
            raise NotFoundError("Account missing")

        with pytest.raises(SystemExit) as exc_info:
            failing()

        assert exc_info.value.code == int(ExitCode.NOT_FOUND)
        assert capsys.readouterr().err == "Not found: Account missing\n"

    def test_bad_request_exits_2(self, capsys: pytest.CaptureFixture[str]) -> None:
        @handle_errors
        def failing() -> None:
            raise BadRequestError("Malformed account")

        with pytest.raises(SystemExit) as exc_info:
            failing()

        assert exc_info.value.code == int(ExitCode.INVALID_USAGE)
        assert capsys.readouterr().err == "Error: Malformed account\n"

    @pytest.mark.parametrize(
        ("message", "expected"),
        [
            ("", "Error: Invalid or missing API key.\n"),
            ("Invalid API key", "Error: Invalid API key.\n"),
            ("Invalid API key.", "Error: Invalid API key.\n"),
        ],
    )
    def test_unauthorized_exits_3(
        self,
        message: str,
        expected: str,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        @handle_errors
        def failing() -> None:
            raise UnauthorizedError(message)

        with pytest.raises(SystemExit) as exc_info:
            failing()

        assert exc_info.value.code == int(ExitCode.AUTH_ERROR)
        assert capsys.readouterr().err == expected

    def test_forbidden_exits_4(self, capsys: pytest.CaptureFixture[str]) -> None:
        @handle_errors
        def failing() -> None:
            raise ForbiddenError("Missing User-Agent")

        with pytest.raises(SystemExit) as exc_info:
            failing()

        assert exc_info.value.code == int(ExitCode.FORBIDDEN)
        assert capsys.readouterr().err == "Error: Missing User-Agent\n"

    def test_rate_limit_exits_5(self, capsys: pytest.CaptureFixture[str]) -> None:
        @handle_errors
        def failing() -> None:
            raise RateLimitError("Rate limit exceeded", retry_after=2)

        with pytest.raises(SystemExit) as exc_info:
            failing()

        assert exc_info.value.code == int(ExitCode.RATE_LIMITED)
        assert capsys.readouterr().err == "Error: Rate limit exceeded\n"

    def test_hibp_error_exits_6(self, capsys: pytest.CaptureFixture[str]) -> None:
        @handle_errors
        def failing() -> None:
            raise HIBPError("Upstream timeout")

        with pytest.raises(SystemExit) as exc_info:
            failing()

        assert exc_info.value.code == int(ExitCode.NETWORK_ERROR)
        assert capsys.readouterr().err == "Error: Upstream timeout\n"

    def test_broken_pipe_error_is_reraised(self, capsys: pytest.CaptureFixture[str]) -> None:
        @handle_errors
        def failing() -> None:
            raise BrokenPipeError("Broken pipe")

        with pytest.raises(BrokenPipeError, match="Broken pipe"):
            failing()

        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    @pytest.mark.parametrize("exc", [OSError("Disk full"), PermissionError("Access denied")])
    def test_other_os_errors_exit_7(
        self,
        exc: OSError,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        @handle_errors
        def failing() -> None:
            raise exc

        with pytest.raises(SystemExit) as exc_info:
            failing()

        assert exc_info.value.code == int(ExitCode.FILE_OR_STORE_ERROR)
        assert capsys.readouterr().err == f"Error: {exc}\n"

    def test_validation_error_exits_1(self, capsys: pytest.CaptureFixture[str]) -> None:
        @handle_errors
        def failing() -> None:
            _SampleSchema.model_validate({"count": "not-an-int"})

        with pytest.raises(SystemExit) as exc_info:
            failing()

        assert exc_info.value.code == int(ExitCode.ERROR)
        assert capsys.readouterr().err.startswith(
            "Error: API response did not match expected schema: "
        )


class TestRequireApiKey:
    def test_returns_api_key_when_configured(self) -> None:
        ctx = _make_ctx({"settings": _DummySettings("my-secret-key")})
        assert require_api_key(ctx) == "my-secret-key"

    @pytest.mark.parametrize("api_key", [None, ""])
    def test_raises_unauthorized_when_missing(self, api_key: str | None) -> None:
        ctx = _make_ctx({"settings": _DummySettings(api_key)})
        with pytest.raises(UnauthorizedError, match="Invalid or missing API key"):
            require_api_key(ctx)


class TestGetOutputFormat:
    def test_returns_explicit_format(self) -> None:
        ctx = _make_ctx({"fmt": "csv", "use_json": True})
        assert get_output_format(ctx) == "csv"

    def test_falls_back_to_json_when_use_json_flag_is_set(self) -> None:
        ctx = _make_ctx({"use_json": True})
        assert get_output_format(ctx) == "json"

    def test_defaults_to_text(self) -> None:
        assert get_output_format(_make_ctx({})) == "text"
        assert get_output_format(_make_ctx({"use_json": False})) == "text"


class TestGetCache:
    def test_returns_cache_when_enabled(self) -> None:
        cache = get_cache(_make_ctx({"use_cache": True}))
        assert isinstance(cache, ResponseCache)

    def test_returns_none_when_disabled_or_unset(self) -> None:
        assert get_cache(_make_ctx({"use_cache": False})) is None
        assert get_cache(_make_ctx({})) is None


class TestWriteOutputFile:
    def test_writes_utf8_and_appends_trailing_newline(self, tmp_path: Path) -> None:
        target = tmp_path / "report.txt"
        write_output_file(target, "héllo — café")

        assert target.read_text(encoding="utf-8") == "héllo — café\n"
        assert list(tmp_path.iterdir()) == [target]

    def test_preserves_existing_trailing_newline(self, tmp_path: Path) -> None:
        target = tmp_path / "report.txt"
        write_output_file(target, "already terminated\n")

        assert target.read_text(encoding="utf-8") == "already terminated\n"

    def test_writes_empty_content_without_newline(self, tmp_path: Path) -> None:
        target = tmp_path / "empty.csv"
        write_output_file(target, "")

        assert target.read_text(encoding="utf-8") == ""

    def test_refuses_existing_file_without_force(self, tmp_path: Path) -> None:
        target = tmp_path / "existing.json"
        target.write_text("original\n", encoding="utf-8")

        with pytest.raises(FileOrStoreError) as exc_info:
            write_output_file(target, "updated")

        assert exc_info.value.exit_code == int(ExitCode.FILE_OR_STORE_ERROR)
        assert exc_info.value.message == (
            f"Output file already exists: {target} (use --force to overwrite)"
        )
        assert target.read_text(encoding="utf-8") == "original\n"

    def test_overwrites_existing_file_with_force(self, tmp_path: Path) -> None:
        target = tmp_path / "existing.json"
        target.write_text("original\n", encoding="utf-8")

        write_output_file(target, "updated", force=True)

        assert target.read_text(encoding="utf-8") == "updated\n"
        assert list(tmp_path.iterdir()) == [target]

    def test_refuses_directory_target(self, tmp_path: Path) -> None:
        with pytest.raises(FileOrStoreError) as exc_info:
            write_output_file(tmp_path, "content", force=True)

        assert exc_info.value.exit_code == int(ExitCode.FILE_OR_STORE_ERROR)
        assert exc_info.value.message == f"Output path is a directory: {tmp_path}"

    def test_refuses_missing_parent_directory(self, tmp_path: Path) -> None:
        missing_parent = tmp_path / "does-not-exist"
        target = missing_parent / "out.json"

        with pytest.raises(FileOrStoreError) as exc_info:
            write_output_file(target, "content")

        assert exc_info.value.exit_code == int(ExitCode.FILE_OR_STORE_ERROR)
        assert exc_info.value.message == f"Output directory does not exist: {missing_parent}"

    def test_cleans_up_temp_file_on_replace_failure(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = tmp_path / "out.json"
        target.write_text("original\n", encoding="utf-8")

        def fail_replace(src: Any, dst: Any) -> None:
            raise OSError("replace failed")

        monkeypatch.setattr(os, "replace", fail_replace)

        with pytest.raises(OSError, match="replace failed"):
            write_output_file(target, "new content", force=True)

        assert target.read_text(encoding="utf-8") == "original\n"
        assert list(tmp_path.iterdir()) == [target]

    def test_cleans_up_temp_file_on_base_exception_during_write(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = tmp_path / "out.txt"
        real_fdopen = os.fdopen

        class _InterruptingHandle:
            def __init__(self, inner: Any) -> None:
                self._inner = inner

            def __enter__(self) -> _InterruptingHandle:
                return self

            def __exit__(self, *args: object) -> None:
                self._inner.close()

            def write(self, data: str) -> int:
                raise KeyboardInterrupt("interrupted mid-write")

        def fake_fdopen(fd: int, mode: str, *, encoding: str) -> _InterruptingHandle:
            return _InterruptingHandle(real_fdopen(fd, mode, encoding=encoding))

        monkeypatch.setattr(os, "fdopen", fake_fdopen)

        with pytest.raises(KeyboardInterrupt, match="interrupted mid-write"):
            write_output_file(target, "hello")

        assert not target.exists()
        assert list(tmp_path.iterdir()) == []

    def test_suppresses_oserror_when_temp_cleanup_fails(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = tmp_path / "out.txt"
        real_unlink = os.unlink

        def fail_replace(src: Any, dst: Any) -> None:
            raise RuntimeError("replace boom")

        def fail_unlink(path: Any) -> None:
            real_unlink(path)
            raise FileNotFoundError("already removed")

        monkeypatch.setattr(os, "replace", fail_replace)
        monkeypatch.setattr(os, "unlink", fail_unlink)

        with pytest.raises(RuntimeError, match="replace boom"):
            write_output_file(target, "hello")

        assert list(tmp_path.iterdir()) == []


class TestRenderOutput:
    @pytest.mark.parametrize(
        ("fmt", "data", "expected_substring"),
        [
            ("json", {"Name": "Adobe"}, '"Name": "Adobe"'),
            ("text", {"Name": "Adobe"}, "Name: Adobe"),
            ("table", {"Name": "Adobe"}, "Field | Value"),
            ("csv", [{"Name": "Adobe"}], "Name\nAdobe"),
        ],
    )
    def test_writes_non_empty_output_to_stdout(
        self,
        fmt: str,
        data: Any,
        expected_substring: str,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ctx = _make_ctx({"fmt": fmt})
        render_output(ctx, data)

        captured = capsys.readouterr()
        assert expected_substring in captured.out
        assert captured.err == ""

    def test_empty_text_still_echoes_newline_to_stdout(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ctx = _make_ctx({"fmt": "text"})
        render_output(ctx, "")

        assert capsys.readouterr().out == "\n"

    def test_empty_json_and_table_echo_to_stdout(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        render_output(_make_ctx({"fmt": "json"}), [])
        assert capsys.readouterr().out == "[]\n"

        render_output(_make_ctx({"fmt": "table"}), [])
        assert capsys.readouterr().out == "No results found.\n"

    def test_empty_csv_emits_nothing_to_stdout(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ctx = _make_ctx({"fmt": "csv"})
        render_output(ctx, [])

        assert capsys.readouterr().out == ""

    def test_writes_formatted_output_to_outfile_instead_of_stdout(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        target = tmp_path / "breaches.json"
        ctx = _make_ctx({"fmt": "json", "outfile": target})

        render_output(ctx, [{"Name": "Adobe"}])

        assert capsys.readouterr().out == ""
        raw = target.read_text(encoding="utf-8")
        assert raw.endswith("\n")
        assert json.loads(raw) == [{"Name": "Adobe"}]

    def test_writes_empty_csv_to_outfile(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        target = tmp_path / "empty.csv"
        ctx = _make_ctx({"fmt": "csv", "outfile": target})

        render_output(ctx, [])

        assert capsys.readouterr().out == ""
        assert target.read_text(encoding="utf-8") == ""

    def test_outfile_respects_force_flag(self, tmp_path: Path) -> None:
        target = tmp_path / "out.json"
        target.write_text("old\n", encoding="utf-8")

        with pytest.raises(FileOrStoreError):
            render_output(_make_ctx({"fmt": "json", "outfile": target}), {"a": 1})

        assert target.read_text(encoding="utf-8") == "old\n"

        render_output(_make_ctx({"fmt": "json", "outfile": target, "force": True}), {"a": 1})
        assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1}


class TestEmitText:
    def test_writes_plain_text_to_outfile_without_ansi_codes(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        target = tmp_path / "status.txt"
        ctx = _make_ctx({"outfile": target})

        emit_text(ctx, "Pwned! Found 42 times.", fg="red", is_tty=True)

        assert capsys.readouterr().out == ""
        content = target.read_text(encoding="utf-8")
        assert content == "Pwned! Found 42 times.\n"
        assert "\x1b[" not in content

    def test_outfile_respects_force_flag(self, tmp_path: Path) -> None:
        target = tmp_path / "status.txt"
        target.write_text("old\n", encoding="utf-8")

        with pytest.raises(FileOrStoreError):
            emit_text(_make_ctx({"outfile": target}), "new", fg="green")

        assert target.read_text(encoding="utf-8") == "old\n"

        emit_text(_make_ctx({"outfile": target, "force": True}), "new", fg="green")
        assert target.read_text(encoding="utf-8") == "new\n"

    def test_stdout_applies_color_when_fg_and_tty_enabled(self, cli_runner: CliRunner) -> None:
        @click.command()
        @click.pass_context
        def cmd(ctx: click.Context) -> None:
            ctx.obj = {}
            emit_text(ctx, "Pwned!", fg="red", is_tty=True)

        result = cli_runner.invoke(cmd, color=True)
        assert result.exit_code == 0
        assert "\x1b[" in result.output
        assert "Pwned!" in result.output

    def test_stdout_omits_color_when_not_tty(self, cli_runner: CliRunner) -> None:
        @click.command()
        @click.pass_context
        def cmd(ctx: click.Context) -> None:
            ctx.obj = {}
            emit_text(ctx, "Pwned!", fg="red", is_tty=False)

        result = cli_runner.invoke(cmd, color=True)
        assert result.exit_code == 0
        assert result.output == "Pwned!\n"

    def test_stdout_omits_color_when_no_color_env_set(
        self,
        cli_runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")

        @click.command()
        @click.pass_context
        def cmd(ctx: click.Context) -> None:
            ctx.obj = {}
            emit_text(ctx, "Pwned!", fg="red", is_tty=True)

        result = cli_runner.invoke(cmd, color=True)
        assert result.exit_code == 0
        assert result.output == "Pwned!\n"

    def test_stdout_omits_color_when_fg_is_none(self, cli_runner: CliRunner) -> None:
        @click.command()
        @click.pass_context
        def cmd(ctx: click.Context) -> None:
            ctx.obj = {}
            emit_text(ctx, "Plain message", fg=None, is_tty=True)

        result = cli_runner.invoke(cmd, color=True)
        assert result.exit_code == 0
        assert result.output == "Plain message\n"
