#!/usr/bin/env python3
from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    import _parsers


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024))
    _parsers.strip_html(text)
    _parsers.parse_input_lines(text.splitlines())
    _parsers.parse_input_lines(
        text.splitlines(),
        strip=False,
        ignore_comments=False,
        deduplicate=False,
    )
    _parsers.parse_pwdump_lines(text.splitlines())
    _parsers._parse_range_response(text)

    raw = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 512))
    _parsers._md4(raw)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
