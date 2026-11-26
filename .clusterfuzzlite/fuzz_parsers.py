#!/usr/bin/env python3
from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from pwned.batch import parse_input_lines
    from pwned.formatting import strip_html
    from pwned.passwords import _md4, _parse_range_response


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024))
    strip_html(text)
    parse_input_lines(text.splitlines())
    _parse_range_response(text)

    raw = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 512))
    _md4(raw)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
