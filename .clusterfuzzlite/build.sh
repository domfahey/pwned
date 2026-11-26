#!/bin/bash -eu
pip3 install --no-cache-dir --require-hashes -r "$SRC/pwned/.clusterfuzzlite/requirements.txt"
PYTHONPATH="$SRC/pwned/src" compile_python_fuzzer "$SRC/pwned/.clusterfuzzlite/fuzz_parsers.py" --paths="$SRC/pwned/src"
