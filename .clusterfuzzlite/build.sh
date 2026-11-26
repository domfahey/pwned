#!/bin/bash -eu
PYTHONPATH="$SRC/pwned/src/pwned" compile_python_fuzzer "$SRC/pwned/.clusterfuzzlite/fuzz_parsers.py" --paths="$SRC/pwned/src/pwned"
