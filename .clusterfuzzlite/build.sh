#!/bin/bash -eu
pip3 install --no-cache-dir .
compile_python_fuzzer "$SRC/pwned/.clusterfuzzlite/fuzz_parsers.py"
