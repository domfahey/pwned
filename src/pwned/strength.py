from __future__ import annotations

import math
import re
from collections.abc import Sequence
from typing import Any

from pydantic import Field

from pwned.models import _HIBPBase

_KEYBOARD_RUNS = [
    "qwer",
    "wert",
    "erty",
    "rtyu",
    "tyui",
    "yuio",
    "uiop",
    "asdf",
    "sdfg",
    "dfgh",
    "fghj",
    "ghjk",
    "hjkl",
    "zxcv",
    "xcvb",
    "cvbn",
    "vbnm",
    "1234",
    "2345",
    "3456",
    "4567",
    "5678",
    "6789",
    "7890",
    "abcd",
    "bcde",
    "cdef",
    "defg",
    "efgh",
    "fghi",
    "ghij",
    "hijk",
    "ijkl",
    "jklm",
    "klmn",
    "lmno",
    "mnop",
    "nopq",
    "opqr",
    "pqrs",
    "qrst",
    "rstu",
    "stuv",
    "tuvw",
    "uvwx",
    "vwxy",
    "wxyz",
]


class StrengthResult(_HIBPBase):
    score: int = Field(ge=0, le=4)
    reasons: list[str] = Field(default_factory=list)
    entropy_bits: float = Field(ge=0.0)


def _compute_entropy(password: str) -> float:
    if not password:
        return 0.0
    length = len(password)
    charset_size = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 32

    entropy = length * math.log2(max(charset_size, 1))
    return round(entropy, 2)


def _zxcvbn_evaluate(password: str, user_inputs: list[str]) -> tuple[int, list[str]] | None:
    try:
        zxcvbn_mod: Any = __import__("zxcvbn")
    except ImportError:
        return None

    try:
        res = zxcvbn_mod.zxcvbn(password, user_inputs=user_inputs)
    except Exception:
        return None

    score = int(res.get("score", 0))
    feedback = res.get("feedback", {})
    warning = feedback.get("warning")
    suggestions = feedback.get("suggestions", [])

    reasons: list[str] = []
    if warning:
        reasons.append(str(warning))
    for s in suggestions:
        if s:
            reasons.append(str(s))
    return score, reasons


def evaluate_password_strength(
    password: str, *, context_terms: Sequence[str] = ()
) -> StrengthResult:
    entropy_bits = _compute_entropy(password)
    reasons: list[str] = []

    length = len(password)
    if length == 0 or length < 8:
        reasons.append("Shorter than 8 characters")
    elif length < 12:
        reasons.append("Shorter than 12 characters")

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    classes_count = sum([has_lower, has_upper, has_digit, has_symbol])
    if classes_count <= 1 and length > 0:
        reasons.append("Uses only one character class")
    elif classes_count == 2 and length < 14:
        reasons.append("Limited character variety")

    # Repeated char runs >= 4
    has_repeated = False
    if length >= 4:
        for i in range(length - 3):
            if password[i] == password[i + 1] == password[i + 2] == password[i + 3]:
                has_repeated = True
                break
    if has_repeated:
        reasons.append("Contains repeated characters")

    # Sequential / keyboard patterns
    lower_pw = password.lower()
    has_pattern = False
    for run in _KEYBOARD_RUNS:
        if run in lower_pw or run[::-1] in lower_pw:
            has_pattern = True
            break
    if has_pattern:
        reasons.append("Contains sequential or keyboard pattern")

    # Context overlap
    user_inputs: list[str] = []
    for term in context_terms:
        if not term:
            continue
        user_inputs.append(term)
        # Split emails on @ and .
        tokens = re.split(r"[@.]", term)
        for tok in tokens:
            if len(tok) >= 3:
                user_inputs.append(tok)

    has_context_overlap = False
    for term in user_inputs:
        if term and len(term) >= 3 and term.lower() in lower_pw:
            has_context_overlap = True
            break

    if has_context_overlap:
        reasons.append("Contains account name or username")

    # Baseline score 0..4
    if length == 0 or length < 8 or entropy_bits < 25.0 or classes_count <= 1:
        base_score = 0
    elif length < 12 or entropy_bits < 40.0 or has_repeated or has_pattern or has_context_overlap:
        base_score = 1 if length < 10 else 2
    elif entropy_bits < 60.0 or classes_count < 3:
        base_score = 3
    else:
        base_score = 4

    # Penalize for reasons
    if len(reasons) >= 3 and base_score > 0:
        base_score -= 1

    zxcvbn_res = _zxcvbn_evaluate(password, user_inputs)
    if zxcvbn_res is not None:
        zx_score, zx_reasons = zxcvbn_res
        base_score = min(base_score, zx_score)
        for r in zx_reasons:
            if r not in reasons:
                reasons.append(r)

    return StrengthResult(
        score=max(0, min(4, base_score)),
        reasons=reasons,
        entropy_bits=entropy_bits,
    )


def compute_vault_risk_score(
    *,
    total_entries: int,
    compromised_entries: int,
    reused_entries: int = 0,
    weak_entries: int = 0,
) -> int:
    if total_entries < 0 or compromised_entries < 0 or reused_entries < 0 or weak_entries < 0:
        raise ValueError("Counts cannot be negative")

    if total_entries == 0:
        return 0

    c = min(compromised_entries, total_entries)
    r = min(reused_entries, total_entries)
    w = min(weak_entries, total_entries)

    score_float = (
        (c / total_entries) * 60.0 + (r / total_entries) * 25.0 + (w / total_entries) * 15.0
    )
    rounded = round(score_float)
    return max(0, min(100, rounded))
