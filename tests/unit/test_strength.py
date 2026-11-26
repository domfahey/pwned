from __future__ import annotations

import pytest

from pwned._parsers import parse_pwdump_lines
from pwned.strength import (
    StrengthResult,
    compute_vault_risk_score,
    evaluate_password_strength,
)


def test_parse_pwdump_lines_valid() -> None:
    lines = [
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
        "CORP\\john.doe:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::",
        "# comment line",
        "",
        "[*] status line",
    ]
    parsed = parse_pwdump_lines(lines)
    assert parsed == [
        ("", "Administrator", "31D6CFE0D16AE931B73C59D7E0C089C0"),
        ("CORP", "john.doe", "8846F7EAEE8FB117AD06BDD830B7586C"),
    ]


def test_parse_pwdump_lines_edge_cases() -> None:
    lines = [
        "short",
        "badrid:abc:lm:31d6cfe0d16ae931b73c59d7e0c089c0:::",
        "badnt:500:lm:not32hexchars:::",
        "\\emptyuser:500:lm:31d6cfe0d16ae931b73c59d7e0c089c0:::",
        "CORP\\   :500:lm:31d6cfe0d16ae931b73c59d7e0c089c0:::",
    ]
    assert parse_pwdump_lines(lines) == []


def test_strength_result_model() -> None:
    res = StrengthResult(score=2, reasons=["Test"], entropy_bits=15.5)
    assert res.score == 2
    assert res.reasons == ["Test"]
    assert res.entropy_bits == 15.5


def test_evaluate_password_strength_empty() -> None:
    res = evaluate_password_strength("")
    assert res.score == 0
    assert res.entropy_bits == 0.0
    assert "Shorter than 8 characters" in res.reasons


def test_evaluate_password_strength_weak() -> None:
    res = evaluate_password_strength("password")
    assert res.score < 3
    assert any("Shorter than 12" in r or "character variety" in r for r in res.reasons)


def test_evaluate_password_strength_patterns_and_context() -> None:
    res = evaluate_password_strength(
        "john1234aaaa",
        context_terms=["john.doe@example.com"],
    )
    assert "Contains account name or username" in res.reasons
    assert "Contains sequential or keyboard pattern" in res.reasons
    assert "Contains repeated characters" in res.reasons


def test_evaluate_password_strength_strong() -> None:
    res = evaluate_password_strength("Tr0ub4dor&3!Secure")
    assert res.score >= 3
    assert res.entropy_bits > 40.0


def test_zxcvbn_integration_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    class MockZxcvbn:
        @staticmethod
        def zxcvbn(password: str, user_inputs: list[str] | None = None) -> dict[str, object]:
            return {
                "score": 1,
                "feedback": {
                    "warning": "Mock warning",
                    "suggestions": ["Mock suggestion", "", "Shorter than 8 characters"],
                },
            }

    monkeypatch.setitem(__import__("sys").modules, "zxcvbn", MockZxcvbn)
    res = evaluate_password_strength("weak")
    assert "Mock warning" in res.reasons
    assert "Mock suggestion" in res.reasons
    assert res.reasons.count("Shorter than 8 characters") == 1
    assert res.score <= 1


def test_zxcvbn_empty_feedback_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    class MockSilentZxcvbn:
        @staticmethod
        def zxcvbn(password: str, user_inputs: list[str] | None = None) -> dict[str, object]:
            return {"score": 4, "feedback": {"warning": "", "suggestions": []}}

    monkeypatch.setitem(__import__("sys").modules, "zxcvbn", MockSilentZxcvbn)
    res = evaluate_password_strength("Tr0ub4dor&3!Secure")
    assert res.score == 4


def test_zxcvbn_exception_handling(monkeypatch: pytest.MonkeyPatch) -> None:
    class MockBadZxcvbn:
        @staticmethod
        def zxcvbn(password: str, user_inputs: list[str] | None = None) -> dict[str, object]:
            raise RuntimeError("zxcvbn error")

    monkeypatch.setitem(__import__("sys").modules, "zxcvbn", MockBadZxcvbn)
    res = evaluate_password_strength("Tr0ub4dor&3!Secure")
    assert res.score >= 3


def test_evaluate_password_strength_various_entropy_tiers() -> None:
    # Length >= 12 with only 2 character classes -> base_score = 3
    res_tier3 = evaluate_password_strength("mxkqzbwp947261")
    assert res_tier3.score == 3
    assert "Limited character variety" not in res_tier3.reasons

    res = evaluate_password_strength("xK9!mP3$vQ7z")
    assert res.score in (3, 4)


def test_evaluate_password_strength_empty_context_terms() -> None:
    res = evaluate_password_strength("password1234", context_terms=["", "ab"])
    assert "Contains account name or username" not in res.reasons


def test_compute_vault_risk_score_valid() -> None:
    assert compute_vault_risk_score(total_entries=0, compromised_entries=0) == 0
    assert (
        compute_vault_risk_score(
            total_entries=100,
            compromised_entries=10,
            reused_entries=20,
            weak_entries=30,
        )
        == 16  # 10*0.6 + 20*0.25 + 30*0.15 = 6 + 5 + 4.5 = 15.5 -> 16
    )


def test_compute_vault_risk_score_clamping_and_validation() -> None:
    assert (
        compute_vault_risk_score(
            total_entries=10,
            compromised_entries=20,
            reused_entries=20,
            weak_entries=20,
        )
        == 100
    )
    with pytest.raises(ValueError):
        compute_vault_risk_score(total_entries=-1, compromised_entries=0)
