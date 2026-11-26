from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from pwned.client import HIBPClient, HIBPError, NotFoundError
from pwned.formatting import format_output
from pwned.models import Breach, Paste, SearchResult
from pwned.monitor import (
    MonitorAccountResult,
    MonitorAccountTarget,
    MonitorConfig,
    MonitorDomainResult,
    MonitorDomainTarget,
    MonitorNotifyConfig,
    MonitorReport,
    load_monitor_config,
    run_monitor,
)


def _account_hash(email: str) -> str:
    return hashlib.sha256(email.lower().encode("utf-8")).hexdigest()[:16]


def _domain_hash(domain: str) -> str:
    return hashlib.sha256(domain.lower().encode("utf-8")).hexdigest()[:16]


class _StubHIBPClient:
    """Minimal stub implementing the HIBPClient methods used by run_monitor."""

    def __init__(
        self,
        *,
        accounts: dict[str, SearchResult | Exception] | None = None,
        domain_breaches: dict[str, dict[str, list[str]] | Exception] | None = None,
        domain_stealer_logs: dict[str, dict[str, list[str]] | Exception] | None = None,
    ) -> None:
        self._accounts = accounts or {}
        self._domain_breaches = domain_breaches or {}
        self._domain_stealer_logs = domain_stealer_logs or {}
        self.account_calls: list[dict[str, Any]] = []
        self.domain_breach_calls: list[str] = []
        self.domain_stealer_calls: list[str] = []

    def search_account(
        self,
        account: str,
        *,
        truncate: bool = True,
        domain: str | None = None,
        include_unverified: bool = True,
        include_stealer_logs: bool = False,
    ) -> SearchResult:
        self.account_calls.append(
            {
                "account": account,
                "truncate": truncate,
                "domain": domain,
                "include_unverified": include_unverified,
                "include_stealer_logs": include_stealer_logs,
            }
        )
        outcome = self._accounts[account]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def get_domain_breaches(self, domain: str) -> dict[str, list[str]]:
        self.domain_breach_calls.append(domain)
        outcome = self._domain_breaches[domain]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def get_stealer_logs_by_email_domain(self, domain: str) -> dict[str, list[str]]:
        self.domain_stealer_calls.append(domain)
        outcome = self._domain_stealer_logs[domain]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_monitor_models_validation_and_immutability() -> None:
    account = MonitorAccountTarget(email="  alice@example.com  ")
    assert account.email == "alice@example.com"
    assert account.include_unverified is True
    assert account.include_stealer_logs is False
    assert account.truncate is True
    assert account.verified_only is False
    assert account.exclude_retired is False

    with pytest.raises(ValidationError):
        account.email = "bob@example.com"
    with pytest.raises(ValidationError):
        MonitorAccountTarget(email="   ")

    domain = MonitorDomainTarget(domain="  example.com  ")
    assert domain.domain == "example.com"
    assert domain.include_stealer_logs is False
    with pytest.raises(ValidationError):
        MonitorDomainTarget(domain="")

    notify = MonitorNotifyConfig()
    assert notify.webhook_url is None
    assert notify.format == "auto"

    cfg = MonitorConfig()
    assert cfg.baseline_dir is None
    assert cfg.cache is False
    assert cfg.format is None
    assert cfg.fail_if_pwned is False
    assert cfg.rpm is None
    assert cfg.accounts == []
    assert cfg.domains == []

    with pytest.raises(ValidationError):
        MonitorConfig(rpm=0)

    acc_res = MonitorAccountResult(email="alice@example.com", status="clean")
    assert acc_res.new_breaches == []
    assert acc_res.new_pastes == []
    assert acc_res.new_stealer_logs == []
    assert acc_res.error is None

    dom_res = MonitorDomainResult(domain="example.com", status="clean")
    assert dom_res.new_aliases == {}
    assert dom_res.new_stealer_logs == {}
    assert dom_res.error is None

    report = MonitorReport(accounts_checked=1, domains_checked=0, new_exposures=0)
    assert report.accounts == []
    assert report.domains == []
    assert report.webhook_sent is False


def test_load_monitor_config_full_and_relative_baseline_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SLACK_TOKEN", "T00/B00/XXX")
    toml_path = tmp_path / "pwned.toml"
    toml_path.write_text(
        """
[monitor]
baseline_dir = ".baselines"
cache = true
format = "json"
fail_if_pwned = true
rpm = 12

[notify]
webhook_url = "https://hooks.slack.com/services/${SLACK_TOKEN}"
format = "slack"

[[accounts]]
email = "alice@example.com"
domain = "adobe.com"
include_unverified = false
include_stealer_logs = true
truncate = false
since = "2020-01-01"
data_class = "Passwords"
verified_only = true
exclude_retired = true

[[domains]]
domain = "example.com"
include_stealer_logs = true
""".strip(),
        encoding="utf-8",
    )

    cfg = load_monitor_config(toml_path)
    assert cfg.baseline_dir == tmp_path / ".baselines"
    assert cfg.cache is True
    assert cfg.format == "json"
    assert cfg.fail_if_pwned is True
    assert cfg.rpm == 12
    assert cfg.notify.webhook_url == "https://hooks.slack.com/services/T00/B00/XXX"
    assert cfg.notify.format == "slack"
    assert len(cfg.accounts) == 1
    assert cfg.accounts[0].email == "alice@example.com"
    assert cfg.accounts[0].domain == "adobe.com"
    assert cfg.accounts[0].include_unverified is False
    assert cfg.accounts[0].include_stealer_logs is True
    assert cfg.accounts[0].truncate is False
    assert cfg.accounts[0].since == "2020-01-01"
    assert cfg.accounts[0].data_class == "Passwords"
    assert cfg.accounts[0].verified_only is True
    assert cfg.accounts[0].exclude_retired is True
    assert len(cfg.domains) == 1
    assert cfg.domains[0].domain == "example.com"
    assert cfg.domains[0].include_stealer_logs is True


def test_load_monitor_config_absolute_baseline_dir_and_env_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    abs_dir = tmp_path / "abs-baselines"
    toml_path = tmp_path / "pwned.toml"
    toml_path.write_text(
        f"""
[monitor]
baseline_dir = "{abs_dir.as_posix()}"

[[domains]]
domain = "example.com"
""".strip(),
        encoding="utf-8",
    )
    cfg = load_monitor_config(toml_path)
    assert cfg.baseline_dir == abs_dir

    # Missing env var
    monkeypatch.delenv("MISSING_HOOK", raising=False)
    toml_path.write_text(
        """
[notify]
webhook_url = "https://example.com/${MISSING_HOOK}"

[[accounts]]
email = "alice@example.com"
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError,
        match="Environment variable 'MISSING_HOOK' referenced in webhook_url is not set.",
    ):
        load_monitor_config(toml_path)

    # Empty env var
    monkeypatch.setenv("EMPTY_HOOK", "")
    toml_path.write_text(
        """
[notify]
webhook_url = "${EMPTY_HOOK}"

[[accounts]]
email = "alice@example.com"
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError, match="Environment variable 'EMPTY_HOOK' referenced in webhook_url is not set."
    ):
        load_monitor_config(toml_path)


def test_load_monitor_config_validation_errors(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_monitor_config(tmp_path / "does_not_exist.toml")

    bad_toml = tmp_path / "bad.toml"
    bad_toml.write_text("[monitor\nbroken =", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid TOML"):
        load_monitor_config(bad_toml)

    no_targets = tmp_path / "empty.toml"
    no_targets.write_text("[monitor]\ncache = true\n", encoding="utf-8")
    with pytest.raises(
        ValueError, match="Monitor config must define at least one account or domain target."
    ):
        load_monitor_config(no_targets)

    bad_monitor_type = tmp_path / "bad_monitor.toml"
    bad_monitor_type.write_text('monitor = "invalid"\n', encoding="utf-8")
    with pytest.raises(ValueError, match=r"\[monitor\]"):
        load_monitor_config(bad_monitor_type)

    bad_notify_type = tmp_path / "bad_notify.toml"
    bad_notify_type.write_text('notify = "invalid"\n', encoding="utf-8")
    with pytest.raises(ValueError, match=r"\[notify\]"):
        load_monitor_config(bad_notify_type)

    bad_accounts_type = tmp_path / "bad_accounts.toml"
    bad_accounts_type.write_text('accounts = "invalid"\n', encoding="utf-8")
    with pytest.raises(ValueError, match=r"\[\[accounts\]\]"):
        load_monitor_config(bad_accounts_type)

    bad_domains_type = tmp_path / "bad_domains.toml"
    bad_domains_type.write_text('domains = "invalid"\n', encoding="utf-8")
    with pytest.raises(ValueError, match=r"\[\[domains\]\]"):
        load_monitor_config(bad_domains_type)

    bad_webhook_type = tmp_path / "bad_webhook.toml"
    bad_webhook_type.write_text(
        "[notify]\nwebhook_url = 123\n\n[[accounts]]\nemail = 'a@b.com'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_monitor_config(bad_webhook_type)

    bad_baseline_type = tmp_path / "bad_baseline.toml"
    bad_baseline_type.write_text(
        "[monitor]\nbaseline_dir = 123\n\n[[accounts]]\nemail = 'a@b.com'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="baseline_dir"):
        load_monitor_config(bad_baseline_type)


def test_run_monitor_accounts_filtering_errors_and_rpm_pacing() -> None:
    cfg = MonitorConfig(
        rpm=60,
        accounts=[
            MonitorAccountTarget(
                email="alice@example.com",
                domain="adobe.com",
                include_unverified=False,
                include_stealer_logs=True,
                truncate=False,
                since="2020-01-01",
                data_class="Passwords",
                verified_only=True,
                exclude_retired=True,
            ),
            MonitorAccountTarget(email="bob@example.com"),
            MonitorAccountTarget(email="carol@example.com"),
        ],
    )

    alice_result = SearchResult(
        breaches=[
            Breach(
                Name="KeepMe",
                BreachDate=date(2022, 5, 1),
                DataClasses=["Passwords"],
                IsVerified=True,
                IsRetired=False,
            ),
            Breach(
                Name="TooOld",
                BreachDate=date(2018, 1, 1),
                DataClasses=["Passwords"],
                IsVerified=True,
                IsRetired=False,
            ),
            Breach(
                Name="Retired",
                BreachDate=date(2023, 1, 1),
                DataClasses=["Passwords"],
                IsVerified=True,
                IsRetired=True,
            ),
        ],
        pastes=[Paste(Source="Pastebin", Id="abc123")],
        stealer_logs=["evil.example"],
    )
    bob_result = SearchResult(breaches=[], pastes=[], stealer_logs=None)

    stub = _StubHIBPClient(
        accounts={
            "alice@example.com": alice_result,
            "bob@example.com": bob_result,
            "carol@example.com": HIBPError("API down"),
        }
    )
    sleeps: list[float] = []

    report = run_monitor(cfg, stub, sleep=sleeps.append)  # type: ignore[arg-type]

    assert sleeps == [1.0, 1.0]
    assert stub.account_calls[0] == {
        "account": "alice@example.com",
        "truncate": False,
        "domain": "adobe.com",
        "include_unverified": False,
        "include_stealer_logs": True,
    }
    assert report.accounts_checked == 3
    assert report.domains_checked == 0
    assert report.new_exposures == 3
    assert report.webhook_sent is False

    assert report.accounts[0] == MonitorAccountResult(
        email="alice@example.com",
        new_breaches=["KeepMe"],
        new_pastes=["Pastebin:abc123"],
        new_stealer_logs=["evil.example"],
        status="pwned",
    )
    assert report.accounts[1] == MonitorAccountResult(
        email="bob@example.com",
        new_breaches=[],
        new_pastes=[],
        new_stealer_logs=[],
        status="clean",
    )
    assert report.accounts[2] == MonitorAccountResult(
        email="carol@example.com",
        new_breaches=[],
        new_pastes=[],
        new_stealer_logs=[],
        status="error",
        error="API down",
    )


def test_run_monitor_domains_and_error_handling() -> None:
    cfg = MonitorConfig(
        domains=[
            MonitorDomainTarget(domain="pwned.example", include_stealer_logs=True),
            MonitorDomainTarget(domain="clean.example", include_stealer_logs=True),
            MonitorDomainTarget(domain="err1.example", include_stealer_logs=True),
            MonitorDomainTarget(domain="err2.example", include_stealer_logs=True),
            MonitorDomainTarget(domain="nologs.example", include_stealer_logs=False),
        ]
    )
    stub = _StubHIBPClient(
        domain_breaches={
            "pwned.example": {"alice": ["Adobe", "LinkedIn"]},
            "clean.example": NotFoundError("Not found"),
            "err1.example": HIBPError("Forbidden"),
            "err2.example": {"bob": ["Canva"]},
            "nologs.example": {},
        },
        domain_stealer_logs={
            "pwned.example": {"alice": ["stealer.site"]},
            "clean.example": NotFoundError("Not found"),
            "err2.example": HIBPError("Stealer error"),
        },
    )

    report = run_monitor(cfg, stub)  # type: ignore[arg-type]

    assert stub.domain_stealer_calls == ["pwned.example", "clean.example", "err2.example"]
    assert report.accounts_checked == 0
    assert report.domains_checked == 5
    assert report.new_exposures == 3
    assert report.domains[0] == MonitorDomainResult(
        domain="pwned.example",
        new_aliases={"alice": ["Adobe", "LinkedIn"]},
        new_stealer_logs={"alice": ["stealer.site"]},
        status="pwned",
    )
    assert report.domains[1] == MonitorDomainResult(
        domain="clean.example",
        new_aliases={},
        new_stealer_logs={},
        status="clean",
    )
    assert report.domains[2] == MonitorDomainResult(
        domain="err1.example",
        new_aliases={},
        new_stealer_logs={},
        status="error",
        error="Forbidden",
    )
    assert report.domains[3] == MonitorDomainResult(
        domain="err2.example",
        new_aliases={},
        new_stealer_logs={},
        status="error",
        error="Stealer error",
    )
    assert report.domains[4] == MonitorDomainResult(
        domain="nologs.example",
        new_aliases={},
        new_stealer_logs={},
        status="clean",
    )


def test_run_monitor_baselines_safe_names_diff_and_save_order(tmp_path: Path) -> None:
    baseline_dir = tmp_path / "baselines"
    traversal_email = "../../etc/passwd@example.com"
    cfg = MonitorConfig(
        baseline_dir=baseline_dir,
        accounts=[MonitorAccountTarget(email=traversal_email, include_stealer_logs=True)],
        domains=[MonitorDomainTarget(domain="Example.COM", include_stealer_logs=True)],
    )

    # First run: save initial baselines and report initial exposures
    stub1 = _StubHIBPClient(
        accounts={
            traversal_email: SearchResult(
                breaches=[Breach(Name="Adobe")],
                pastes=[Paste(Source="Pastebin", Id="1")],
                stealer_logs=["log1"],
            )
        },
        domain_breaches={"Example.COM": {"alice": ["Adobe"]}},
        domain_stealer_logs={"Example.COM": {"alice": ["log1"]}},
    )
    report1 = run_monitor(cfg, stub1, save_baselines=True)  # type: ignore[arg-type]
    assert report1.new_exposures == 5

    acc_file = baseline_dir / f"account_{_account_hash(traversal_email)}.json"
    dom_file = baseline_dir / f"domain_{_domain_hash('Example.COM')}.json"
    assert acc_file.is_file()
    assert dom_file.is_file()
    assert acc_file.parent == baseline_dir
    assert dom_file.parent == baseline_dir

    # Second run with identical results and save_baselines=False -> 0 new exposures
    report2 = run_monitor(cfg, stub1, save_baselines=False)  # type: ignore[arg-type]
    assert report2.new_exposures == 0
    assert report2.accounts[0].status == "clean"
    assert report2.domains[0].status == "clean"

    # Third run with new exposures AND save_baselines=True:
    # Must read prior baseline BEFORE saving so diff only sees newly added items!
    stub2 = _StubHIBPClient(
        accounts={
            traversal_email: SearchResult(
                breaches=[Breach(Name="Adobe"), Breach(Name="LinkedIn")],
                pastes=[Paste(Source="Pastebin", Id="1"), Paste(Source="Ghostbin", Id="2")],
                stealer_logs=["log1", "log2"],
            )
        },
        domain_breaches={"Example.COM": {"alice": ["Adobe", "LinkedIn"]}},
        domain_stealer_logs={"Example.COM": {"alice": ["log1", "log2"]}},
    )
    report3 = run_monitor(cfg, stub2, save_baselines=True)  # type: ignore[arg-type]
    assert report3.new_exposures == 5
    assert report3.accounts[0].new_breaches == ["LinkedIn"]
    assert report3.accounts[0].new_pastes == ["Ghostbin:2"]
    assert report3.accounts[0].new_stealer_logs == ["log2"]
    assert report3.domains[0].new_aliases == {"alice": ["LinkedIn"]}
    assert report3.domains[0].new_stealer_logs == {"alice": ["log2"]}

    # Fourth run after save_baselines=True -> updated baseline has everything, so 0 new
    report4 = run_monitor(cfg, stub2, save_baselines=False)  # type: ignore[arg-type]
    assert report4.new_exposures == 0


def test_run_monitor_corrupt_domain_baseline_raises_value_error(tmp_path: Path) -> None:
    baseline_dir = tmp_path / "baselines"
    baseline_dir.mkdir()
    dom_file = baseline_dir / f"domain_{_domain_hash('example.com')}.json"
    dom_file.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")

    cfg = MonitorConfig(
        baseline_dir=baseline_dir,
        domains=[MonitorDomainTarget(domain="example.com")],
    )
    stub = _StubHIBPClient(domain_breaches={"example.com": {"alice": ["Adobe"]}})

    with pytest.raises(ValueError, match="JSON object"):
        run_monitor(cfg, stub)  # type: ignore[arg-type]


def test_run_monitor_webhooks_and_formatting(httpx_mock: Any) -> None:
    webhook_url = "https://hooks.slack.com/services/T00/B00/XXX"
    override_url = "https://discord.com/api/webhooks/123/token"
    cfg = MonitorConfig(
        notify=MonitorNotifyConfig(webhook_url=webhook_url, format="slack"),
        accounts=[MonitorAccountTarget(email="alice@example.com")],
    )

    # Clean run -> webhook NOT sent
    clean_stub = _StubHIBPClient(accounts={"alice@example.com": SearchResult()})
    with httpx.Client() as wh_client:
        clean_report = run_monitor(
            cfg,
            clean_stub,  # type: ignore[arg-type]
            webhook_client=wh_client,
        )
    assert clean_report.webhook_sent is False
    assert len(httpx_mock.get_requests()) == 0

    # Pwned run with overrides -> webhook sent to override_url with discord format
    httpx_mock.add_response(url=override_url, status_code=200, json={"ok": True})
    pwned_stub = _StubHIBPClient(
        accounts={"alice@example.com": SearchResult(breaches=[Breach(Name="Adobe")])}
    )
    with httpx.Client() as wh_client:
        pwned_report = run_monitor(
            cfg,
            pwned_stub,  # type: ignore[arg-type]
            webhook_url_override=override_url,
            webhook_format_override="discord",
            webhook_client=wh_client,
        )
    assert pwned_report.webhook_sent is True
    req = httpx_mock.get_request()
    assert req is not None
    body = json.loads(req.content.decode("utf-8"))
    assert body["content"] == "pwned Monitor Alert"
    assert "embeds" in body

    # Verify MonitorReport renders cleanly across format_output modes
    md = format_output(pwned_report, fmt="markdown")
    assert "## Monitor Report" in md
    assert "### Accounts" in md
    assert "### Domains" in md
    html_out = format_output(pwned_report, fmt="html")
    assert "<h1>Monitor Report</h1>" in html_out
    json_out = json.loads(format_output(pwned_report, fmt="json"))
    assert json_out["new_exposures"] == 1
    assert json_out["webhook_sent"] is True


def test_run_monitor_with_real_hibp_client_type(httpx_mock: Any) -> None:
    httpx_mock.add_response(
        url="https://haveibeenpwned.com/api/v3/breachedaccount/alice%40example.com",
        status_code=404,
    )
    httpx_mock.add_response(
        url="https://haveibeenpwned.com/api/v3/pasteaccount/alice%40example.com",
        status_code=404,
    )
    cfg = MonitorConfig(accounts=[MonitorAccountTarget(email="alice@example.com")])
    with HIBPClient(api_key="test-key") as client:
        report = run_monitor(cfg, client)
    assert report.accounts_checked == 1
    assert report.new_exposures == 0
    assert report.accounts[0].status == "clean"
