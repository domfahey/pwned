from __future__ import annotations

import hashlib
import json
import smtplib
from datetime import date
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from pwned.client import HIBPClient, HIBPError, NotFoundError
from pwned.formatting import format_output, serialize
from pwned.history import ExposureHistoryStore
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
from pwned.notify import (
    PAGERDUTY_EVENTS_URL,
    EmailNotifyConfig,
    GitHubIssueNotifyConfig,
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
        latest_breach: Breach | Exception | None = None,
    ) -> None:
        self._accounts = accounts or {}
        self._domain_breaches = domain_breaches or {}
        self._domain_stealer_logs = domain_stealer_logs or {}
        self._latest_breach = latest_breach
        self.account_calls: list[dict[str, Any]] = []
        self.domain_breach_calls: list[str] = []
        self.domain_stealer_calls: list[str] = []
        self.latest_breach_calls = 0

    def get_latest_breach(self) -> Breach:
        self.latest_breach_calls += 1
        if isinstance(self._latest_breach, Exception):
            raise self._latest_breach
        if self._latest_breach is None:
            raise AssertionError("latest_breach not configured on stub")
        return self._latest_breach

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


def test_run_monitor_smart_precheck_skips_unchanged_domains_and_handles_edge_cases(
    tmp_path: Path,
) -> None:
    from datetime import UTC, datetime

    baseline_dir = tmp_path / "baselines"
    toml_path = tmp_path / "pwned.toml"
    toml_path.write_text(
        """
[monitor]
baseline_dir = "baselines"
smart_precheck = true

[[domains]]
domain = "example.com"

[[domains]]
domain = "stealer.example"
include_stealer_logs = true
""".strip(),
        encoding="utf-8",
    )
    cfg = load_monitor_config(toml_path)
    assert cfg.smart_precheck is True

    latest_v1 = Breach(
        Name="BreachV1",
        AddedDate=datetime(2026, 1, 1, tzinfo=UTC),
        ModifiedDate=datetime(2026, 1, 2, tzinfo=UTC),
    )
    stub1 = _StubHIBPClient(
        domain_breaches={
            "example.com": {"alice": ["Adobe"]},
            "stealer.example": {"bob": ["Adobe"]},
        },
        domain_stealer_logs={"stealer.example": {"bob": ["log1.test"]}},
        latest_breach=latest_v1,
    )
    # 1. Initial run: no saved marker or baselines -> queries everything and saves marker.
    report1 = run_monitor(cfg, stub1, save_baselines=True)  # type: ignore[arg-type]
    assert stub1.latest_breach_calls == 1
    assert stub1.domain_breach_calls == ["example.com", "stealer.example"]
    assert stub1.domain_stealer_calls == ["stealer.example"]
    assert report1.domains_skipped == 0
    assert report1.new_exposures == 3
    ex_file = baseline_dir / f"domain_{_domain_hash('example.com')}.json"
    st_file = baseline_dir / f"domain_{_domain_hash('stealer.example')}.json"
    assert json.loads(ex_file.read_text(encoding="utf-8"))["latest_breach"]["Name"] == "BreachV1"
    assert json.loads(st_file.read_text(encoding="utf-8"))["latest_breach"]["Name"] == "BreachV1"
    assert not (baseline_dir / "_latest_breach.json").exists()

    # 2. Second run with identical latestBreach: skips domain breach calls,
    # still runs stealer logs for stealer.example and reports new stealer log!
    stub2 = _StubHIBPClient(
        domain_breaches={},
        domain_stealer_logs={"stealer.example": {"bob": ["log1.test", "log2.test"]}},
        latest_breach=latest_v1,
    )
    report2 = run_monitor(cfg, stub2, save_baselines=True)  # type: ignore[arg-type]
    assert stub2.latest_breach_calls == 1
    assert stub2.domain_breach_calls == []
    assert stub2.domain_stealer_calls == ["stealer.example"]
    assert report2.domains_skipped == 2
    assert report2.new_exposures == 1
    assert report2.domains[0] == MonitorDomainResult(domain="example.com", status="clean")
    assert report2.domains[1] == MonitorDomainResult(
        domain="stealer.example",
        new_aliases={},
        new_stealer_logs={"bob": ["log2.test"]},
        status="pwned",
    )

    # 2b. Skipped domain with stealer logs returning 404 or HIBPError handled cleanly.
    stub2_err = _StubHIBPClient(
        domain_breaches={},
        domain_stealer_logs={"stealer.example": NotFoundError("Not found")},
        latest_breach=latest_v1,
    )
    report2_404 = run_monitor(cfg, stub2_err, save_baselines=False)  # type: ignore[arg-type]
    assert report2_404.domains_skipped == 2
    assert report2_404.domains[1].status == "clean"

    stub2_fail = _StubHIBPClient(
        domain_breaches={},
        domain_stealer_logs={"stealer.example": HIBPError("Stealer 503")},
        latest_breach=latest_v1,
    )
    report2_fail = run_monitor(cfg, stub2_fail, save_baselines=False)  # type: ignore[arg-type]
    assert report2_fail.domains_skipped == 2
    assert report2_fail.domains[1].status == "error"
    assert report2_fail.domains[1].error == "Stealer 503"

    # 3. Newly added domain without baseline is NOT skipped even when latestBreach unchanged.
    cfg_with_new = MonitorConfig(
        baseline_dir=baseline_dir,
        smart_precheck=False,
        domains=[
            MonitorDomainTarget(domain="example.com"),
            MonitorDomainTarget(domain="brandnew.example"),
        ],
    )
    stub3 = _StubHIBPClient(
        domain_breaches={"brandnew.example": {"carol": ["Canva"]}},
        latest_breach=latest_v1,
    )
    report3 = run_monitor(
        cfg_with_new,
        stub3,  # type: ignore[arg-type]
        save_baselines=True,
        smart_precheck_override=True,
    )
    assert stub3.domain_breach_calls == ["brandnew.example"]
    assert report3.domains_skipped == 1
    assert report3.new_exposures == 1

    # 4. Per-domain marker: temporarily omit stealer.example while BreachV2 arrives.
    # example.com errors (stays at V1); brandnew.example succeeds (advances to V2).
    latest_v2 = Breach(Name="BreachV2")
    stub4 = _StubHIBPClient(
        domain_breaches={
            "example.com": HIBPError("Upstream 503"),
            "brandnew.example": {"carol": ["Canva"]},
        },
        latest_breach=latest_v2,
    )
    report4 = run_monitor(
        cfg_with_new,
        stub4,  # type: ignore[arg-type]
        save_baselines=True,
        smart_precheck_override=True,
    )
    assert report4.domains_skipped == 0
    assert report4.domains[0].status == "error"
    assert json.loads(ex_file.read_text(encoding="utf-8"))["latest_breach"]["Name"] == "BreachV1"
    bn_file = baseline_dir / f"domain_{_domain_hash('brandnew.example')}.json"
    assert json.loads(bn_file.read_text(encoding="utf-8"))["latest_breach"]["Name"] == "BreachV2"

    # 5. Restoring stealer.example (still stamped V1) alongside brandnew.example (V2)
    # and example.com (still V1): skips ONLY brandnew.example and refreshes both V1 domains!
    cfg_restored = MonitorConfig(
        baseline_dir=baseline_dir,
        smart_precheck=True,
        domains=[
            MonitorDomainTarget(domain="example.com"),
            MonitorDomainTarget(domain="brandnew.example"),
            MonitorDomainTarget(domain="stealer.example"),
        ],
    )
    stub5 = _StubHIBPClient(
        domain_breaches={
            "example.com": {"alice": ["Adobe", "BreachV2"]},
            "stealer.example": {"bob": ["Adobe", "BreachV2"]},
        },
        latest_breach=latest_v2,
    )
    report5 = run_monitor(cfg_restored, stub5, save_baselines=True)  # type: ignore[arg-type]
    assert stub5.domain_breach_calls == ["example.com", "stealer.example"]
    assert report5.domains_skipped == 1
    assert report5.new_exposures == 2
    assert json.loads(ex_file.read_text(encoding="utf-8"))["latest_breach"]["Name"] == "BreachV2"
    assert json.loads(st_file.read_text(encoding="utf-8"))["latest_breach"]["Name"] == "BreachV2"

    # 6. get_latest_breach() raising HIBPError falls back gracefully.
    stub_err_latest = _StubHIBPClient(
        domain_breaches={"example.com": {"alice": ["Adobe", "BreachV2"]}},
        latest_breach=HIBPError("Network timeout"),
    )
    cfg_single = MonitorConfig(
        baseline_dir=baseline_dir,
        smart_precheck=True,
        domains=[MonitorDomainTarget(domain="example.com")],
    )
    report_fallback = run_monitor(cfg_single, stub_err_latest)  # type: ignore[arg-type]
    assert stub_err_latest.domain_breach_calls == ["example.com"]
    assert report_fallback.domains_skipped == 0

    # 7. Corrupt domain baseline JSON raises ValueError instead of silently skipping.
    corrupt_dom_file = baseline_dir / f"domain_{_domain_hash('stealer.example')}.json"
    corrupt_dom_file.write_text(json.dumps(["bad"]), encoding="utf-8")
    cfg_corrupt = MonitorConfig(
        baseline_dir=baseline_dir,
        smart_precheck=True,
        domains=[MonitorDomainTarget(domain="stealer.example")],
    )
    stub_corrupt_dom = _StubHIBPClient(
        domain_breaches={"stealer.example": {}},
        latest_breach=latest_v2,
    )
    with pytest.raises(ValueError, match="JSON object"):
        run_monitor(cfg_corrupt, stub_corrupt_dom)  # type: ignore[arg-type]


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


def test_load_monitor_config_db_path_options_and_validation(tmp_path: Path) -> None:
    assert MonitorConfig().db_path is None

    # Canonical TOML key `monitor.db` (relative path resolved against TOML parent)
    rel_toml = tmp_path / "rel.toml"
    rel_toml.write_text(
        """
[monitor]
db = "state/history.db"

[[accounts]]
email = "alice@example.com"
""".strip(),
        encoding="utf-8",
    )
    rel_cfg = load_monitor_config(rel_toml)
    assert rel_cfg.db_path == tmp_path / "state/history.db"

    # Absolute `monitor.db`
    abs_db = tmp_path / "abs" / "history.db"
    abs_toml = tmp_path / "abs.toml"
    abs_toml.write_text(
        f"""
[monitor]
db = "{abs_db.as_posix()}"

[[domains]]
domain = "example.com"
""".strip(),
        encoding="utf-8",
    )
    abs_cfg = load_monitor_config(abs_toml)
    assert abs_cfg.db_path == abs_db

    # Alternate TOML key `monitor.db_path`
    alt_toml = tmp_path / "alt.toml"
    alt_toml.write_text(
        """
[monitor]
db_path = "alt_history.db"

[[accounts]]
email = "alice@example.com"
""".strip(),
        encoding="utf-8",
    )
    alt_cfg = load_monitor_config(alt_toml)
    assert alt_cfg.db_path == tmp_path / "alt_history.db"

    # Non-string `monitor.db` or `monitor.db_path` raises ValueError
    bad_db_toml = tmp_path / "bad_db.toml"
    bad_db_toml.write_text(
        "[monitor]\ndb = 123\n\n[[accounts]]\nemail = 'alice@example.com'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"monitor\.db must be a string path\."):
        load_monitor_config(bad_db_toml)

    bad_db_path_toml = tmp_path / "bad_db_path.toml"
    bad_db_path_toml.write_text(
        "[monitor]\ndb_path = 456\n\n[[accounts]]\nemail = 'alice@example.com'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"monitor\.db must be a string path\."):
        load_monitor_config(bad_db_path_toml)


def test_run_monitor_without_db_preserves_exclude_unset_contract() -> None:
    cfg = MonitorConfig(accounts=[MonitorAccountTarget(email="alice@example.com")])
    stub = _StubHIBPClient(accounts={"alice@example.com": SearchResult()})

    report = run_monitor(cfg, stub)  # type: ignore[arg-type]
    assert report.resolved_exposures == 0
    assert report.history_summary is None

    dumped = report.model_dump(exclude_unset=True)
    assert "resolved_exposures" not in dumped
    assert "history_summary" not in dumped
    assert "notifications_sent" not in dumped

    serialized = serialize(report)
    assert "resolved_exposures" not in serialized
    assert "history_summary" not in serialized
    assert "notifications_sent" not in serialized


def test_run_monitor_history_tracking_with_baselines_errors_and_precheck(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    baseline_dir = tmp_path / "baselines"
    db_path = tmp_path / "history.db"
    override_db = tmp_path / "override.db"

    cfg = MonitorConfig(
        baseline_dir=baseline_dir,
        db_path=db_path,
        smart_precheck=True,
        accounts=[MonitorAccountTarget(email="Alice@Example.com", include_stealer_logs=True)],
        domains=[
            MonitorDomainTarget(domain="Example.COM", include_stealer_logs=False),
            MonitorDomainTarget(domain="stealer.example", include_stealer_logs=True),
        ],
    )

    latest_v1 = Breach(Name="BreachV1", AddedDate=datetime(2026, 1, 1, tzinfo=UTC))

    # Run 1: initial exposures across all 5 categories
    stub1 = _StubHIBPClient(
        accounts={
            "Alice@Example.com": SearchResult(
                breaches=[Breach(Name="Adobe")],
                pastes=[Paste(Source="Pastebin", Id="p1")],
                stealer_logs=["log.site"],
            )
        },
        domain_breaches={
            "Example.COM": {"bob": ["LinkedIn"]},
            "stealer.example": {"carol": ["Canva"]},
        },
        domain_stealer_logs={
            "stealer.example": {"carol": ["stealer1.test"]},
        },
        latest_breach=latest_v1,
    )
    report1 = run_monitor(cfg, stub1, save_baselines=True)  # type: ignore[arg-type]
    assert report1.new_exposures == 6
    assert report1.resolved_exposures == 0
    assert report1.history_summary is not None
    assert report1.history_summary.total_runs == 1
    assert report1.history_summary.active_exposures == 6
    assert report1.history_summary.new_in_latest_run == 6
    assert report1.history_summary.resolved_in_latest_run == 0
    assert report1.history_summary.remediation_rate == 0.0

    dumped1 = report1.model_dump(exclude_unset=True)
    assert dumped1["resolved_exposures"] == 0
    assert "history_summary" in dumped1

    # Verify formatting works cleanly with history_summary set
    assert "resolved_exposures" in format_output(report1, fmt="json")
    assert "## Monitor Report" in format_output(report1, fmt="markdown")
    assert "<h1>Monitor Report</h1>" in format_output(report1, fmt="html")
    assert "history_summary:" in format_output(report1, fmt="text")

    # Run 2: SAME exposures with baseline_dir + smart_precheck!
    # Baseline diff says 0 new account exposures, and smart_precheck skips domain breach calls,
    # while stealer.example observes a NEW stealer log (`stealer2.test`).
    # NONE of the previously-known exposures may be falsely marked resolved!
    stub2 = _StubHIBPClient(
        accounts={
            "Alice@Example.com": SearchResult(
                breaches=[Breach(Name="Adobe")],
                pastes=[Paste(Source="Pastebin", Id="p1")],
                stealer_logs=["log.site"],
            )
        },
        domain_breaches={},
        domain_stealer_logs={
            "stealer.example": {"carol": ["stealer1.test", "stealer2.test"]},
        },
        latest_breach=latest_v1,
    )
    report2 = run_monitor(cfg, stub2, save_baselines=True)  # type: ignore[arg-type]
    assert report2.domains_skipped == 2
    assert report2.new_exposures == 1  # only stealer2.test
    assert report2.resolved_exposures == 0
    assert report2.history_summary is not None
    assert report2.history_summary.total_runs == 2
    assert report2.history_summary.active_exposures == 7
    assert report2.history_summary.new_in_latest_run == 1
    assert report2.history_summary.resolved_in_latest_run == 0

    with ExposureHistoryStore(db_path) as store:
        alice_records = store.list_exposures(target_type="account", target="alice@example.com")
        assert len(alice_records) == 3
        assert all(rec.times_seen == 2 and rec.resolved_at is None for rec in alice_records)

    # Run 3: transient API errors on account and non-skipped domains MUST NOT resolve active rows
    latest_v2 = Breach(Name="BreachV2", AddedDate=datetime(2026, 2, 1, tzinfo=UTC))
    stub3 = _StubHIBPClient(
        accounts={"Alice@Example.com": HIBPError("API 503")},
        domain_breaches={
            "Example.COM": HIBPError("Domain 503"),
            "stealer.example": {"carol": ["Canva"]},
        },
        domain_stealer_logs={
            "stealer.example": HIBPError("Stealer 503"),
        },
        latest_breach=latest_v2,
    )
    report3 = run_monitor(cfg, stub3, save_baselines=False)  # type: ignore[arg-type]
    assert report3.accounts[0].status == "error"
    assert report3.domains[0].status == "error"
    assert report3.domains[1].status == "error"
    assert report3.resolved_exposures == 0
    assert report3.history_summary is not None
    assert report3.history_summary.active_exposures == 7
    assert report3.history_summary.total_resolved == 0

    # Run 4: genuine remediation (account paste & stealer_log gone; Example.COM clean)
    stub4 = _StubHIBPClient(
        accounts={
            "Alice@Example.com": SearchResult(
                breaches=[Breach(Name="Adobe")],
                pastes=[],
                stealer_logs=[],
            )
        },
        domain_breaches={
            "Example.COM": {},
            "stealer.example": {"carol": ["Canva"]},
        },
        domain_stealer_logs={
            "stealer.example": {"carol": ["stealer1.test", "stealer2.test"]},
        },
        latest_breach=latest_v2,
    )
    report4 = run_monitor(cfg, stub4, save_baselines=True)  # type: ignore[arg-type]
    assert report4.resolved_exposures == 3  # paste p1, log.site, bob:LinkedIn
    assert report4.history_summary is not None
    assert report4.history_summary.active_exposures == 4
    assert report4.history_summary.total_resolved == 3
    assert report4.history_summary.resolved_in_latest_run == 3
    assert report4.history_summary.remediation_rate == 42.9

    # Verify db_path_override takes precedence over config.db_path
    stub_override = _StubHIBPClient(
        accounts={"Alice@Example.com": SearchResult(breaches=[Breach(Name="Adobe")])},
        domain_breaches={"Example.COM": {}, "stealer.example": {}},
        domain_stealer_logs={"stealer.example": {}},
        latest_breach=latest_v2,
    )
    report_override = run_monitor(
        cfg,
        stub_override,  # type: ignore[arg-type]
        db_path_override=override_db,
    )
    assert override_db.is_file()
    assert report_override.history_summary is not None
    assert report_override.history_summary.total_runs == 1
    assert report_override.history_summary.active_exposures == 1

    # Run 5 on original db: previously resolved paste reappears!
    stub5 = _StubHIBPClient(
        accounts={
            "Alice@Example.com": SearchResult(
                breaches=[Breach(Name="Adobe")],
                pastes=[Paste(Source="Pastebin", Id="p1")],
                stealer_logs=[],
            )
        },
        domain_breaches={
            "Example.COM": {},
            "stealer.example": {"carol": ["Canva"]},
        },
        domain_stealer_logs={
            "stealer.example": {"carol": ["stealer1.test", "stealer2.test"]},
        },
        latest_breach=latest_v2,
    )
    report5 = run_monitor(cfg, stub5, save_baselines=True)  # type: ignore[arg-type]
    assert report5.resolved_exposures == 0
    assert report5.history_summary is not None
    assert report5.history_summary.active_exposures == 5
    assert report5.history_summary.total_resolved == 2
    assert report5.history_summary.new_in_latest_run == 1
    with ExposureHistoryStore(db_path) as store:
        paste_rec = next(
            rec
            for rec in store.list_exposures(target_type="account", target="alice@example.com")
            if rec.category == "paste"
        )
        assert paste_rec.resolved_at is None
        assert paste_rec.times_seen == 3


def test_run_monitor_history_reconciliation_respects_queried_scope(tmp_path: Path) -> None:
    from datetime import UTC, date, datetime

    baseline_dir = tmp_path / "baselines"
    db_path = tmp_path / "scoped_history.db"
    latest_v1 = Breach(Name="BreachV1", AddedDate=datetime(2026, 1, 1, tzinfo=UTC))

    # Run 1: full unfiltered monitoring with stealer logs enabled for both account & domain
    cfg_full = MonitorConfig(
        baseline_dir=baseline_dir,
        db_path=db_path,
        smart_precheck=True,
        accounts=[MonitorAccountTarget(email="alice@example.com", include_stealer_logs=True)],
        domains=[MonitorDomainTarget(domain="example.com", include_stealer_logs=True)],
    )
    stub1 = _StubHIBPClient(
        accounts={
            "alice@example.com": SearchResult(
                breaches=[Breach(Name="Adobe")],
                pastes=[Paste(Source="Pastebin", Id="p1")],
                stealer_logs=["evil.test"],
            )
        },
        domain_breaches={"example.com": {"bob": ["LinkedIn"]}},
        domain_stealer_logs={"example.com": {"bob": ["stealer1.test"]}},
        latest_breach=latest_v1,
    )
    report1 = run_monitor(cfg_full, stub1, save_baselines=True)  # type: ignore[arg-type]
    assert report1.history_summary is not None
    assert report1.history_summary.active_exposures == 5

    # Run 2: disable stealer logs AND add a breach filter (since=...) on the account.
    # Neither unqueried stealer logs nor filtered-out breaches may be falsely marked resolved!
    cfg_narrow = MonitorConfig(
        baseline_dir=baseline_dir,
        db_path=db_path,
        smart_precheck=False,
        accounts=[
            MonitorAccountTarget(
                email="alice@example.com",
                include_stealer_logs=False,
                since="2025-01-01",
            )
        ],
        domains=[MonitorDomainTarget(domain="example.com", include_stealer_logs=False)],
    )
    stub2 = _StubHIBPClient(
        accounts={
            "alice@example.com": SearchResult(
                breaches=[Breach(Name="Adobe", BreachDate=date(2013, 10, 4))],
                pastes=[Paste(Source="Pastebin", Id="p1")],
            )
        },
        domain_breaches={"example.com": {"bob": ["LinkedIn"]}},
        latest_breach=latest_v1,
    )
    report2 = run_monitor(cfg_narrow, stub2, save_baselines=False)  # type: ignore[arg-type]
    assert report2.resolved_exposures == 0
    assert report2.history_summary is not None
    assert report2.history_summary.active_exposures == 5

    # Run 3: smart_precheck skips domain breaches while stealer logs ARE queried and cleared.
    # alias_stealer_log resolves cleanly while alias_breach stays active!
    stub3 = _StubHIBPClient(
        accounts={
            "alice@example.com": SearchResult(
                breaches=[Breach(Name="Adobe")],
                pastes=[Paste(Source="Pastebin", Id="p1")],
                stealer_logs=["evil.test"],
            )
        },
        domain_breaches={},
        domain_stealer_logs={"example.com": {}},
        latest_breach=latest_v1,
    )
    report3 = run_monitor(cfg_full, stub3, save_baselines=False)  # type: ignore[arg-type]
    assert report3.domains_skipped == 1
    assert report3.resolved_exposures == 1
    with ExposureHistoryStore(db_path) as store:
        dom_active = store.list_exposures(target_type="domain", target="example.com")
        assert [(r.category, r.identifier) for r in dom_active] == [
            ("alias_breach", "bob:LinkedIn")
        ]


def test_load_monitor_config_expanded_notify_destinations_and_env_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    default_notify = MonitorNotifyConfig()
    assert default_notify.pagerduty_routing_key is None
    assert default_notify.pagerduty_severity == "error"
    assert default_notify.email is None
    assert default_notify.github_issue is None
    redacted_notify = MonitorNotifyConfig(pagerduty_routing_key="secret-pd-key")
    assert "secret-pd-key" not in repr(redacted_notify)

    expected_smtp_cred = "smtp-secret-pass"
    expected_gh_cred = "ghp-secret-val"
    monkeypatch.setenv("PD_ROUTING_KEY", "pd-live-key")
    monkeypatch.setenv("SMTP_USER", "alerts-user")
    monkeypatch.setenv("SMTP_PASS", expected_smtp_cred)
    monkeypatch.setenv("GH_TOKEN", expected_gh_cred)

    toml_path = tmp_path / "expanded.toml"
    toml_path.write_text(
        f"""
[notify]
webhook_url = "{PAGERDUTY_EVENTS_URL}"
format = "pagerduty"
pagerduty_routing_key = "${{PD_ROUTING_KEY}}"
pagerduty_severity = "critical"

[notify.email]
host = "smtp.example.com"
port = 587
from_addr = "alerts@example.com"
to_addrs = ["sec@example.com", "ops@example.com"]
username = "${{SMTP_USER}}"
password = "${{SMTP_PASS}}"
use_tls = true
use_ssl = false

[notify.github_issue]
repo = "acme/security-alerts"
token = "${{GH_TOKEN}}"
labels = ["security", "hibp"]
dedup_title = false

[[accounts]]
email = "alice@example.com"
""".strip(),
        encoding="utf-8",
    )

    cfg = load_monitor_config(toml_path)
    assert cfg.notify.webhook_url == PAGERDUTY_EVENTS_URL
    assert cfg.notify.format == "pagerduty"
    assert cfg.notify.pagerduty_routing_key == "pd-live-key"
    assert cfg.notify.pagerduty_severity == "critical"
    assert cfg.notify.email is not None
    assert cfg.notify.email.host == "smtp.example.com"
    assert cfg.notify.email.username == "alerts-user"
    assert cfg.notify.email.password == expected_smtp_cred
    assert cfg.notify.github_issue is not None
    assert cfg.notify.github_issue.repo == "acme/security-alerts"
    assert cfg.notify.github_issue.token == expected_gh_cred
    assert cfg.notify.github_issue.labels == ["security", "hibp"]
    assert cfg.notify.github_issue.dedup_title is False

    # Email config without username/password (optional strings omitted)
    no_auth_toml = tmp_path / "no_auth_email.toml"
    no_auth_toml.write_text(
        """
[notify.email]
host = "localhost"
port = 25
from_addr = "alerts@example.com"
to_addrs = ["sec@example.com"]
use_tls = false

[[accounts]]
email = "alice@example.com"
""".strip(),
        encoding="utf-8",
    )
    no_auth_cfg = load_monitor_config(no_auth_toml)
    assert no_auth_cfg.notify.email is not None
    assert no_auth_cfg.notify.email.username is None
    assert no_auth_cfg.notify.email.password is None

    # Non-string pagerduty_routing_key
    bad_pd_type = tmp_path / "bad_pd.toml"
    bad_pd_type.write_text(
        "[notify]\npagerduty_routing_key = 123\n\n[[accounts]]\nemail = 'a@b.com'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"notify\.pagerduty_routing_key must be a string\."):
        load_monitor_config(bad_pd_type)

    # Missing env var in pagerduty_routing_key
    monkeypatch.delenv("MISSING_PD", raising=False)
    missing_pd = tmp_path / "missing_pd.toml"
    missing_pd.write_text(
        "[notify]\npagerduty_routing_key = '${MISSING_PD}'\n\n[[accounts]]\nemail = 'a@b.com'\n",
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError,
        match=(
            r"Environment variable 'MISSING_PD' referenced in "
            r"notify\.pagerduty_routing_key is not set\."
        ),
    ):
        load_monitor_config(missing_pd)

    # Non-table notify.email
    bad_email_type = tmp_path / "bad_email.toml"
    bad_email_type.write_text(
        "[notify]\nemail = 'invalid'\n\n[[accounts]]\nemail = 'a@b.com'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"\[notify\.email\]"):
        load_monitor_config(bad_email_type)

    # Missing env var in notify.email.username and notify.email.password
    monkeypatch.delenv("MISSING_SMTP_USER", raising=False)
    missing_user = tmp_path / "missing_user.toml"
    missing_user.write_text(
        """
[notify.email]
host = "smtp.example.com"
from_addr = "a@b.com"
to_addrs = ["c@d.com"]
username = "${MISSING_SMTP_USER}"
password = "pw"

[[accounts]]
email = "alice@example.com"
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError,
        match=(
            r"Environment variable 'MISSING_SMTP_USER' referenced in "
            r"notify\.email\.username is not set\."
        ),
    ):
        load_monitor_config(missing_user)

    monkeypatch.delenv("MISSING_SMTP_PASS", raising=False)
    missing_pass = tmp_path / "missing_pass.toml"
    missing_pass.write_text(
        """
[notify.email]
host = "smtp.example.com"
from_addr = "a@b.com"
to_addrs = ["c@d.com"]
username = "user"
password = "${MISSING_SMTP_PASS}"

[[accounts]]
email = "alice@example.com"
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError,
        match=(
            r"Environment variable 'MISSING_SMTP_PASS' referenced in "
            r"notify\.email\.password is not set\."
        ),
    ):
        load_monitor_config(missing_pass)

    # Non-table notify.github_issue
    bad_gh_type = tmp_path / "bad_gh.toml"
    bad_gh_type.write_text(
        "[notify]\ngithub_issue = 'invalid'\n\n[[accounts]]\nemail = 'a@b.com'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"\[notify\.github_issue\]"):
        load_monitor_config(bad_gh_type)

    # Non-string github_issue.token fails Pydantic validation
    bad_gh_tok = tmp_path / "bad_gh_tok.toml"
    bad_gh_tok.write_text(
        """
[notify.github_issue]
repo = "acme/sec"
token = 999

[[accounts]]
email = "alice@example.com"
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        load_monitor_config(bad_gh_tok)

    # Missing env var in notify.github_issue.token
    monkeypatch.delenv("MISSING_GH_TOKEN", raising=False)
    missing_gh = tmp_path / "missing_gh.toml"
    missing_gh.write_text(
        """
[notify.github_issue]
repo = "acme/sec"
token = "${MISSING_GH_TOKEN}"

[[accounts]]
email = "alice@example.com"
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError,
        match=(
            r"Environment variable 'MISSING_GH_TOKEN' referenced in "
            r"notify\.github_issue\.token is not set\."
        ),
    ):
        load_monitor_config(missing_gh)


class _MonitorFakeSMTP:
    def __init__(self, host: str, port: int, timeout: float = 30.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sent_messages: list[EmailMessage] = []

    def __enter__(self) -> _MonitorFakeSMTP:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def send_message(self, msg: EmailMessage) -> None:
        self.sent_messages.append(msg)


def test_run_monitor_pagerduty_email_and_github_issue_notifications(
    monkeypatch: pytest.MonkeyPatch,
    httpx_mock: Any,
) -> None:
    smtp_instances: list[_MonitorFakeSMTP] = []

    def fake_smtp(host: str, port: int, timeout: float = 30.0) -> _MonitorFakeSMTP:
        inst = _MonitorFakeSMTP(host, port, timeout=timeout)
        smtp_instances.append(inst)
        return inst

    monkeypatch.setattr(smtplib, "SMTP", fake_smtp)

    pwned_stub = _StubHIBPClient(
        accounts={"alice@example.com": SearchResult(breaches=[Breach(Name="Adobe")])}
    )
    clean_stub = _StubHIBPClient(accounts={"alice@example.com": SearchResult()})

    # 1. PagerDuty webhook only (config key + override): records "webhook" in notifications_sent
    pd_cfg = MonitorConfig(
        notify=MonitorNotifyConfig(
            webhook_url=PAGERDUTY_EVENTS_URL,
            format="pagerduty",
            pagerduty_routing_key="cfg-pd-key",
            pagerduty_severity="critical",
        ),
        accounts=[MonitorAccountTarget(email="alice@example.com")],
    )
    httpx_mock.add_response(url=PAGERDUTY_EVENTS_URL, status_code=202, json={"status": "success"})
    with httpx.Client() as wh_client:
        pd_report = run_monitor(
            pd_cfg,
            pwned_stub,  # type: ignore[arg-type]
            pagerduty_routing_key_override="override-pd-key",
            webhook_client=wh_client,
        )
    assert pd_report.webhook_sent is True
    assert pd_report.notifications_sent == ["webhook"]
    assert pd_report.model_dump(exclude_unset=True)["notifications_sent"] == ["webhook"]
    pd_req = httpx_mock.get_requests()[0]
    pd_body = json.loads(pd_req.content.decode("utf-8"))
    assert pd_body["routing_key"] == "override-pd-key"
    assert pd_body["payload"]["severity"] == "critical"

    # 2. All three channels (webhook + email + github_issue): clean run sends nothing
    email_cfg = EmailNotifyConfig(
        host="localhost",
        port=25,
        from_addr="alerts@example.com",
        to_addrs=["sec@example.com"],
        use_tls=False,
    )
    gh_cfg = GitHubIssueNotifyConfig(
        repo="acme/sec-alerts",
        token="ghp_test_token",
        dedup_title=False,
    )
    all_cfg = MonitorConfig(
        notify=MonitorNotifyConfig(
            webhook_url=PAGERDUTY_EVENTS_URL,
            format="auto",
            pagerduty_routing_key="cfg-pd-key",
            pagerduty_severity="warning",
            email=email_cfg,
            github_issue=gh_cfg,
        ),
        accounts=[MonitorAccountTarget(email="alice@example.com")],
    )
    with httpx.Client() as wh_client:
        clean_all = run_monitor(
            all_cfg,
            clean_stub,  # type: ignore[arg-type]
            webhook_client=wh_client,
        )
    assert clean_all.webhook_sent is False
    assert clean_all.notifications_sent == []
    assert "notifications_sent" in clean_all.model_dump(exclude_unset=True)
    assert smtp_instances == []

    # 3. All three channels on pwned run: webhook + email + github_issue all fire
    gh_issues_url = "https://api.github.com/repos/acme/sec-alerts/issues"
    httpx_mock.add_response(url=PAGERDUTY_EVENTS_URL, status_code=202, json={"status": "success"})
    httpx_mock.add_response(
        method="POST",
        url=gh_issues_url,
        status_code=201,
        json={"number": 11, "html_url": "https://github.com/acme/sec-alerts/issues/11"},
    )
    with httpx.Client() as wh_client:
        pwned_all = run_monitor(
            all_cfg,
            pwned_stub,  # type: ignore[arg-type]
            webhook_client=wh_client,
        )
        assert not wh_client.is_closed
    assert pwned_all.webhook_sent is True
    assert pwned_all.notifications_sent == ["webhook", "email", "github_issue"]
    assert len(smtp_instances) == 1
    assert smtp_instances[0].sent_messages[0]["Subject"] == "pwned Monitor Alert"
    gh_req = httpx_mock.get_requests()[-1]
    assert str(gh_req.url) == gh_issues_url
    gh_body = json.loads(gh_req.content.decode("utf-8"))
    assert gh_body["title"] == "pwned Monitor Alert"
    assert "## Monitor Report" in gh_body["body"]

    # 4. Email only (no webhook, no github_issue) on pwned run
    email_only_cfg = MonitorConfig(
        notify=MonitorNotifyConfig(email=email_cfg),
        accounts=[MonitorAccountTarget(email="alice@example.com")],
    )
    email_only_report = run_monitor(email_only_cfg, pwned_stub)  # type: ignore[arg-type]
    assert email_only_report.webhook_sent is False
    assert email_only_report.notifications_sent == ["email"]

    # 5. GitHub issue only (no webhook, no email) on pwned run
    gh_only_cfg = MonitorConfig(
        notify=MonitorNotifyConfig(github_issue=gh_cfg),
        accounts=[MonitorAccountTarget(email="alice@example.com")],
    )
    httpx_mock.add_response(
        method="POST",
        url=gh_issues_url,
        status_code=201,
        json={"number": 12, "html_url": "https://github.com/acme/sec-alerts/issues/12"},
    )
    gh_only_report = run_monitor(gh_only_cfg, pwned_stub)  # type: ignore[arg-type]
    assert gh_only_report.webhook_sent is False
    assert gh_only_report.notifications_sent == ["github_issue"]
