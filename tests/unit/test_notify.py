from __future__ import annotations

import json
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from pwned.audit import AuditSummary, BreachCorrelationFinding
from pwned.client import HIBPError
from pwned.notify import (
    DEFAULT_GITHUB_API_URL,
    PAGERDUTY_EVENTS_URL,
    WEBHOOK_FORMATS,
    EmailNotifyConfig,
    GitHubIssueNotifyConfig,
    build_webhook_payload,
    detect_webhook_format,
    has_exposures,
    send_email_notification,
    send_github_issue_notification,
    send_webhook_notification,
    validate_webhook_url,
)


def test_validate_webhook_url() -> None:
    assert (
        validate_webhook_url("  https://hooks.slack.com/services/T/B/X  ")
        == "https://hooks.slack.com/services/T/B/X"
    )
    assert (
        validate_webhook_url("http://localhost:8000/hook", allow_insecure_http=True)
        == "http://localhost:8000/hook"
    )

    with pytest.raises(ValueError):
        validate_webhook_url("http://example.com/hook", allow_insecure_http=False)
    with pytest.raises(ValueError):
        validate_webhook_url("ftp://example.com/hook")
    with pytest.raises(ValueError):
        validate_webhook_url("   ")
    with pytest.raises(ValueError):
        validate_webhook_url("https://")


def test_detect_webhook_format() -> None:
    assert detect_webhook_format("https://hooks.slack.com/services/T00/B00/XXX") == "slack"
    assert detect_webhook_format("https://hooks.gov.slack.com/services/T00/B00/XXX") == "slack"
    assert detect_webhook_format("https://discord.com/api/webhooks/123/token") == "discord"
    assert detect_webhook_format("https://discordapp.com/api/webhooks/123/token") == "discord"
    assert detect_webhook_format("https://ptb.discord.com/api/webhooks/123/token") == "discord"
    assert detect_webhook_format("https://canary.discord.com/api/webhooks/123/token") == "discord"
    assert detect_webhook_format("https://discord.com/channels/@me") == "generic"
    assert detect_webhook_format("https://webhook.site/abc-123") == "generic"


def test_has_exposures() -> None:
    assert not has_exposures([])
    assert not has_exposures([{"status": "safe"}])
    assert has_exposures([{"status": "pwned"}])
    assert has_exposures(["some-non-status-item"])

    assert not has_exposures(
        {
            "findings": [],
            "reused_groups": [],
            "strength_findings": [],
            "ad_findings": [],
            "wordlist_findings": [],
            "breach_findings": [],
        }
    )
    assert has_exposures({"findings": [{"account": "alice"}]})
    assert has_exposures({"reused_groups": [["a", "b"]]})
    assert has_exposures({"strength_findings": [{"account": "bob"}]})
    assert has_exposures({"findings": [], "ad_findings": [{"issue": "empty_ntlm"}]})
    assert has_exposures({"findings": [], "wordlist_findings": [{"match_type": "exact"}]})
    assert has_exposures(
        {
            "findings": [],
            "breach_findings": [
                {"source": "site_domain", "domain": "adobe.com", "breaches": ["Adobe"]}
            ],
        }
    )
    assert has_exposures(
        AuditSummary(
            total_entries=1,
            unique_passwords=1,
            compromised_entries=0,
            findings=[],
            breach_correlated_entries=1,
            breach_findings=[
                BreachCorrelationFinding(
                    name="Adobe",
                    username="alice@example.com",
                    source="site_domain",
                    domain="adobe.com",
                    breaches=["Adobe"],
                )
            ],
        )
    )
    assert not has_exposures(
        AuditSummary(
            total_entries=1,
            unique_passwords=1,
            compromised_entries=0,
            findings=[],
            breach_correlated_entries=0,
            breach_findings=[],
        )
    )

    assert not has_exposures({"new_exposures": 0})
    assert has_exposures({"new_exposures": 1})

    assert not has_exposures({"total_exposed_aliases": 0, "stealer_log_aliases": []})
    assert has_exposures({"total_exposed_aliases": 1})
    assert has_exposures({"stealer_log_aliases": {"alice": ["log"]}})

    assert not has_exposures({"breaches": [], "pastes": [], "stealer_logs": []})
    assert has_exposures({"breaches": [{"Name": "Adobe"}]})

    assert not has_exposures({})
    assert has_exposures({"alice": ["Adobe"]})
    assert not has_exposures("")


def test_build_webhook_payload() -> None:
    data = {"breaches": [{"Name": "Adobe"}]}
    slack_payload = build_webhook_payload(data, fmt="slack", title="Test Alert")
    assert slack_payload["text"].startswith("Test Alert:")
    assert slack_payload["blocks"][0]["text"]["text"] == "Test Alert"

    discord_payload = build_webhook_payload(data, fmt="discord", title="Test Alert")
    assert discord_payload["content"] == "Test Alert"
    assert discord_payload["embeds"][0]["color"] == 0xE74C3C

    generic_payload = build_webhook_payload(data, fmt="generic", title="Test Alert")
    assert generic_payload["source"] == "pwned"
    assert generic_payload["title"] == "Test Alert"
    assert "data" in generic_payload

    # Test summary truncation branch
    large_data = {"breaches": [{"Name": "X" * 2000}]}
    large_payload = build_webhook_payload(large_data, fmt="generic", title="Large")
    assert "..." in large_payload["summary"]


def test_send_webhook_notification_no_exposures(httpx_mock: Any) -> None:
    url = "https://hooks.slack.com/services/T/B/X"
    assert not send_webhook_notification(url, [])
    assert len(httpx_mock.get_requests()) == 0


def test_send_webhook_notification_success(httpx_mock: Any) -> None:
    url = "https://hooks.slack.com/services/T/B/X"
    httpx_mock.add_response(url=url, status_code=200, json={"ok": True})

    assert send_webhook_notification(url, [{"status": "pwned"}], fmt="auto")
    request = httpx_mock.get_request()
    assert request is not None
    assert request.method == "POST"


def test_send_webhook_notification_errors(httpx_mock: Any) -> None:
    url = "https://hooks.slack.com/services/T/B/X"
    httpx_mock.add_response(url=url, status_code=500)

    with pytest.raises(HIBPError):
        send_webhook_notification(url, [{"status": "pwned"}])

    httpx_mock.add_exception(
        httpx.RequestError("Connection failed", request=httpx.Request("POST", url))
    )
    with pytest.raises(HIBPError):
        send_webhook_notification(url, [{"status": "pwned"}])


def test_send_webhook_notification_with_client(httpx_mock: Any) -> None:
    url = "https://hooks.slack.com/services/T/B/X"
    httpx_mock.add_response(url=url, status_code=200)
    client = httpx.Client()
    try:
        assert send_webhook_notification(url, [{"status": "pwned"}], client=client)
    finally:
        client.close()


def test_webhook_constants_and_expanded_detection() -> None:
    assert WEBHOOK_FORMATS == ("auto", "slack", "discord", "teams", "pagerduty", "generic")
    assert PAGERDUTY_EVENTS_URL == "https://events.pagerduty.com/v2/enqueue"
    assert DEFAULT_GITHUB_API_URL == "https://api.github.com"

    # Microsoft Teams O365 connector & Power Automate / Logic Apps workflows
    assert (
        detect_webhook_format("https://contoso.webhook.office.com/webhookb2/abc/IncomingWebhook/1")
        == "teams"
    )
    assert (
        detect_webhook_format(
            "https://prod-01.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke"
        )
        == "teams"
    )
    assert (
        detect_webhook_format(
            "https://default123.environment.api.powerplatform.com/powerautomate/Workflows/abc/invoke"
        )
        == "teams"
    )
    assert detect_webhook_format("https://webhook.office.com/webhookb2/abc") == "generic"
    assert detect_webhook_format("https://prod-01.westus.logic.azure.com/api/other") == "generic"
    assert (
        detect_webhook_format("https://default123.environment.api.powerplatform.com/api/other")
        == "generic"
    )

    # PagerDuty US & EU Events API v2
    assert detect_webhook_format("https://events.pagerduty.com/v2/enqueue") == "pagerduty"
    assert detect_webhook_format("https://events.eu.pagerduty.com/v2/enqueue") == "pagerduty"
    assert detect_webhook_format("https://events.pagerduty.com/v1/enqueue") == "generic"


def test_build_webhook_payload_teams_and_pagerduty() -> None:
    data = {"breaches": [{"Name": "Adobe"}]}
    long_title = "T" * 1200

    teams_payload = build_webhook_payload(data, fmt="teams", title=long_title)
    assert teams_payload["type"] == "message"
    assert len(teams_payload["attachments"]) == 1
    attachment = teams_payload["attachments"][0]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert attachment["contentUrl"] is None
    card = attachment["content"]
    assert card["$schema"] == "http://adaptivecards.io/schemas/adaptive-card.json"
    assert card["type"] == "AdaptiveCard"
    assert card["version"] == "1.4"
    assert len(card["body"]) == 2
    assert card["body"][0] == {
        "type": "TextBlock",
        "text": "T" * 256,
        "weight": "Bolder",
        "size": "Medium",
        "wrap": True,
    }
    assert card["body"][1]["type"] == "TextBlock"
    assert card["body"][1]["wrap"] is True
    assert card["body"][1]["fontType"] == "Monospace"
    assert "Adobe" in card["body"][1]["text"]

    # PagerDuty requires non-empty routing_key
    for bad_key in (None, "", "   "):
        with pytest.raises(
            ValueError, match="PagerDuty notifications require a non-empty routing_key."
        ):
            build_webhook_payload(data, fmt="pagerduty", routing_key=bad_key)

    pd_payload = build_webhook_payload(
        data,
        fmt="pagerduty",
        title=long_title,
        routing_key="  pd-routing-key-123  ",
    )
    assert pd_payload["routing_key"] == "pd-routing-key-123"
    assert pd_payload["event_action"] == "trigger"
    assert "dedup_key" not in pd_payload
    assert pd_payload["payload"]["summary"] == "T" * 1024
    assert pd_payload["payload"]["source"] == "pwned"
    assert pd_payload["payload"]["severity"] == "error"
    assert pd_payload["payload"]["custom_details"]["data"] == data
    assert "Adobe" in pd_payload["payload"]["custom_details"]["summary"]

    pd_custom = build_webhook_payload(
        data,
        fmt="pagerduty",
        title="Critical Alert",
        routing_key="pd-key",
        severity="critical",
        dedup_key="pwned-dedup-42",
    )
    assert pd_custom["dedup_key"] == "pwned-dedup-42"
    assert pd_custom["payload"]["severity"] == "critical"


def test_send_webhook_notification_teams_and_pagerduty(httpx_mock: Any) -> None:
    teams_url = "https://contoso.webhook.office.com/webhookb2/abc"
    httpx_mock.add_response(url=teams_url, status_code=200)
    assert send_webhook_notification(teams_url, [{"status": "pwned"}], fmt="auto")
    req_teams = httpx_mock.get_requests()[0]
    body_teams = json.loads(req_teams.content.decode("utf-8"))
    assert body_teams["type"] == "message"
    assert body_teams["attachments"][0]["content"]["type"] == "AdaptiveCard"

    pd_url = PAGERDUTY_EVENTS_URL
    httpx_mock.add_response(url=pd_url, status_code=202, json={"status": "success"})
    assert send_webhook_notification(
        pd_url,
        [{"status": "pwned"}],
        fmt="auto",
        title="PD Alert",
        routing_key="rk-123",
        severity="warning",
        dedup_key="dk-1",
    )
    req_pd = httpx_mock.get_requests()[1]
    body_pd = json.loads(req_pd.content.decode("utf-8"))
    assert body_pd["routing_key"] == "rk-123"
    assert body_pd["dedup_key"] == "dk-1"
    assert body_pd["payload"]["severity"] == "warning"
    assert body_pd["payload"]["summary"] == "PD Alert"


def test_email_notify_config_validation_and_redaction() -> None:
    cfg = EmailNotifyConfig(
        host="  smtp.example.com  ",
        from_addr="  alerts@example.com  ",
        to_addrs=["  sec@example.com  ", "ops@example.com"],
        username="alerts",
        password="super-secret-smtp-password",
    )
    assert cfg.host == "smtp.example.com"
    assert cfg.port == 587
    assert cfg.from_addr == "alerts@example.com"
    assert cfg.to_addrs == ["sec@example.com", "ops@example.com"]
    assert cfg.use_tls is True
    assert cfg.use_ssl is False
    assert "super-secret-smtp-password" not in repr(cfg)

    with pytest.raises(ValidationError):
        EmailNotifyConfig(host="   ", from_addr="a@b.com", to_addrs=["c@d.com"])
    with pytest.raises(ValidationError):
        EmailNotifyConfig(host="smtp.example.com", from_addr="", to_addrs=["c@d.com"])
    with pytest.raises(ValidationError):
        EmailNotifyConfig(
            host="smtp.example.com", port=0, from_addr="a@b.com", to_addrs=["c@d.com"]
        )
    with pytest.raises(ValidationError):
        EmailNotifyConfig(
            host="smtp.example.com", port=70000, from_addr="a@b.com", to_addrs=["c@d.com"]
        )
    with pytest.raises(ValidationError):
        EmailNotifyConfig(host="smtp.example.com", from_addr="a@b.com", to_addrs=[])
    with pytest.raises(ValidationError):
        EmailNotifyConfig(host="smtp.example.com", from_addr="a@b.com", to_addrs=["a@b.com", "  "])
    with pytest.raises(ValidationError, match=r"use_tls and use_ssl cannot both be True\."):
        EmailNotifyConfig(
            host="smtp.example.com",
            from_addr="a@b.com",
            to_addrs=["c@d.com"],
            use_tls=True,
            use_ssl=True,
        )
    with pytest.raises(
        ValidationError,
        match=r"Both username and password must be provided together for SMTP auth\.",
    ):
        EmailNotifyConfig(
            host="smtp.example.com",
            from_addr="a@b.com",
            to_addrs=["c@d.com"],
            username="user-only",
        )
    with pytest.raises(
        ValidationError,
        match=r"Both username and password must be provided together for SMTP auth\.",
    ):
        EmailNotifyConfig(
            host="smtp.example.com",
            from_addr="a@b.com",
            to_addrs=["c@d.com"],
            password="password-only",
        )


class _FakeSMTP:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: float,
        context: ssl.SSLContext | None = None,
        ssl_mode: bool = False,
        fail_with: Exception | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.ssl_mode = ssl_mode
        self.fail_with = fail_with
        self.starttls_calls: list[ssl.SSLContext | None] = []
        self.login_calls: list[tuple[str, str]] = []
        self.sent_messages: list[EmailMessage] = []
        self.closed = False

    def __enter__(self) -> _FakeSMTP:
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed = True

    def starttls(self, *, context: ssl.SSLContext | None = None) -> None:
        self.starttls_calls.append(context)

    def login(self, user: str, password: str) -> None:
        self.login_calls.append((user, password))

    def send_message(self, msg: EmailMessage) -> None:
        if self.fail_with is not None:
            raise self.fail_with
        self.sent_messages.append(msg)


def test_send_email_notification_modes_and_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[_FakeSMTP] = []

    def fake_smtp(host: str, port: int, timeout: float = 30.0) -> _FakeSMTP:
        inst = _FakeSMTP(host, port, timeout=timeout, ssl_mode=False)
        created.append(inst)
        return inst

    def fake_smtp_ssl(
        host: str,
        port: int,
        timeout: float = 30.0,
        context: ssl.SSLContext | None = None,
    ) -> _FakeSMTP:
        inst = _FakeSMTP(host, port, timeout=timeout, context=context, ssl_mode=True)
        created.append(inst)
        return inst

    monkeypatch.setattr(smtplib, "SMTP", fake_smtp)
    monkeypatch.setattr(smtplib, "SMTP_SSL", fake_smtp_ssl)

    # No exposures -> False, no connection
    cfg_tls = EmailNotifyConfig(
        host="smtp.example.com",
        port=587,
        from_addr="alerts@example.com",
        to_addrs=["sec@example.com", "ops@example.com"],
        username="alerts",
        password="secret",
        use_tls=True,
        use_ssl=False,
    )
    assert send_email_notification(cfg_tls, []) is False
    assert created == []

    # STARTTLS + auth
    data = {"breaches": [{"Name": "Adobe"}]}
    assert send_email_notification(cfg_tls, data, title="Custom Email Title", timeout=12.5) is True
    assert len(created) == 1
    tls_conn = created[0]
    assert tls_conn.ssl_mode is False
    assert tls_conn.host == "smtp.example.com"
    assert tls_conn.port == 587
    assert tls_conn.timeout == 12.5
    assert len(tls_conn.starttls_calls) == 1
    assert isinstance(tls_conn.starttls_calls[0], ssl.SSLContext)
    assert tls_conn.login_calls == [("alerts", "secret")]
    assert len(tls_conn.sent_messages) == 1
    sent_msg = tls_conn.sent_messages[0]
    assert sent_msg["Subject"] == "Custom Email Title"
    assert sent_msg["From"] == "alerts@example.com"
    assert sent_msg["To"] == "sec@example.com, ops@example.com"
    assert "Adobe" in sent_msg.get_content()
    assert tls_conn.closed is True

    # Plain SMTP (no TLS, no auth)
    cfg_plain = EmailNotifyConfig(
        host="localhost",
        port=25,
        from_addr="alerts@example.com",
        to_addrs=["sec@example.com"],
        use_tls=False,
        use_ssl=False,
    )
    assert send_email_notification(cfg_plain, data) is True
    plain_conn = created[1]
    assert plain_conn.ssl_mode is False
    assert plain_conn.starttls_calls == []
    assert plain_conn.login_calls == []
    assert len(plain_conn.sent_messages) == 1

    # Implicit SSL + auth
    cfg_ssl = EmailNotifyConfig(
        host="smtp.example.com",
        port=465,
        from_addr="alerts@example.com",
        to_addrs=["sec@example.com"],
        username="ssl-user",
        password="ssl-password",
        use_tls=False,
        use_ssl=True,
    )
    assert send_email_notification(cfg_ssl, data) is True
    ssl_conn = created[2]
    assert ssl_conn.ssl_mode is True
    assert isinstance(ssl_conn.context, ssl.SSLContext)
    assert ssl_conn.starttls_calls == []
    assert ssl_conn.login_calls == [("ssl-user", "ssl-password")]
    assert len(ssl_conn.sent_messages) == 1

    # SMTPException wrapped in HIBPError
    def fake_smtp_fail(host: str, port: int, timeout: float = 30.0) -> _FakeSMTP:
        return _FakeSMTP(
            host,
            port,
            timeout=timeout,
            fail_with=smtplib.SMTPServerDisconnected("server closed"),
        )

    monkeypatch.setattr(smtplib, "SMTP", fake_smtp_fail)
    with pytest.raises(HIBPError, match="Email notification failed:"):
        send_email_notification(cfg_plain, data)

    # OSError during connect wrapped in HIBPError
    def fake_smtp_oserror(host: str, port: int, timeout: float = 30.0) -> _FakeSMTP:
        raise OSError("connection refused")

    monkeypatch.setattr(smtplib, "SMTP", fake_smtp_oserror)
    with pytest.raises(HIBPError, match="Email notification failed: connection refused"):
        send_email_notification(cfg_plain, data)


def test_github_issue_notify_config_validation_and_redaction() -> None:
    expected_auth = "ghp_secret_val"
    cfg = GitHubIssueNotifyConfig(repo="  octocat/hello-world  ", token=f"  {expected_auth}  ")
    assert cfg.repo == "octocat/hello-world"
    assert cfg.token == expected_auth
    assert cfg.labels == ["security", "pwned"]
    assert cfg.api_base_url == DEFAULT_GITHUB_API_URL
    assert cfg.dedup_title is True
    assert expected_auth not in repr(cfg)

    for bad_repo in ("", "   ", "noslash", "owner/", "/repo", "a/b/c", "my owner/repo", "a/b c"):
        with pytest.raises(ValidationError, match=r"GitHub repo must be in 'owner/repo' format\."):
            GitHubIssueNotifyConfig(repo=bad_repo, token="ghp_tok")

    with pytest.raises(ValidationError):
        GitHubIssueNotifyConfig(repo="owner/repo", token="   ")


def test_send_github_issue_notification_create_comment_and_errors(httpx_mock: Any) -> None:
    cfg = GitHubIssueNotifyConfig(repo="acme/sec-alerts", token="ghp_token_123")
    data = {"breaches": [{"Name": "Adobe"}]}

    # Invalid api_base_url rejected before checking exposures
    insecure_cfg = GitHubIssueNotifyConfig(
        repo="acme/sec-alerts",
        token="ghp_token_123",
        api_base_url="http://ghe.local/api/v3",
    )
    with pytest.raises(ValueError, match="https"):
        send_github_issue_notification(insecure_cfg, data)

    # No exposures -> None, 0 requests
    assert send_github_issue_notification(cfg, []) is None
    assert len(httpx_mock.get_requests()) == 0

    # dedup_title=True, no matching open issue (PRs, non-dicts, wrong title, non-int number ignored)
    issues_url = "https://api.github.com/repos/acme/sec-alerts/issues"
    httpx_mock.add_response(
        method="GET",
        url=f"{issues_url}?state=open&per_page=100&labels=security%2Cpwned",
        json=[
            "not-a-dict",
            {"title": "pwned Exposure Alert", "number": 1, "pull_request": {"url": "..."}},
            {"title": "Other Issue", "number": 2},
            {"title": "pwned Exposure Alert", "number": "not-an-int"},
        ],
    )
    httpx_mock.add_response(
        method="POST",
        url=issues_url,
        status_code=201,
        json={"number": 42, "html_url": "https://github.com/acme/sec-alerts/issues/42"},
    )
    created = send_github_issue_notification(cfg, data)
    assert created == {
        "action": "created",
        "number": 42,
        "url": "https://github.com/acme/sec-alerts/issues/42",
    }
    reqs = httpx_mock.get_requests()
    assert len(reqs) == 2
    assert reqs[0].headers["Authorization"] == "Bearer ghp_token_123"
    assert reqs[0].headers["Accept"] == "application/vnd.github+json"
    assert reqs[0].headers["X-GitHub-Api-Version"] == "2022-11-28"
    post_body = json.loads(reqs[1].content.decode("utf-8"))
    assert post_body["title"] == "pwned Exposure Alert"
    assert post_body["labels"] == ["security", "pwned"]
    assert "Adobe" in post_body["body"]

    # dedup_title=True, matching open issue found -> comments on existing issue
    httpx_mock.add_response(
        method="GET",
        url=f"{issues_url}?state=open&per_page=100&labels=security%2Cpwned",
        json=[{"title": "pwned Exposure Alert", "number": 7}],
    )
    httpx_mock.add_response(
        method="POST",
        url=f"{issues_url}/7/comments",
        status_code=201,
        json={"html_url": "https://github.com/acme/sec-alerts/issues/7#issuecomment-99"},
    )
    commented = send_github_issue_notification(cfg, data)
    assert commented == {
        "action": "commented",
        "number": 7,
        "url": "https://github.com/acme/sec-alerts/issues/7#issuecomment-99",
    }

    # dedup_title=True with empty labels + non-list GET response falls back to creating issue
    no_labels_cfg = GitHubIssueNotifyConfig(
        repo="acme/sec-alerts",
        token="ghp_token_123",
        labels=[],
        api_base_url="http://ghe.local/api/v3/",
    )
    ghe_issues = "http://ghe.local/api/v3/repos/acme/sec-alerts/issues"
    httpx_mock.add_response(
        method="GET",
        url=f"{ghe_issues}?state=open&per_page=100",
        json={"unexpected": "object"},
    )
    httpx_mock.add_response(
        method="POST",
        url=ghe_issues,
        status_code=201,
        json={"number": 9, "html_url": "http://ghe.local/acme/sec-alerts/issues/9"},
    )
    res_ghe = send_github_issue_notification(no_labels_cfg, data, allow_insecure_http=True)
    assert res_ghe == {
        "action": "created",
        "number": 9,
        "url": "http://ghe.local/acme/sec-alerts/issues/9",
    }

    # dedup_title=False with injected client (client must NOT be closed!)
    no_dedup_cfg = GitHubIssueNotifyConfig(
        repo="acme/sec-alerts",
        token="ghp_token_123",
        dedup_title=False,
    )
    httpx_mock.add_response(
        method="POST",
        url=issues_url,
        status_code=201,
        json={"number": 100, "html_url": "https://github.com/acme/sec-alerts/issues/100"},
    )
    client = httpx.Client()
    try:
        res_injected = send_github_issue_notification(no_dedup_cfg, data, client=client)
        assert res_injected == {
            "action": "created",
            "number": 100,
            "url": "https://github.com/acme/sec-alerts/issues/100",
        }
        assert not client.is_closed
    finally:
        client.close()

    # HTTPStatusError and RequestError wrapped in HIBPError
    httpx_mock.add_response(method="POST", url=issues_url, status_code=403)
    with pytest.raises(HIBPError, match="GitHub issue notification failed:"):
        send_github_issue_notification(no_dedup_cfg, data)

    httpx_mock.add_exception(
        httpx.RequestError("network down", request=httpx.Request("POST", issues_url))
    )
    with pytest.raises(HIBPError, match="GitHub issue notification failed:"):
        send_github_issue_notification(no_dedup_cfg, data)
