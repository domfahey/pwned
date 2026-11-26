from __future__ import annotations

from typing import Any

import httpx
import pytest

from pwned.client import HIBPError
from pwned.notify import (
    build_webhook_payload,
    detect_webhook_format,
    has_exposures,
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

    assert not has_exposures({"findings": [], "reused_groups": [], "strength_findings": []})
    assert has_exposures({"findings": [{"account": "alice"}]})
    assert has_exposures({"reused_groups": [["a", "b"]]})
    assert has_exposures({"strength_findings": [{"account": "bob"}]})

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
