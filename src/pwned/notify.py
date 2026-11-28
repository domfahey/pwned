from __future__ import annotations

import json
from typing import Any, Literal
from urllib.parse import urlparse

import httpx

from pwned.client import REQUEST_TIMEOUT, HIBPError
from pwned.formatting import serialize

WebhookFormat = Literal["auto", "slack", "discord", "generic"]
WEBHOOK_FORMATS: tuple[WebhookFormat, ...] = ("auto", "slack", "discord", "generic")


def validate_webhook_url(url: str, *, allow_insecure_http: bool = False) -> str:
    cleaned = url.strip()
    if not cleaned:
        raise ValueError("Webhook URL cannot be empty.")
    parsed = urlparse(cleaned)
    if not parsed.netloc:
        raise ValueError(f"Invalid webhook URL: {url}")
    scheme = parsed.scheme.lower()
    if scheme == "https":
        return cleaned
    if scheme == "http" and allow_insecure_http:
        return cleaned
    raise ValueError(f"Webhook URL must use https scheme (got {scheme!r}).")


def detect_webhook_format(url: str) -> Literal["slack", "discord", "generic"]:
    parsed = urlparse(url)
    host = parsed.netloc.lower().split(":")[0]
    path = parsed.path

    if host in {"hooks.slack.com", "hooks.gov.slack.com"}:
        return "slack"
    if host in {
        "discord.com",
        "discordapp.com",
        "ptb.discord.com",
        "canary.discord.com",
    } and path.startswith("/api/webhooks/"):
        return "discord"
    return "generic"


def has_exposures(data: Any) -> bool:
    serialized = serialize(data)
    if isinstance(serialized, list):
        if not serialized:
            return False
        if any(isinstance(item, dict) and "status" in item for item in serialized):
            return any(
                item.get("status") == "pwned" for item in serialized if isinstance(item, dict)
            )
        return bool(serialized)
    if isinstance(serialized, dict):
        if "compromised_entries" in serialized or "findings" in serialized:
            return (
                bool(serialized.get("findings"))
                or bool(serialized.get("reused_groups"))
                or bool(serialized.get("strength_findings"))
                or bool(serialized.get("ad_findings"))
                or bool(serialized.get("wordlist_findings"))
                or bool(serialized.get("breach_findings"))
            )
        if "new_exposures" in serialized:
            return int(serialized["new_exposures"]) > 0
        if "total_exposed_aliases" in serialized:
            return int(serialized["total_exposed_aliases"]) > 0 or bool(
                serialized.get("stealer_log_aliases")
            )
        if "breaches" in serialized or "pastes" in serialized or "stealer_logs" in serialized:
            return (
                bool(serialized.get("breaches"))
                or bool(serialized.get("pastes"))
                or bool(serialized.get("stealer_logs"))
            )
        return bool(serialized)
    return bool(serialized)


def _summarize_data(data: Any) -> str:
    serialized = serialize(data)
    text = json.dumps(serialized, indent=2)
    if len(text) > 1800:
        return text[:1797] + "..."
    return text


def build_webhook_payload(
    data: Any,
    *,
    fmt: Literal["slack", "discord", "generic"],
    title: str = "pwned Exposure Alert",
) -> dict[str, Any]:
    summary = _summarize_data(data)
    if fmt == "slack":
        return {
            "text": f"{title}: {summary}",
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": title[:150]}},
                {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
            ],
        }
    if fmt == "discord":
        return {
            "content": title,
            "embeds": [{"title": title[:256], "description": summary, "color": 0xE74C3C}],
        }
    return {
        "source": "pwned",
        "title": title,
        "summary": summary,
        "data": serialize(data),
    }


def send_webhook_notification(
    url: str,
    data: Any,
    *,
    fmt: WebhookFormat = "auto",
    title: str = "pwned Exposure Alert",
    timeout: float = REQUEST_TIMEOUT,
    allow_insecure_http: bool = False,
    client: httpx.Client | None = None,
) -> bool:
    validated_url = validate_webhook_url(url, allow_insecure_http=allow_insecure_http)
    if not has_exposures(data):
        return False

    resolved_fmt = detect_webhook_format(validated_url) if fmt == "auto" else fmt
    payload = build_webhook_payload(data, fmt=resolved_fmt, title=title)

    def _do_post(c: httpx.Client) -> httpx.Response:
        try:
            resp = c.post(validated_url, json=payload)
            resp.raise_for_status()
            return resp
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            raise HIBPError(f"Webhook notification failed: {e}") from e

    if client is not None:
        _do_post(client)
    else:
        with httpx.Client(timeout=timeout) as c:
            _do_post(c)

    return True
