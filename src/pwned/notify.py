from __future__ import annotations

import json
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
from pydantic import Field, field_validator, model_validator

from pwned.client import REQUEST_TIMEOUT, HIBPError
from pwned.formatting import format_output, serialize
from pwned.models import _HIBPBase

WebhookFormat = Literal["auto", "slack", "discord", "teams", "pagerduty", "generic"]
WEBHOOK_FORMATS: tuple[WebhookFormat, ...] = (
    "auto",
    "slack",
    "discord",
    "teams",
    "pagerduty",
    "generic",
)
PagerDutySeverity = Literal["critical", "error", "warning", "info"]
PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
DEFAULT_GITHUB_API_URL = "https://api.github.com"


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


def detect_webhook_format(
    url: str,
) -> Literal["slack", "discord", "teams", "pagerduty", "generic"]:
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
    if host.endswith(".webhook.office.com") or (
        (host.endswith(".logic.azure.com") or host.endswith(".api.powerplatform.com"))
        and "workflows" in path.lower()
    ):
        return "teams"
    if host in {"events.pagerduty.com", "events.eu.pagerduty.com"} and path == "/v2/enqueue":
        return "pagerduty"
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
    fmt: Literal["slack", "discord", "teams", "pagerduty", "generic"],
    title: str = "pwned Exposure Alert",
    routing_key: str | None = None,
    severity: PagerDutySeverity = "error",
    dedup_key: str | None = None,
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
    if fmt == "teams":
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": title[:256],
                                "weight": "Bolder",
                                "size": "Medium",
                                "wrap": True,
                            },
                            {
                                "type": "TextBlock",
                                "text": summary,
                                "wrap": True,
                                "fontType": "Monospace",
                            },
                        ],
                    },
                }
            ],
        }
    if fmt == "pagerduty":
        cleaned_key = (routing_key or "").strip()
        if not cleaned_key:
            raise ValueError("PagerDuty notifications require a non-empty routing_key.")
        payload: dict[str, Any] = {
            "routing_key": cleaned_key,
            "event_action": "trigger",
            "payload": {
                "summary": title[:1024],
                "source": "pwned",
                "severity": severity,
                "custom_details": {
                    "summary": summary,
                    "data": serialize(data),
                },
            },
        }
        if dedup_key:
            payload["dedup_key"] = dedup_key
        return payload
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
    routing_key: str | None = None,
    severity: PagerDutySeverity = "error",
    dedup_key: str | None = None,
    timeout: float = REQUEST_TIMEOUT,
    allow_insecure_http: bool = False,
    client: httpx.Client | None = None,
) -> bool:
    validated_url = validate_webhook_url(url, allow_insecure_http=allow_insecure_http)
    if not has_exposures(data):
        return False

    resolved_fmt = detect_webhook_format(validated_url) if fmt == "auto" else fmt
    payload = build_webhook_payload(
        data,
        fmt=resolved_fmt,
        title=title,
        routing_key=routing_key,
        severity=severity,
        dedup_key=dedup_key,
    )

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


class EmailNotifyConfig(_HIBPBase):
    """SMTP email notification configuration."""

    host: str
    port: int = Field(default=587, ge=1, le=65535)
    from_addr: str
    to_addrs: list[str]
    username: str | None = None
    password: str | None = Field(default=None, repr=False)
    use_tls: bool = True
    use_ssl: bool = False

    @field_validator("host", "from_addr")
    @classmethod
    def _validate_non_empty(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Field must not be empty.")
        return cleaned

    @field_validator("to_addrs")
    @classmethod
    def _validate_to_addrs(cls, value: list[str]) -> list[str]:
        cleaned = [addr.strip() for addr in value]
        if not cleaned or any(not addr for addr in cleaned):
            raise ValueError("to_addrs must be a non-empty list of non-empty email addresses.")
        return cleaned

    @model_validator(mode="after")
    def _validate_transport_and_auth(self) -> EmailNotifyConfig:
        if self.use_tls and self.use_ssl:
            raise ValueError("use_tls and use_ssl cannot both be True.")
        if bool(self.username) != bool(self.password):
            raise ValueError("Both username and password must be provided together for SMTP auth.")
        return self


def send_email_notification(
    config: EmailNotifyConfig,
    data: Any,
    *,
    title: str = "pwned Exposure Alert",
    timeout: float = REQUEST_TIMEOUT,
) -> bool:
    if not has_exposures(data):
        return False

    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = config.from_addr
    msg["To"] = ", ".join(config.to_addrs)
    msg.set_content(format_output(data, fmt="text"), charset="utf-8")

    try:
        smtp_cm: smtplib.SMTP = (
            smtplib.SMTP_SSL(
                config.host,
                config.port,
                timeout=timeout,
                context=ssl.create_default_context(),
            )
            if config.use_ssl
            else smtplib.SMTP(config.host, config.port, timeout=timeout)
        )
        with smtp_cm as smtp:
            if config.use_tls:
                smtp.starttls(context=ssl.create_default_context())
            if config.username and config.password:
                smtp.login(config.username, config.password)
            smtp.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        raise HIBPError(f"Email notification failed: {exc}") from exc

    return True


class GitHubIssueNotifyConfig(_HIBPBase):
    """GitHub issue creation/commenting notification configuration."""

    repo: str
    token: str = Field(repr=False)
    labels: list[str] = Field(default_factory=lambda: ["security", "pwned"])
    api_base_url: str = DEFAULT_GITHUB_API_URL
    dedup_title: bool = True

    @field_validator("repo")
    @classmethod
    def _validate_repo(cls, value: str) -> str:
        cleaned = value.strip()
        parts = cleaned.split("/")
        if len(parts) != 2 or not parts[0] or not parts[1] or any(ch.isspace() for ch in cleaned):
            raise ValueError("GitHub repo must be in 'owner/repo' format.")
        return cleaned

    @field_validator("token")
    @classmethod
    def _validate_token(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("GitHub token must not be empty.")
        return cleaned


def send_github_issue_notification(
    config: GitHubIssueNotifyConfig,
    data: Any,
    *,
    title: str = "pwned Exposure Alert",
    timeout: float = REQUEST_TIMEOUT,
    allow_insecure_http: bool = False,
    client: httpx.Client | None = None,
) -> dict[str, Any] | None:
    base_url = validate_webhook_url(
        config.api_base_url, allow_insecure_http=allow_insecure_http
    ).rstrip("/")
    if not has_exposures(data):
        return None

    body = format_output(data, fmt="markdown")
    headers = {
        "Authorization": f"Bearer {config.token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    issues_url = f"{base_url}/repos/{config.repo}/issues"

    def _send(c: httpx.Client) -> dict[str, Any]:
        try:
            if config.dedup_title:
                page = 1
                while True:
                    params: dict[str, str] = {"state": "open", "per_page": "100"}
                    if config.labels:
                        params["labels"] = ",".join(config.labels)
                    if page > 1:
                        params["page"] = str(page)
                    list_resp = c.get(issues_url, params=params, headers=headers)
                    list_resp.raise_for_status()
                    existing = list_resp.json()
                    if not isinstance(existing, list):
                        break
                    for item in existing:
                        if (
                            isinstance(item, dict)
                            and "pull_request" not in item
                            and item.get("title") == title
                            and isinstance(item.get("number"), int)
                        ):
                            number = item["number"]
                            comment_resp = c.post(
                                f"{issues_url}/{number}/comments",
                                json={"body": body},
                                headers=headers,
                            )
                            comment_resp.raise_for_status()
                            comment_data = comment_resp.json()
                            return {
                                "action": "commented",
                                "number": number,
                                "url": str(comment_data.get("html_url", "")),
                            }
                    if len(existing) < 100:
                        break
                    page += 1

            create_resp = c.post(
                issues_url,
                json={"title": title, "body": body, "labels": list(config.labels)},
                headers=headers,
            )
            create_resp.raise_for_status()
            issue_data = create_resp.json()
            return {
                "action": "created",
                "number": int(issue_data["number"]),
                "url": str(issue_data.get("html_url", "")),
            }
        except (httpx.HTTPStatusError, httpx.RequestError) as exc:
            raise HIBPError(f"GitHub issue notification failed: {exc}") from exc

    if client is not None:
        return _send(client)
    with httpx.Client(timeout=timeout) as c:
        return _send(c)
