from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from pwned.client import HIBPClient, HIBPError, NotFoundError
from pwned.models import Breach
from pwned.reporting import (
    BreachExposureSummary,
    DataClassExposure,
    DomainReport,
    build_domain_report,
    generate_domain_report,
)


def test_models_frozen_and_alias() -> None:
    summary = BreachExposureSummary(
        name="Adobe",
        title="Adobe Breach",
        exposed_aliases=2,
        is_verified=True,
    )
    with pytest.raises(ValidationError):
        summary.exposed_aliases = 3

    dc = DataClassExposure(data_class="Passwords", exposed_aliases=2, breach_count=1)
    with pytest.raises(ValidationError):
        dc.exposed_aliases = 5

    report = DomainReport(
        domain="example.com",
        total_exposed_aliases=2,
        total_exposures=2,
        unique_breaches=1,
    )
    with pytest.raises(ValidationError):
        report.domain = "other.com"


def test_build_domain_report_basic() -> None:
    domain = "example.com"
    domain_breaches = {
        "alice@example.com": ["Adobe", "LinkedIn"],
        "bob@example.com": ["Adobe"],
    }
    catalog = [
        Breach.model_validate(
            {
                "Name": "Adobe",
                "Title": "Adobe",
                "BreachDate": "2013-10-04",
                "DataClasses": ["Passwords", "Email addresses"],
                "IsVerified": True,
                "IsSensitive": False,
            }
        ),
        Breach.model_validate(
            {
                "Name": "LinkedIn",
                "Title": "LinkedIn",
                "BreachDate": "2016-05-18",
                "DataClasses": ["Passwords", "Usernames"],
                "IsVerified": True,
                "IsSensitive": True,
            }
        ),
    ]

    report = build_domain_report(domain, domain_breaches, catalog)

    assert report.domain == "example.com"
    assert report.total_exposed_aliases == 2
    assert report.total_exposures == 3
    assert report.unique_breaches == 2
    assert report.most_recent_breach_date == date(2016, 5, 18)
    assert report.sensitive_breach_count == 1
    assert report.stealer_log_aliases is None

    # Top breaches sorted by (-exposed_aliases, name)
    # Adobe: 2 aliases, LinkedIn: 1 alias
    assert len(report.top_breaches) == 2
    assert report.top_breaches[0].name == "Adobe"
    assert report.top_breaches[0].exposed_aliases == 2
    assert report.top_breaches[1].name == "LinkedIn"
    assert report.top_breaches[1].exposed_aliases == 1

    # Data classes sorted by (-exposed_aliases, -breach_count, data_class)
    assert len(report.data_classes) == 3
    assert report.data_classes[0].data_class == "Passwords"
    assert report.data_classes[0].exposed_aliases == 2
    assert report.data_classes[0].breach_count == 2
    assert report.data_classes[1].data_class == "Email addresses"
    assert report.data_classes[1].exposed_aliases == 2
    assert report.data_classes[1].breach_count == 1
    assert report.data_classes[2].data_class == "Usernames"
    assert report.data_classes[2].exposed_aliases == 1
    assert report.data_classes[2].breach_count == 1


def test_build_domain_report_unknown_breach_and_sorting() -> None:
    domain = "example.com"
    # Duplicate breach name per alias deduplicated
    domain_breaches = {
        "alice@example.com": ["UnknownBreach", "UnknownBreach", "Adobe"],
        "bob@example.com": ["Adobe"],
    }
    catalog = [
        Breach.model_validate(
            {
                "Name": "adobe",  # case-insensitive catalog lookup
                "Title": "Adobe System",
                "BreachDate": "2015-01-01",
                "DataClasses": ["Passwords"],
                "IsVerified": True,
            }
        )
    ]
    stealer_logs = {"alice@example.com": ["log1"]}

    report = build_domain_report(domain, domain_breaches, catalog, stealer_logs=stealer_logs)

    assert report.unique_breaches == 2
    assert report.total_exposed_aliases == 2
    assert report.total_exposures == 3  # alice: 2 unique, bob: 1 unique
    assert report.most_recent_breach_date == date(2015, 1, 1)  # UnknownBreach has no date
    assert report.stealer_log_aliases == 1

    # Check UnknownBreach fallback rendering
    unknown_summary = next(b for b in report.top_breaches if b.name == "UnknownBreach")
    assert unknown_summary.title == "UnknownBreach"
    assert unknown_summary.breach_date is None
    assert unknown_summary.data_classes == []


def test_generate_domain_report_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock(spec=HIBPClient)
    client.get_domain_breaches.side_effect = NotFoundError("Not found")

    report = generate_domain_report(client, "clean.com", include_stealer_logs=True)
    assert report.domain == "clean.com"
    assert report.total_exposed_aliases == 0
    assert report.unique_breaches == 0
    assert report.stealer_log_aliases == 0
    client.get_breaches.assert_not_called()


def test_generate_domain_report_success_with_stealer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock(spec=HIBPClient)
    client.get_domain_breaches.return_value = {"user@example.com": ["Adobe"]}
    client.get_breaches.return_value = [
        Breach.model_validate(
            {
                "Name": "Adobe",
                "Title": "Adobe",
                "BreachDate": "2013-10-04",
                "DataClasses": ["Passwords"],
            }
        )
    ]
    client.get_stealer_logs_by_email_domain.return_value = {"user@example.com": ["log"]}

    report = generate_domain_report(client, "example.com", include_stealer_logs=True)
    assert report.total_exposed_aliases == 1
    assert report.stealer_log_aliases == 1
    client.get_breaches.assert_called_once()


def test_generate_domain_report_catalog_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock(spec=HIBPClient)
    client.get_domain_breaches.return_value = {"user@example.com": ["Adobe"]}
    client.get_breaches.side_effect = HIBPError("API error")

    report = generate_domain_report(client, "example.com", include_stealer_logs=False)
    assert report.total_exposed_aliases == 1
    assert report.unique_breaches == 1
    assert report.top_breaches[0].title == "Adobe"


def test_generate_domain_report_stealer_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock(spec=HIBPClient)
    client.get_domain_breaches.return_value = {"user@example.com": ["Adobe"]}
    client.get_breaches.return_value = []
    client.get_stealer_logs_by_email_domain.side_effect = NotFoundError("Not found")

    report = generate_domain_report(client, "example.com", include_stealer_logs=True)
    assert report.stealer_log_aliases == 0
