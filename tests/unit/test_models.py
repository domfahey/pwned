from __future__ import annotations

import pytest
from pydantic import ValidationError

from pwned.client import RateLimitError
from pwned.models import (
    Breach,
    BreachedAccountRangeResult,
    DataClassDescription,
    DnsToken,
    SearchResult,
    Subscription,
)


class TestNewModelsAndFields:
    def test_breach_disclosure_url_default_and_populated(self) -> None:
        minimal = Breach.model_validate({"Name": "Adobe"})
        assert minimal.disclosure_url is None

        full = Breach.model_validate(
            {"Name": "Adobe", "DisclosureUrl": "https://example.com/disclosure"}
        )
        assert full.disclosure_url == "https://example.com/disclosure"

    def test_subscription_extended_fields_optional_defaults(self) -> None:
        minimal = Subscription.model_validate(
            {
                "SubscriptionName": "Core",
                "Description": "Core tier",
                "SubscribedUntil": "2026-12-31T00:00:00Z",
                "Rpm": 10,
                "IncludesStealerLogs": False,
            }
        )
        assert minimal.max_breached_domains is None
        assert minimal.includes_bulk_domain_add is False
        assert minimal.includes_auto_subdomain_verification is False
        assert minimal.includes_customer_domains is False
        assert minimal.includes_k_anon is False

        pro = Subscription.model_validate(
            {
                "SubscriptionName": "Pro",
                "Description": "Pro tier",
                "SubscribedUntil": "2026-12-31T00:00:00Z",
                "Rpm": 100,
                "DomainSearchMaxBreachedAccounts": 500,
                "MaxBreachedDomains": 10,
                "IncludesStealerLogs": True,
                "IncludesBulkDomainAdd": True,
                "IncludesAutoSubdomainVerification": True,
                "IncludesCustomerDomains": True,
                "IncludesKAnon": True,
            }
        )
        assert pro.max_breached_domains == 10
        assert pro.includes_bulk_domain_add is True
        assert pro.includes_auto_subdomain_verification is True
        assert pro.includes_customer_domains is True
        assert pro.includes_k_anon is True

    def test_subscription_negative_max_breached_domains_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Subscription.model_validate(
                {
                    "SubscriptionName": "Pro",
                    "Description": "Pro tier",
                    "SubscribedUntil": "2026-12-31T00:00:00Z",
                    "Rpm": 100,
                    "MaxBreachedDomains": -1,
                    "IncludesStealerLogs": True,
                }
            )

    def test_data_class_description(self) -> None:
        item = DataClassDescription.model_validate(
            {"name": "Email addresses", "description": "User email addresses."}
        )
        assert item.name == "Email addresses"
        assert item.description == "User email addresses."
        assert item.model_dump(by_alias=True) == {
            "name": "Email addresses",
            "description": "User email addresses.",
        }

    def test_breached_account_range_result(self) -> None:
        item = BreachedAccountRangeResult.model_validate(
            {
                "hashSuffix": "C6C0AADE0C085843D66E4944E108C4A4CD",
                "websites": ["Adobe", "Gawker"],
            }
        )
        assert item.hash_suffix == "C6C0AADE0C085843D66E4944E108C4A4CD"
        assert item.websites == ["Adobe", "Gawker"]
        assert item.model_dump(by_alias=True) == {
            "hashSuffix": "C6C0AADE0C085843D66E4944E108C4A4CD",
            "websites": ["Adobe", "Gawker"],
        }

    def test_dns_token(self) -> None:
        token = DnsToken.model_validate({"txtRecordValue": "hibp-verify=abc123"})
        assert token.txt_record_value == "hibp-verify=abc123"
        assert token.model_dump(by_alias=True) == {"txtRecordValue": "hibp-verify=abc123"}

    def test_search_result_defaults_and_dump(self) -> None:
        res = SearchResult(
            breaches=[Breach.model_validate({"Name": "Adobe"})],
            pastes=[],
        )
        assert len(res.breaches) == 1
        assert res.pastes == []
        assert res.stealer_logs is None

    def test_rate_limit_error_retry_after_attribute(self) -> None:
        err_default = RateLimitError("Rate limit exceeded")
        assert err_default.retry_after is None
        assert str(err_default) == "Rate limit exceeded"

        err_with_retry = RateLimitError("Rate limit exceeded", retry_after=5)
        assert err_with_retry.retry_after == 5
