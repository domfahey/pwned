from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field


class Breach(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    name: str = Field(alias="Name")
    title: str = Field(default="", alias="Title")
    domain: str = Field(default="", alias="Domain")
    breach_date: date | None = Field(default=None, alias="BreachDate")
    added_date: datetime | None = Field(default=None, alias="AddedDate")
    modified_date: datetime | None = Field(default=None, alias="ModifiedDate")
    pwn_count: int = Field(default=0, alias="PwnCount", ge=0)
    description: str = Field(default="", alias="Description")
    data_classes: list[str] = Field(default_factory=list, alias="DataClasses")
    is_verified: bool = Field(default=False, alias="IsVerified")
    is_fabricated: bool = Field(default=False, alias="IsFabricated")
    is_sensitive: bool = Field(default=False, alias="IsSensitive")
    is_retired: bool = Field(default=False, alias="IsRetired")
    is_spam_list: bool = Field(default=False, alias="IsSpamList")
    is_malware: bool = Field(default=False, alias="IsMalware")
    is_subscription_free: bool = Field(default=False, alias="IsSubscriptionFree")
    is_stealer_log: bool = Field(default=False, alias="IsStealerLog")
    logo_path: str = Field(default="", alias="LogoPath")
    attribution: str | None = Field(default=None, alias="Attribution")


class Paste(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    source: str = Field(alias="Source")
    id: str = Field(alias="Id")
    title: str | None = Field(default=None, alias="Title")
    date: datetime | None = Field(default=None, alias="Date")
    email_count: int = Field(default=0, alias="EmailCount", ge=0)


class Subscription(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    subscription_name: str = Field(alias="SubscriptionName")
    description: str = Field(alias="Description")
    subscribed_until: date = Field(alias="SubscribedUntil")
    rpm: int = Field(alias="Rpm")
    domain_search_max_breached_accounts: int = Field(alias="DomainSearchMaxBreachedAccounts")
    includes_stealer_logs: bool = Field(alias="IncludesStealerLogs")


class SubscribedDomain(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    domain_name: str = Field(alias="DomainName")
    pwn_count: int | None = Field(default=None, alias="PwnCount")
    pwn_count_excluding_spam_lists: int | None = Field(
        default=None, alias="PwnCountExcludingSpamLists"
    )
    pwn_count_excluding_spam_lists_at_last_subscription_renewal: int | None = Field(
        default=None, alias="PwnCountExcludingSpamListsAtLastSubscriptionRenewal"
    )
    next_subscription_renewal: datetime | None = Field(
        default=None, alias="NextSubscriptionRenewal"
    )
