from __future__ import annotations

from datetime import date, datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

NonNegativeInt = Annotated[int, Field(ge=0)]


class _HIBPBase(BaseModel):
    """Shared config for all HIBP API response models."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)


class Breach(_HIBPBase):
    name: str = Field(alias="Name", description="Unique identifier for the breach.")
    title: str = Field(default="", alias="Title", description="Display title.")
    domain: str = Field(
        default="", alias="Domain", description="Primary domain of the breached site."
    )
    breach_date: date | None = Field(
        default=None, alias="BreachDate", description="Date the breach occurred."
    )
    added_date: datetime | None = Field(
        default=None, alias="AddedDate", description="When the breach was added to HIBP."
    )
    modified_date: datetime | None = Field(
        default=None, alias="ModifiedDate", description="When the breach record was last modified."
    )
    pwn_count: NonNegativeInt = Field(
        default=0, alias="PwnCount", description="Total number of accounts in the breach."
    )
    description: str = Field(
        default="", alias="Description", description="HTML description of the breach."
    )
    data_classes: list[str] = Field(
        default_factory=list, alias="DataClasses", description="Types of data compromised."
    )
    is_verified: bool = Field(
        default=False, alias="IsVerified", description="Whether the breach has been verified."
    )
    is_fabricated: bool = Field(
        default=False, alias="IsFabricated", description="Whether the breach is fabricated."
    )
    is_sensitive: bool = Field(
        default=False, alias="IsSensitive", description="Whether the breach is sensitive."
    )
    is_retired: bool = Field(
        default=False, alias="IsRetired", description="Whether the breach has been retired."
    )
    is_spam_list: bool = Field(
        default=False, alias="IsSpamList", description="Whether the breach is a spam list."
    )
    is_malware: bool = Field(
        default=False, alias="IsMalware", description="Whether the breach is from malware."
    )
    is_subscription_free: bool = Field(
        default=False,
        alias="IsSubscriptionFree",
        description="Whether the breach is accessible without a subscription.",
    )
    is_stealer_log: bool = Field(
        default=False, alias="IsStealerLog", description="Whether the breach is from stealer logs."
    )
    logo_path: str = Field(default="", alias="LogoPath", description="Path to the breach logo.")
    attribution: str | None = Field(
        default=None, alias="Attribution", description="Who the breach is attributed to."
    )


class Paste(_HIBPBase):
    source: str = Field(alias="Source", description="Paste site (e.g. Pastebin).")
    id: str = Field(alias="Id", description="Paste identifier on the source site.")
    title: str | None = Field(default=None, alias="Title", description="Title of the paste.")
    date: datetime | None = Field(
        default=None, alias="Date", description="When the paste was posted."
    )
    email_count: NonNegativeInt = Field(
        default=0, alias="EmailCount", description="Number of email addresses in the paste."
    )


class Subscription(_HIBPBase):
    subscription_name: str = Field(
        alias="SubscriptionName", description="Name of the subscription tier."
    )
    description: str = Field(alias="Description", description="Human-readable description.")
    subscribed_until: datetime = Field(
        alias="SubscribedUntil", description="Subscription expiry date."
    )
    rpm: int = Field(alias="Rpm", description="Requests per minute allowed.")
    domain_search_max_breached_accounts: int = Field(
        alias="DomainSearchMaxBreachedAccounts",
        description="Max breached accounts in domain search.",
    )
    includes_stealer_logs: bool = Field(
        alias="IncludesStealerLogs",
        description="Whether the subscription includes stealer log access.",
    )


class SubscribedDomain(_HIBPBase):
    domain_name: str = Field(alias="DomainName", description="The subscribed domain name.")
    pwn_count: int | None = Field(
        default=None, alias="PwnCount", description="Total breached accounts for this domain."
    )
    pwn_count_excluding_spam_lists: int | None = Field(
        default=None,
        alias="PwnCountExcludingSpamLists",
        description="Breached accounts excluding spam lists.",
    )
    pwn_count_excluding_spam_lists_at_last_subscription_renewal: int | None = Field(
        default=None,
        alias="PwnCountExcludingSpamListsAtLastSubscriptionRenewal",
        description="Breach count at last subscription renewal.",
    )
    next_subscription_renewal: datetime | None = Field(
        default=None,
        alias="NextSubscriptionRenewal",
        description="When the domain subscription renews.",
    )
