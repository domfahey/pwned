from __future__ import annotations

from typing import TypedDict


class Breach(TypedDict, total=False):
    Name: str
    Title: str
    Domain: str
    BreachDate: str
    AddedDate: str
    ModifiedDate: str
    PwnCount: int
    Description: str
    DataClasses: list[str]
    IsVerified: bool
    IsFabricated: bool
    IsSensitive: bool
    IsRetired: bool
    IsSpamList: bool
    IsMalware: bool
    IsSubscriptionFree: bool
    IsStealerLog: bool
    LogoPath: str
    Attribution: str | None


class Paste(TypedDict, total=False):
    Source: str
    Id: str
    Title: str | None
    Date: str | None
    EmailCount: int


class Subscription(TypedDict):
    SubscriptionName: str
    Description: str
    SubscribedUntil: str
    Rpm: int
    DomainSearchMaxBreachedAccounts: int
    IncludesStealerLogs: bool


class SubscribedDomain(TypedDict):
    DomainName: str
    PwnCount: int | None
    PwnCountExcludingSpamLists: int | None
    PwnCountExcludingSpamListsAtLastSubscriptionRenewal: int | None
    NextSubscriptionRenewal: str
