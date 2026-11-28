from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date
from pathlib import Path

from pydantic import Field, NonNegativeInt

from pwned.client import HIBPClient, HIBPError, NotFoundError
from pwned.history import ExposureHistoryStore, HistoryTrendSummary
from pwned.models import Breach, _HIBPBase


class BreachExposureSummary(_HIBPBase):
    name: str
    title: str
    breach_date: date | None = None
    exposed_aliases: NonNegativeInt
    is_verified: bool = False
    is_sensitive: bool = False
    is_spam_list: bool = False
    data_classes: list[str] = Field(default_factory=list)


class DataClassExposure(_HIBPBase):
    data_class: str
    exposed_aliases: NonNegativeInt
    breach_count: NonNegativeInt


class DomainReport(_HIBPBase):
    domain: str
    total_exposed_aliases: NonNegativeInt
    total_exposures: NonNegativeInt
    unique_breaches: NonNegativeInt
    most_recent_breach_date: date | None = None
    sensitive_breach_count: NonNegativeInt = 0
    stealer_log_aliases: NonNegativeInt | None = None
    top_breaches: list[BreachExposureSummary] = Field(default_factory=list)
    data_classes: list[DataClassExposure] = Field(default_factory=list)
    history_summary: HistoryTrendSummary | None = None


def build_domain_report(
    domain: str,
    domain_breaches: Mapping[str, Sequence[str]],
    catalog: Sequence[Breach],
    *,
    stealer_logs: Mapping[str, Sequence[str]] | None = None,
    history_summary: HistoryTrendSummary | None = None,
) -> DomainReport:
    catalog_map = {b.name.lower(): b for b in catalog}

    # Map breach name -> set of unique aliases
    breach_to_aliases: dict[str, set[str]] = {}
    # Map alias -> set of unique breach names
    alias_to_breaches: dict[str, set[str]] = {}

    for alias, breaches in domain_breaches.items():
        unique_bnames = set(breaches)
        alias_to_breaches[alias] = unique_bnames
        for bname in unique_bnames:
            breach_to_aliases.setdefault(bname, set()).add(alias)

    total_exposed_aliases = len(alias_to_breaches)
    total_exposures = sum(len(bnames) for bnames in alias_to_breaches.values())
    unique_breaches = len(breach_to_aliases)

    all_breach_dates = [
        catalog_map[bname.lower()].breach_date
        for bname in breach_to_aliases
        if bname.lower() in catalog_map and catalog_map[bname.lower()].breach_date is not None
    ]
    most_recent_breach_date = (
        max(d for d in all_breach_dates if d is not None) if all_breach_dates else None
    )

    sensitive_breach_count = sum(
        1
        for bname in breach_to_aliases
        if bname.lower() in catalog_map and catalog_map[bname.lower()].is_sensitive
    )

    stealer_log_aliases = len(stealer_logs) if stealer_logs is not None else None

    # Build top_breaches
    top_breaches_list: list[BreachExposureSummary] = []
    # Build data classes tracking: data_class -> set of aliases, set of breach names
    dc_to_aliases: dict[str, set[str]] = {}
    dc_to_breaches: dict[str, set[str]] = {}

    for bname, aliases in breach_to_aliases.items():
        b_lower = bname.lower()
        breach_obj = catalog_map.get(b_lower)
        if breach_obj is not None:
            title = breach_obj.title
            breach_date = breach_obj.breach_date
            is_verified = breach_obj.is_verified
            is_sensitive = breach_obj.is_sensitive
            is_spam_list = breach_obj.is_spam_list
            dcs = list(breach_obj.data_classes)
        else:
            title = bname
            breach_date = None
            is_verified = False
            is_sensitive = False
            is_spam_list = False
            dcs = []

        exposed_aliases_count = len(aliases)
        summary = BreachExposureSummary(
            name=bname,
            title=title,
            breach_date=breach_date,
            exposed_aliases=exposed_aliases_count,
            is_verified=is_verified,
            is_sensitive=is_sensitive,
            is_spam_list=is_spam_list,
            data_classes=dcs,
        )
        top_breaches_list.append(summary)

        for dc in dcs:
            dc_to_aliases.setdefault(dc, set()).update(aliases)
            dc_to_breaches.setdefault(dc, set()).add(bname)

    top_breaches_list.sort(key=lambda item: (-item.exposed_aliases, item.name))

    data_classes_list: list[DataClassExposure] = []
    for dc, aliases in dc_to_aliases.items():
        b_set = dc_to_breaches[dc]
        data_classes_list.append(
            DataClassExposure(
                data_class=dc,
                exposed_aliases=len(aliases),
                breach_count=len(b_set),
            )
        )

    data_classes_list.sort(
        key=lambda item: (-item.exposed_aliases, -item.breach_count, item.data_class)
    )

    if history_summary is not None:
        return DomainReport(
            domain=domain,
            total_exposed_aliases=total_exposed_aliases,
            total_exposures=total_exposures,
            unique_breaches=unique_breaches,
            most_recent_breach_date=most_recent_breach_date,
            sensitive_breach_count=sensitive_breach_count,
            stealer_log_aliases=stealer_log_aliases,
            top_breaches=top_breaches_list,
            data_classes=data_classes_list,
            history_summary=history_summary,
        )

    return DomainReport(
        domain=domain,
        total_exposed_aliases=total_exposed_aliases,
        total_exposures=total_exposures,
        unique_breaches=unique_breaches,
        most_recent_breach_date=most_recent_breach_date,
        sensitive_breach_count=sensitive_breach_count,
        stealer_log_aliases=stealer_log_aliases,
        top_breaches=top_breaches_list,
        data_classes=data_classes_list,
    )


def generate_domain_report(
    client: HIBPClient,
    domain: str,
    *,
    include_stealer_logs: bool = False,
    history_db: Path | None = None,
) -> DomainReport:
    try:
        domain_breaches = client.get_domain_breaches(domain)
    except NotFoundError:
        domain_breaches = {}

    catalog: list[Breach] = []
    if domain_breaches:
        try:
            catalog = client.get_breaches()
        except HIBPError:
            catalog = []

    stealer_logs: Mapping[str, Sequence[str]] | None = None
    if include_stealer_logs:
        try:
            stealer_logs = client.get_stealer_logs_by_email_domain(domain)
        except NotFoundError:
            stealer_logs = {}

    history_summary: HistoryTrendSummary | None = None
    if history_db is not None:
        with ExposureHistoryStore(history_db) as store:
            history_summary = store.get_trend_summary(target_type="domain", target=domain)

    return build_domain_report(
        domain,
        domain_breaches,
        catalog,
        stealer_logs=stealer_logs,
        history_summary=history_summary,
    )
