from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from pwned.history import (
    ExposureHistoryStore,
    ExposureRecord,
    HistorySyncResult,
    HistoryTrendSummary,
)


def test_history_models_validation_and_immutability() -> None:
    record = ExposureRecord(
        target_type="account",
        target="alice@example.com",
        category="breach",
        identifier="Adobe",
        first_seen_at="2026-01-01T00:00:00+00:00",
        last_seen_at="2026-01-02T00:00:00+00:00",
        times_seen=2,
    )
    assert record.resolved_at is None
    with pytest.raises(ValidationError):
        record.times_seen = 3
    with pytest.raises(ValidationError):
        ExposureRecord(
            target_type="account",
            target="alice@example.com",
            category="breach",
            identifier="Adobe",
            first_seen_at="2026-01-01T00:00:00+00:00",
            last_seen_at="2026-01-02T00:00:00+00:00",
            times_seen=-1,
        )

    summary = HistoryTrendSummary(
        total_runs=2,
        active_exposures=1,
        new_in_latest_run=0,
        resolved_in_latest_run=1,
        total_resolved=1,
        remediation_rate=50.0,
    )
    with pytest.raises(ValidationError):
        HistoryTrendSummary(
            total_runs=1,
            active_exposures=0,
            new_in_latest_run=0,
            resolved_in_latest_run=0,
            total_resolved=0,
            remediation_rate=101.0,
        )
    with pytest.raises(ValidationError):
        HistoryTrendSummary(
            total_runs=1,
            active_exposures=0,
            new_in_latest_run=0,
            resolved_in_latest_run=0,
            total_resolved=0,
            remediation_rate=-0.1,
        )

    sync = HistorySyncResult(
        run_id=1,
        new_exposures=1,
        resolved_exposures=0,
        active_exposures=1,
        summary=summary,
    )
    assert sync.run_id == 1


def test_store_creates_parent_dirs_wal_mode_and_empty_summary(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "dir" / "history.db"
    assert not db_path.parent.exists()

    with ExposureHistoryStore(db_path) as store:
        assert db_path.is_file()
        assert store.list_exposures() == []
        assert store.list_exposures(include_resolved=True) == []

        empty_global = store.get_trend_summary()
        assert empty_global == HistoryTrendSummary(
            total_runs=0,
            active_exposures=0,
            new_in_latest_run=0,
            resolved_in_latest_run=0,
            total_resolved=0,
            remediation_rate=0.0,
        )

        empty_filtered = store.get_trend_summary(target_type="domain", target="example.com")
        assert empty_filtered == empty_global

    conn = sqlite3.connect(str(db_path))
    try:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert str(journal_mode).lower() == "wal"
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert {"monitor_runs", "exposures"}.issubset(tables)
        run_cols = [row[1] for row in conn.execute("PRAGMA table_info(monitor_runs)").fetchall()]
        assert run_cols == [
            "id",
            "recorded_at",
            "accounts_checked",
            "domains_checked",
            "new_exposures",
            "resolved_exposures",
            "active_exposures",
        ]
        exp_cols = [row[1] for row in conn.execute("PRAGMA table_info(exposures)").fetchall()]
        assert exp_cols == [
            "target_type",
            "target",
            "category",
            "identifier",
            "first_seen_at",
            "activated_at",
            "last_seen_at",
            "resolved_at",
            "times_seen",
        ]
    finally:
        conn.close()


def test_record_snapshot_lifecycle_new_active_resolved_reappeared(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    ts1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    ts2 = datetime(2026, 1, 2, 10, 0, 0)  # naive UTC timestamp
    tz_plus2 = timezone(timedelta(hours=2))
    ts3 = datetime(2026, 1, 3, 12, 0, 0, tzinfo=tz_plus2)  # converts to 10:00:00+00:00

    with ExposureHistoryStore(db_path) as store:
        # Run 1: initial observations with duplicate entries and mixed-case targets
        sync1 = store.record_snapshot(
            checked_targets=[
                ("account", "Alice@Example.COM"),
                ("account", "alice@example.com"),
                ("domain", "Example.COM"),
            ],
            observed_exposures=[
                ("account", "Alice@Example.COM", "breach", "Adobe"),
                ("account", "alice@example.com", "breach", "Adobe"),
                ("account", "alice@example.com", "paste", "Pastebin:abc"),
                ("domain", "Example.COM", "alias_breach", "bob:LinkedIn"),
                ("domain", "example.com", "alias_stealer_log", "bob:stealer.test"),
            ],
            accounts_checked=1,
            domains_checked=1,
            timestamp=ts1,
        )
        assert sync1.run_id == 1
        assert sync1.new_exposures == 4
        assert sync1.resolved_exposures == 0
        assert sync1.active_exposures == 4
        assert sync1.summary == HistoryTrendSummary(
            total_runs=1,
            active_exposures=4,
            new_in_latest_run=4,
            resolved_in_latest_run=0,
            total_resolved=0,
            remediation_rate=0.0,
        )

        # Run 2: Adobe stays active, Pastebin:abc disappears (resolved!), Canva is new.
        # Domain is NOT in checked_targets (simulating error/skip) -> domain exposures untouched!
        sync2 = store.record_snapshot(
            checked_targets=[("account", "alice@example.com")],
            observed_exposures=[
                ("account", "alice@example.com", "breach", "Adobe"),
                ("account", "alice@example.com", "breach", "Canva"),
            ],
            accounts_checked=1,
            domains_checked=0,
            timestamp=ts2,
        )
        assert sync2.run_id == 2
        assert sync2.new_exposures == 1
        assert sync2.resolved_exposures == 1
        assert sync2.active_exposures == 4
        assert sync2.summary == HistoryTrendSummary(
            total_runs=2,
            active_exposures=4,
            new_in_latest_run=1,
            resolved_in_latest_run=1,
            total_resolved=1,
            remediation_rate=20.0,
        )

        # Verify sorting and filtering of list_exposures
        active = store.list_exposures()
        assert [(r.target_type, r.target, r.category, r.identifier) for r in active] == [
            ("account", "alice@example.com", "breach", "Adobe"),
            ("account", "alice@example.com", "breach", "Canva"),
            ("domain", "example.com", "alias_breach", "bob:LinkedIn"),
            ("domain", "example.com", "alias_stealer_log", "bob:stealer.test"),
        ]
        assert active[0].first_seen_at == "2026-01-01T10:00:00+00:00"
        assert active[0].last_seen_at == "2026-01-02T10:00:00+00:00"
        assert active[0].times_seen == 2
        assert active[0].resolved_at is None

        all_alice = store.list_exposures(
            target_type="account",
            target="ALICE@EXAMPLE.COM",
            include_resolved=True,
        )
        assert len(all_alice) == 3
        paste_rec = next(r for r in all_alice if r.category == "paste")
        assert paste_rec.resolved_at == "2026-01-02T10:00:00+00:00"
        assert paste_rec.times_seen == 1

        # Run 3: Pastebin:abc REAPPEARS, and domain example.com is now clean (both resolved!)
        sync3 = store.record_snapshot(
            checked_targets=[
                ("account", "alice@example.com"),
                ("domain", "example.com"),
            ],
            observed_exposures=[
                ("account", "alice@example.com", "breach", "Adobe"),
                ("account", "alice@example.com", "breach", "Canva"),
                ("account", "alice@example.com", "paste", "Pastebin:abc"),
            ],
            accounts_checked=1,
            domains_checked=1,
            timestamp=ts3,
        )
        assert sync3.run_id == 3
        assert sync3.new_exposures == 1  # Pastebin:abc reappeared!
        assert sync3.resolved_exposures == 2  # both domain exposures resolved!
        assert sync3.active_exposures == 3
        assert sync3.summary == HistoryTrendSummary(
            total_runs=3,
            active_exposures=3,
            new_in_latest_run=1,
            resolved_in_latest_run=2,
            total_resolved=2,
            remediation_rate=40.0,
        )

        # Reappeared exposure preserves original first_seen_at, clears resolved_at, bumps times_seen
        reappeared = next(
            r
            for r in store.list_exposures(target_type="account", target="alice@example.com")
            if r.category == "paste"
        )
        assert reappeared.first_seen_at == "2026-01-01T10:00:00+00:00"
        assert reappeared.last_seen_at == "2026-01-03T10:00:00+00:00"
        assert reappeared.resolved_at is None
        assert reappeared.times_seen == 2

    # Re-open store to verify persistence and per-target trend summaries
    with ExposureHistoryStore(db_path) as reopened:
        domain_summary = reopened.get_trend_summary(target_type="domain", target="Example.COM")
        assert domain_summary == HistoryTrendSummary(
            total_runs=3,
            active_exposures=0,
            new_in_latest_run=0,
            resolved_in_latest_run=2,
            total_resolved=2,
            remediation_rate=100.0,
        )

        account_summary = reopened.get_trend_summary(target_type="account")
        assert account_summary == HistoryTrendSummary(
            total_runs=3,
            active_exposures=3,
            new_in_latest_run=1,
            resolved_in_latest_run=0,
            total_resolved=0,
            remediation_rate=0.0,
        )

        by_target_only = reopened.get_trend_summary(target="example.com")
        assert by_target_only == domain_summary

        unknown_summary = reopened.get_trend_summary(target_type="domain", target="missing.example")
        assert unknown_summary == HistoryTrendSummary(
            total_runs=3,
            active_exposures=0,
            new_in_latest_run=0,
            resolved_in_latest_run=0,
            total_resolved=0,
            remediation_rate=0.0,
        )


def test_record_snapshot_default_timestamp_empty_snapshot_and_rounding(tmp_path: Path) -> None:
    db_path = tmp_path / "rounding.db"
    with ExposureHistoryStore(db_path) as store:
        # Empty snapshot with default UTC timestamp
        empty_sync = store.record_snapshot(
            checked_targets=[],
            observed_exposures=[],
        )
        assert empty_sync.run_id == 1
        assert empty_sync.new_exposures == 0
        assert empty_sync.resolved_exposures == 0
        assert empty_sync.active_exposures == 0
        assert empty_sync.summary.total_runs == 1
        assert empty_sync.summary.remediation_rate == 0.0

        # 3 exposures on domain, then 1 resolved -> 33.3%
        ts_a = datetime(2026, 2, 1, 0, 0, 0, tzinfo=UTC)
        ts_b = datetime(2026, 2, 2, 0, 0, 0, tzinfo=UTC)
        store.record_snapshot(
            checked_targets=[("domain", "corp.example")],
            observed_exposures=[
                ("domain", "corp.example", "alias_breach", "a:B1"),
                ("domain", "corp.example", "alias_breach", "b:B2"),
                ("domain", "corp.example", "alias_breach", "c:B3"),
            ],
            domains_checked=1,
            timestamp=ts_a,
        )
        sync_b = store.record_snapshot(
            checked_targets=[("domain", "corp.example")],
            observed_exposures=[
                ("domain", "corp.example", "alias_breach", "a:B1"),
                ("domain", "corp.example", "alias_breach", "b:B2"),
            ],
            domains_checked=1,
            timestamp=ts_b,
        )
        assert sync_b.summary.remediation_rate == 33.3

        # Filtered summary sees newly added exposure in latest run
        ts_c = datetime(2026, 2, 3, 0, 0, 0, tzinfo=UTC)
        store.record_snapshot(
            checked_targets=[("domain", "corp.example")],
            observed_exposures=[
                ("domain", "corp.example", "alias_breach", "a:B1"),
                ("domain", "corp.example", "alias_breach", "b:B2"),
                ("domain", "corp.example", "alias_breach", "d:B4"),
            ],
            domains_checked=1,
            timestamp=ts_c,
        )
        corp_summary = store.get_trend_summary(target_type="domain", target="corp.example")
        assert corp_summary.active_exposures == 3
        assert corp_summary.total_resolved == 1
        assert corp_summary.new_in_latest_run == 1
        assert corp_summary.resolved_in_latest_run == 0
        assert corp_summary.remediation_rate == 25.0

        # Account stealer_log category support
        store.record_snapshot(
            checked_targets=[("account", "user@corp.example")],
            observed_exposures=[("account", "user@corp.example", "stealer_log", "evil.site")],
            accounts_checked=1,
        )
        records = store.list_exposures(target_type="account")
        assert len(records) == 1
        assert records[0].category == "stealer_log"
        assert records[0].identifier == "evil.site"
        assert datetime.fromisoformat(records[0].first_seen_at).tzinfo is not None

    # Direct open/close without context manager & verify monitor_runs persisted rows
    direct_store = ExposureHistoryStore(db_path)
    try:
        assert direct_store.get_trend_summary().total_runs == 5
    finally:
        direct_store.close()

    conn = sqlite3.connect(str(db_path))
    try:
        runs = conn.execute(
            "SELECT id, accounts_checked, domains_checked, new_exposures, "
            "resolved_exposures, active_exposures FROM monitor_runs ORDER BY id"
        ).fetchall()
        assert runs == [
            (1, 0, 0, 0, 0, 0),
            (2, 0, 1, 3, 0, 3),
            (3, 0, 1, 0, 1, 2),
            (4, 0, 1, 1, 0, 3),
            (5, 1, 0, 1, 0, 4),
        ]
    finally:
        conn.close()


def test_reconcile_scopes_and_reopened_filtered_domain_summary(tmp_path: Path) -> None:
    db_path = tmp_path / "scoped.db"
    ts1 = datetime(2026, 3, 1, tzinfo=UTC)
    ts2 = datetime(2026, 3, 2, tzinfo=UTC)
    ts3 = datetime(2026, 3, 3, tzinfo=UTC)

    with ExposureHistoryStore(db_path) as store:
        # Run 1: observe breach + stealer_log on account and alias exposures on domain
        store.record_snapshot(
            checked_targets=[("account", "alice@example.com"), ("domain", "example.com")],
            reconcile_scopes=[
                ("account", "alice@example.com", "breach"),
                ("account", "alice@example.com", "stealer_log"),
                ("domain", "example.com", "alias_breach"),
                ("domain", "example.com", "alias_stealer_log"),
            ],
            observed_exposures=[
                ("account", "alice@example.com", "breach", "Adobe"),
                ("account", "alice@example.com", "stealer_log", "evil.test"),
                ("domain", "example.com", "alias_breach", "alice:Adobe"),
                ("domain", "example.com", "alias_stealer_log", "alice:evil.test"),
            ],
            timestamp=ts1,
        )

        # Run 2: only reconcile breach and alias_breach (stealer logs not queried -> untouched!)
        sync2 = store.record_snapshot(
            checked_targets=[("account", "alice@example.com"), ("domain", "example.com")],
            reconcile_scopes=[
                ("account", "alice@example.com", "breach"),
                ("domain", "example.com", "alias_breach"),
            ],
            observed_exposures=[
                ("account", "alice@example.com", "breach", "Adobe"),
            ],
            timestamp=ts2,
        )
        assert sync2.resolved_exposures == 1  # only alias_breach resolved
        active = store.list_exposures()
        assert [(r.target_type, r.category, r.identifier) for r in active] == [
            ("account", "breach", "Adobe"),
            ("account", "stealer_log", "evil.test"),
            ("domain", "alias_stealer_log", "alice:evil.test"),
        ]

        # Run 3: alice:Adobe reappears on domain -> domain-filtered new_in_latest_run MUST be 1
        sync3 = store.record_snapshot(
            checked_targets=[("domain", "example.com")],
            reconcile_scopes=[("domain", "example.com", "alias_breach")],
            observed_exposures=[("domain", "example.com", "alias_breach", "alice:Adobe")],
            timestamp=ts3,
        )
        assert sync3.new_exposures == 1
        domain_summary = store.get_trend_summary(target_type="domain", target="example.com")
        assert domain_summary.new_in_latest_run == 1
        assert domain_summary.active_exposures == 2
        assert domain_summary.total_resolved == 0
