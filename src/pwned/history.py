from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from pydantic import Field

from pwned.models import NonNegativeInt, _HIBPBase

ExposureTargetType = Literal["account", "domain"]
ExposureCategory = Literal["breach", "paste", "stealer_log", "alias_breach", "alias_stealer_log"]


class ExposureRecord(_HIBPBase):
    """Persisted lifecycle record for an individual account or domain exposure."""

    target_type: ExposureTargetType
    target: str
    category: ExposureCategory
    identifier: str
    first_seen_at: str
    last_seen_at: str
    resolved_at: str | None = None
    times_seen: NonNegativeInt


class HistoryTrendSummary(_HIBPBase):
    """Aggregate exposure remediation trend metrics."""

    total_runs: NonNegativeInt
    active_exposures: NonNegativeInt
    new_in_latest_run: NonNegativeInt
    resolved_in_latest_run: NonNegativeInt
    total_resolved: NonNegativeInt
    remediation_rate: float = Field(ge=0.0, le=100.0)


class HistorySyncResult(_HIBPBase):
    """Outcome of recording a monitoring run snapshot into ExposureHistoryStore."""

    run_id: int
    new_exposures: NonNegativeInt
    resolved_exposures: NonNegativeInt
    active_exposures: NonNegativeInt
    summary: HistoryTrendSummary


def _format_timestamp(timestamp: datetime | None) -> str:
    if timestamp is None:
        return datetime.now(UTC).isoformat()
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=UTC).isoformat()
    return timestamp.astimezone(UTC).isoformat()


class ExposureHistoryStore:
    """SQLite-backed store tracking exposure discovery, persistence, and remediation."""

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitor_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at TEXT NOT NULL,
                    accounts_checked INTEGER NOT NULL,
                    domains_checked INTEGER NOT NULL,
                    new_exposures INTEGER NOT NULL,
                    resolved_exposures INTEGER NOT NULL,
                    active_exposures INTEGER NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS exposures (
                    target_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    category TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    activated_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    resolved_at TEXT,
                    times_seen INTEGER NOT NULL,
                    PRIMARY KEY (target_type, target, category, identifier)
                )
                """
            )

    def __enter__(self) -> ExposureHistoryStore:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    def record_snapshot(
        self,
        *,
        checked_targets: Sequence[tuple[ExposureTargetType, str]],
        observed_exposures: Sequence[tuple[ExposureTargetType, str, ExposureCategory, str]],
        reconcile_scopes: Sequence[tuple[ExposureTargetType, str, ExposureCategory]] | None = None,
        accounts_checked: int = 0,
        domains_checked: int = 0,
        timestamp: datetime | None = None,
    ) -> HistorySyncResult:
        """Record a monitoring run snapshot and update active/resolved exposure state.

        When ``reconcile_scopes`` is supplied, only active exposures matching one of the
        explicit ``(target_type, target, category)`` scopes are reconciled for resolution;
        categories outside the queried scope are preserved untouched.
        """
        ts = _format_timestamp(timestamp)
        normalized_targets: set[tuple[ExposureTargetType, str]] = {
            (target_type, target.lower()) for target_type, target in checked_targets
        }
        normalized_scopes: set[tuple[ExposureTargetType, str, ExposureCategory]] | None = (
            {
                (target_type, target.lower(), category)
                for target_type, target, category in reconcile_scopes
            }
            if reconcile_scopes is not None
            else None
        )
        normalized_exposures: set[tuple[ExposureTargetType, str, ExposureCategory, str]] = {
            (target_type, target.lower(), category, identifier)
            for target_type, target, category, identifier in observed_exposures
        }

        new_count = 0
        resolved_count = 0

        with self._conn:
            for target_type, target_norm, category, identifier in sorted(normalized_exposures):
                existing = self._conn.execute(
                    """
                    SELECT resolved_at
                    FROM exposures
                    WHERE target_type = ? AND target = ? AND category = ? AND identifier = ?
                    """,
                    (target_type, target_norm, category, identifier),
                ).fetchone()
                if existing is None:
                    self._conn.execute(
                        """
                        INSERT INTO exposures (
                            target_type,
                            target,
                            category,
                            identifier,
                            first_seen_at,
                            activated_at,
                            last_seen_at,
                            resolved_at,
                            times_seen
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 1)
                        """,
                        (target_type, target_norm, category, identifier, ts, ts, ts),
                    )
                    new_count += 1
                elif existing["resolved_at"] is not None:
                    self._conn.execute(
                        """
                        UPDATE exposures
                        SET activated_at = ?, last_seen_at = ?, resolved_at = NULL,
                            times_seen = times_seen + 1
                        WHERE target_type = ? AND target = ? AND category = ? AND identifier = ?
                        """,
                        (ts, ts, target_type, target_norm, category, identifier),
                    )
                    new_count += 1
                else:
                    self._conn.execute(
                        """
                        UPDATE exposures
                        SET last_seen_at = ?, times_seen = times_seen + 1
                        WHERE target_type = ? AND target = ? AND category = ? AND identifier = ?
                        """,
                        (ts, target_type, target_norm, category, identifier),
                    )

            if normalized_scopes is not None:
                for target_type, target_norm, category in sorted(normalized_scopes):
                    active_rows = self._conn.execute(
                        """
                        SELECT identifier
                        FROM exposures
                        WHERE target_type = ? AND target = ? AND category = ?
                          AND resolved_at IS NULL
                        """,
                        (target_type, target_norm, category),
                    ).fetchall()
                    for row in active_rows:
                        key = (target_type, target_norm, category, str(row["identifier"]))
                        if key not in normalized_exposures:
                            self._conn.execute(
                                """
                                UPDATE exposures
                                SET resolved_at = ?
                                WHERE target_type = ? AND target = ? AND category = ?
                                  AND identifier = ?
                                """,
                                (ts, target_type, target_norm, category, key[3]),
                            )
                            resolved_count += 1
            else:
                for target_type, target_norm in sorted(normalized_targets):
                    active_rows = self._conn.execute(
                        """
                        SELECT category, identifier
                        FROM exposures
                        WHERE target_type = ? AND target = ? AND resolved_at IS NULL
                        """,
                        (target_type, target_norm),
                    ).fetchall()
                    for row in active_rows:
                        key = (
                            target_type,
                            target_norm,
                            cast(ExposureCategory, row["category"]),
                            str(row["identifier"]),
                        )
                        if key not in normalized_exposures:
                            self._conn.execute(
                                """
                                UPDATE exposures
                                SET resolved_at = ?
                                WHERE target_type = ? AND target = ? AND category = ?
                                  AND identifier = ?
                                """,
                                (ts, target_type, target_norm, key[2], key[3]),
                            )
                            resolved_count += 1

            active_row = self._conn.execute(
                "SELECT COUNT(*) AS active_count FROM exposures WHERE resolved_at IS NULL"
            ).fetchone()
            active_count = int(active_row["active_count"])

            self._conn.execute(
                """
                INSERT INTO monitor_runs (
                    recorded_at,
                    accounts_checked,
                    domains_checked,
                    new_exposures,
                    resolved_exposures,
                    active_exposures
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    accounts_checked,
                    domains_checked,
                    new_count,
                    resolved_count,
                    active_count,
                ),
            )
            run_id_row = self._conn.execute("SELECT last_insert_rowid()").fetchone()
            run_id = int(run_id_row[0])

        summary = self.get_trend_summary()
        return HistorySyncResult(
            run_id=run_id,
            new_exposures=new_count,
            resolved_exposures=resolved_count,
            active_exposures=active_count,
            summary=summary,
        )

    def list_exposures(
        self,
        *,
        target_type: ExposureTargetType | None = None,
        target: str | None = None,
        include_resolved: bool = False,
    ) -> list[ExposureRecord]:
        """Return stored exposure records sorted deterministically."""
        target_norm = target.lower() if target is not None else None
        rows = self._conn.execute(
            """
            SELECT
                target_type,
                target,
                category,
                identifier,
                first_seen_at,
                last_seen_at,
                resolved_at,
                times_seen
            FROM exposures
            WHERE (? IS NULL OR target_type = ?)
              AND (? IS NULL OR target = ?)
              AND (? = 1 OR resolved_at IS NULL)
            ORDER BY target_type, target, category, identifier
            """,
            (target_type, target_type, target_norm, target_norm, int(include_resolved)),
        ).fetchall()
        return [
            ExposureRecord(
                target_type=row["target_type"],
                target=row["target"],
                category=row["category"],
                identifier=row["identifier"],
                first_seen_at=row["first_seen_at"],
                last_seen_at=row["last_seen_at"],
                resolved_at=row["resolved_at"],
                times_seen=row["times_seen"],
            )
            for row in rows
        ]

    def get_trend_summary(
        self,
        *,
        target_type: ExposureTargetType | None = None,
        target: str | None = None,
    ) -> HistoryTrendSummary:
        """Compute aggregate or target-filtered exposure remediation trend metrics."""
        target_norm = target.lower() if target is not None else None
        counts_row = self._conn.execute(
            """
            SELECT
                COALESCE(SUM(CASE WHEN resolved_at IS NULL THEN 1 ELSE 0 END), 0) AS active_count,
                COALESCE(
                    SUM(CASE WHEN resolved_at IS NOT NULL THEN 1 ELSE 0 END), 0
                ) AS resolved_count
            FROM exposures
            WHERE (? IS NULL OR target_type = ?)
              AND (? IS NULL OR target = ?)
            """,
            (target_type, target_type, target_norm, target_norm),
        ).fetchone()
        active_exposures = int(counts_row["active_count"])
        total_resolved = int(counts_row["resolved_count"])

        runs_row = self._conn.execute("SELECT COUNT(*) AS total_runs FROM monitor_runs").fetchone()
        total_runs = int(runs_row["total_runs"])

        latest_row = self._conn.execute(
            """
            SELECT recorded_at, new_exposures, resolved_exposures
            FROM monitor_runs
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

        if latest_row is None:
            new_in_latest_run = 0
            resolved_in_latest_run = 0
        elif target_type is None and target_norm is None:
            new_in_latest_run = int(latest_row["new_exposures"])
            resolved_in_latest_run = int(latest_row["resolved_exposures"])
        else:
            latest_ts = str(latest_row["recorded_at"])
            latest_filtered_row = self._conn.execute(
                """
                SELECT
                    COALESCE(
                        SUM(
                            CASE
                                WHEN activated_at = ? AND resolved_at IS NULL THEN 1
                                ELSE 0
                            END
                        ),
                        0
                    ) AS new_count,
                    COALESCE(
                        SUM(CASE WHEN resolved_at = ? THEN 1 ELSE 0 END),
                        0
                    ) AS resolved_count
                FROM exposures
                WHERE (? IS NULL OR target_type = ?)
                  AND (? IS NULL OR target = ?)
                """,
                (latest_ts, latest_ts, target_type, target_type, target_norm, target_norm),
            ).fetchone()
            new_in_latest_run = int(latest_filtered_row["new_count"])
            resolved_in_latest_run = int(latest_filtered_row["resolved_count"])

        total_seen = active_exposures + total_resolved
        remediation_rate = (
            round((total_resolved / total_seen) * 100.0, 1) if total_seen > 0 else 0.0
        )

        return HistoryTrendSummary(
            total_runs=total_runs,
            active_exposures=active_exposures,
            new_in_latest_run=new_in_latest_run,
            resolved_in_latest_run=resolved_in_latest_run,
            total_resolved=total_resolved,
            remediation_rate=remediation_rate,
        )
