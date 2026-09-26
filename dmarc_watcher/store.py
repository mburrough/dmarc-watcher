"""SQLite persistence: dedupe seen reports, keep records for rollups."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .parser import Report

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    key              TEXT PRIMARY KEY,
    org_name         TEXT NOT NULL,
    report_id        TEXT,
    domain           TEXT,
    begin_ts         INTEGER,
    end_ts           INTEGER,
    fetched_at       INTEGER,
    total_messages   INTEGER,
    failed_messages  INTEGER,
    enforced_messages INTEGER,
    policy_p         TEXT,
    source_name      TEXT
);
CREATE TABLE IF NOT EXISTS records (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    report_key   TEXT NOT NULL REFERENCES reports(key) ON DELETE CASCADE,
    source_ip    TEXT,
    count        INTEGER,
    disposition  TEXT,
    dkim_aligned TEXT,
    spf_aligned  TEXT,
    header_from  TEXT,
    passed       INTEGER,
    reasons      TEXT,
    auth         TEXT
);
CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT);
CREATE INDEX IF NOT EXISTS idx_reports_end ON reports(end_ts);
CREATE INDEX IF NOT EXISTS idx_records_key ON records(report_key);
"""


@dataclass
class Summary:
    days: int
    reports_total: int = 0
    reports_clean: int = 0
    messages_total: int = 0
    messages_failed: int = 0
    messages_enforced: int = 0

    @property
    def reports_failed(self) -> int:
        return self.reports_total - self.reports_clean

    @property
    def healthy(self) -> bool:
        return self.messages_failed == 0

    def short(self) -> str:
        if self.reports_total == 0:
            return f"No reports in {self.days}d"
        if self.healthy:
            return f"{self.reports_clean}/{self.reports_total} reports clean ({self.days}d)"
        return (f"{self.reports_failed} of {self.reports_total} reports w/ failures "
                f"({self.messages_failed} msgs)")


class Store:
    """All access is serialised: the tray polls on a worker thread while the
    GUI thread renders the menu from the same connection, and sqlite3 does not
    serialise that for us (concurrent use raises InterfaceError or returns torn
    rows)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.executescript(SCHEMA)
        self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- dedupe ---------------------------------------------------------
    def has_report(self, key: str) -> bool:
        with self._lock:
            cur = self._db.execute("SELECT 1 FROM reports WHERE key = ?", (key,))
            return cur.fetchone() is not None

    def add_report(self, rep: Report) -> bool:
        """Insert a report and its records atomically.

        Returns False if it was already stored.
        """
        with self._lock:
            if self.has_report(rep.key):
                return False
            try:
                self._db.execute(
                    "INSERT INTO reports (key, org_name, report_id, domain,"
                    " begin_ts, end_ts, fetched_at, total_messages,"
                    " failed_messages, enforced_messages, policy_p, source_name)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rep.key, rep.org_name, rep.report_id, rep.domain, rep.begin,
                     rep.end, int(time.time()), rep.total_messages,
                     rep.failed_messages, rep.enforced_messages, rep.policy_p,
                     rep.source_name),
                )
                for r in rep.records:
                    self._db.execute(
                        "INSERT INTO records (report_key, source_ip, count,"
                        " disposition, dkim_aligned, spf_aligned, header_from,"
                        " passed, reasons, auth) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (rep.key, r.source_ip, r.count, r.disposition,
                         r.dkim_aligned, r.spf_aligned, r.header_from,
                         int(r.dmarc_pass), json.dumps(r.reasons),
                         json.dumps([a.describe() for a in r.auth])),
                    )
            except Exception:
                # Never leave a report row without its records: a half-written
                # report would read back as a passing report with no failures.
                self._db.rollback()
                raise
            self._db.commit()
            return True

    # -- rollups --------------------------------------------------------
    def summary(self, days: int = 30) -> Summary:
        cutoff = int(time.time()) - days * 86400
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*) AS n,"
                " SUM(CASE WHEN failed_messages = 0 THEN 1 ELSE 0 END) AS clean,"
                " COALESCE(SUM(total_messages),0) AS msgs,"
                " COALESCE(SUM(failed_messages),0) AS failed,"
                " COALESCE(SUM(enforced_messages),0) AS enforced"
                " FROM reports WHERE end_ts >= ?", (cutoff,)).fetchone()
        return Summary(
            days=days,
            reports_total=row["n"] or 0,
            reports_clean=row["clean"] or 0,
            messages_total=row["msgs"] or 0,
            messages_failed=row["failed"] or 0,
            messages_enforced=row["enforced"] or 0,
        )

    def recent_failures(self, days: int = 30, limit: int = 50) -> list[sqlite3.Row]:
        cutoff = int(time.time()) - days * 86400
        with self._lock:
            return self._db.execute(
                "SELECT rec.*, rep.org_name, rep.end_ts FROM records rec"
                " JOIN reports rep ON rep.key = rec.report_key"
                " WHERE rec.passed = 0 AND rep.end_ts >= ?"
                " ORDER BY rep.end_ts DESC, rec.count DESC LIMIT ?",
                (cutoff, limit)).fetchall()

    def top_sources(self, days: int = 30, limit: int = 10) -> list[sqlite3.Row]:
        cutoff = int(time.time()) - days * 86400
        with self._lock:
            return self._db.execute(
                "SELECT rec.source_ip, SUM(rec.count) AS msgs,"
                " SUM(CASE WHEN rec.passed = 0 THEN rec.count ELSE 0 END) AS failed"
                " FROM records rec JOIN reports rep ON rep.key = rec.report_key"
                " WHERE rep.end_ts >= ? GROUP BY rec.source_ip"
                " ORDER BY msgs DESC LIMIT ?", (cutoff, limit)).fetchall()

    def prune(self, keep_days: int = 0) -> int:
        """Delete reports older than keep_days. 0 (the default) keeps everything.

        Retention defaults to forever on purpose: reports arrive once and are
        never re-sent, and the IMAP UID pointer means a pruned report is not
        re-fetched. Deleting one destroys history that cannot be rebuilt.
        """
        if keep_days <= 0:
            return 0
        cutoff = int(time.time()) - keep_days * 86400
        with self._lock:
            cur = self._db.execute("DELETE FROM reports WHERE end_ts < ?", (cutoff,))
            self._db.execute(
                "DELETE FROM records WHERE report_key NOT IN (SELECT key FROM reports)")
            self._db.commit()
            return cur.rowcount

    # -- key/value state ------------------------------------------------
    def get_state(self, k: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT v FROM state WHERE k = ?", (k,)).fetchone()
        return row["v"] if row else default

    def reset_imap_state(self) -> int:
        """Forget UID pointers so the next fetch re-reads the whole folder.

        Needed to rebuild history: reports are dropped as duplicates on the way
        back in, so re-reading is safe.
        """
        with self._lock:
            cur = self._db.execute("DELETE FROM state WHERE k LIKE 'imap:%'")
            self._db.commit()
            return cur.rowcount

    def set_state(self, k: str, v: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO state (k, v) VALUES (?, ?)"
                " ON CONFLICT(k) DO UPDATE SET v = excluded.v", (k, str(v)))
            self._db.commit()
