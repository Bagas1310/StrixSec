"""
SQLite Persistence Database Manager for StrixSec.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strixsec.core.errors import StorageError
from strixsec.findings.models import (
    Evidence,
    Finding,
    FindingCategory,
    FindingStatus,
    ScanRecord,
    SeverityLevel,
)
from strixsec.findings.sanitizer import sanitize_evidence

DEFAULT_DB_PATH = Path(".strixsec.db")


class DatabaseManager:
    """Simple, thread-safe SQLite storage manager using context-managed connections."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path) if isinstance(db_path, str) else db_path
        self.init_db()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing a clean, auto-closing SQLite connection with WAL mode."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as err:
            conn.rollback()
            raise StorageError(f"Database transaction error: {err}") from err
        finally:
            conn.close()

    def init_db(self) -> None:
        """Initialize database schema tables if they do not exist."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT UNIQUE NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    num_findings INTEGER DEFAULT 0,
                    metadata TEXT
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    asset TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    description TEXT NOT NULL,
                    impact TEXT NOT NULL,
                    remediation TEXT,
                    references_json TEXT,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    description TEXT NOT NULL,
                    sanitized_value TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_findings_dedup ON findings(asset, category, title);
                CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                """
            )

    # --- Scan History Operations ---

    def create_scan(self, scan_id: str, target: str, scan_type: str) -> ScanRecord:
        """Create a new scan execution record in database."""
        now_utc = datetime.now(UTC).isoformat()
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO scans (scan_id, target, scan_type, started_at, status, num_findings)
                VALUES (?, ?, ?, ?, 'RUNNING', 0)
                """,
                (scan_id, target, scan_type, now_utc),
            )
        return ScanRecord(
            scan_id=scan_id,
            target=target,
            scan_type=scan_type,
            started_at=now_utc,
            status="RUNNING",
            num_findings=0,
        )

    def complete_scan(self, scan_id: str, num_findings: int, status: str = "COMPLETED") -> None:
        """Mark a scan record as completed."""
        now_utc = datetime.now(UTC).isoformat()
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE scans
                SET completed_at = ?, status = ?, num_findings = ?
                WHERE scan_id = ?
                """,
                (now_utc, status, num_findings, scan_id),
            )

    def list_scans(self) -> list[ScanRecord]:
        """Retrieve all scan history records."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM scans ORDER BY started_at DESC")
            rows = cur.fetchall()

        records: list[ScanRecord] = []
        for r in rows:
            meta = json.loads(r["metadata"]) if r["metadata"] else {}
            records.append(
                ScanRecord(
                    scan_id=r["scan_id"],
                    target=r["target"],
                    scan_type=r["scan_type"],
                    started_at=r["started_at"],
                    completed_at=r["completed_at"],
                    status=r["status"],
                    num_findings=r["num_findings"],
                    metadata=meta,
                )
            )
        return records

    # --- Finding & Deduplication Operations ---

    def save_finding(self, finding: Finding) -> Finding:
        """Save finding to SQLite with deduplication on asset + category + title."""
        now_utc = datetime.now(UTC).isoformat()
        refs_json = json.dumps(finding.references)

        with self.get_connection() as conn:
            cur = conn.cursor()

            # Check if active (non-FIXED) finding exists for asset + category + title
            cur.execute(
                """
                SELECT id FROM findings
                WHERE asset = ? AND category = ? AND title = ? AND status != 'FIXED'
                """,
                (finding.asset, finding.category, finding.title),
            )
            existing_row = cur.fetchone()

            if existing_row:
                target_id = existing_row["id"]
                # Update existing finding
                cur.execute(
                    """
                    UPDATE findings
                    SET severity = ?, confidence = ?, description = ?, impact = ?,
                        remediation = ?, references_json = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        finding.severity,
                        finding.confidence,
                        finding.description,
                        finding.impact,
                        finding.remediation,
                        refs_json,
                        now_utc,
                        target_id,
                    ),
                )
                # Replace evidence for updated finding
                cur.execute("DELETE FROM evidence WHERE finding_id = ?", (target_id,))
                self._insert_evidence(cur, target_id, finding.evidence)

                # Return updated finding with stable ID
                updated_finding = finding.model_copy()
                updated_finding.id = target_id
                updated_finding.updated_at = now_utc
                return updated_finding
            else:
                # Generate new finding ID if not supplied (e.g. STRX-0001)
                final_id = finding.id or self._generate_next_finding_id(cur)
                cur.execute(
                    """
                    INSERT INTO findings
                    (id, title, asset, category, severity, confidence, description,
                     impact, remediation, references_json, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        final_id,
                        finding.title,
                        finding.asset,
                        finding.category,
                        finding.severity,
                        finding.confidence,
                        finding.description,
                        finding.impact,
                        finding.remediation,
                        refs_json,
                        finding.status,
                        finding.created_at or now_utc,
                        now_utc,
                    ),
                )
                self._insert_evidence(cur, final_id, finding.evidence)

                saved_finding = finding.model_copy()
                saved_finding.id = final_id
                saved_finding.created_at = finding.created_at or now_utc
                saved_finding.updated_at = now_utc
                return saved_finding

    def _insert_evidence(
        self, cur: sqlite3.Cursor, finding_id: str, evidence_list: list[Evidence]
    ) -> None:
        """Insert evidence items with mandatory sanitization."""
        for ev in evidence_list:
            sanitized = sanitize_evidence(ev.sanitized_value)
            cur.execute(
                """
                INSERT INTO evidence
                    (finding_id, type, source, description, sanitized_value, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    ev.type,
                    ev.source,
                    ev.description,
                    sanitized,
                    ev.timestamp,
                ),
            )

    def _generate_next_finding_id(self, cur: sqlite3.Cursor) -> str:
        """Generate auto-incrementing stable finding ID format: STRX-0001."""
        cur.execute("SELECT COUNT(*) as count FROM findings")
        count = cur.fetchone()["count"] + 1
        return f"STRX-{count:04d}"

    def get_finding(self, finding_id: str) -> Finding | None:
        """Retrieve finding by ID with attached evidence."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
            row = cur.fetchone()
            if not row:
                return None

            cur.execute("SELECT * FROM evidence WHERE finding_id = ?", (finding_id,))
            ev_rows = cur.fetchall()

        evidence_items = [
            Evidence(
                type=e["type"],
                source=e["source"],
                description=e["description"],
                sanitized_value=e["sanitized_value"],
                timestamp=e["timestamp"],
            )
            for e in ev_rows
        ]

        refs = json.loads(row["references_json"]) if row["references_json"] else []

        return Finding(
            id=row["id"],
            title=row["title"],
            asset=row["asset"],
            category=FindingCategory(row["category"]),
            severity=SeverityLevel(row["severity"]),
            confidence=row["confidence"],
            description=row["description"],
            evidence=evidence_items,
            impact=row["impact"],
            remediation=row["remediation"],
            references=refs,
            status=FindingStatus(row["status"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def list_findings(
        self,
        severity: str | None = None,
        status: str | None = None,
        category: str | None = None,
    ) -> list[Finding]:
        """List findings with optional filtering parameters."""
        query = "SELECT id FROM findings WHERE 1=1"
        params: list[Any] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if status:
            query += " AND status = ?"
            params.append(status.upper())
        if category:
            query += " AND category = ?"
            params.append(category.upper())

        query += " ORDER BY created_at DESC"

        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            rows = cur.fetchall()

        findings: list[Finding] = []
        for r in rows:
            f = self.get_finding(r["id"])
            if f:
                findings.append(f)
        return findings

    def update_finding_status(self, finding_id: str, new_status: str) -> bool:
        """Update lifecycle status of a finding."""
        try:
            status_enum = FindingStatus(new_status.upper())
        except ValueError as err:
            raise StorageError(f"Invalid finding status '{new_status}'") from err

        now_utc = datetime.now(UTC).isoformat()
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE findings
                SET status = ?, updated_at = ?
                WHERE id = ?
                """,
                (status_enum, now_utc, finding_id),
            )
            return cur.rowcount > 0
