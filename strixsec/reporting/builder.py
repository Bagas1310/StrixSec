"""
Report Builder — Assembles ReportContext from Phase 5 SQLite data.
"""

from __future__ import annotations

from datetime import UTC, datetime

from strixsec import __version__
from strixsec.findings.models import SeverityLevel
from strixsec.findings.sanitizer import sanitize_evidence
from strixsec.reporting.models import ReportContext, ReportMetadata, SeveritySummary
from strixsec.scope.storage import ScopeStorage
from strixsec.storage.database import DatabaseManager


class ReportBuilder:
    """Assembles a ReportContext from live SQLite findings and scan history."""

    def __init__(
        self,
        db: DatabaseManager | None = None,
        scope_storage: ScopeStorage | None = None,
    ) -> None:
        self.db = db or DatabaseManager()
        self.scope_storage = scope_storage or ScopeStorage()

    def build(
        self,
        title: str = "StrixSec Security Assessment Report",
        severity_filter: str | None = None,
        status_filter: str | None = None,
    ) -> ReportContext:
        """Assemble a complete ReportContext from stored SQLite data.

        Args:
            title: Report title string.
            severity_filter: Optional severity filter to pass to list_findings.
            status_filter: Optional status filter to pass to list_findings.

        Returns:
            Populated ReportContext ready for rendering.
        """
        generated_at = datetime.now(UTC).isoformat()

        # Load scope targets
        scope_config = self.scope_storage.load_scope()
        scope_entries = [t.raw_target for t in scope_config.allowed_targets]

        # Load findings from database with optional filters
        findings = self.db.list_findings(
            severity=severity_filter,
            status=status_filter,
        )

        # Re-sanitize all evidence values as defence-in-depth
        for finding in findings:
            for ev in finding.evidence:
                ev.sanitized_value = sanitize_evidence(ev.sanitized_value)

        # Load scan history
        scan_records = self.db.list_scans()

        # Collect unique assets from findings
        assets = sorted({f.asset for f in findings})

        # Build severity summary
        severity_summary = self._compute_severity_summary(findings)

        # Generate executive summary (counts only — no invented statements)
        executive_summary = self._generate_executive_summary(assets, severity_summary, scan_records)

        metadata = ReportMetadata(
            title=title,
            strixsec_version=__version__,
            generated_at=generated_at,
            scope=scope_entries,
            assets=assets,
        )

        return ReportContext(
            metadata=metadata,
            executive_summary=executive_summary,
            severity_summary=severity_summary,
            findings=findings,
            scan_records=scan_records,
        )

    def _compute_severity_summary(self, findings: list) -> SeveritySummary:
        """Count findings per severity level."""
        counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }
        for f in findings:
            sev = str(f.severity).upper()
            if sev == SeverityLevel.CRITICAL:
                counts["critical"] += 1
            elif sev == SeverityLevel.HIGH:
                counts["high"] += 1
            elif sev == SeverityLevel.MEDIUM:
                counts["medium"] += 1
            elif sev == SeverityLevel.LOW:
                counts["low"] += 1
            else:
                counts["informational"] += 1

        return SeveritySummary(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            informational=counts["informational"],
            total=len(findings),
        )

    def _generate_executive_summary(
        self,
        assets: list[str],
        severity_summary: SeveritySummary,
        scan_records: list,
    ) -> str:
        """Generate factual prose summary based only on actual finding counts."""
        if severity_summary.total == 0:
            return (
                "This StrixSec assessment completed successfully. "
                "No findings were recorded in the current database."
            )

        asset_str = (
            f"{len(assets)} asset{'s' if len(assets) != 1 else ''}"
            f" ({', '.join(assets[:3])}{'...' if len(assets) > 3 else ''})"
        )
        scan_str = f"{len(scan_records)} scan record{'s' if len(scan_records) != 1 else ''}"

        parts = []
        if severity_summary.critical > 0:
            parts.append(f"{severity_summary.critical} Critical")
        if severity_summary.high > 0:
            parts.append(f"{severity_summary.high} High")
        if severity_summary.medium > 0:
            parts.append(f"{severity_summary.medium} Medium")
        if severity_summary.low > 0:
            parts.append(f"{severity_summary.low} Low")
        if severity_summary.informational > 0:
            parts.append(f"{severity_summary.informational} Informational")

        severity_str = ", ".join(parts)

        return (
            f"This StrixSec assessment evaluated {asset_str} across {scan_str}. "
            f"A total of {severity_summary.total} finding(s) were identified: "
            f"{severity_str}. "
            "All findings are based on passive, non-destructive assessment "
            "techniques only. Each finding should be reviewed in its operational "
            "context before remediation is prioritized."
        )
