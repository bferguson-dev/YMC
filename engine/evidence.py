"""
evidence.py
-----------
Defines the CheckResult dataclass — the single unit of evidence produced
by every check in the tool. Every reporter, every output format, consumes
this object. Structure is designed to satisfy audit evidence requirements
for PCI DSS, NIST 800-53, SOC 2, HIPAA, CMMC, and ISO 27001.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# Valid status values for a check result
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_ERROR = "ERROR"  # Check could not execute (e.g. permission denied)
STATUS_WARNING = "WARNING"  # Returned a result but it requires human review
STATUS_SKIP = "SKIP"  # Check intentionally skipped (e.g. not applicable)


@dataclass
class CheckResult:
    """
    A single compliance check result.

    Contains everything an auditor needs to accept this as valid evidence:
    - What system was checked (hostname + IP)
    - When the check was run (UTC timestamp)
    - What tool produced it (name + version)
    - Who ran it (executing username)
    - What was checked (check metadata)
    - Which controls it maps to across all supported frameworks
    - What the system returned (raw evidence — the audit-grade proof)
    - What the result means (human-readable finding + remediation)
    """

    # --- Target identity ---
    hostname: str
    ip_address: str

    # --- Execution context (audit chain of custody) ---
    timestamp_utc: str  # ISO 8601, e.g. "2025-02-17T14:32:01Z"
    tool_name: str  # e.g. "YMC"
    tool_version: str  # e.g. "1.0.0"
    executed_by: str  # Username that authenticated to run the check

    # --- Check identity ---
    check_id: str  # e.g. "AC-001"
    check_name: str  # e.g. "Inactive Accounts > 90 Days"
    check_category: str  # e.g. "Access Control"
    description: str  # What this check looks for

    # --- Framework control mappings ---
    # Populated from the active compliance profile YAML.
    # Key = framework name, Value = control ID within that framework.
    # e.g. {"NIST_800_53": "AC-2", "PCI_DSS": "Req 8.2", "SOC2": "CC6.2"}
    framework_mappings: dict = field(default_factory=dict)

    # --- Result ---
    status: str = STATUS_ERROR  # One of the STATUS_* constants above

    # Raw output captured from the target system — the core audit evidence.
    # This is the programmatic equivalent of a timestamped screenshot.
    # Contains actual PowerShell command output, verbatim.
    raw_evidence: str = ""

    # Human-readable summary of what the check found
    finding: str = ""

    # What to do if status is FAIL or WARNING
    remediation: str = ""

    # Optional: additional context (e.g. list of flagged account names)
    details: Optional[dict] = None

    def is_compliant(self) -> bool:
        """Returns True only if this check passed."""
        return self.status == STATUS_PASS

    def to_dict(self) -> dict:
        """
        Serializes the result to a plain dictionary.
        Used by the JSON reporter and for structured log output.
        """
        return {
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "timestamp_utc": self.timestamp_utc,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "executed_by": self.executed_by,
            "check_id": self.check_id,
            "check_name": self.check_name,
            "check_category": self.check_category,
            "description": self.description,
            "framework_mappings": self.framework_mappings,
            "status": self.status,
            "raw_evidence": self.raw_evidence,
            "finding": self.finding,
            "remediation": self.remediation,
            "details": self.details,
        }


@dataclass
class HostScanResult:
    """
    Aggregates all CheckResults for a single target host.
    This is what gets passed to reporters.
    """

    hostname: str
    ip_address: str
    scan_start_utc: str
    scan_end_utc: str
    profile_name: str  # e.g. "PCI DSS 4.0"
    executed_by: str
    checks: list = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == STATUS_PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == STATUS_FAIL)

    @property
    def errors(self) -> int:
        return sum(1 for c in self.checks if c.status == STATUS_ERROR)

    @property
    def warnings(self) -> int:
        return sum(1 for c in self.checks if c.status == STATUS_WARNING)

    @property
    def compliance_percentage(self) -> float:
        """Pass rate excluding checks that errored or were skipped."""
        actionable = [
            c
            for c in self.checks
            if c.status in (STATUS_PASS, STATUS_FAIL, STATUS_WARNING)
        ]
        if not actionable:
            return 0.0
        passing = sum(1 for c in actionable if c.status == STATUS_PASS)
        return round((passing / len(actionable)) * 100, 1)


def make_timestamp() -> str:
    """Returns current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
