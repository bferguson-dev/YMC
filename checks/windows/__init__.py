"""
common.py
---------
Shared helpers used by every Windows check module.

Importing this module is the only import a check file needs beyond
the standard library. It re-exports everything a check function requires:
  - CheckResult and status constants from engine.evidence
  - make_timestamp from engine.evidence
  - WinRMConnector and WinRMExecutionError from connector.winrm_connector
  - register_check from checks.registry
  - The base_result() helper function

Usage in a check file
---------------------
    from checks.windows.common import (
        base_result, register_check,
        WinRMConnector, WinRMExecutionError,
        CheckResult, STATUS_PASS, STATUS_FAIL, STATUS_WARNING, STATUS_ERROR
    )
"""

import logging
from engine.evidence import (
    CheckResult,
    STATUS_PASS,
    STATUS_FAIL,
    STATUS_WARNING,
    STATUS_ERROR,
    make_timestamp,
)
from connector.winrm_connector import WinRMConnector, WinRMExecutionError
from checks.registry import register_check

# Re-export everything so check files only need one import block
__all__ = [
    "base_result",
    "register_check",
    "WinRMConnector",
    "WinRMExecutionError",
    "CheckResult",
    "STATUS_PASS",
    "STATUS_FAIL",
    "STATUS_WARNING",
    "STATUS_ERROR",
    "make_timestamp",
    "logging",
]


def base_result(
    connector: WinRMConnector,
    check_id: str,
    check_name: str,
    description: str,
    category: str,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Builds a CheckResult pre-populated with identity and metadata fields
    that every check shares. The check function then sets status, finding,
    remediation, and raw_evidence on the returned object.

    Parameters
    ----------
    connector : WinRMConnector
        Active connection to the target host. Used to populate hostname
        and IP address fields for audit trail purposes.
    check_id : str
        The check identifier, e.g. "AC-001".
    check_name : str
        Human-readable check name, e.g. "Inactive Accounts (>90 Days)".
    description : str
        One-sentence description of what the check verifies.
    category : str
        Control category, e.g. "Access Control", "Audit & Logging".
    tool_name : str
        Name of the tool, recorded in evidence metadata.
    tool_version : str
        Version of the tool, recorded in evidence metadata.
    executed_by : str
        Username that ran the scan, recorded in evidence metadata.

    Returns
    -------
    CheckResult
        A CheckResult with all identity fields populated.
        status defaults to STATUS_ERROR so any unhandled exception
        produces a meaningful result rather than a silent failure.
    """
    return CheckResult(
        hostname=connector.host,
        ip_address=connector.ip_address,
        timestamp_utc=make_timestamp(),
        tool_name=tool_name,
        tool_version=tool_version,
        executed_by=executed_by,
        check_id=check_id,
        check_name=check_name,
        check_category=category,
        description=description,
    )
