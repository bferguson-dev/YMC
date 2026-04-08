"""
AU-017_audit_subcategories.py
-------------------------------
Verifies key audit subcategories are configured at the required auditing level
using auditpol. Advanced audit policy should cover Logon, Special Logon,
Account Lockout, Process Creation, and Security State Change.

Check ID : AU-017
Category : Audit & Logging
Framework: NIST AU-12, DISA STIG CAT-II, CIS 17.x
"""

import logging
from checks.windows.common import (
    base_result,
    register_check,
    WinRMConnector,
    WinRMExecutionError,
    CheckResult,
    STATUS_PASS,
    STATUS_FAIL,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)

# Required subcategory -> minimum inclusion setting
# "Success and Failure" > "Failure" > "Success" > "No Auditing"
_REQUIRED = {
    "Logon": "Success and Failure",
    "Special Logon": "Success",
    "Account Lockout": "Success and Failure",
    "Process Creation": "Success",
    "Security State Change": "Success and Failure",
}

_LEVEL_RANK = {
    "No Auditing": 0,
    "Success": 1,
    "Failure": 2,
    "Success and Failure": 3,
}


def _meets_requirement(actual: str, required: str) -> bool:
    """Returns True if the actual auditing level satisfies the required level."""
    actual_rank = _LEVEL_RANK.get(actual, 0)
    if required == "Success and Failure":
        return actual_rank >= 3
    if required == "Success":
        return actual_rank in (1, 3)
    if required == "Failure":
        return actual_rank in (2, 3)
    return True


@register_check("AU-017")
def check_audit_subcategories(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies key audit subcategories meet required auditing levels via auditpol."""
    result = base_result(
        connector,
        "AU-017",
        "Audit Subcategory Verification",
        "Verify Logon, Special Logon, Account Lockout, Process Creation, and Security State Change subcategories are audited.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = r"""
$output = auditpol /get /category:* /r 2>&1
Write-Output $output
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        # Parse CSV: Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,...
        found = {}
        for line in cmd.stdout.splitlines():
            parts = line.split(",")
            if len(parts) < 5:
                continue
            subcategory = parts[2].strip().strip('"')
            inclusion = parts[4].strip().strip('"')
            if subcategory in _REQUIRED:
                found[subcategory] = inclusion

        failing = []
        for subcat, required_level in _REQUIRED.items():
            actual = found.get(subcat, "No Auditing")
            if not _meets_requirement(actual, required_level):
                failing.append(
                    f"{subcat}: found '{actual}', required '{required_level}'"
                )

        if not failing:
            result.status = STATUS_PASS
            result.finding = (
                "All required audit subcategories are configured at the required level: "
                + ", ".join(f"{k}={found.get(k, 'No Auditing')}" for k in _REQUIRED)
            )
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"Audit subcategories not meeting requirements ({len(failing)}): "
                + "; ".join(failing)
            )
            result.remediation = (
                "Configure the failing subcategories via auditpol or Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Advanced Audit Policy Configuration. "
                "Required: Logon (S+F), Special Logon (S), Account Lockout (S+F), "
                "Process Creation (S), Security State Change (S+F)."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
