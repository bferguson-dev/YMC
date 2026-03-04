"""
AC-019_sam_access_restriction.py
--------------------------------
Without restriction, unauthenticated users can enumerate local account names
from the network, aiding targeted attacks.

Check ID : AC-019
Category : Credential & Authentication
Framework: NIST AC-3, CIS 3.4
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


@register_check("AC-019")
def check_sam_access_restriction(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies anonymous access to the SAM database is restricted."""
    result = base_result(
        connector,
        "AC-019",
        "SAM Database Access Restriction",
        "Verify anonymous enumeration of SAM accounts is restricted.",
        "Credential & Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$noAnon = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymousSAM' -ErrorAction SilentlyContinue).RestrictAnonymousSAM
$noEnum = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymous' -ErrorAction SilentlyContinue).RestrictAnonymous
Write-Output "RestrictAnonymousSAM: $noAnon  (1=restricted)"
Write-Output "RestrictAnonymous   : $noEnum  (1=no SAM enum, 2=no anon access at all)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        sam = None
        anon = None
        for line in cmd.stdout.splitlines():
            if "RestrictAnonymousSAM:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    sam = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
            if "RestrictAnonymous   :" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    anon = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if sam == 1 or (anon is not None and anon >= 1):
            result.status = STATUS_PASS
            result.finding = f"SAM anonymous access is restricted (RestrictAnonymousSAM={sam}, RestrictAnonymous={anon})."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = f"SAM anonymous access restriction is NOT enabled (RestrictAnonymousSAM={sam}, RestrictAnonymous={anon})."
            result.remediation = (
                "Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa RestrictAnonymousSAM=1 "
                "and RestrictAnonymous=1 via GPO or registry."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
