"""
NH-006_null_session_restrictions.py
-----------------------------------
Null sessions allow unauthenticated enumeration of network shares and named pipes,
providing attackers with reconnaissance data about the target system.

Check ID : NH-006
Category : Network Hardening
Framework: NIST AC-3, CIS 18.3.3
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


@register_check("NH-006")
def check_null_session_restrictions(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies null session (anonymous) network access is restricted."""
    result = base_result(
        connector,
        "NH-006",
        "Null Session Restrictions",
        "Verify null sessions cannot enumerate shares, pipes, and account information.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$lsa = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue
Write-Output "RestrictAnonymous         : $($lsa.RestrictAnonymous)  (1=no SAM/shares enum, 2=no anon access)"
Write-Output "RestrictAnonymousSAM      : $($lsa.RestrictAnonymousSAM)  (1=restricted)"
Write-Output "EveryoneIncludesAnonymous : $($lsa.EveryoneIncludesAnonymous)  (0=safe)"
$shares = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'NullSessionShares' -ErrorAction SilentlyContinue).NullSessionShares
Write-Output "NullSessionShares         : $shares"
$pipes = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'NullSessionPipes' -ErrorAction SilentlyContinue).NullSessionPipes
Write-Output "NullSessionPipes          : $pipes"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        findings = []
        everyone = None
        restrict = None
        for line in cmd.stdout.splitlines():
            if "RestrictAnonymous         :" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    restrict = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
            if "EveryoneIncludesAnonymous :" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    everyone = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if everyone == 1:
            findings.append(
                "EveryoneIncludesAnonymous=1 - anonymous users have Everyone group permissions"
            )
        if restrict == 0 or restrict is None:
            findings.append(
                f"RestrictAnonymous={restrict} - anonymous enumeration not restricted"
            )
        if findings:
            result.status = STATUS_FAIL
            result.finding = " | ".join(findings)
            result.remediation = (
                "Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa: "
                "RestrictAnonymous=1, RestrictAnonymousSAM=1, EveryoneIncludesAnonymous=0."
            )
        else:
            result.status = STATUS_PASS
            result.finding = f"Null session restrictions are configured (RestrictAnonymous={restrict}, EveryoneInclAnon={everyone})."
            result.remediation = ""
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
