"""
AC-017_cached_credentials.py
----------------------------
Cached credentials allow domain logon when the DC is unreachable but also mean
NTLM hashes are stored on disk and can be extracted offline.

Check ID : AC-017
Category : Credential & Authentication
Framework: NIST IA-5, CIS 2.3
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
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("AC-017")
def check_cached_credentials(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies the number of cached domain credentials does not exceed the recommended maximum."""
    result = base_result(
        connector,
        "AC-017",
        "Cached Domain Credentials Count",
        "Verify cached domain credential count is set to 0-2 to limit offline credential exposure.",
        "Credential & Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$val = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'CachedLogonsCount' -ErrorAction SilentlyContinue).CachedLogonsCount
Write-Output "CachedLogonsCount: $val  (0=disabled, recommended 0-2)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if "CachedLogonsCount:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except (TypeError, ValueError, IndexError):
                    val = None
        if val is None:
            result.status = STATUS_WARNING
            result.finding = "CachedLogonsCount registry value not found. Default Windows behavior caches 10 credentials."
            result.remediation = "Set CachedLogonsCount to 0 or a low value (1-2 max) via GPO or registry."
        elif val <= 2:
            result.status = STATUS_PASS
            result.finding = f"Cached domain credentials count is {val} - within the recommended limit of 0-2."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = f"Cached domain credentials count is {val} - exceeds recommended maximum of 2."
            result.remediation = (
                "Reduce via GPO: Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > Security Options > "
                "'Interactive logon: Number of previous logons to cache'. Set to 0 or 1."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
