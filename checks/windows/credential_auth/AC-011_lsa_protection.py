"""
AC-011_lsa_protection.py
------------------------
RunAsPPL forces lsass.exe to run as a Protected Process Light, preventing
credential dumping tools like Mimikatz from reading its memory.

Check ID : AC-011
Category : Credential & Authentication
Framework: NIST IA-5, CIS 3.1
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


@register_check("AC-011")
def check_lsa_protection(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies LSA is configured as Protected Process Light to block credential dumping."""
    result = base_result(
        connector,
        "AC-011",
        "LSA Protection (RunAsPPL)",
        "Verify lsass.exe runs as Protected Process Light (RunAsPPL) to prevent credential dumping.",
        "Credential & Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$ppl = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
Write-Output "RunAsPPL: $ppl"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        ppl = None
        for line in cmd.stdout.splitlines():
            if line.startswith("RunAsPPL:"):
                val = line.split(":", 1)[1].strip()
                ppl = val if val != "" else None
        if ppl == "1":
            result.status = STATUS_PASS
            result.finding = "LSA Protection (RunAsPPL) is enabled. lsass.exe is protected against credential dumping."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = f"LSA Protection (RunAsPPL) is NOT enabled (value: {ppl or 'not set'}). lsass.exe memory can be read by credential dumping tools."
            result.remediation = (
                "Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa RunAsPPL=1 (DWORD) and reboot. "
                "GPO path: Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > Security Options > 'Configure LSASS to run as a protected process'."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
