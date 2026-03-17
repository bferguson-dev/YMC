"""
AC-018_wdigest_disabled.py
--------------------------
WDigest stores plaintext credentials in LSASS memory when enabled.
Mimikatz and similar tools can extract these directly. Must be explicitly disabled on pre-Win8.1 systems.

Check ID : AC-018
Category : Credential & Authentication
Framework: NIST IA-5, CIS 3.3
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


@register_check("AC-018")
def check_wdigest_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies WDigest authentication is explicitly disabled to prevent plaintext credential exposure."""
    result = base_result(
        connector,
        "AC-018",
        "WDigest Authentication Disabled",
        "Verify WDigest is disabled so plaintext credentials are not stored in LSASS memory.",
        "Credential & Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$val = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential
Write-Output "UseLogonCredential: $val  (0=disabled/safe, 1=enabled/unsafe, null=default-safe on Win8.1+)"
$os = (Get-WmiObject Win32_OperatingSystem).Version
Write-Output "OS Version: $os"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        os_ver = ""
        for line in cmd.stdout.splitlines():
            if "UseLogonCredential:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except (TypeError, ValueError, IndexError):
                    val = None
            if line.startswith("OS Version:"):
                os_ver = line.split(":", 1)[1].strip()
        if val == 0:
            result.status = STATUS_PASS
            result.finding = "WDigest is explicitly disabled (UseLogonCredential=0). Plaintext credentials are not cached in LSASS."
            result.remediation = ""
        elif val == 1:
            result.status = STATUS_FAIL
            result.finding = "WDigest is ENABLED (UseLogonCredential=1). Plaintext credentials are stored in LSASS memory."
            result.remediation = (
                "Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest "
                "UseLogonCredential=0 (DWORD). Requires logoff/logon to take effect."
            )
        else:
            # Not set - safe on Windows 8.1+ / Server 2012R2+, risky on older
            result.status = STATUS_PASS
            result.finding = (
                f"WDigest UseLogonCredential registry key not set. "
                f"Safe on modern Windows (8.1+/2012R2+) where default is disabled. OS: {os_ver}"
            )
            result.remediation = (
                "Consider explicitly setting UseLogonCredential=0 for defence in depth."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
