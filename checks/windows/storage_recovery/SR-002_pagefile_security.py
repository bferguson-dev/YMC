"""
SR-002_pagefile_security.py
---------------------------
The Windows pagefile can contain fragments of sensitive data including passwords.
Clearing it on shutdown prevents offline recovery attacks.

Check ID : SR-002
Category : Storage & Recovery
Framework: NIST SC-28, CIS 18.3.2
"""

import logging
from checks.windows.common import (
    base_result,
    register_check,
    WinRMConnector,
    WinRMExecutionError,
    CheckResult,
    STATUS_PASS,
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("SR-002")
def check_pagefile_security(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies the pagefile is configured to be cleared on system shutdown."""
    result = base_result(
        connector,
        "SR-002",
        "Pagefile Cleared on Shutdown",
        "Verify the pagefile is cleared on shutdown to prevent sensitive data recovery.",
        "Storage & Recovery",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$clear = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management' -Name 'ClearPageFileAtShutdown' -ErrorAction SilentlyContinue).ClearPageFileAtShutdown
Write-Output "ClearPageFileAtShutdown: $clear  (1=cleared on shutdown)"
$pagefile = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management' -Name 'PagingFiles' -ErrorAction SilentlyContinue).PagingFiles
Write-Output "PagingFiles configured: $pagefile"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if "ClearPageFileAtShutdown:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if val == 1:
            result.status = STATUS_PASS
            result.finding = "Pagefile is configured to be cleared on shutdown (ClearPageFileAtShutdown=1)."
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = f"Pagefile is NOT cleared on shutdown (value: {val}). Sensitive data fragments may be recoverable."
            result.remediation = (
                "Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management "
                "ClearPageFileAtShutdown=1. Note: increases shutdown time on systems with large pagefiles. "
                "GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > "
                "Security Options > 'Shutdown: Clear virtual memory pagefile'."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
