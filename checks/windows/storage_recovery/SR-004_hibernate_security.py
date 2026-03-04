"""
SR-004_hibernate_security.py
----------------------------
The hibernate file contains a full snapshot of memory at hibernation time,
including credentials. If BitLocker is not enabled this is recoverable.

Check ID : SR-004
Category : Storage & Recovery
Framework: NIST SC-28, CIS 18.3.4
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


@register_check("SR-004")
def check_hibernate_security(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies hibernation is disabled or the hibernate file is encrypted."""
    result = base_result(
        connector,
        "SR-004",
        "Hibernate File Security",
        "Verify hibernate (hiberfil.sys) does not expose unencrypted memory to offline attacks.",
        "Storage & Recovery",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$hibr = powercfg /hibernate query 2>&1
Write-Output "Hibernate query: $hibr"
$hiberFile = Test-Path "C:\\hiberfil.sys"
Write-Output "hiberfil.sys exists: $hiberFile"
$blv = Get-BitLockerVolume C: -ErrorAction SilentlyContinue
Write-Output "BitLocker on C: $($blv.ProtectionStatus)"
$hiberboot = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' -Name 'HiberbootEnabled' -ErrorAction SilentlyContinue).HiberbootEnabled
Write-Output "Fast Startup (HiberBoot): $hiberboot  (0=disabled)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        hibr_exists = "hiberfil.sys exists: true" in output.lower()
        bl_on = "protectionstatus" in output.lower() and "on" in output.lower()
        for line in output.splitlines():
            if "Fast Startup (HiberBoot):" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if not hibr_exists:
            result.status = STATUS_PASS
            result.finding = "Hibernation is disabled â€” no hiberfil.sys present."
            result.remediation = ""
        elif hibr_exists and bl_on:
            result.status = STATUS_PASS
            result.finding = "hiberfil.sys exists but BitLocker is enabled on C: â€” hibernate file is encrypted."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = "hiberfil.sys exists and BitLocker is NOT enabled. Memory contents (including credentials) can be recovered from the hibernate file."
            result.remediation = (
                "Either disable hibernate: powercfg /hibernate off, "
                "or enable BitLocker on the OS volume to encrypt the hibernate file. "
                "Also disable Fast Startup (HiberbootEnabled=0) if not using hibernate."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
