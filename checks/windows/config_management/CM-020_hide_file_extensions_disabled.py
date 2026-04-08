"""
CM-020_hide_file_extensions_disabled.py
-----------------------------------------
Windows hides file extensions by default. Attackers exploit this to disguise
malicious files (e.g., malware.pdf.exe appears as malware.pdf). File extensions
must be visible so users can identify file types correctly.

Check ID : CM-020
Category : Configuration Management
Framework: NIST CM-7, DISA STIG CAT-III
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


@register_check("CM-020")
def check_hide_file_extensions_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies file extensions are shown (HideFileExt=0)."""
    result = base_result(
        connector,
        "CM-020",
        "File Extensions Visible (HideFileExt Disabled)",
        "Verify HideFileExt=0 so file extensions are always shown to users.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = r"""
$hkcu = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -ErrorAction SilentlyContinue).HideFileExt
$hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -ErrorAction SilentlyContinue).HideFileExt
Write-Output "HKCU_HideFileExt: $hkcu"
Write-Output "HKLM_HideFileExt: $hklm"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        hkcu_val = None
        hklm_val = None
        for line in cmd.stdout.splitlines():
            if line.startswith("HKCU_HideFileExt:"):
                v = line.split(":", 1)[1].strip()
                try:
                    hkcu_val = int(v)
                except (TypeError, ValueError):
                    pass
            elif line.startswith("HKLM_HideFileExt:"):
                v = line.split(":", 1)[1].strip()
                try:
                    hklm_val = int(v)
                except (TypeError, ValueError):
                    pass

        # Policy (HKLM) overrides user setting; either must be 0 for compliant
        # If HKLM enforces 0 that is definitive. If HKCU is 0 and HKLM is absent, also OK.
        hklm_enforces_hide = hklm_val == 1
        hkcu_shows = hkcu_val == 0

        if hklm_val == 0:
            result.status = STATUS_PASS
            result.finding = "File extensions are forced visible by machine policy (HKLM HideFileExt=0)."
            result.remediation = ""
        elif hklm_enforces_hide:
            result.status = STATUS_FAIL
            result.finding = (
                "HKLM policy forces file extensions to be HIDDEN (HideFileExt=1). "
                "Users cannot override this setting."
            )
            result.remediation = (
                "Set HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced "
                "HideFileExt=0 via Group Policy: "
                "User Configuration > Administrative Templates > Windows Components > "
                "File Explorer > Hide extensions for known file types > Disabled."
            )
        elif hkcu_shows:
            result.status = STATUS_PASS
            result.finding = (
                f"File extensions are visible for the current user (HKCU HideFileExt=0). "
                f"HKLM policy: {hklm_val} (not enforcing)."
            )
            result.remediation = (
                "Consider enforcing via HKLM/Group Policy for all users."
            )
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"File extensions are HIDDEN. HKCU HideFileExt={hkcu_val} (None=default-hide), "
                f"HKLM HideFileExt={hklm_val}. "
                "Hidden extensions facilitate file-type spoofing attacks."
            )
            result.remediation = (
                "Set HideFileExt=0 via Group Policy for all users: "
                "User Configuration > Administrative Templates > Windows Components > "
                "File Explorer > Hide extensions for known file types > Disabled."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
