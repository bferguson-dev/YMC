"""
CM-009_laps.py
--------------
Checks whether Microsoft LAPS (Legacy or Windows LAPS) is installed

Check ID : CM-009
Category : Config Management
Framework: NIST AC-2

This file is auto-discovered by the check registry at startup.
To add a new check, create a new file in this directory following
the same pattern — no other files need to be modified.
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


@register_check("CM-009")
def check_laps(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Checks whether Microsoft LAPS (Legacy or Windows LAPS) is installed
    and configured. LAPS randomizes local administrator passwords and stores
    them in Active Directory, eliminating the lateral movement risk of
    shared local admin passwords across systems.
    """
    result = base_result(
        connector,
        "CM-009",
        "LAPS (Local Administrator Password Solution)",
        "Verify LAPS is installed and managing the local administrator password.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Windows LAPS (Built-in, Windows 2022/11+) ---"
$winLaps = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS\\Config' -ErrorAction SilentlyContinue
if ($winLaps) {
    Write-Output "Windows LAPS config key found."
    Write-Output "BackupDirectory    : $($winLaps.BackupDirectory)"
    Write-Output "PasswordAgeDays    : $($winLaps.PasswordAgeDays)"
    Write-Output "PasswordLength     : $($winLaps.PasswordLength)"
} else {
    Write-Output "Windows LAPS config key NOT found."
}

Write-Output ""
Write-Output "--- Legacy LAPS (CSE) ---"
$legacyLaps = Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd' -ErrorAction SilentlyContinue
if ($legacyLaps) {
    Write-Output "Legacy LAPS policy key found."
    Write-Output "AdmPwdEnabled      : $($legacyLaps.AdmPwdEnabled)"
    Write-Output "PasswordAgeDays    : $($legacyLaps.PasswordAgeDays)"
    Write-Output "PasswordLength     : $($legacyLaps.PasswordLength)"
} else {
    Write-Output "Legacy LAPS policy key NOT found."
}

Write-Output ""
Write-Output "--- LAPS CSE DLL (Legacy) ---"
$lapsDll = Test-Path 'C:\\Program Files\\LAPS\\CSE\\AdmPwd.dll'
Write-Output "Legacy LAPS DLL present: $lapsDll"

Write-Output ""
Write-Output "--- Domain Join Status ---"
$domain = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
Write-Output "Domain joined: $domain"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout

        domain_joined = "Domain joined: True" in output
        win_laps = "Windows LAPS config key found" in output
        legacy_laps = (
            "Legacy LAPS policy key found" in output
            or "Legacy LAPS DLL present: True" in output
        )

        if not domain_joined:
            result.status = STATUS_WARNING
            result.finding = (
                "This system is not domain-joined. LAPS is an Active Directory feature "
                "and is not applicable to standalone systems. Ensure a strong, unique "
                "local administrator password is set manually."
            )
            result.remediation = (
                "For standalone systems, ensure the local Administrator account uses a "
                "unique, complex password documented in a privileged access management (PAM) solution."
            )
        elif win_laps or legacy_laps:
            result.status = STATUS_PASS
            laps_type = "Windows LAPS" if win_laps else "Legacy LAPS (CSE)"
            result.finding = f"{laps_type} is configured on this domain-joined system."
        else:
            result.status = STATUS_FAIL
            result.finding = (
                "System is domain-joined but LAPS is NOT configured. "
                "The local Administrator password is not being managed — "
                "shared or default passwords create lateral movement risk."
            )
            result.remediation = (
                "Deploy Windows LAPS (built into Windows Server 2022/Windows 11) or "
                "Legacy LAPS via GPO. Configure backup to Active Directory or Azure AD. "
                "See: learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# SI-004 — Missing Windows Updates
# ---------------------------------------------------------------------------
