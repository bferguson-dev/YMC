"""
SR-005_bitlocker_recovery.py
-----------------------------
Verifies BitLocker recovery key is backed up (not just that BitLocker is enabled).

Check ID : SR-005
Category : Storage & Recovery
Framework: NIST CP-9, CIS 18.9.12
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


@register_check("SR-005")
def check_bitlocker_recovery(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies BitLocker recovery keys are backed up to AD or a designated location."""
    result = base_result(
        connector,
        "SR-005",
        "BitLocker Recovery Key Backup",
        "Verify BitLocker recovery keys are backed up to Active Directory or a recovery location.",
        "Storage & Recovery",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
if (-not $volumes) {
    Write-Output "BitLocker: not available or not enabled on any volume"
} else {
    foreach ($v in $volumes) {
        Write-Output "Volume: $($v.MountPoint) | Status: $($v.ProtectionStatus) | EncryptionMethod: $($v.EncryptionMethod)"
        foreach ($p in $v.KeyProtector) {
            Write-Output "  Protector: $($p.KeyProtectorType) | ID: $($p.KeyProtectorId)"
        }
    }
}
$recoveryPolicy = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\FVE' -ErrorAction SilentlyContinue)
Write-Output "RequireActiveDirectoryBackup: $($recoveryPolicy.RequireActiveDirectoryBackup)"
Write-Output "OSRequireActiveDirectoryBackup: $($recoveryPolicy.OSRequireActiveDirectoryBackup)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout

        if "not available" in output.lower():
            result.status = STATUS_WARNING
            result.finding = "BitLocker is not enabled. Recovery key backup cannot be verified. (See CM-007 for BitLocker enablement.)"
            result.remediation = "Enable BitLocker first (see CM-007), then configure recovery key backup policy."
            return result

        has_recovery = "RecoveryPassword" in output or "RecoveryKey" in output
        ad_backup_required = any(
            v in output
            for v in [
                "RequireActiveDirectoryBackup: 1",
                "OSRequireActiveDirectoryBackup: 1",
            ]
        )

        if has_recovery and ad_backup_required:
            result.status = STATUS_PASS
            result.finding = (
                "BitLocker recovery key is configured and AD backup policy is enforced."
            )
            result.remediation = ""
        elif has_recovery:
            result.status = STATUS_WARNING
            result.finding = "BitLocker recovery protector exists but AD backup enforcement policy is not configured. Recovery key backup to AD is not guaranteed."
            result.remediation = (
                "Enable AD recovery key backup via GPO: Computer Configuration > "
                "Administrative Templates > Windows Components > BitLocker Drive Encryption > "
                "Operating System Drives > 'Choose how BitLocker-protected operating system drives can be recovered'. "
                "Enable 'Save BitLocker recovery information to AD DS'."
            )
        else:
            result.status = STATUS_FAIL
            result.finding = "No BitLocker recovery key protector found. Drive cannot be recovered if primary key is lost."
            result.remediation = (
                "Add a recovery key: manage-bde -protectors -add C: -RecoveryPassword. "
                "Back up to AD: manage-bde -protectors -adbackup C: -id <KeyProtectorID>."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
