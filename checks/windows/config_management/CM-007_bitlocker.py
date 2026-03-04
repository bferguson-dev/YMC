"""
CM-007_bitlocker.py
-------------------
Checks BitLocker encryption status on all fixed drives, with focus on

Check ID : CM-007
Category : Config Management
Framework: NIST SC-28

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


@register_check("CM-007")
def check_bitlocker(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Checks BitLocker encryption status on all fixed drives, with focus on
    the OS drive (C:). Reports protection status, encryption method,
    and whether a TPM protector is configured.
    """
    result = base_result(
        connector,
        "CM-007",
        "BitLocker Drive Encryption",
        "Verify BitLocker is enabled and protecting the OS drive.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- BitLocker Status ---"
$volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue

if ($null -eq $volumes) {
    Write-Output "BITLOCKER_UNAVAILABLE: BitLocker cmdlets not available on this system."
} else {
    foreach ($vol in $volumes) {
        Write-Output "Drive              : $($vol.MountPoint)"
        Write-Output "VolumeType         : $($vol.VolumeType)"
        Write-Output "ProtectionStatus   : $($vol.ProtectionStatus)"
        Write-Output "EncryptionMethod   : $($vol.EncryptionMethod)"
        Write-Output "VolumeStatus       : $($vol.VolumeStatus)"
        $protectors = $vol.KeyProtector | ForEach-Object { $_.KeyProtectorType }
        Write-Output "KeyProtectors      : $($protectors -join ', ')"
        Write-Output "---"
    }
}

Write-Output ""
Write-Output "--- TPM Status ---"
$tpm = Get-Tpm -ErrorAction SilentlyContinue
if ($tpm) {
    Write-Output "TpmPresent   : $($tpm.TpmPresent)"
    Write-Output "TpmReady     : $($tpm.TpmReady)"
    Write-Output "TpmEnabled   : $($tpm.TpmEnabled)"
} else {
    Write-Output "TPM information not available."
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout

        if "BITLOCKER_UNAVAILABLE" in output:
            result.status = STATUS_WARNING
            result.finding = "BitLocker cmdlets unavailable — this may be Windows Server Core or a non-supported edition."
            result.remediation = (
                "Verify drive encryption status manually using manage-bde -status."
            )
            return result

        # Look for OS drive protection
        lines = output.splitlines()
        os_drive_protected = False
        in_os_drive = False

        for i, line in enumerate(lines):
            if "VolumeType         : OperatingSystem" in line:
                in_os_drive = True
            if in_os_drive and "ProtectionStatus   : On" in line:
                os_drive_protected = True
                in_os_drive = False
            if "---" in line:
                in_os_drive = False

        unprotected = [
            line.split(":")[1].strip()
            for line in lines
            if "ProtectionStatus   : Off" in line
        ]

        if os_drive_protected and not unprotected:
            result.status = STATUS_PASS
            result.finding = (
                "BitLocker is enabled and protecting all drives including the OS drive."
            )
        elif not os_drive_protected:
            result.status = STATUS_FAIL
            result.finding = (
                "BitLocker is NOT protecting the OS drive. Data at rest is unencrypted."
            )
            result.remediation = (
                "Enable BitLocker on the OS drive: "
                "Control Panel > BitLocker Drive Encryption > Turn on BitLocker. "
                "Use TPM + PIN protector for strongest protection. "
                "Escrow recovery keys to Active Directory or Azure AD."
            )
        elif unprotected:
            result.status = STATUS_WARNING
            result.finding = f"OS drive is protected but these drives are unencrypted: {', '.join(unprotected)}"
            result.remediation = "Enable BitLocker on all fixed data drives containing sensitive information."

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# CM-008 — TLS / Schannel Configuration
# ---------------------------------------------------------------------------
