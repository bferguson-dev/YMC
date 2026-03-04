"""
AU-015_removable_storage_auditing.py
--------------------------------------
Verifies removable storage device access is audited.

Check ID : AU-015
Category : Audit & Logging
Framework: NIST AU-2, PCI DSS 12.3
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


@register_check("AU-015")
def check_removable_storage_auditing(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies removable storage device read/write access is audited."""
    result = base_result(
        connector,
        "AU-015",
        "Removable Storage Device Auditing",
        "Verify read and write access to removable storage devices is audited.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$read = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices' -Name 'Audit_Read' -ErrorAction SilentlyContinue).Audit_Read
$write = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices' -Name 'Audit_Write' -ErrorAction SilentlyContinue).Audit_Write
Write-Output "Audit_Read : $read  (1=enabled)"
Write-Output "Audit_Write: $write  (1=enabled)"
$removable = auditpol /get /subcategory:"Removable Storage" /r 2>&1 | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting'
Write-Output "Removable Storage audit policy: $removable"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        read_val = None
        write_val = None
        auditpol_val = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("Audit_Read :"):
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    read_val = int(v)
                except ValueError:
                    pass
            if line.startswith("Audit_Write:"):
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    write_val = int(v)
                except ValueError:
                    pass
            if "Removable Storage audit policy:" in line:
                auditpol_val = line.split(":", 1)[1].strip().lower()

        auditpol_enabled = "success" in auditpol_val or "failure" in auditpol_val
        policy_enabled = read_val == 1 or write_val == 1

        if auditpol_enabled or policy_enabled:
            result.status = STATUS_PASS
            result.finding = f"Removable storage auditing is enabled (auditpol: {auditpol_val}, Read={read_val}, Write={write_val})."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = "Removable storage device access is NOT being audited. Data exfiltration via USB is undetected."
            result.remediation = (
                "Enable via auditpol: auditpol /set /subcategory:'Removable Storage' "
                "/success:enable /failure:enable. "
                "Or GPO: Computer Configuration > Windows Settings > Security Settings > "
                "Advanced Audit Policy > Object Access > Audit Removable Storage."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
