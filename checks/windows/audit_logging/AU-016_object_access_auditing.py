"""
AU-016_object_access_auditing.py
---------------------------------
Verifies object access auditing is enabled for sensitive file system paths.

Check ID : AU-016
Category : Audit & Logging
Framework: NIST AU-2, CIS 17.6.1
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


@register_check("AU-016")
def check_object_access_auditing(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies object access auditing is configured for file system and registry."""
    result = base_result(
        connector,
        "AU-016",
        "Object Access Auditing",
        "Verify file system and registry object access auditing is enabled.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$fs = auditpol /get /subcategory:"File System" /r 2>&1 | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting'
Write-Output "File System audit   : $fs"
$reg = auditpol /get /subcategory:"Registry" /r 2>&1 | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting'
Write-Output "Registry audit      : $reg"
$kernel = auditpol /get /subcategory:"Kernel Object" /r 2>&1 | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting'
Write-Output "Kernel Object audit : $kernel"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        fs_val = ""
        reg_val = ""
        for line in cmd.stdout.splitlines():
            if "File System audit" in line:
                fs_val = line.split(":", 1)[1].strip().lower()
            if "Registry audit" in line:
                reg_val = line.split(":", 1)[1].strip().lower()

        fs_on = "success" in fs_val or "failure" in fs_val
        reg_on = "success" in reg_val or "failure" in reg_val

        if fs_on and reg_on:
            result.status = STATUS_PASS
            result.finding = f"Object access auditing is enabled (FileSystem: {fs_val}, Registry: {reg_val})."
            result.remediation = ""
        elif fs_on or reg_on:
            result.status = STATUS_WARNING
            result.finding = f"Object access auditing is partially configured (FileSystem: {fs_val}, Registry: {reg_val})."
            result.remediation = (
                "Enable both: auditpol /set /subcategory:'File System' /success:enable /failure:enable. "
                "auditpol /set /subcategory:'Registry' /success:enable /failure:enable."
            )
        else:
            result.status = STATUS_FAIL
            result.finding = "Object access auditing is NOT enabled. Unauthorized file and registry access goes undetected."
            result.remediation = (
                "Enable via auditpol or GPO: Computer Configuration > Windows Settings > "
                "Security Settings > Advanced Audit Policy > Object Access > "
                "Audit File System and Audit Registry."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
