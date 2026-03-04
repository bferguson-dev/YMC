"""
IA-001_password_policy.py
-------------------------
Reads the local password policy and validates length, complexity,

Check ID : IA-001, IA-002, IA-003
Category : Identity & Auth
Framework: NIST IA-5, PCI DSS 8.3

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


@register_check("IA-001", "IA-002", "IA-003", dedup_group="password_policy")
def check_password_policy(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Reads the local password policy and validates length, complexity,
    and maximum age against configured thresholds.
    """
    result = base_result(
        connector,
        "IA-001",
        "Password Policy",
        "Verify password length, complexity, and maximum age meet compliance requirements.",
        "Identification and Authentication",
        tool_name,
        tool_version,
        executed_by,
    )
    min_length = settings.get("min_password_length", 14)
    max_age = settings.get("max_password_age_days", 90)

    ps_script = f"""
Write-Output "--- Password Policy ---"
$policy = net accounts
$policy | ForEach-Object {{ Write-Output $_ }}
Write-Output ""

# Also pull from secedit for more detail
$tmpFile = "$env:TEMP\\secpol_$([System.Guid]::NewGuid().ToString('N')).cfg"
secedit /export /areas SECURITYPOLICY /cfg $tmpFile /quiet
if (Test-Path $tmpFile) {{
    $content = Get-Content $tmpFile
    $minLen     = ($content | Select-String 'MinimumPasswordLength').ToString().Split('=')[1].Trim()
    $complexity = ($content | Select-String 'PasswordComplexity').ToString().Split('=')[1].Trim()
    $maxAgeDays = ($content | Select-String 'MaximumPasswordAge').ToString().Split('=')[1].Trim()
    Write-Output "Minimum Password Length   : $minLen (required: {min_length})"
    Write-Output "Password Complexity       : $complexity (1=Enabled, 0=Disabled)"
    Write-Output "Maximum Password Age      : $maxAgeDays days (required: <= {max_age})"

    $fails = @()
    if ([int]$minLen -lt {min_length})  {{ $fails += "Length ($minLen) below minimum {min_length}" }}
    if ($complexity -ne '1')            {{ $fails += "Complexity not enabled" }}
    if ([int]$maxAgeDays -gt {max_age} -and [int]$maxAgeDays -ne -1) {{
        $fails += "Max age ($maxAgeDays days) exceeds {max_age} days"
    }}

    if ($fails.Count -eq 0) {{
        Write-Output "PASSWORD_STATUS: PASS"
    }} else {{
        Write-Output "PASSWORD_STATUS: FAIL - $($fails -join ' | ')"
    }}
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
}}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "PASSWORD_STATUS: PASS" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = f"Password policy meets requirements (min length {min_length}, complexity enabled, max age {max_age} days)."
        elif "PASSWORD_STATUS: FAIL" in cmd.stdout:
            result.status = STATUS_FAIL
            # Extract the failure reasons from the output
            for line in cmd.stdout.splitlines():
                if "PASSWORD_STATUS: FAIL" in line:
                    result.finding = line.replace(
                        "PASSWORD_STATUS: FAIL - ", ""
                    ).strip()
                    break
            result.remediation = (
                f"Configure via Group Policy: Computer Configuration > Windows Settings > "
                f"Security Settings > Account Policies > Password Policy.\n"
                f"Required: Minimum length = {min_length}, Complexity = Enabled, Max age = {max_age} days."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = (
                "Password policy could not be fully evaluated. Review raw evidence."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# IA-004 — RDP Network Level Authentication (NLA)
# ---------------------------------------------------------------------------
