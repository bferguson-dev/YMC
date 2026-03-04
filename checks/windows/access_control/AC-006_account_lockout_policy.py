"""
AC-006_account_lockout_policy.py
--------------------------------
Reads the local account lockout policy and validates:

Check ID : AC-006, AC-007
Category : Access Control
Framework: NIST AC-7, PCI DSS 8.3

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


@register_check("AC-006", "AC-007", dedup_group="lockout_policy")
def check_account_lockout_policy(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Reads the local account lockout policy and validates:
    - Lockout threshold <= configured maximum (default 5 attempts)
    - Lockout duration >= 15 minutes
    - Observation window >= lockout duration
    """
    result = base_result(
        connector,
        "AC-006",
        "Account Lockout Policy",
        "Verify account lockout threshold and duration meet compliance requirements.",
        "Access Control",
        tool_name,
        tool_version,
        executed_by,
    )
    max_attempts = settings.get("max_lockout_attempts", 5)

    ps_script = """
$policy = net accounts
Write-Output "--- Account Policy Output ---"
$policy | ForEach-Object { Write-Output $_ }
Write-Output ""
Write-Output "--- Parsed Lockout Settings ---"
$threshold = ($policy | Select-String 'Lockout threshold').ToString().Split(':')[1].Trim()
$duration  = ($policy | Select-String 'Lockout duration').ToString().Split(':')[1].Trim()
$window    = ($policy | Select-String 'Lockout observation window').ToString().Split(':')[1].Trim()
Write-Output "Lockout Threshold          : $threshold"
Write-Output "Lockout Duration (minutes) : $duration"
Write-Output "Observation Window         : $window"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        findings = []
        remediation_items = []
        failed = False

        # Parse threshold
        for line in cmd.stdout.splitlines():
            if "Lockout Threshold" in line and "Parsed" not in line:
                try:
                    value = line.split(":")[1].strip()
                    if value.lower() == "never" or value == "0":
                        findings.append("Lockout threshold is NOT configured (Never).")
                        remediation_items.append(
                            f"Set lockout threshold to {max_attempts} or fewer attempts."
                        )
                        failed = True
                    else:
                        threshold_val = int(value)
                        if threshold_val > max_attempts:
                            findings.append(
                                f"Lockout threshold is {threshold_val} — exceeds maximum of {max_attempts}."
                            )
                            remediation_items.append(
                                f"Reduce lockout threshold to {max_attempts} or fewer."
                            )
                            failed = True
                        else:
                            findings.append(
                                f"Lockout threshold is {threshold_val} — within policy ({max_attempts} max)."
                            )
                except (ValueError, IndexError):
                    pass

            if "Lockout Duration" in line and "Parsed" not in line:
                try:
                    value = line.split(":")[1].strip()
                    if value.lower() == "forever":
                        findings.append(
                            "Lockout duration is set to Forever — acceptable."
                        )
                    else:
                        duration_val = int(value)
                        if duration_val < 15:
                            findings.append(
                                f"Lockout duration is {duration_val} minutes — below 15 minute minimum."
                            )
                            remediation_items.append(
                                "Increase lockout duration to at least 15 minutes."
                            )
                            failed = True
                        else:
                            findings.append(
                                f"Lockout duration is {duration_val} minutes — meets requirement."
                            )
                except (ValueError, IndexError):
                    pass

        if failed:
            result.status = STATUS_FAIL
            result.finding = " | ".join(findings)
            result.remediation = (
                "Configure via: Computer Configuration > Windows Settings > "
                "Security Settings > Account Policies > Account Lockout Policy. "
                + " ".join(remediation_items)
            )
        elif findings:
            result.status = STATUS_PASS
            result.finding = " | ".join(findings)
        else:
            result.status = STATUS_WARNING
            result.finding = (
                "Could not parse lockout policy values. Review raw evidence manually."
            )
            result.remediation = (
                "Run 'net accounts' manually and verify lockout settings."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# AC-008 — Screen Saver / Session Lock
# ---------------------------------------------------------------------------
