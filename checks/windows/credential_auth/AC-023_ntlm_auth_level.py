"""
AC-023_ntlm_auth_level.py
--------------------------
LmCompatibilityLevel controls which NTLM challenge/response protocols are
accepted. Level 5 (NTLMv2 only, refuse LM and NTLM) is required for
hardened environments. Lower values allow weak legacy protocols susceptible
to offline cracking and pass-the-hash attacks.

Check ID : AC-023
Category : Credential & Authentication
Framework: NIST IA-5, DISA STIG CAT-I, CIS 2.3.11.1
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


@register_check("AC-023")
def check_ntlm_auth_level(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies LmCompatibilityLevel is set to 5 (NTLMv2 only, refuse LM and NTLM)."""
    result = base_result(
        connector,
        "AC-023",
        "NTLM Authentication Level (LmCompatibilityLevel)",
        "Verify LmCompatibilityLevel=5 to enforce NTLMv2 and reject legacy LM/NTLM auth.",
        "Credential & Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = r"""
$val = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue).LmCompatibilityLevel
Write-Output "LmCompatibilityLevel: $val"
# Levels: 0=LM+NTLM, 1=NTLMv2session, 2=NTLMv2, 3=NTLMv2 client only, 4=NTLMv2 refuse LM, 5=NTLMv2 refuse LM+NTLM
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if line.startswith("LmCompatibilityLevel:"):
                v = line.split(":", 1)[1].strip()
                try:
                    val = int(v)
                except (TypeError, ValueError):
                    pass

        if val is None:
            result.status = STATUS_FAIL
            result.finding = (
                "LmCompatibilityLevel is not set. Default allows LM and NTLM authentication — "
                "vulnerable to pass-the-hash and offline cracking."
            )
            result.remediation = (
                "Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa LmCompatibilityLevel=5 (DWORD) "
                "via GPO: Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > Security Options > "
                "Network security: LAN Manager authentication level > "
                "Send NTLMv2 response only, refuse LM and NTLM."
            )
        elif val == 5:
            result.status = STATUS_PASS
            result.finding = "LmCompatibilityLevel=5: NTLMv2 only, LM and NTLM rejected. Optimal configuration."
            result.remediation = ""
        elif val == 4:
            result.status = STATUS_WARNING
            result.finding = (
                f"LmCompatibilityLevel={val}: NTLMv2 only (outbound) and refuse LM, but NTLM responses "
                "are still accepted from clients. Upgrade to level 5."
            )
            result.remediation = "Set LmCompatibilityLevel=5 to also refuse incoming NTLM authentication."
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"LmCompatibilityLevel={val}: Weak legacy NTLM authentication is permitted. "
                "Values below 4 allow LM or NTLM responses which are crackable offline."
            )
            result.remediation = (
                "Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa LmCompatibilityLevel=5 (DWORD). "
                "Test with domain controllers first to avoid authentication disruption."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
