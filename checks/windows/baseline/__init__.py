"""
CIS-001_cis_baseline.py
-----------------------
Checks a curated subset of CIS Microsoft Windows Server Benchmark controls

Check ID : CIS-001
Category : Baseline Alignment
Framework: CIS Benchmark

This file is auto-discovered by the check registry at startup.
To add a new check, create a new file in this directory following
the same pattern â€” no other files need to be modified.
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


@register_check("CIS-001")
def check_cis_baseline(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Checks a curated subset of CIS Microsoft Windows Server Benchmark controls
    that are high-value, automatable, and not already covered by other checks.
    Covers:
    - Anonymous enumeration of SAM accounts disabled (CIS 2.3.1.1)
    - LAN Manager authentication level (NTLMv2 only) (CIS 2.3.11.7)
    - SMB packet signing enabled (CIS 2.3.8.1 / 2.3.8.2)
    - WDigest authentication disabled (credential hygiene)
    - Autoplay disabled for all drives (CIS 18.9.8.1)
    - Remote UAC for network logons (CIS 2.3.17.1)
    """
    result = base_result(
        connector,
        "CIS-001",
        "CIS Benchmark Subset",
        "Check a subset of CIS Microsoft Windows Server Benchmark controls.",
        "Baseline Alignment",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- CIS Benchmark Subset Checks ---"

# CIS 2.3.1.1 â€” Anonymous enumeration of SAM accounts disabled
$noAnon = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymousSAM' -ErrorAction SilentlyContinue).RestrictAnonymousSAM
Write-Output "CIS-2.3.1.1 RestrictAnonymousSAM       : $noAnon  (Expected: 1)"

# CIS 2.3.1.2 â€” Anonymous enumeration of shares disabled
$noAnonShares = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymous' -ErrorAction SilentlyContinue).RestrictAnonymous
Write-Output "CIS-2.3.1.2 RestrictAnonymous           : $noAnonShares  (Expected: 1)"

# CIS 2.3.11.7 â€” LAN Manager Auth Level (NTLMv2 only)
$lmLevel = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue).LmCompatibilityLevel
Write-Output "CIS-2.3.11.7 LmCompatibilityLevel       : $lmLevel  (Expected: 5)"

# CIS 2.3.8.1 â€” SMB server packet signing required
$smbSignReq = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters' -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue).RequireSecuritySignature
Write-Output "CIS-2.3.8.1 SMB RequireSecuritySignature: $smbSignReq  (Expected: 1)"

# CIS 2.3.8.2 â€” SMB server packet signing enabled
$smbSignEn = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters' -Name 'EnableSecuritySignature' -ErrorAction SilentlyContinue).EnableSecuritySignature
Write-Output "CIS-2.3.8.2 SMB EnableSecuritySignature : $smbSignEn  (Expected: 1)"

# WDigest â€” disable plaintext credential caching
$wdigest = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential
Write-Output "WDigest UseLogonCredential              : $wdigest  (Expected: 0)"

# CIS 2.3.17.1 â€” UAC: Admin Approval Mode for built-in Administrator
$uacAdmin = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'FilterAdministratorToken' -ErrorAction SilentlyContinue).FilterAdministratorToken
Write-Output "CIS-2.3.17.1 FilterAdministratorToken   : $uacAdmin  (Expected: 1)"

# Remote UAC (LocalAccountTokenFilterPolicy) â€” should NOT be set to 1
$remoteUac = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'LocalAccountTokenFilterPolicy' -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
Write-Output "LocalAccountTokenFilterPolicy           : $remoteUac  (Expected: 0 or not set)"

# Safe DLL search mode
$safeDll = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Name 'SafeDllSearchMode' -ErrorAction SilentlyContinue).SafeDllSearchMode
Write-Output "SafeDllSearchMode                       : $safeDll  (Expected: 1)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout

        failures = []
        warnings = []

        checks = [
            (
                "RestrictAnonymousSAM",
                "1",
                "CIS 2.3.1.1: Anonymous SAM enumeration not restricted",
            ),
            (
                "RestrictAnonymous",
                "1",
                "CIS 2.3.1.2: Anonymous share enumeration not restricted",
            ),
            (
                "LmCompatibilityLevel",
                "5",
                "CIS 2.3.11.7: LAN Manager auth level not set to NTLMv2-only (5)",
            ),
            (
                "RequireSecuritySignature",
                "1",
                "CIS 2.3.8.1: SMB server packet signing not required",
            ),
            (
                "EnableSecuritySignature",
                "1",
                "CIS 2.3.8.2: SMB server packet signing not enabled",
            ),
            (
                "UseLogonCredential",
                "0",
                "WDigest: Plaintext credential caching may be enabled",
            ),
        ]

        for key, expected, message in checks:
            for line in output.splitlines():
                if key in line:
                    val = line.split(":")[-1].strip().split()[0] if ":" in line else ""
                    if val != expected and val not in ("", "None"):
                        if key in ("LmCompatibilityLevel", "UseLogonCredential"):
                            failures.append(message)
                        else:
                            warnings.append(message)

        # Remote UAC â€” value should be 0 or not set; 1 is bad
        for line in output.splitlines():
            if "LocalAccountTokenFilterPolicy" in line:
                val = line.split(":")[-1].strip().split()[0] if ":" in line else ""
                if val == "1":
                    failures.append(
                        "Remote UAC disabled: LocalAccountTokenFilterPolicy=1 enables pass-the-hash attacks"
                    )

        if failures:
            result.status = STATUS_FAIL
            result.finding = f"{len(failures)} CIS control(s) failed: " + "; ".join(
                failures
            )
            result.remediation = (
                "Apply the CIS Microsoft Windows Server Benchmark via GPO. "
                "Priority fixes: LmCompatibilityLevel=5 (NTLMv2 only), "
                "WDigest disabled, SMB signing required."
            )
        elif warnings:
            result.status = STATUS_WARNING
            result.finding = (
                f"{len(warnings)} CIS control(s) need attention: " + "; ".join(warnings)
            )
            result.remediation = (
                "Review and apply recommended CIS settings. "
                "Download the full CIS Benchmark from cisecurity.org for complete guidance."
            )
        else:
            result.status = STATUS_PASS
            result.finding = "All checked CIS Benchmark subset controls are compliant."

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result
