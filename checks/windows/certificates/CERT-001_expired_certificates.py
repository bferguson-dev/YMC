"""
CERT-001_expired_certificates.py
--------------------------------
Expired certificates cause authentication failures, TLS errors, and service outages.
Regular audit and removal is required.

Check ID : CERT-001
Category : Certificates
Framework: NIST SC-17, CIS 18.1.1
"""

import logging
from checks.windows.common import (
    base_result,
    register_check,
    WinRMConnector,
    WinRMExecutionError,
    CheckResult,
    STATUS_PASS,
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("CERT-001")
def check_expired_certificates(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Identifies expired certificates in the local machine certificate stores."""
    result = base_result(
        connector,
        "CERT-001",
        "Expired Certificates in Local Store",
        "Identify expired certificates in the local machine store that may cause service failures.",
        "Certificates",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Expired Certificates in Local Machine Stores ---"
$now = Get-Date
$stores = @("My","Root","CA","TrustedPublisher","TrustedPeople")
$expired = @()
foreach ($storeName in $stores) {
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName,"LocalMachine")
        $store.Open("ReadOnly")
        foreach ($cert in $store.Certificates) {
            if ($cert.NotAfter -lt $now) {
                $expired += [PSCustomObject]@{
                    Store   = $storeName
                    Subject = $cert.Subject
                    Expiry  = $cert.NotAfter.ToString("yyyy-MM-dd")
                    Issuer  = $cert.Issuer
                }
            }
        }
        $store.Close()
    } catch {}
}
Write-Output "Expired certificate count: $($expired.Count)"
foreach ($c in $expired) {
    Write-Output "  [$($c.Store)] $($c.Subject) | Expired: $($c.Expiry) | Issuer: $($c.Issuer)"
}
if ($expired.Count -eq 0) { Write-Output "COMPLIANT: No expired certificates found." }
else { Write-Output "NON-COMPLIANT: $($expired.Count) expired certificate(s) found." }
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        if "COMPLIANT: No expired" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = (
                "No expired certificates found in local machine certificate stores."
            )
            result.remediation = ""
        else:
            count = 0
            for line in cmd.stdout.splitlines():
                if "Expired certificate count:" in line:
                    try:
                        count = int(line.split(":", 1)[1].strip())
                    except (TypeError, ValueError, IndexError):
                        pass
            result.status = STATUS_WARNING
            result.finding = f"{count} expired certificate(s) found in local machine stores. See raw evidence for details."
            result.remediation = (
                "Remove expired certificates via certlm.msc (Local Computer certificate manager). "
                "Review whether they are still referenced by services before removing."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
