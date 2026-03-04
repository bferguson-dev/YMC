"""
CERT-002_untrusted_root_certs.py
--------------------------------
Rogue root certificates can enable silent SSL/TLS interception (MITM).
Malware and stalkerware commonly install their own root certificates.

Check ID : CERT-002
Category : Certificates
Framework: NIST SC-17, CIS 18.1.2
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


@register_check("CERT-002")
def check_untrusted_root_certs(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Identifies root certificates in the Untrusted store and checks for unexpected trusted roots."""
    result = base_result(
        connector,
        "CERT-002",
        "Untrusted Root Certificates",
        "Verify no unexpected certificates are in the Trusted Root CA store.",
        "Certificates",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Untrusted Certificate Store ---"
$untrusted = New-Object System.Security.Cryptography.X509Certificates.X509Store("Disallowed","LocalMachine")
$untrusted.Open("ReadOnly")
Write-Output "Untrusted/Disallowed store count: $($untrusted.Certificates.Count)"
$untrusted.Close()
Write-Output ""
Write-Output "--- Trusted Root CA Count ---"
$roots = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
$roots.Open("ReadOnly")
Write-Output "Trusted Root CA count: $($roots.Certificates.Count)"
$nonMs = $roots.Certificates | Where-Object {
    $_.Issuer -notmatch "Microsoft" -and
    $_.Issuer -notmatch "DigiCert" -and
    $_.Issuer -notmatch "Entrust" -and
    $_.Issuer -notmatch "VeriSign" -and
    $_.Issuer -notmatch "GlobalSign" -and
    $_.Issuer -notmatch "Comodo" -and
    $_.Issuer -notmatch "Sectigo" -and
    $_.Issuer -notmatch "Let.s Encrypt" -and
    $_.Issuer -notmatch "ISRG" -and
    $_.Issuer -notmatch "USERTrust" -and
    $_.Issuer -notmatch "GeoTrust" -and
    $_.Issuer -notmatch "Thawte" -and
    $_.Issuer -notmatch "Baltimore" -and
    $_.Issuer -notmatch "Cybertrust"
}
Write-Output "Non-standard root certs: $($nonMs.Count)"
foreach ($c in $nonMs) {
    Write-Output "  REVIEW: $($c.Subject) | Issuer: $($c.Issuer) | Expires: $($c.NotAfter.ToString('yyyy-MM-dd'))"
}
$roots.Close()
if ($nonMs.Count -eq 0) { Write-Output "COMPLIANT: No unexpected root certificates found." }
else { Write-Output "NON-COMPLIANT: $($nonMs.Count) non-standard root certificate(s) found." }
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        if "COMPLIANT: No unexpected" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = (
                "No unexpected root certificates found in the Trusted Root CA store."
            )
            result.remediation = ""
        else:
            count = 0
            for line in cmd.stdout.splitlines():
                if "Non-standard root certs:" in line:
                    try:
                        count = int(line.split(":", 1)[1].strip())
                    except (TypeError, ValueError, IndexError):
                        pass
            result.status = STATUS_WARNING
            result.finding = f"{count} non-standard root certificate(s) found in Trusted Root CA store. Review for rogue/interception certificates."
            result.remediation = (
                "Review each non-standard root in certlm.msc > Trusted Root Certification Authorities. "
                "Remove any certificates not explicitly required by your organization or a known software vendor."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
