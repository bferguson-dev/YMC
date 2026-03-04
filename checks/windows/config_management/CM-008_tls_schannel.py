"""
CM-008_tls_schannel.py
----------------------
Checks Schannel registry settings for weak protocol enablement:

Check ID : CM-008
Category : Config Management
Framework: NIST SC-8, PCI DSS 4.2

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


@register_check("CM-008")
def check_tls_schannel(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Checks Schannel registry settings for weak protocol enablement:
    - SSL 2.0 disabled (critically weak)
    - SSL 3.0 disabled (POODLE vulnerability)
    - TLS 1.0 disabled (PCI DSS 4.0 requirement)
    - TLS 1.1 disabled (deprecated)
    - TLS 1.2 enabled
    - TLS 1.3 enabled (where supported)
    """
    result = base_result(
        connector,
        "CM-008",
        "TLS/Schannel Protocol Configuration",
        "Verify weak SSL/TLS protocols are disabled and TLS 1.2+ is enabled.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$schannelBase = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols'

$protocols = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3')

Write-Output "--- Schannel Protocol Configuration ---"

foreach ($proto in $protocols) {
    $serverPath = "$schannelBase\\$proto\\Server"
    $clientPath = "$schannelBase\\$proto\\Client"

    $serverEnabled = $null
    $clientEnabled = $null

    if (Test-Path $serverPath) {
        $serverEnabled = (Get-ItemProperty $serverPath -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
        $serverDisabled = (Get-ItemProperty $serverPath -Name 'DisabledByDefault' -ErrorAction SilentlyContinue).DisabledByDefault
    }
    if (Test-Path $clientPath) {
        $clientEnabled = (Get-ItemProperty $clientPath -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
    }

    Write-Output "Protocol: $proto"
    Write-Output "  Server Enabled       : $(if ($null -eq $serverEnabled) { 'Not set (OS default)' } else { $serverEnabled })"
    Write-Output "  Server DisabledByDef : $(if ($null -eq $serverDisabled) { 'Not set' } else { $serverDisabled })"
    Write-Output "  Client Enabled       : $(if ($null -eq $clientEnabled) { 'Not set (OS default)' } else { $clientEnabled })"
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout

        failures = []
        warnings = []
        # Weak protocols that MUST be disabled
        # Registry value 0 = disabled, 1 = enabled, not set = OS default
        # Modern Windows defaults disable SSL2/3 but explicit config is better
        weak_protocols = ["ssl 2.0", "ssl 3.0", "tls 1.0", "tls 1.1"]
        strong_protocols = ["tls 1.2", "tls 1.3"]

        # Parse output block by block
        current_proto = None
        proto_data = {}

        for line in output.splitlines():
            if line.startswith("Protocol:"):
                current_proto = line.split(":", 1)[1].strip().lower()
                proto_data[current_proto] = {}
            elif current_proto and "Server Enabled" in line:
                val = line.split(":", 1)[1].strip()
                proto_data[current_proto]["server_enabled"] = val

        for proto in weak_protocols:
            data = proto_data.get(proto, {})
            server_val = data.get("server_enabled", "Not set (OS default)")
            if server_val == "1":
                failures.append(f"{proto.upper()} is explicitly ENABLED on server")
            elif server_val == "Not set (OS default)":
                warnings.append(
                    f"{proto.upper()} relies on OS default (explicit disable recommended)"
                )

        for proto in strong_protocols:
            data = proto_data.get(proto, {})
            server_val = data.get("server_enabled", "Not set (OS default)")
            if server_val == "0":
                failures.append(
                    f"{proto.upper()} is explicitly DISABLED — this will break connectivity"
                )

        if failures:
            result.status = STATUS_FAIL
            result.finding = "TLS/Schannel issues: " + "; ".join(failures)
            result.remediation = (
                "Explicitly disable weak protocols via registry or use IIS Crypto tool "
                "(nartac.com/Products/IISCrypto). Apply the 'Best Practices' template as a baseline. "
                "PCI DSS 4.0 requires TLS 1.0 and 1.1 to be disabled."
            )
        elif warnings:
            result.status = STATUS_WARNING
            result.finding = (
                "Weak protocols are not explicitly disabled — relying on OS defaults. "
                "Explicit configuration is required for PCI DSS 4.0 compliance. "
                + "; ".join(warnings)
            )
            result.remediation = (
                "Explicitly disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 via registry. "
                "Use IIS Crypto or a GPO to enforce Schannel settings consistently."
            )
        else:
            result.status = STATUS_PASS
            result.finding = (
                "Weak protocols are explicitly disabled. TLS 1.2 and/or 1.3 are active."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# CM-009 — LAPS (Local Administrator Password Solution)
# ---------------------------------------------------------------------------
