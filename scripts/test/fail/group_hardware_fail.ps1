#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets EM-012 (TPM) and EM-013 (HVCI) checks to non-compliant (FAIL) state.

.DESCRIPTION
    What this script does:
      EM-012  TPM: Cannot be forced to FAIL via registry alone — depends on vTPM
              hardware. This script reports the current state. To test FAIL:
              remove the vTPM from the Proxmox VM config and reboot.
              (Use a dedicated second VM for vTPM-absent testing.)

      EM-013  HVCI: Sets the registry key Enabled=0, which causes the YMC check
              to report FAIL.

    What state it leaves the system in:
      EM-013 registry set to Enabled=0 (FAIL state).
      EM-012 state depends on hardware — reported but not changed.

    How to reverse it:
      Run pass/group_hardware_pass.ps1, or revert to the Proxmox snapshot.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Output "[$ts] $Message"
}

# --- EM-012: TPM (hardware-dependent — cannot be forced via registry) ---
Write-Log "EM-012: TPM state is hardware-dependent."
Write-Log "  To test FAIL state: remove vTPM from Proxmox VM config and reboot."
Write-Log "  qm set <VMID> -delete tpmstate0  (WARNING: destroys TPM state)"
Write-Log "  Recommended: use a separate VM without vTPM for EM-012 FAIL coverage."
Write-Log "  Current TPM state (informational):"
try {
    $tpm = Get-WmiObject -Namespace 'root\CIMv2\Security\MicrosoftTpm' `
        -Class Win32_Tpm -ErrorAction SilentlyContinue
    if ($tpm) {
        Write-Log "  TPM present: IsEnabled=$($tpm.IsEnabled_InitialValue) IsActivated=$($tpm.IsActivated_InitialValue)"
    } else {
        Write-Log "  No TPM found — EM-012 will already report FAIL on this VM."
    }
} catch {
    Write-Log "  TPM query failed: $_ (EM-012 will report ERROR/FAIL)"
}

# --- EM-013: HVCI (Hypervisor-Protected Code Integrity) ---
Write-Log "EM-013: Setting HVCI registry key to Enabled=0 (FAIL state)..."

$hvciPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
if (-not (Test-Path $hvciPath)) {
    New-Item -Path $hvciPath -Force | Out-Null
    Write-Log "  Created registry path: $hvciPath"
}
Set-ItemProperty -Path $hvciPath -Name 'Enabled' -Value 0 -Type DWord
Write-Log "  Set $hvciPath\Enabled = 0"

Write-Log "EM-013: HVCI registry set to FAIL state (Enabled=0)."
Write-Log "Run YMC scan to verify: python main.py --host <TARGET> --profile disa_stig"
Write-Log "IMPORTANT: Run pass/group_hardware_pass.ps1 AND revert snapshot after verifying FAIL results."

exit 0
