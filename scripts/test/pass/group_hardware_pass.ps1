#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets EM-012 (TPM) and EM-013 (HVCI) checks to compliant (PASS) state.

.DESCRIPTION
    What this script does:
      EM-012  TPM: Sets the registry flag that tells the WMI Win32_Tpm class
              that TPM is present and enabled. On a VM with a vTPM, the real
              hardware state governs — this script verifies current vTPM status
              and reports it. No registry workaround can substitute for a missing vTPM.

      EM-013  HVCI (Hypervisor-Protected Code Integrity): Sets the registry key
              HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\
              HypervisorEnforcedCodeIntegrity\Enabled = 1

    What state it leaves the system in:
      EM-013 registry is set to PASS state (HVCI enabled = 1).
      EM-012 depends on vTPM hardware; this script reports current state.
      HVCI change requires a REBOOT to take effect at the kernel level,
      but the registry key is readable immediately so the YMC scan passes
      before rebooting.

    How to reverse it:
      Run fail/group_hardware_fail.ps1, or revert to the Proxmox snapshot.
      IMPORTANT: Take a Proxmox snapshot BEFORE enabling HVCI.
      If the VM CPU does not support VBS, enabling HVCI may cause boot failure.
      Only enable on Server 2022 with VBS-capable CPU.

.NOTES
    HVCI SAFETY WARNING:
      Enabling HVCI on an older CPU or incompatible VM configuration can cause
      the VM to fail to boot after reboot. Always have a Proxmox snapshot ready
      before setting HVCI Enabled=1 and rebooting.

    TPM NOTE:
      For EM-012 to report PASS, the Proxmox VM must have a vTPM (tpmstate0)
      configured. If no vTPM is present, EM-012 will remain ERROR/FAIL regardless
      of this script. Check VM config: qm config <VMID> | grep tpm
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

# --- EM-012: TPM Status (read-only check) ---
Write-Log "EM-012: Checking vTPM status..."
try {
    $tpm = Get-WmiObject -Namespace 'root\CIMv2\Security\MicrosoftTpm' `
        -Class Win32_Tpm -ErrorAction Stop
    if ($tpm) {
        $enabled = $tpm.IsEnabled_InitialValue
        $activated = $tpm.IsActivated_InitialValue
        Write-Log "  TPM found: IsEnabled=$enabled IsActivated=$activated"
        if ($enabled -and $activated) {
            Write-Log "  EM-012: vTPM is enabled and activated — PASS state confirmed."
        } else {
            Write-Log "  EM-012: vTPM found but not fully enabled/activated."
            Write-Log "  To fix: enable vTPM in Proxmox VM config and restart."
        }
    } else {
        Write-Log "  EM-012: No TPM device found. Add vTPM to this VM in Proxmox."
        Write-Log "  qm set <VMID> -tpmstate0 local:4,version=v2.0"
    }
} catch {
    Write-Log "  EM-012: WMI TPM query failed: $_"
    Write-Log "  This may indicate no TPM/vTPM is present."
}

# --- EM-013: HVCI (Hypervisor-Protected Code Integrity) ---
Write-Log "EM-013: Setting HVCI registry key to Enabled=1 (PASS state)..."

$hvciPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
if (-not (Test-Path $hvciPath)) {
    New-Item -Path $hvciPath -Force | Out-Null
    Write-Log "  Created registry path: $hvciPath"
}
Set-ItemProperty -Path $hvciPath -Name 'Enabled' -Value 1 -Type DWord
Write-Log "  Set $hvciPath\Enabled = 1"

Write-Log "EM-013: HVCI registry set to PASS state."
Write-Log "NOTE: HVCI requires a REBOOT to take effect at the kernel level."
Write-Log "      The YMC check reads the registry value, so it will PASS immediately."
Write-Log "      Do NOT reboot unless you have a Proxmox snapshot and a VBS-capable CPU."
Write-Log "Run YMC scan to verify: python main.py --host <TARGET> --profile disa_stig"

exit 0
