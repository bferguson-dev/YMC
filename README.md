# YMC

YMC is an automated Windows Server compliance scanner. It connects remotely via WinRM, executes checks against hardened security controls, and produces timestamped audit-ready reports.

Built by an infrastructure engineer who has done this work manually, screenshot by screenshot. YMC automates that process and produces evidence output aligned to major audit frameworks.

---

## Supported Compliance Frameworks

| Profile File | Framework | Version |
|---|---|---|
| `nist_800_53.yaml` | NIST SP 800-53 | Rev 5 |
| `pci_dss_4.yaml` | PCI DSS | 4.0 |
| `soc2.yaml` | SOC 2 Trust Services Criteria | 2022 |
| `hipaa.yaml` | HIPAA Security Rule | 45 CFR Part 164 |
| `cmmc_2.yaml` | CMMC | 2.0 Level 2 |
| `iso_27001.yaml` | ISO/IEC 27001 | 2022 |

Every check maps to all six frameworks simultaneously. Adding a new framework requires only a new YAML profile file — no code changes.

---

## Checks Implemented (27 checks across 4 control families)

### Access Control
- Inactive accounts (>90 days)
- Guest account disabled
- Built-in Administrator renamed
- Local Administrators group membership review
- Account lockout policy (threshold + duration)
- Screen saver / session lock

### Identification and Authentication
- Password minimum length
- Password complexity
- Password maximum age
- RDP Network Level Authentication (NLA)

### Audit and Logging
- Audit policy: logon events (success + failure)
- Audit policy: privilege use
- Audit policy: account management
- Security event log minimum size (192MB)
- Event log retention configuration
- Remote log forwarding (WEF / Splunk / Elastic / NXLog)

### Configuration Management and System Integrity
- SMBv1 disabled
- Unnecessary services (Telnet, FTP, Remote Registry, etc.)
- Administrative shares review
- AutoRun/AutoPlay disabled
- Windows Firewall (all profiles)
- Automatic updates / patch management
- Antivirus/EDR status and definition currency
- OS patch level and last update date

---

## Architecture

```
ymc/
├── main.py                    # CLI entry point
├── config/
│   └── settings.yaml          # Thresholds and connection settings
├── profiles/                  # One YAML per compliance framework
│   ├── nist_800_53.yaml
│   ├── pci_dss_4.yaml
│   ├── soc2.yaml
│   ├── hipaa.yaml
│   ├── cmmc_2.yaml
│   └── iso_27001.yaml
├── connector/
│   └── winrm_connector.py     # WinRM session management
├── checks/
│   └── windows/
│       ├── access_control.py
│       ├── audit_logging.py
│       └── config_management.py   # Also contains IA and SI checks
├── engine/
│   ├── evidence.py            # CheckResult / HostScanResult dataclasses
│   └── runner.py              # Orchestration engine
└── reporters/
    ├── base_reporter.py       # Abstract base — extend to add new formats
    ├── html_reporter.py       # Audit-ready HTML output
    └── json_reporter.py       # Machine-readable JSON output
```

**Key design decisions:**

- **Check once, map to all frameworks** — each PowerShell check runs once; YAML profiles handle the control ID mapping per framework
- **Agentless** — uses WinRM (port 5985/5986). No software installed on target systems
- **Credential hygiene** — passwords are never stored, logged, or written to disk. Interactive prompt via `getpass` or `COLLECTOR_PASSWORD` environment variable for pipelines
- **Extensible reporters** — all reporters inherit from `BaseReporter`. Adding PDF, CSV, or styled HTML output requires one new file
- **Audit chain of custody** — every check result captures hostname, IP, UTC timestamp, tool version, and executing username — the same information a timestamped screenshot would provide

---

## Requirements

**Controller machine** (where you run the tool):
- Python 3.10+
- `pip install -r requirements.txt`

**Target Windows Server** (machines being checked):
- WinRM enabled (HTTP port 5985 or HTTPS 5986)
- Account with remote management rights

### Enable WinRM on target (run as Administrator):
```powershell
winrm quickconfig -y
# Allow HTTP (if not using HTTPS):
winrm set winrm/config/client/auth '@{Basic="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
# Allow unencrypted (for HTTP only — use HTTPS in production):
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
```

For HTTPS (recommended in production), configure WinRM with a certificate and use port 5986.

---

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# List available compliance profiles
python main.py --list-profiles

# Run a NIST 800-53 scan (HTML report)
python main.py --host 192.168.1.10 --username DOMAIN\\auditor --profile nist_800_53

# Run a PCI DSS scan and generate both HTML and JSON
python main.py --host WEBSERVER01 --username administrator --profile pci_dss_4 --format both

# Run via environment variable (for automation pipelines)
export COLLECTOR_PASSWORD="your_password"
python main.py --host 192.168.1.10 --username DOMAIN\\svcaccount --profile hipaa
```

### Exit codes
| Code | Meaning |
|------|---------|
| 0 | Scan completed, no failures |
| 1 | Scan could not complete (connection error, bad profile) |
| 2 | Scan completed, one or more FAIL findings |

---

## Report Output

Reports are written to `./reports/` by default.

**HTML report** — human-readable, audit-ready. Contains:
- Full chain of custody header (host, IP, timestamp, profile, executing account)
- Summary statistics with compliance percentage
- Per-check results organized by control family
- Click-to-expand raw evidence for each check (the PowerShell output captured from the remote system)
- Remediation guidance for failed checks

**JSON report** — machine-readable. Suitable for import into SIEM, GRC platforms, or ticketing systems.

---

## Adding a New Compliance Framework

1. Create `profiles/your_framework.yaml` following the existing profile structure
2. Map each `check_id` to the appropriate control number in your framework
3. That's it — no code changes required

## Adding a New Check

1. Write the check function in the appropriate `checks/windows/` module
2. Register it in `engine/runner.py` under `CHECK_REGISTRY`
3. Add the `check_id` to any profile YAML files where it applies

## Adding a New Output Format

1. Create `reporters/your_reporter.py`
2. Inherit from `BaseReporter` and implement `generate()`
3. Wire it into `main.py`

---

## Roadmap

- [ ] Multi-host scanning (CSV input of target hosts)
- [ ] Linux/RHEL checks via SSH (Paramiko)
- [ ] AWS cloud resource checks (boto3)
- [ ] Azure cloud resource checks (azure-mgmt)
- [ ] PDF report output
- [ ] CSV/Excel output for GRC platform import
- [ ] STIG SCAP import for automated benchmark mapping
- [ ] Drift detection mode (compare against previous scan baseline)
- [ ] Ansible integration for automated remediation of failed checks

---

## Security Notes

- WinRM HTTP (port 5985) transmits credentials and results unencrypted. Use WinRM HTTPS (port 5986) in production environments
- The service account used for scanning requires read-only access to WMI, registry, and local security policy — it does not need to be a local administrator on target systems (though some checks require elevated read access)
- Credentials are held in memory only for the duration of the scan session and are not persisted anywhere

## Secret Scanning (Gitleaks)

YMC includes a tracked pre-commit hook at `.githooks/pre-commit` that runs `gitleaks` against staged changes.

One-time setup (inside this repo):
```bash
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit
```

Install `gitleaks` on your system:

Ubuntu/Debian:
```bash
sudo apt-get install -y gitleaks
```

macOS (Homebrew):
```bash
brew install gitleaks
```

Verify installation and hook wiring:
```bash
gitleaks version
git config --get core.hooksPath
```

Expected hook path output:
```text
.githooks
```

How to test the hook:
1. Stage any file change.
2. Run `git commit -m "test hook"`.
3. The hook should run `gitleaks` before the commit is created.

If `gitleaks` is missing, commits will be blocked with an error until it is installed.

---

## License

MIT
