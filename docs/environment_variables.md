# Environment Variables Reference

Every CLI flag and settings.yaml key has a corresponding environment variable.
Set these for automation, CI/CD pipelines, or to avoid typing the same flags repeatedly.

**Priority order** (highest to lowest):
1. CLI flag
2. Environment variable
3. Named config profile (`--config`)
4. Personal settings (`~/.compliance-collector/settings.yaml`)
5. Program defaults (`config/settings.yaml`)

---

## Connectivity

| Variable | Type | Default | Description |
|---|---|---|---|
| `COLLECTOR_USERNAME` | string | — | Default WinRM username |
| `COLLECTOR_DOMAIN` | string | — | DNS suffix appended to bare hostnames |
| `COLLECTOR_WINRM_PORT` | integer | `5985` | WinRM port (5985=HTTP, 5986=HTTPS) |
| `COLLECTOR_WINRM_TRANSPORT` | string | `ntlm` | Auth transport: `ntlm` \| `kerberos` \| `basic` \| `certificate` |
| `COLLECTOR_CONN_TIMEOUT` | integer | `30` | TCP connection timeout in seconds |
| `COLLECTOR_READ_TIMEOUT` | integer | `120` | PowerShell command timeout in seconds |

---

## Credentials

Passwords are never stored in files or on the command line.

| Variable | Description |
|---|---|
| `COLLECTOR_PASSWORD` | Default password used for all usernames that don't have a per-username variable |
| `COLLECTOR_PASSWORD_<USERNAME>` | Per-username password. Username is uppercased with non-alphanumeric characters replaced by underscores |

**Per-username variable naming examples:**

| Username | Environment variable |
|---|---|
| `administrator` | `COLLECTOR_PASSWORD_ADMINISTRATOR` |
| `compliance-svc` | `COLLECTOR_PASSWORD_COMPLIANCE_SVC` |
| `CORP\compliance-svc` | `COLLECTOR_PASSWORD_CORP_COMPLIANCE_SVC` |
| `svc@corp.local` | `COLLECTOR_PASSWORD_SVC_CORP_LOCAL` |

**Setting credentials for a pipeline (Linux/macOS):**
```bash
export COLLECTOR_USERNAME="compliance-svc"
export COLLECTOR_PASSWORD_COMPLIANCE_SVC="YourSecurePassword"
export COLLECTOR_DOMAIN="corp.local"
python main.py --csv hosts.csv --profile nist_800_53
```

**Setting credentials for a pipeline (Windows PowerShell):**
```powershell
$env:COLLECTOR_USERNAME = "compliance-svc"
$env:COLLECTOR_PASSWORD_COMPLIANCE_SVC = "YourSecurePassword"
$env:COLLECTOR_DOMAIN = "corp.local"
python main.py --csv hosts.csv --profile nist_800_53
```

---

## Scan Behaviour

| Variable | Type | Default | Description |
|---|---|---|---|
| `COLLECTOR_PROFILE` | string | `nist_800_53` | Compliance framework profile |
| `COLLECTOR_FORMAT` | string | `html` | Report format: `html` \| `json` \| `both` |
| `COLLECTOR_CONFIG` | string | — | Named config profile name |
| `COLLECTOR_PARALLEL` | boolean | `false` | Parallel scanning (future capability) |

---

## Output

| Variable | Type | Default | Description |
|---|---|---|---|
| `COLLECTOR_OUTPUT_DIR` | path | platform default | Root directory for scan report folders |

**Platform defaults when `COLLECTOR_OUTPUT_DIR` is not set:**

| OS | Default path |
|---|---|
| Windows | `C:\Users\<user>\Documents\Compliance Scans\` |
| Linux | `~/Documents/Compliance Scans/` or `~/Compliance Scans/` |
| macOS | `~/Documents/Compliance Scans/` |

---

## Evidence Thresholds

| Variable | Type | Default | Description |
|---|---|---|---|
| `COLLECTOR_INACTIVE_DAYS` | integer | `90` | Days before inactive account is flagged |
| `COLLECTOR_MAX_LOCKOUT` | integer | `5` | Max lockout attempts before flagging |
| `COLLECTOR_LOG_SIZE_MB` | integer | `192` | Min security log size in MB |

---

## Runtime

| Variable | Type | Default | Description |
|---|---|---|---|
| `COLLECTOR_VERBOSE` | boolean | `false` | Enable debug logging |
| `COLLECTOR_NO_COLOR` | boolean | `false` | Disable colour output |
| `COLLECTOR_NO_BANNER` | boolean | `false` | Suppress startup banner |

---

## Full pipeline example

```bash
#!/bin/bash
# Monthly PCI DSS compliance scan — runs unattended via cron

export COLLECTOR_USERNAME="compliance-svc"
export COLLECTOR_PASSWORD_COMPLIANCE_SVC="${SECRET_VAULT_PASSWORD}"
export COLLECTOR_DOMAIN="corp.local"
export COLLECTOR_PROFILE="pci_dss_4"
export COLLECTOR_FORMAT="both"
export COLLECTOR_OUTPUT_DIR="/var/compliance-reports"
export COLLECTOR_NO_BANNER="true"
export COLLECTOR_NO_COLOR="true"

python /opt/compliance-collector/main.py --csv /etc/compliance/pci_hosts.csv

# Exit code: 0=all pass, 1=connection errors, 2=compliance findings
echo "Scan exit code: $?"
```
