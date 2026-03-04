# Settings Reference

Complete reference for every configurable setting. For each setting, the table shows:
- The CLI flag
- The environment variable
- The settings.yaml key (under `cli_defaults` unless noted)
- The built-in default value

Settings are resolved in priority order: **CLI flag > env var > named config profile > personal settings > program defaults**

---

## Connectivity

| CLI Flag | Env Var | settings.yaml key | Default | Description |
|---|---|---|---|---|
| `--username` | `COLLECTOR_USERNAME` | `cli_defaults.username` | — | WinRM username |
| `--domain` | `COLLECTOR_DOMAIN` | `cli_defaults.domain` | — | DNS suffix for bare hostnames |
| `--winrm-port` | `COLLECTOR_WINRM_PORT` | `cli_defaults.winrm_port` | `5985` | WinRM port |
| — | `COLLECTOR_WINRM_TRANSPORT` | `connection.winrm_transport` | `ntlm` | Auth transport |
| — | `COLLECTOR_CONN_TIMEOUT` | `connection.connection_timeout` | `30` | TCP timeout (seconds) |
| — | `COLLECTOR_READ_TIMEOUT` | `connection.read_timeout` | `120` | Command timeout (seconds) |

---

## Scan Behaviour

| CLI Flag | Env Var | settings.yaml key | Default | Description |
|---|---|---|---|---|
| `--profile` | `COLLECTOR_PROFILE` | `cli_defaults.profile` | `nist_800_53` | Compliance framework |
| `--config` | `COLLECTOR_CONFIG` | `cli_defaults.config` | — | Named config profile |
| — | `COLLECTOR_PARALLEL` | `cli_defaults.parallel` | `false` | Parallel scanning (future) |

---

## Output

| CLI Flag | Env Var | settings.yaml key | Default | Description |
|---|---|---|---|---|
| `--format` | `COLLECTOR_FORMAT` | `cli_defaults.format` | `html` | Report format |
| `--output-dir` | `COLLECTOR_OUTPUT_DIR` | `cli_defaults.output_dir` | platform default | Report root directory |

---

## Evidence Thresholds

These live under the `evidence` section in settings.yaml, not `cli_defaults`.

| Env Var | settings.yaml key | Default | Description |
|---|---|---|---|
| `COLLECTOR_INACTIVE_DAYS` | `evidence.inactive_account_threshold_days` | `90` | Days before inactive account flagged |
| `COLLECTOR_MAX_LOCKOUT` | `evidence.max_lockout_attempts` | `5` | Max lockout attempts |
| `COLLECTOR_LOG_SIZE_MB` | `evidence.min_security_log_size_kb` | `192` MB | Min security log size |

---

## Runtime Flags

| CLI Flag | Env Var | settings.yaml key | Default | Description |
|---|---|---|---|---|
| `--verbose` | `COLLECTOR_VERBOSE` | `cli_defaults.verbose` | `false` | Debug logging |
| `--no-color` | `COLLECTOR_NO_COLOR` | `cli_defaults.no_color` | `false` | Disable colour |
| `--no-banner` | `COLLECTOR_NO_BANNER` | `cli_defaults.no_banner` | `false` | Suppress banner |

---

## Config File Locations

| Priority | Path | Purpose |
|---|---|---|
| 5 (lowest) | `<install_dir>/config/settings.yaml` | Program defaults — shipped with tool |
| 4 | `~/.ymc/settings.yaml` | Personal user defaults |
| 3 | `~/.ymc/profiles/<n>.yaml` | Named user config profiles |
| 3 | `<install_dir>/config/profiles/<n>.yaml` | Named program config profiles |
| 2 | Environment variables | Pipeline / automation overrides |
| 1 (highest) | CLI flags | Always win |

---

## Named Config Profiles

Create profiles for different environments or use cases:

```bash
# Create your profiles directory
mkdir -p ~/.ymc/profiles

# Copy the default as a starting point
cp config/profiles/default.yaml ~/.ymc/profiles/corporate.yaml

# Edit to suit your environment
nano ~/.ymc/profiles/corporate.yaml

# Use it
python main.py --config corporate --csv hosts.csv
```

**Example profile for a PCI audit engagement:**
```yaml
# ~/.ymc/profiles/pci_audit.yaml
cli_defaults:
  profile: pci_dss_4
  format: both
  domain: corp.local
  username: pci-audit-svc
  winrm_port: 5986        # HTTPS WinRM for PCI environments

connection:
  winrm_transport: ntlm
  connection_timeout: 30
  read_timeout: 120

evidence:
  inactive_account_threshold_days: 90
  max_lockout_attempts: 5
  min_password_length: 12

output:
  include_raw_evidence: true
```
