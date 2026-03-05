# YMC

YMC is an agentless Windows Server compliance scanner. It connects over WinRM, runs security checks remotely, and generates audit-ready reports with evidence.

---

## Current Capability Snapshot

- Registered checks: **109** (runtime registry)
- Windows control families: **13**
- Framework profiles included: **6**
- Report formats: **HTML**, **JSON**, or both
- Scan targets: single host, comma-separated host list, or CSV input

### Windows control families currently implemented

| Family | Check Count |
|---|---:|
| access_control | 10 |
| audit_logging | 16 |
| baseline | 1 |
| certificates | 2 |
| config_management | 16 |
| credential_auth | 9 |
| exploit_mitigations | 11 |
| identity_auth | 2 |
| network_hardening | 13 |
| powershell_security | 6 |
| services | 7 |
| storage_recovery | 5 |
| system_integrity | 6 |

### Profile coverage

| Profile File | Framework | Version | Checks in Profile |
|---|---|---|---:|
| `nist_800_53.yaml` | NIST SP 800-53 | Rev 5 | 109 |
| `pci_dss_4.yaml` | PCI DSS | 4.0 | 81 |
| `soc2.yaml` | SOC 2 Trust Services Criteria | 2022 | 77 |
| `hipaa.yaml` | HIPAA Security Rule | 45 CFR Part 164 | 53 |
| `cmmc_2.yaml` | CMMC | 2.0 Level 2 | 75 |
| `iso_27001.yaml` | ISO/IEC 27001 | 2022 | 76 |

---

## Architecture

```text
compliance-collector/
├── main.py                     # CLI entrypoint and scan orchestration
├── check.sh                    # Local quality gate script
├── checks/
│   ├── registry.py             # Decorator-based check registry
│   └── windows/
│       ├── access_control/
│       ├── audit_logging/
│       ├── baseline/
│       ├── certificates/
│       ├── config_management/
│       ├── credential_auth/
│       ├── exploit_mitigations/
│       ├── identity_auth/
│       ├── network_hardening/
│       ├── powershell_security/
│       ├── services/
│       ├── storage_recovery/
│       ├── system_integrity/
│       └── common.py
├── connector/
│   └── winrm_connector.py      # WinRM session + command execution
├── engine/
│   ├── runner.py               # Profile loading, check execution, dedup logic
│   ├── evidence.py             # CheckResult/HostScanResult models
│   └── registry.py
├── reporters/
│   ├── base_reporter.py
│   ├── html_reporter.py
│   └── json_reporter.py
├── profiles/                   # Framework mapping YAMLs
├── config/
│   ├── settings.yaml           # Program defaults
│   └── profiles/default.yaml   # Named config profile example
├── docs/
│   ├── environment_variables.md
│   ├── settings_reference.md
│   ├── hosts_template.csv
│   └── hosts_example.csv
└── tests/
    └── test_cli_smoke.py
```

### Design details

- **Dynamic check discovery**: `engine/runner.py` imports all check modules under `checks/` at runtime.
- **Decorator registration**: each check function uses `@register_check(...)` from `checks/registry.py`.
- **Dedup support**: related check IDs can share one execution result via `dedup_group`.
- **Framework mapping via YAML**: checks are mapped to control IDs in `profiles/*.yaml`; adding mappings does not require runner changes.
- **Agentless operation**: no software is installed on target Windows hosts.

---

## Requirements

Controller machine:
- Python 3.10+
- Access to target hosts over WinRM

Install dependencies:

```bash
pip install -r requirements.txt
```

Target Windows hosts:
- WinRM enabled (5985 HTTP or 5986 HTTPS)
- Account with permissions to read security-relevant configuration and logs

---

## Usage

List compliance profiles:

```bash
python main.py --list-profiles
```

List named config profiles:

```bash
python main.py --list-configs
```

Single host:

```bash
python main.py --host web01.corp.local --username CORP\\auditor --profile nist_800_53
```

Multiple hosts (comma-separated):

```bash
python main.py --host web01,db01,dc01 --domain corp.local --username CORP\\auditor --profile pci_dss_4
```

CSV-driven scan:

```bash
python main.py --csv docs/hosts_example.csv --profile iso_27001 --format both
```

Custom output directory:

```bash
python main.py --host web01 --username CORP\\auditor --output-dir ./reports --format both
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed with no failing findings |
| 1 | Scan could not complete (configuration/connection/runtime error) |
| 2 | Scan completed with one or more FAIL findings |

---

## Configuration

Resolution order (highest to lowest):
1. CLI flags
2. Environment variables (`COLLECTOR_*`)
3. Named config profile (`--config`)
4. Personal settings (`~/.ymc/settings.yaml`)
5. Program defaults (`config/settings.yaml`)

Reference docs:
- [docs/environment_variables.md](docs/environment_variables.md)
- [docs/settings_reference.md](docs/settings_reference.md)

---

## Testing And Quality Gates

### Automated tests currently in repo

- `tests/test_cli_smoke.py`
- Smoke coverage:
  - `python main.py --help`
  - `python main.py --list-profiles`
  - `python main.py --list-configs`

Run tests:

```bash
python -m pytest -q
```

### `check.sh` quality gate

`check.sh` runs the project gate sequence:
1. `ruff format`
2. `ruff check` (auto-fix then enforce)
3. `bandit` (policy threshold: medium+ severity/confidence)
4. `pip-audit` (with network-failure handling)
5. `pytest`

Run:

```bash
./check.sh
```

---

## Secret Scanning (Gitleaks)

YMC includes a tracked pre-commit hook at `.githooks/pre-commit` that runs `gitleaks` against staged changes.

One-time setup (inside this repo):

```bash
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit
```

Install `gitleaks`:

Ubuntu/Debian:

```bash
sudo apt-get update && sudo apt-get install -y gitleaks
```

macOS:

```bash
brew install gitleaks
```

Verify:

```bash
gitleaks version
git config --get core.hooksPath
```

Manual scans:

```bash
gitleaks detect --source . --config .gitleaks.toml --redact --verbose
gitleaks protect --staged --config .gitleaks.toml --redact --verbose
```

---

## Extending YMC

### Add a new framework profile

1. Create `profiles/<framework>.yaml`.
2. Map `check_id` values to framework control IDs.
3. Run `python main.py --list-profiles` to confirm it is discoverable.

### Add a new check

1. Add a new module under the relevant folder in `checks/windows/`.
2. Register function(s) with `@register_check("XX-000", ...)`.
3. Add the check ID to one or more `profiles/*.yaml`.
4. Run `python -m pytest -q` and `./check.sh`.

### Add a reporter

1. Create `reporters/<new_reporter>.py` inheriting from `BaseReporter`.
2. Implement `generate()`.
3. Wire selection into `main.py` format handling.

---

## Roadmap

- [ ] Linux/RHEL checks via SSH
- [ ] Cloud checks (AWS/Azure)
- [ ] PDF output
- [ ] CSV/Excel export for GRC import
- [ ] Drift/baseline comparison mode
- [ ] Automated remediation integration

---

## License

MIT
