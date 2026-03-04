# WSL2 Migration Handoff (Linux-First Workflow)

Date: 2026-03-03
Project: `compliance-collector`

## Why this handoff exists
Recent friction came from Windows-specific execution constraints (launcher alias issues, firewall outbound blocks, temp/registry write restrictions in some shells). Moving to WSL2 should remove most of that and make Python tooling predictable.

## One-time WSL2 bootstrap
From Ubuntu in WSL2:

```bash
cd /mnt/c/Projects/compliance-collector
bash scripts/bootstrap_wsl.sh
```

That script:
1. Installs Python 3.13, venv tooling, pip tooling, and build basics.
2. Creates `.venv` in repo.
3. Installs project deps + dev tools (`ruff`, `pytest`, `bandit`, `pip-audit`).
4. Creates `.envrc.example` with sane environment defaults.

## Daily workflow in Linux

```bash
cd /mnt/c/Projects/compliance-collector
source .venv/bin/activate
ruff check .
pytest
```

Optional security pass:

```bash
bandit -r . -x .venv,scan_*,out,out_localhost
pip-audit
```

## CLI smoke tests

```bash
python main.py --list-profiles
python main.py --list-configs
python main.py --help
```

## Notes for future Codex sessions
1. Use Linux Python directly (`python`, `python -m pip`); do not rely on Windows `py.exe`.
2. Keep output directories in-repo during debugging:
   - `--output-dir ./out`
3. Prefer UTF-8 locale in shell:
   - `export LANG=C.UTF-8`
   - `export LC_ALL=C.UTF-8`
4. If WinRM connectivity tests are needed from WSL, ensure Windows-side firewall/policy still allows outbound from WSL virtual NIC.

## Suggested first gate after migration
Run this exact sequence and fix failures before feature work:

```bash
source .venv/bin/activate
ruff check .
pytest -q
bandit -r . -x .venv,scan_*,out,out_localhost
pip-audit
```

## Known migration caveats
1. Paths in docs/examples may be Windows-style; convert to Linux paths where needed.
2. If you keep repo on `/mnt/c`, filesystem performance is lower than native ext4. If test runtime feels slow, clone into WSL home (e.g., `~/src/compliance-collector`).
3. WinRM target reachability can differ between Windows host and WSL network namespace; verify with target-specific smoke tests.

## Done criteria in Linux
1. `ruff` clean.
2. `pytest` green.
3. `bandit` reviewed (no unresolved high severity).
4. `pip-audit` reviewed (no unresolved criticals).
5. `python main.py --list-profiles` and one local dry-run command succeed.
