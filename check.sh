#!/usr/bin/env bash
set -euo pipefail

# =========================
# Config (override via env)
# =========================
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"

# Bandit policy: fail on MEDIUM+ (treat as P2 or higher)
BANDIT_MIN_SEVERITY="${BANDIT_MIN_SEVERITY:-medium}"      # low|medium|high
BANDIT_MIN_CONFIDENCE="${BANDIT_MIN_CONFIDENCE:-medium}"  # low|medium|high

# pip-audit policy: fail if any vulnerability is found
PIP_AUDIT_FAIL_ON_VULNS="${PIP_AUDIT_FAIL_ON_VULNS:-1}"    # 1=yes, 0=no

# Ruff policy
RUFF_AUTO_FIX="${RUFF_AUTO_FIX:-1}"                        # 1=yes, 0=no

# =========================
# Step: repo root + venv
# =========================
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "ERROR: $PYTHON_BIN not found."
  exit 2
fi

if [[ ! -d "$VENV_DIR" ]]; then
  echo "[setup] Creating venv at $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "[setup] Upgrading pip + installing tooling"
python -m pip install -U pip >/dev/null
python -m pip install -U ruff bandit pip-audit pytest >/dev/null

# =========================
# Step: format (auto)
# =========================
echo "[format] ruff format"
ruff format .

# =========================
# Step: lint (auto-fix then enforce)
# =========================
if [[ "$RUFF_AUTO_FIX" == "1" ]]; then
  echo "[lint] ruff check (with auto-fix)"
  # Auto-fix what Ruff can. We ignore the return code on this pass because
  # the enforcement pass below is authoritative.
  ruff check . --fix || true
fi

echo "[lint] ruff check (enforce)"
ruff check .

# =========================
# Step: security scan (Bandit)
# =========================
echo "[security] bandit (fail on ${BANDIT_MIN_SEVERITY}+ severity, ${BANDIT_MIN_CONFIDENCE}+ confidence)"
BANDIT_JSON="$(mktemp)"
bandit -r . \
  -x "./.venv,./.venv*,./venv,./.git,./__pycache__,./build,./dist" \
  -f json -o "$BANDIT_JSON" >/dev/null || true

python - <<PY
import json, sys

path = r"$BANDIT_JSON"
min_sev = "$BANDIT_MIN_SEVERITY".lower()
min_conf = "$BANDIT_MIN_CONFIDENCE".lower()

order = {"low": 1, "medium": 2, "high": 3}
min_sev_n = order.get(min_sev, 2)
min_conf_n = order.get(min_conf, 2)

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

results = data.get("results", [])
bad = []
for r in results:
    sev = (r.get("issue_severity") or "").lower()
    conf = (r.get("issue_confidence") or "").lower()
    if order.get(sev, 0) >= min_sev_n and order.get(conf, 0) >= min_conf_n:
        bad.append(r)

if bad:
    print(f"FAIL: Bandit found {len(bad)} issue(s) at severity>={min_sev} and confidence>={min_conf}.")
    for r in bad[:25]:
        print(f"- {r.get('filename')}:{r.get('line_number')} {r.get('test_id')} {r.get('issue_text')} "
              f"(sev={r.get('issue_severity')}, conf={r.get('issue_confidence')})")
    if len(bad) > 25:
        print(f"... plus {len(bad)-25} more.")
    sys.exit(10)

print("OK: Bandit policy passed")
PY

rm -f "$BANDIT_JSON"

# =========================
# Step: dependency audit (pip-audit)
# =========================
echo "[deps] pip-audit"
is_pip_audit_network_error() {
  grep -Eiq "NameResolutionError|ConnectionError|Failed to resolve|Temporary failure in name resolution|Max retries exceeded" <<<"$1"
}

set +e
AUDIT_OUTPUT="$(pip-audit 2>&1)"
AUDIT_RC=$?
set -e
if [[ "$AUDIT_RC" != "0" ]]; then
  echo "$AUDIT_OUTPUT"
fi

if [[ "$PIP_AUDIT_FAIL_ON_VULNS" == "1" && "$AUDIT_RC" != "0" ]]; then
  if is_pip_audit_network_error "$AUDIT_OUTPUT"; then
    echo "WARN: pip-audit could not reach vulnerability service; skipping enforced failure."
  else
    echo "FAIL: pip-audit reported vulnerabilities (treat as P1/P2)."
    exit 11
  fi
fi

for req in requirements.txt requirements-dev.txt; do
  if [[ -f "$req" ]]; then
    echo "[deps] pip-audit -r $req"
    set +e
    AUDIT_OUTPUT="$(pip-audit -r "$req" --no-deps --disable-pip 2>&1)"
    RC=$?
    set -e
    if [[ "$RC" != "0" ]]; then
      echo "$AUDIT_OUTPUT"
    fi
    if [[ "$PIP_AUDIT_FAIL_ON_VULNS" == "1" && "$RC" != "0" ]]; then
      if is_pip_audit_network_error "$AUDIT_OUTPUT"; then
        echo "WARN: pip-audit could not reach vulnerability service for $req; skipping enforced failure."
      else
        echo "FAIL: pip-audit found vulnerabilities in $req (treat as P1/P2)."
        exit 12
      fi
    fi
  fi
done

echo "OK: Dependency audit policy passed"

# =========================
# Step: tests
# =========================
if [[ -d "tests" || -f "pytest.ini" || -f "pyproject.toml" || -f "setup.cfg" ]]; then
  echo "[tests] pytest"
  set +e
  pytest -q
  PYTEST_RC=$?
  set -e
  if [[ "$PYTEST_RC" == "5" ]]; then
    echo "[tests] No tests collected; continuing."
  elif [[ "$PYTEST_RC" != "0" ]]; then
    echo "FAIL: pytest returned exit code $PYTEST_RC."
    exit "$PYTEST_RC"
  fi
else
  echo "[tests] No obvious test config found; skipping pytest."
fi

echo "OK: checks passed"
