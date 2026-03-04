#!/usr/bin/env bash
set -euo pipefail

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required for package install" >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y \
  software-properties-common \
  curl \
  git \
  build-essential \
  python3.13 \
  python3.13-venv \
  python3-pip

if [ ! -d .venv ]; then
  python3.13 -m venv .venv
fi

source .venv/bin/activate
python -m pip install --upgrade pip wheel setuptools

if [ -f requirements.txt ]; then
  python -m pip install -r requirements.txt
fi

python -m pip install --upgrade ruff pytest bandit pip-audit

cat > .envrc.example <<'ENVEOF'
# Optional defaults for local runs in WSL
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export COLLECTOR_NO_COLOR=true
export COLLECTOR_NO_BANNER=true
# export COLLECTOR_OUTPUT_DIR=./out
ENVEOF

echo ""
echo "Bootstrap complete."
echo "Next steps:"
echo "  source .venv/bin/activate"
echo "  ruff check ."
echo "  pytest"
