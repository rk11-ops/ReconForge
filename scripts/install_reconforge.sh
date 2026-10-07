#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements.txt"
"$ROOT/.venv/bin/python" -m pip install -e "$ROOT"
if command -v sudo >/dev/null 2>&1; then
  sudo ln -sf "$ROOT/.venv/bin/reconforge" /usr/local/bin/reconforge
  echo "Installed: /usr/local/bin/reconforge"
else
  echo "Installed in: $ROOT/.venv/bin/reconforge"
fi
