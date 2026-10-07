#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$ROOT/scripts/bootstrap_kali.sh"
"$ROOT/scripts/install_reconforge.sh"
printf "\nReconForge is installed. Run: reconforge\n"
