#!/usr/bin/env bash
set -euo pipefail
sudo apt update
sudo apt install -y python3-venv python3-pip git nmap nikto wapiti sqlmap ffuf feroxbuster seclists nuclei
if command -v nmap >/dev/null 2>&1; then
  sudo nmap --script-updatedb >/dev/null 2>&1 || true
fi
if [ ! -x "$(dirname "$0")/../tools/testssl.sh/testssl.sh" ]; then
  "$(dirname "$0")/install_testssl.sh"
fi
printf "\nToolchain bootstrap complete.\n"
printf "Verify: command -v nmap nikto wapiti nuclei sqlmap ffuf feroxbuster\n"
