#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${ROOT_DIR}/tools/testssl.sh"
REPO="https://github.com/testssl/testssl.sh.git"
mkdir -p "${ROOT_DIR}/tools"
if [[ -d "${TARGET}/.git" ]]; then
  echo "testssl.sh already installed at ${TARGET}"
  echo "Update manually with: git -C \"${TARGET}\" pull --ff-only"
else
  git clone --depth 1 "${REPO}" "${TARGET}"
fi
chmod +x "${TARGET}/testssl.sh"
echo "Installed: ${TARGET}/testssl.sh"
