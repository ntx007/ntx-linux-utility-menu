#!/bin/bash

# Simple installer to place ntxmenu + ntx-utility-menu.sh into /usr/local/bin
set -euo pipefail

TARGET_DIR="${TARGET_DIR:-/usr/local/bin}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root (e.g., sudo $0)."
    exit 1
fi

if [[ ! -f "${SCRIPT_DIR}/ntx-utility-menu.sh" || ! -f "${SCRIPT_DIR}/ntxmenu" ]]; then
    echo "ntx-utility-menu.sh or ntxmenu not found in ${SCRIPT_DIR}"
    exit 1
fi

install -m 0755 "${SCRIPT_DIR}/ntx-utility-menu.sh" "${TARGET_DIR}/ntx-utility-menu"
install -m 0755 "${SCRIPT_DIR}/ntxmenu" "${TARGET_DIR}/ntxmenu"

echo "Installed:"
echo "  ${TARGET_DIR}/ntx-utility-menu"
echo "  ${TARGET_DIR}/ntxmenu (wrapper)"
echo
echo "Run with: sudo ntxmenu"
