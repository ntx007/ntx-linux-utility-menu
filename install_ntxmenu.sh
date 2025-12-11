#!/bin/bash

# Simple installer to place ntxmenu + ntx-utility-menu.sh into /usr/local/bin.
# If scripts are missing locally, they are downloaded from GitHub main.
set -euo pipefail

TARGET_DIR="${TARGET_DIR:-/usr/local/bin}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL_BASE="https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main"

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root (e.g., sudo $0)."
    exit 1
fi

fetch_if_missing() {
    local src_path="$1"
    local url="$2"
    if [[ -f "$src_path" ]]; then
        return 0
    fi
    echo "Fetching $(basename "$src_path") from $url..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$src_path"
    else
        wget -qO "$src_path" "$url"
    fi
}

fetch_if_missing "${SCRIPT_DIR}/ntx-utility-menu.sh" "${URL_BASE}/ntx-utility-menu.sh"
fetch_if_missing "${SCRIPT_DIR}/ntxmenu" "${URL_BASE}/ntxmenu"

if [[ ! -f "${SCRIPT_DIR}/ntx-utility-menu.sh" || ! -f "${SCRIPT_DIR}/ntxmenu" ]]; then
    echo "ntx-utility-menu.sh or ntxmenu not found and could not be downloaded."
    exit 1
fi

chmod +x "${SCRIPT_DIR}/ntx-utility-menu.sh" "${SCRIPT_DIR}/ntxmenu"

install -m 0755 "${SCRIPT_DIR}/ntx-utility-menu.sh" "${TARGET_DIR}/ntx-utility-menu"
install -m 0755 "${SCRIPT_DIR}/ntxmenu" "${TARGET_DIR}/ntxmenu"

echo "Installed:"
echo "  ${TARGET_DIR}/ntx-utility-menu"
echo "  ${TARGET_DIR}/ntxmenu (wrapper)"
echo
echo "Run with: sudo ntxmenu"
