# Installation

## Prerequisites
- Debian/Ubuntu-based system with `apt`
- Root privileges (or `sudo`)
- Basic utilities: `curl`, `wget`, `bash`

## Install from source
```bash
git clone https://github.com/ntx007/ntx-linux-utility-menu.git
cd ntx-linux-utility-menu
chmod +x ntx-utility-menu.sh
```

## Quick download (one-liner)
Review the script before running.
```bash
curl -fsSL -o ntx-utility-menu.sh https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/refs/heads/main/ntx-utility-menu.sh
sudo bash ntx-utility-menu.sh
```

## Optional: install to PATH
```bash
sudo mv ntx-utility-menu.sh /usr/local/bin/ntx-utility-menu
```

## Self-update
- In the main menu, press `u` to download the latest script from `https://ntx-menu.re-vent.de` (GitHub main).
- If `realpath`/`readlink -f` are unavailable and you launch via `$PATH`, run with the full path so the updater replaces the installed file instead of writing to the current directory.
