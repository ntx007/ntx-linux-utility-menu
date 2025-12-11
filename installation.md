# Installation

## Prerequisites
- Debian/Ubuntu-based system with `apt`
- Root privileges (or `sudo`)
- Basic utilities: `curl`, `wget`, `bash`
- If you sit behind a proxy, export `http_proxy`/`https_proxy` so `apt-get update` can succeed.

## Install from source
```bash
git clone https://github.com/ntx007/ntx-linux-utility-menu.git
cd ntx-linux-utility-menu
chmod +x ntx-utility-menu.sh ntxmenu
```

## Quick download (one-liner)
Review the script before running.
```bash
curl -fsSL -o ntx-utility-menu.sh https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/refs/heads/main/ntx-utility-menu.sh
sudo bash ntx-utility-menu.sh
```

## Install to PATH
Use the installer to copy both the wrapper and script:
```bash
sudo ./install_ntxmenu.sh
```
One-liner install to PATH:
```bash
wget -qO ./i https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main/install_ntxmenu.sh && chmod +x ./i && sudo ./i
```
If `/usr/local/bin` is not in your PATH, the installer will add a profile snippet and symlink to `/usr/bin` when possible; otherwise, add it manually (e.g., `export PATH=/usr/local/bin:$PATH`) or re-login.
Or do it manually:
```bash
sudo mv ntxmenu /usr/local/bin/ntxmenu
sudo mv ntx-utility-menu.sh /usr/local/bin/ntx-utility-menu
```

## Self-update
- In the main menu, press `u` to download the latest script from GitHub main (`https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main/ntx-utility-menu.sh`).
- If `realpath`/`readlink -f` are unavailable and you launch via `$PATH`, run with the full path so the updater replaces the installed file instead of writing to the current directory.
