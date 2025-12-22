# Installation 🛠️

## Prerequisites 📋
- Debian/Ubuntu-based system with `apt`
- Root privileges (or `sudo`)
- Basic utilities: `curl`, `wget`, `bash`
- Behind a proxy? Export `http_proxy`/`https_proxy` so `apt-get update` succeeds.

## From source 🧱
```bash
git clone https://github.com/ntx007/ntx-linux-utility-menu.git
cd ntx-linux-utility-menu
chmod +x ntx-utility-menu.sh ntxmenu
```

## Quick download ⚡
Review the script before running.
```bash
curl -fsSL -o ntx-utility-menu.sh https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/refs/heads/main/ntx-utility-menu.sh
sudo bash ntx-utility-menu.sh
```

## Install to PATH 🚀
- One-liner:
```bash
wget -qO ./i https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main/install_ntxmenu.sh && chmod +x ./i && sudo ./i
```
- Bundled installer:
```bash
sudo ./install_ntxmenu.sh
```
- Manual copy:
```bash
sudo mv ntxmenu /usr/local/bin/ntxmenu
sudo mv ntx-utility-menu.sh /usr/local/bin/ntx-utility-menu
```

If `/usr/local/bin` is not in your PATH, the installer will add a profile snippet and, when possible, a symlink in `/usr/bin`. Otherwise add it manually (e.g., `export PATH=/usr/local/bin:$PATH`) or re-login.

## Self-update 🔄
- In the menu, press `u` to download the latest script from GitHub main.
- If `realpath`/`readlink -f` are unavailable and you launch via `$PATH`, run with the full path so the updater replaces the installed file instead of writing to the current directory.
