# Installation (v1.4.0-dev) 🛠️

## Prerequisites 📋
- Debian/Ubuntu-based system with `apt` (primary); dnf/pacman are best-effort for some actions
- Root privileges (or `sudo`)
- Basic utilities: `curl`, `wget`, `bash`
- Behind a proxy? Export `http_proxy`/`https_proxy` so `apt-get update` succeeds.

## Package support matrix 🧾

| Feature area | apt (Debian/Ubuntu) | dnf (Fedora/RHEL) | pacman (Arch) |
| --- | --- | --- | --- |
| System update/upgrade | yes | yes | yes |
| Apt sources/proxy/unattended upgrades | yes | no | no |
| Speedtest repo helper | yes | no | no |
| Netmaker/CrowdSec repo installers | yes | no | no |
| Docker install + compose plugin | yes | yes (best-effort) | yes (best-effort) |
| Essentials bundle | yes | best-effort | best-effort |
| UFW/Fail2ban/ClamAV installs | yes | best-effort | best-effort |
| WireGuard installs | yes | best-effort | best-effort |
| needrestart summary | yes | no | no |

## Feature notes 🧾
- Docker menu includes quick stop/remove helpers for containers and images.
- Maintenance includes a backup routine (etc + config).
- Containers menu includes Arcane (installer/compose) and Pangolin (native installer).
- Containers menu warns when `/var/run/docker.sock` is mounted in a container.
- AI tools include Gemini CLI, OpenAI Codex, Gemini API key export, Claude Code, and Node.js v22 check/install helpers.
- System update menu includes a package install prompt for adding software via the package manager.

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
Pin a specific version:
```bash
NTX_VERSION=v1.3.2 wget -qO ./i https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main/install_ntxmenu.sh && chmod +x ./i && sudo ./i
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

## Logs 🧾
- Main log: `/var/log/ntx-menu.log`
- Error log: `/var/log/ntx-utility.log`
- Backups: `BACKUP_COMPRESS=gzip|zstd` and `BACKUP_KEEP=<count>`
