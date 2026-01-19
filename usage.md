# Usage 📘

## Run the menu ▶️
From the project directory:
```bash
sudo ./ntx-utility-menu.sh
```
If installed to PATH:
```bash
sudo ntxmenu
```

Quick install to PATH (one-liner):
```bash
wget -qO ./i https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main/install_ntxmenu.sh && chmod +x ./i && sudo ./i
```
If `/usr/local/bin` is not in your PATH, the installer will add a profile snippet and symlink to `/usr/bin` when possible; otherwise, add it manually (e.g., `export PATH=/usr/local/bin:$PATH`) or re-login.

## Non-interactive actions 🤖
```bash
sudo ./ntx-utility-menu.sh --run update_all
sudo ./ntx-utility-menu.sh --run maintenance_bundle
sudo ./ntx-utility-menu.sh --run status_report
sudo ./ntx-utility-menu.sh --run status_report_json
sudo ./ntx-utility-menu.sh --run ssh_audit
sudo ./ntx-utility-menu.sh --run docker_compose_health
sudo ./ntx-utility-menu.sh --run wireguard_qr
sudo ./ntx-utility-menu.sh --run apt_health
sudo ./ntx-utility-menu.sh --run update_health
sudo ./ntx-utility-menu.sh --run clamav_scan
sudo ./ntx-utility-menu.sh --run ssh_start|ssh_stop|ssh_restart|ssh_enable|ssh_disable
sudo ./ntx-utility-menu.sh --run change_password
sudo ./ntx-utility-menu.sh --run health_brief
sudo ./ntx-utility-menu.sh --run cmatrix
sudo ./ntx-utility-menu.sh --run config_json
```
Use `--help` for the supported list.

If installed in PATH, you can also use the wrapper:

```bash
sudo ntxmenu --run update_all
sudo ntxmenu --run health_brief
sudo ntxmenu --help
```

## Modes & shortcuts ⌨️
- `DRY_RUN=true ./ntx-utility-menu.sh`: preview commands.
- `SAFE_MODE=true ./ntx-utility-menu.sh`: skip destructive actions.
- `CONFIRM=false ./ntx-utility-menu.sh`: skip confirmation prompts.
- Shortcuts: `h` Help/About, `s` Status dashboard, `l` Tail logs, `c` Config/env, `u` Self-update, `i` Install to PATH, `m` launches cmatrix, `q` Quit.
- Language toggle: `d` switches between English and German labels.
- Header now shows distro, OS version, and detected package manager.

## Logs 🧾
- Main log: `/var/log/ntx-menu.log`
- Error log: `/var/log/ntx-utility.log` (captures failures with line/command)
- Backups: `BACKUP_COMPRESS=gzip|zstd` and `BACKUP_KEEP=<count>`

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

## Menu at a glance (v1.4.1-dev) 🗺️
- Core: updates (incl. unattended, apt lock wait, apt source validator, package install prompt), do-release-upgrade, apt source hygiene + proxy toggle, APT/update health, self-update; DNS presets/backups + custom nameserver (append/overwrite) and restore+restart systemd-resolved; network views (incl. top talkers), MTR and nmap quick scans, VLAN/bond helpers, SSH key helper; Speedtest/YABS; security submenus (firewall, Fail2ban, SSH w/ service controls incl. enable/disable, WireGuard, agents, anti-malware, config backup, first-run checklist for Docker/Compose/SSH/UFW/Fail2ban, SSH cipher/KEX/MAC audit).
- Operations: tools/essentials/nvm (includes mariadb-client-core), MariaDB server (host install, systemd), Node/npm version check, containers (Docker/Compose, quick stop/remove helpers, hardening checks, prune/scan/update images/compose manager, container log tail/follow, app installers incl. Nginx Proxy Manager, Traefik, Pangolin, and Arcane), monitoring (status dashboard, reports, node exporter, SMART single/all disks, container count/SMART in reports, headless `health_brief`), system info (incl. service uptime and hardware overview), maintenance (cleanup/bundle/log cleanup/log integrity/kernel list/purge, backup routine, /etc backup, config template writer, custom journal vacuum, needrestart summary), Proxmox helpers (submenus for LXC, VMs, backups/storage/tasks, tools/scripts covering list/enter/start/stop/restart/snapshots/backup/restore/rotate, storage/resources/status, tasks/backups view, QM VM helpers and ISO downloader, community post-installtemplates scripts), users/time (create sudo user, change user password, time sync, chrony), system control, AI tools (check Node.js v22, install Node.js v22, install Gemini CLI, install OpenAI Codex, set Gemini API key, install Claude Code).
- Shortcuts: `h` help, `s` dashboard, `l` logs, `c` config/env, `u` self-update, `d` language, `i` install to PATH, `q` quit.

## Known behaviors & caveats ⚠️
- Self-update uses `https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main/ntx-utility-menu.sh` (GitHub main); use full path if `realpath`/`readlink -f` are absent to avoid writing to the current directory.
- Service status uses standard systemd unit names; adjust unit variables if your distro differs.
- Pending updates count may undercount on localized systems.
- Distro support: Debian/Ubuntu are primary; dnf/pacman flows are best-effort and some apt-only features are unavailable.
- Docker: the Containers menu warns when `/var/run/docker.sock` is mounted; consider a socket proxy.
- WireGuard enable/disable assumes `/etc/wireguard/wg0.conf` exists; QR requires `qrencode`.
- ClamAV `freshclam` can fail if the daemon holds the DB lock; stop/reload `clamav-freshclam` before updating if needed.
- Display adapters view now auto-installs `lshw` if missing; monitoring functions (node exporter/top/iostat/SMART) are bundled in the current release.
- SMART checks: virtio disks may need `-d scsi`; the menu tries this fallback but unusual storage can require a manual `smartctl -a -d <type> /dev/<disk>`.
- Rootkit check installs `binutils` so `strings` is available; install binutils manually if it’s still missing.
- Offline/proxy: `apt-get update` must succeed for upgrades; if blocked, set `http_proxy/https_proxy` or skip update steps (they will stop early with a hint).
- Minimal envs: Inode view may be skipped if `df -i` is unsupported; IP listing falls back to `ip addr` or `ifconfig` if `ip` is absent.
- MariaDB server install assumes a systemd host (not containerized); enable/start may fail inside containers.
- Speedtest repo helper is pinned to Ubuntu jammy; on other releases it writes jammy entries, so add a distro-appropriate repo if needed.
- Public IP lookup in the header uses OpenDNS with a short timeout; set `HEADER_PUBLIC_TIMEOUT` to adjust or expect `unknown` when offline.
