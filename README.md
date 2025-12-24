# NTX Command Center 🚀

A portable, menu-driven Bash utility for common Linux admin tasks. Built for Debian/Ubuntu (and derivatives), it centralizes updates, diagnostics, networking tools, security hardening, and maintenance in a single interactive script.

- Current version: **v1.2.1-dev**.
- Self-update URL: `https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main/ntx-utility-menu.sh` (GitHub main). If `realpath`/`readlink -f` are unavailable and you launch via `$PATH`, run the script with its full path (e.g., `/usr/local/bin/ntx-utility-menu`) so the updater replaces the installed file instead of writing into the current directory.
- UI: grouped main menu (Core / Operations / Shortcuts) with header info (host, threads, RAM, IP) and update notice; language toggle `d` (en/de).

## Highlights ✨

- Interactive nested menu with shortcuts (Help, Status, Logs) and search via `/keyword`; language toggle `d` (en/de)
- Clean header with host/threads/RAM/IP + update notice, and a grouped main menu (Core / Operations / Shortcuts) for faster navigation
- Updates: unattended-upgrades enable/disable/status/run; reboot-if-needed flow; apt source hygiene (list/remove); version-aware self-update (pick release/rollback or dev); non-interactive `--run` actions; cadence warning and health checks; APT proxy toggle
- Networking: public IP with fallback, interfaces/routes/connections, DNS backups/restore (option to restart systemd-resolved), custom nameserver append/overwrite, ping/traceroute, top talkers, VLAN/Bond helpers, SSH key generator
- Security/remote: organized submenus (firewall, Fail2ban, SSH/access, WireGuard, agents, anti-malware, config backup); UFW with snapshots/revert, Fail2ban (summary/list/unban + tuning helper), auditd minimal rules, OpenSSH, Tailscale, Netmaker netclient, CrowdSec + firewall bouncer, WireGuard (client/server, QR, validate/diff, interface choice), SSH hardening and service start/stop/restart/enable/disable, rootkit check, ClamAV improved workflow, Proxmox SSH config updater (PermitRootLogin yes)
  - First-run checklist: install/enable Docker/Compose, SSH, UFW, and Fail2ban in one pass
- Tools/monitoring: essentials bundle (with mariadb-client-core) and dedicated submenu, nvm installer, node exporter, top CPU/mem, iostat summary, SMART checks (single/all disks), status dashboard, exportable status report (text/JSON with optional upload path) including container count/SMART health where available, service uptime + hardware overview
- Containers: Docker + Compose plugin install, service status/info, running/all containers, Compose health (ls/ps), hardening checks (privileged, root user, host network, sensitive mounts)
- Maintenance/info: cleanup, daily maintenance bundle (optional pre-update + log rotate + status report), log cleanup preset, kernel list/purge helper, /etc backup, disk usage, largest `/var` dirs, system info (os-release, neofetch, VM check, display adapters, uptime/hardware overview), GitHub link, Proxmox helpers (LXC + VM start/stop/restart, snapshots, backup/restore, ISO download, community scripts)
- Logging/backups: `/var/log/ntx-menu.log` with rotation/history; `/etc/resolv.conf` backups; config backup/restore with optional Docker Compose includes
- Modes: `DRY_RUN=true` to preview commands; `SAFE_MODE=true` to skip destructive actions

## Requirements 📋

- A Unix-like system with Bash or POSIX sh
- Basic shell utilities available on most Linux systems (curl, wget, ip, ifconfig or iproute2)
- Root (or sudo) is required for most actions; the script exits if not run as root

## Install 🛠️

Clone the repo:

```bash
git clone https://github.com/ntx007/ntx-linux-utility-menu.git
cd ntx-linux-utility-menu
```

Make the scripts executable:

```bash
chmod +x ntx-utility-menu.sh ntxmenu
```

Install to PATH (pick one):

- One-liner installer:
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

## Run ▶️

- Run from the project directory:

```bash
sudo ./ntx-utility-menu.sh
```

- If installed in PATH:

```bash
sudo ntx-utility-menu
```

### Download & run (one-liner) ⚡

You can quickly download the script and run it directly on a server using curl and bash. Always review scripts downloaded from the internet before running them.

```bash
curl -fsSL -o ntx-utility-menu.sh https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/refs/heads/main/ntx-utility-menu.sh
sudo bash ntx-utility-menu.sh
```

If you prefer to make it executable and run it from the current directory:

```bash
chmod +x ntx-utility-menu.sh
./ntx-utility-menu.sh
```

## Non-interactive usage 🤖

Run common actions without the menu:

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
```

Run `./ntx-utility-menu.sh --help` for the full list.

## Menu map (v1.2.1-dev) 🗺️

- **Core**
  - System update: upgrade flows, unattended-upgrades, apt source list/remove, APT health/update health, APT proxy toggle, version-aware self-update (release/dev/rollback)
  - DNS: backups/edit, Netcup presets (46.38.225.230 + 46.38.252.230 + 1.1.1.1), Cloudflare/Google IPv4+IPv6, restore last backup, add custom nameserver (append or overwrite)
  - Network/IP: public IP (fallback), interfaces, routes, connections, ping common endpoints, traceroute, top talkers (TCP), VLAN/bond helpers, SSH key generator
  - Speedtest/benchmarks: Speedtest install/update/run, repo/key removal, YABS + presets
  - Security/remote: firewall, Fail2ban, SSH/access, WireGuard, agents (CrowdSec/Netmaker/Tailscale), anti-malware, config backup/restore

- **Operations**
  - Tools/env: essentials bundle (sudo, nano, curl, net-tools, iproute2, unzip, python3-pip, gcc/python3-dev, mariadb-client-core, psutil via pip, gdown, dos2unix, glances, tmux, zsh, mc, npm), ibramenu, QEMU guest agent, nvm installer, MariaDB server (host install, systemd), Node/npm version check
  - Containers: Docker + Compose plugin, status/info, running/all containers, Compose health, hardening checks (privileged/root/host network/sensitive mounts), prune/scan helpers, compose project manager, installers for Portainer, Nginx Proxy Manager, Traefik, Pi-hole, Pi-hole+Unbound, Nextcloud AIO, Tactical RMM, Hemmelig.app
  - Monitoring: node exporter, top CPU/mem, iostat, SMART (single/all disks), status dashboard, export report (text/JSON)
  - System info: `/etc/os-release`, neofetch, memory info, VM check, display adapters, GitHub link, service uptime summary, hardware overview
  - Maintenance/disks: cleanup, log cleanup preset, disks, largest `/var`, maintenance bundle (update + cleanup + log rotate + status report), log integrity, kernel list/purge helper, /etc backup
  - Proxmox: list LXC, enter shell (lists VMIDs first), start/stop/restart, storage status, snapshots (create/list/rollback), backup/restore (vzdump/pct restore), resource tuning, services/cluster status, recent tasks, backup listing, community post-install/templates scripts, Proxmox SSH config updater (PermitRootLogin yes), qm VM helpers (list/start/stop/restart/snapshots/backup/restore) and ISO downloader
  - Users/time: create sudo user, change user password, time sync info, chrony install
- System control: reboot, power down (SAFE_MODE-aware)

- **Shortcuts**
  - `h` Help/About, `s` Status dashboard, `l` Tail log, `c` Config/env
  - `u` Self-update, `d` Language (en/de), `i` Install to PATH, `q` Quit

Quick one-liner install to PATH:
```bash
wget -qO ./i https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main/install_ntxmenu.sh && chmod +x ./i && sudo ./i
```
If `/usr/local/bin` is not in your PATH, the installer will add a profile snippet and also symlink to `/usr/bin` when possible; otherwise, add it manually (e.g., `export PATH=/usr/local/bin:$PATH`) or re-login.

## Modes & shortcuts ⌨️

- `DRY_RUN=true ./ntx-utility-menu.sh`: print commands instead of executing them.
- `SAFE_MODE=true ./ntx-utility-menu.sh`: skip destructive actions (cleanup, reboot, powerdown, apt source removal).
- Shortcuts in the main menu: `h` Help/About, `s` Status dashboard, `l` Tail log, `c` Config/env, `q` Quit.

Note on service status: the dashboard queries systemd unit names like `ssh`, `docker`, etc. If a service uses a non-standard unit name, it may show as “not installed.” Adjust the unit names in `show_service_status` if your distro uses different service names.

Search tip: in the main menu, type `/keyword` (e.g., `/docker`, `/dns`) to jump directly to a matching section.

## Known behaviors ⚠️

- Self-update: if `realpath`/`readlink -f` are unavailable and you launch via `$PATH`, run the script with its full path so the updater replaces the installed file instead of writing into the current directory.
- Service status: uses standard systemd unit names (e.g., `ssh`, `docker`); non-standard names may show as “not installed.”
- Pending updates: uses `apt-get -s upgrade | grep '^Inst'` and can undercount on localized systems.
- WireGuard: enable/disable assumes `/etc/wireguard/wg0.conf` exists.
- WireGuard QR: requires `qrencode`; Docker Compose health assumes the Docker Compose plugin is available.
- ClamAV: `freshclam` may fail if the daemon holds the DB lock; stop/reload `clamav-freshclam` before updating if needed.
- SMART: virtio disks may need `-d scsi`; the menu tries this fallback but atypical storage may require manual `smartctl -a -d <type> /dev/<disk>`.
- Rootkit check: installs `binutils` to provide `strings`; if `strings` is still missing, install binutils manually.
- Offline/proxy: `apt-get update` must succeed for upgrades; if blocked, set `http_proxy/https_proxy` or skip update steps (they will now stop early with a hint).
- Minimal envs: Inode view may be skipped if `df -i` is unsupported; IP listing falls back to `ip addr` or `ifconfig` if `ip` is absent.
- MariaDB server install assumes a systemd host (not containerized); enable/start may fail inside containers.
- Speedtest repo helper is pinned to Ubuntu jammy; on other releases it writes jammy entries, so add a distro-appropriate repo if needed.

## Troubleshooting 🛠️
- APT blocked by proxy: set `http_proxy`/`https_proxy` and re-run `apt-get update`; use the APT proxy toggle in System update.
- Docker Compose missing: install via Containers → option 1 (official script) or ensure the compose plugin is available.
- `qrencode` missing: install `qrencode` for WireGuard QR rendering.
- `ntxmenu` not found: ensure `/usr/local/bin` is in PATH or re-run the installer (`install_ntxmenu.sh`); a symlink to `/usr/bin` is created when possible.
- SMART permissions: some environments require `sudo smartctl` or `--device` hints (e.g., `-d scsi` for virtio); the menu uses best-effort defaults but may need manual flags.
- systemd-resolved: after DNS changes, use the DNS menu’s “restore backup + restart systemd-resolved” if name resolution breaks; on systems without systemd-resolved, it will skip the restart.

## Quick start 🏁

- Run as root on Debian/Ubuntu (or derivatives). If testing, start with `DRY_RUN=true` or `SAFE_MODE=true`.
- Skim the config block (log/backup paths, DNS presets, service unit names) before first use.
- Open `Help/About` (`h`) for paths, modes, and shortcuts; tail the log (`l`) if something looks off.
- Use the status dashboard (`s`) to check services (SSH, UFW, Fail2ban, Tailscale, Netmaker, CrowdSec, Docker), pending upgrades, kernel vs. running versions, public/private IPs, and CPU/mem/disk/inode snapshots.
- Before adding repos, review custom sources in **System update → list/remove apt sources**.
- For VPN/remote, use the Security menu: Tailscale, Netmaker netclient, CrowdSec + bouncer, and WireGuard (client/server installs).

## Customization 🧩

- Open `ntx-utility-menu.sh` in your editor to change menu labels or add/remove functions.
- Keep a backup copy before changing behavior that performs destructive actions (e.g., disk operations, package removal).

Suggested quick edits:

- Adjust the config section to your defaults (log path, backup dir, DNS presets, service units).
- Factor repeated code into functions and call them from the menu dispatcher.
- Optional config override: create `/etc/ntx-menu.conf` (or `./ntx-menu.conf`) to set variables like `LOG_FILE`, `BACKUP_DIR`, `REPORT_DIR`, and service unit names without editing the script.

## Contributing 🤝

Contributions are welcome. Small suggestions:

- Open an issue to propose features or report bugs.
- Submit a pull request with focused changes and a short description.

When contributing, include:

- What you changed and why
- How to reproduce or test the change

## Security & Safety 🔐

- The script can perform system-level actions. Review the code before running, especially if you obtained it from an untrusted source.
- Use a non-root account where possible and elevate privileges only for specific actions (via `sudo`).

## License 📄

This project is licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0).

You are free to share and adapt the material for any purpose, even commercially, provided you give appropriate credit, provide a link to the license, and indicate if changes were made. See the full license text in the `LICENSE` file or at https://creativecommons.org/licenses/by/4.0/legalcode.

SPDX-License-Identifier: CC-BY-4.0

## Author 👤

ntx007 — maintained by the repository owner.
