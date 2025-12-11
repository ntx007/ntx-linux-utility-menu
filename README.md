# NTX Command Center

A portable, menu-driven Bash utility for common Linux admin tasks. Built for Debian/Ubuntu (and derivatives), it centralizes updates, diagnostics, networking tools, security hardening, and maintenance in a single interactive script.

- Current version: **v0.6-dev** (main branch).
- Self-update URL: `https://ntx-menu.re-vent.de` serves the latest script from GitHub main. If `realpath`/`readlink -f` are unavailable and you launch via `$PATH`, run the script with its full path (e.g., `/usr/local/bin/ntx-utility-menu`) so the updater replaces the installed file instead of writing into the current directory.

## Highlights (v0.6-dev)

- Interactive nested menu with shortcuts (Help, Status, Logs) and search via `/keyword`; language toggle `d` (en/de)
- Updates: unattended-upgrades enable/disable/status/run; reboot-if-needed flow; apt source hygiene (list/remove); version-aware self-update (pick release/rollback or dev); non-interactive `--run` actions; cadence warning and health checks
- Networking: public IP with fallback, interfaces/routes/connections, DNS backups/restore, ping common endpoints, traceroute
- Security/remote: organized submenus (firewall, Fail2ban, SSH/access, WireGuard, agents, anti-malware, config backup); UFW with snapshots/revert, Fail2ban (summary/list/unban), OpenSSH, Tailscale, Netmaker netclient, CrowdSec + firewall bouncer, WireGuard (client/server, QR, validate/diff, interface choice), SSH hardening, rootkit check, ClamAV improved workflow, Proxmox SSH config updater (PermitRootLogin yes)
- Tools/monitoring: essentials bundle (and dedicated submenu), node exporter, top CPU/mem, iostat summary, SMART checks, status dashboard, exportable status report (text/JSON with optional upload path)
- Containers: Docker + Compose plugin install, service status/info, running/all containers, Compose health (ls/ps), hardening checks (privileged, root user, host network, sensitive mounts)
- Maintenance/info: cleanup, daily maintenance bundle (optional pre-update + log rotate + status report), disk usage, largest `/var` dirs, system info (os-release, neofetch, VM check, display adapters), GitHub link, Proxmox helpers (pct list/enter)
- Logging/backups: `/var/log/ntx-menu.log` with rotation/history; `/etc/resolv.conf` backups; config backup/restore with optional Docker Compose includes
- Modes: `DRY_RUN=true` to preview commands; `SAFE_MODE=true` to skip destructive actions

## Requirements

- A Unix-like system with Bash or POSIX sh
- Basic shell utilities available on most Linux systems (curl, wget, ip, ifconfig or iproute2)
- Root (or sudo) is required for most actions; the script exits if not run as root

## Installation

1. Clone or download this repository:

```bash
git clone https://github.com/ntx007/ntx-linux-utility-menu.git
cd ntx-linux-utility-menu
```

2. Make the script executable:

```bash
chmod +x ntx-utility-menu.sh
```

3. (Optional) Move it to a directory in your PATH for global usage:

```bash
sudo mv ntx-utility-menu.sh /usr/local/bin/ntx-utility-menu
```

## Usage

- Run from the project directory:

```bash
sudo ./ntx-utility-menu.sh
```

- Or, if installed in your PATH:

```bash
sudo ntx-utility-menu
```

The script shows a numbered interactive menu. Enter the number of the action you want to run and press Enter.

### Download & run (one-liner)

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

## Non-interactive usage

You can run common actions without the menu:

```bash
sudo ./ntx-utility-menu.sh --run update_all
sudo ./ntx-utility-menu.sh --run maintenance_bundle
sudo ./ntx-utility-menu.sh --run status_report
sudo ./ntx-utility-menu.sh --run ssh_audit
sudo ./ntx-utility-menu.sh --run docker_compose_health
sudo ./ntx-utility-menu.sh --run wireguard_qr
```

Run `./ntx-utility-menu.sh --help` for the full list.

## Menu map (v0.6-dev)

- **System update**: standard upgrade, reboot-if-needed, unattended-upgrades (enable/disable/status/run), list/remove custom apt sources, APT health/update health checks, version-aware self-update (choose release/dev/rollback)
- **DNS**: view/edit with backups, preset DNS choices (Netcup 46.38.225.230 + 46.38.252.230 + 1.1.1.1), restore last backup, append/overwrite IPv4 Cloudflare/Google and IPv6 Cloudflare/Google
- **Network/IP**: public IP (fallback), interfaces, routes, connections, ping common endpoints, traceroute
- **Speedtest/benchmarks**: Speedtest install/update/run, repo/key removal, YABS, YABS preset submenu (all/disk/network/system)
- **Security/remote**: organized submenus (firewall, Fail2ban, SSH/access, WireGuard, agents, anti-malware, config backup); UFW snapshots/presets, Fail2ban summary/reload/list/unban, OpenSSH, Tailscale, Netmaker netclient (install/remove repo), CrowdSec + firewall bouncer, WireGuard (client/server, QR, validate/diff, interface choice), SSH hardening check, failed logins, rootkit check, ClamAV install + quick scan, Google Authenticator install, config backup/restore
- **Tools/env**: essentials (sudo, nano, curl, net-tools, iproute2, unzip, python3-pip, gcc/python3-dev, psutil via pip, gdown, dos2unix, glances, tmux, zsh, mc, npm) with a dedicated submenu, plus ibramenu and QEMU guest agent
- **Containers**: Docker + Compose plugin, service status, short info, running containers, list all containers, Docker Compose health, Docker rootless check, list privileged containers, list containers with sensitive mounts, containers running as root, containers using host network
- **Monitoring**: node exporter, top CPU/mem processes, iostat summary, SMART health check, status dashboard (services, IPs, CPU/mem snapshot), export status report to file/JSON (optional upload path)
- **System info**: `/etc/os-release`, neofetch, memory info, VM check, display adapters, GitHub link
- **Maintenance/disks**: cleanup, disks usage, largest `/var` dirs, maintenance bundle (update + cleanup + log rotate + status report), log integrity check
- **Proxmox**: list LXC containers, enter with `pct enter <vmid>`, and run the Proxmox SSH config updater (PermitRootLogin yes)
- **Users/time**: create sudo user, time sync info, chrony install
- **System control**: reboot, power down (SAFE_MODE-aware)
- **Help/logs**: Help/About (config, modes, repo), tail log; **Self-update** shortcut `u` to pull the latest NTX Command Center

## Modes and shortcuts

- `DRY_RUN=true ./ntx-utility-menu.sh`: print commands instead of executing them.
- `SAFE_MODE=true ./ntx-utility-menu.sh`: skip destructive actions (cleanup, reboot, powerdown, apt source removal).
- Shortcuts in the main menu: `h` Help/About, `s` Status dashboard, `l` Tail log, `c` Config/env, `q` Quit.

Note on service status: the dashboard queries systemd unit names like `ssh`, `docker`, etc. If a service uses a non-standard unit name, it may show as “not installed.” Adjust the unit names in `show_service_status` if your distro uses different service names.

Search tip: in the main menu, type `/keyword` (e.g., `/docker`, `/dns`) to jump directly to a matching section.

## Known behaviors

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

## Quick start (best practice)

- Run as root on Debian/Ubuntu (or derivatives). If testing, start with `DRY_RUN=true` or `SAFE_MODE=true`.
- Before first use, skim the config section in the script for paths (log/backup), DNS presets, and service unit names.
- Open `Help/About` (`h`) to see paths, modes, and shortcuts; tail the log (`l`) if something looks off.
- Use the status dashboard (`s`) to check key services (SSH, UFW, Fail2ban, Tailscale, Netmaker, CrowdSec, Docker), pending upgrades, kernel vs. running versions, public/private IPs, and CPU/mem/disk/inode snapshot.
- Before adding repos, review custom sources in **System update → list/remove apt sources**.
- For VPN/remote, use the Security menu: Tailscale, Netmaker netclient, CrowdSec + bouncer, and WireGuard (client/server installs).

## Customization

- Open `ntx-utility-menu.sh` in your editor to change menu labels or add/remove functions.
- Keep a backup copy before changing behavior that performs destructive actions (e.g., disk operations, package removal).

Suggested quick edits:

- Adjust the config section to your defaults (log path, backup dir, DNS presets, service units).
- Factor repeated code into functions and call them from the menu dispatcher.
- Optional config override: create `/etc/ntx-menu.conf` (or `./ntx-menu.conf`) to set variables like `LOG_FILE`, `BACKUP_DIR`, `REPORT_DIR`, and service unit names without editing the script.

## Contributing

Contributions are welcome. Small suggestions:

- Open an issue to propose features or report bugs.
- Submit a pull request with focused changes and a short description.

When contributing, include:

- What you changed and why
- How to reproduce or test the change

## Security & Safety

- The script can perform system-level actions. Review the code before running, especially if you obtained it from an untrusted source.
- Use a non-root account where possible and elevate privileges only for specific actions (via `sudo`).

## License

This project is licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0).

You are free to share and adapt the material for any purpose, even commercially, provided you give appropriate credit, provide a link to the license, and indicate if changes were made. See the full license text in the `LICENSE` file or at https://creativecommons.org/licenses/by/4.0/legalcode.

SPDX-License-Identifier: CC-BY-4.0

## Author

ntx007 — maintained by the repository owner.
