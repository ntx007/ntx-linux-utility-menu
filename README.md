# NTX Command Center

A portable, menu-driven Bash utility for common Linux admin tasks: `ntx-utility-menu.sh`. Built for Debian/Ubuntu (and derivatives), it centralizes updates, diagnostics, networking tools, security hardening, and maintenance in a single interactive script.

<<<<<<< HEAD
This repository provides a menu-driven shell script you can run on Debian/Ubuntu and many other Linux distributions to perform system updates, quick diagnostics, networking helpers, install common tools, and more.

## Features

<<<<<<< HEAD
<<<<<<< HEAD
- Interactive, text-based menu (Bash/sh)
- Common sysadmin helpers (updates, package installs, networking tools)
- Quick system information and maintenance actions (reboot, shutdown)
=======
- Interactive, text-based menu (Bash/sh), versioned (v0.3-dev)
- Common sysadmin helpers (updates, unattended-upgrades, networking tools, DNS backups/restore)
- Security/remote helpers (UFW, Fail2ban, OpenSSH, Tailscale, Netmaker netclient)
- Quick system information, monitoring (top processes, iostat, SMART), and maintenance actions
- Logging to `/var/log/ntx-menu.log` and backups for `/etc/resolv.conf` in `/var/backups/ntx-menu`
>>>>>>> b3bc974 (Update version to v0.3-dev in README, CHANGELOG, and script file)
=======
- Interactive, text-based menu (Bash/sh), versioned (v0.3-dev) with nested sections
- Common sysadmin helpers (updates, unattended-upgrades enable/disable/status/run, networking tools, DNS backups/restore)
- Security/remote helpers (UFW, Fail2ban, OpenSSH, Tailscale, Netmaker netclient + repo removal)
- Quick system information, monitoring (top processes, iostat, SMART), and maintenance actions
- Logging to `/var/log/ntx-menu.log` with rotation and backups for `/etc/resolv.conf` in `/var/backups/ntx-menu`
- DRY_RUN support (`DRY_RUN=true ./ntx-utility-menu.sh`) to preview commands
>>>>>>> 8cd0d8a (Enhance usability and features in ntx Command Center (v0.3-dev))
- Easy to customize — edit the script to add or remove menu items
=======
## Highlights (v0.3-dev)

- Interactive, nested menu (Bash) with shortcuts for help, status dashboard, and logs
- Updates: unattended-upgrades enable/disable/status/run; reboot-if-needed flow
- Networking: public IP with fallback, interfaces/routes/connections, DNS backups/restore, ping common endpoints, traceroute
- Security/remote: UFW, Fail2ban, OpenSSH, Tailscale, Netmaker netclient (install/remove repo), CrowdSec + firewall bouncer, firewall/SSH status, failed logins
- Tools/monitoring: essentials/extra tools, node exporter, top CPU/mem, iostat summary, SMART checks, status dashboard
- Containers: Docker + Compose plugin install, service status, short info, running containers
- Maintenance/info: apt source hygiene, cleanup, disk usage, largest `/var` dirs, system info (os-release, neofetch, VM check), GitHub link
- Logging/backups: `/var/log/ntx-menu.log` with rotation; `/etc/resolv.conf` backups to `/var/backups/ntx-menu`
- Modes: `DRY_RUN=true` to preview commands; `SAFE_MODE=true` to skip destructive actions
>>>>>>> 28b13f9 (Enhance NTX Command Center with new features and safety modes)

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

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
### Download & run (one-liner)
=======
### Command-line (tested on Debian / Ubuntu)
>>>>>>> aea6eb4 (Add command-line usage instructions for downloading and running the script)
=======
### Run from the command line (download & run)
>>>>>>> ba07bf3 (Add instructions for downloading and running the script directly from the command line)
=======
### Download & run (one-liner)
>>>>>>> 35aa4af (Refactor command-line usage instructions in README for clarity and conciseness. Check out CHANGELOG)

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

## Menu map (v0.3-dev)

- **System update**: standard upgrade, reboot-if-needed, unattended-upgrades (enable/disable/status/run), list/remove custom apt sources
- **DNS**: view/edit with backups, preset DNS choices, restore last backup
- **Network/IP**: public IP (fallback), interfaces, routes, connections, ping common endpoints, traceroute
- **Speedtest/benchmarks**: Speedtest install/update/run, repo/key removal, YABS
- **Security/remote**: UFW, Fail2ban, OpenSSH, Tailscale, Netmaker netclient (install/remove repo), CrowdSec + firewall bouncer, firewall/SSH status, failed logins
- **Tools/env**: essentials, extra tools, ibramenu, QEMU guest agent
- **Containers**: Docker + Compose plugin, service status, short info, running containers
- **Monitoring**: node exporter, top CPU/mem processes, iostat summary, SMART health check, status dashboard
- **System info**: `/etc/os-release`, neofetch, memory info, VM check, GitHub link
- **Maintenance/disks**: cleanup, disks usage, largest `/var` dirs
- **Users/time**: create sudo user, time sync info, chrony install
- **System control**: reboot, power down (SAFE_MODE-aware)
- **Help/logs**: Help/About (config, modes, repo), tail log

## Modes and shortcuts

- `DRY_RUN=true ./ntx-utility-menu.sh`: print commands instead of executing them.
- `SAFE_MODE=true ./ntx-utility-menu.sh`: skip destructive actions (cleanup, reboot, powerdown, apt source removal).
- Shortcuts in the main menu: `h` Help/About, `s` Status dashboard, `l` Tail log, `q` Quit.

## Customization

- Open `ntx-utility-menu.sh` in your editor to change menu labels or add/remove functions.
- Keep a backup copy before changing behavior that performs destructive actions (e.g., disk operations, package removal).

Suggested quick edits:

- Adjust the config section to your defaults (log path, backup dir, DNS presets, service units).
- Factor repeated code into functions and call them from the menu dispatcher.

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
