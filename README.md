# ntx Command Center

A small, portable, interactive Bash utility menu ("ntx Command Center") that bundles common Linux admin and maintenance tasks into a single script: `ntx-utility-menu.sh`.

This repository provides a menu-driven shell script you can run on Debian/Ubuntu (and derivatives) to perform system updates, quick diagnostics, networking helpers, install common tools, and more.

## Features

- Interactive, text-based menu (Bash/sh), versioned (v0.3-dev) with nested sections
- Common sysadmin helpers (updates, unattended-upgrades enable/disable/status/run, networking tools, DNS backups/restore)
- Security/remote helpers (UFW, Fail2ban, OpenSSH, Tailscale, Netmaker netclient + repo removal)
- Quick system information, monitoring (top processes, iostat, SMART), and maintenance actions
- Logging to `/var/log/ntx-menu.log` with rotation and backups for `/etc/resolv.conf` in `/var/backups/ntx-menu`
- DRY_RUN support (`DRY_RUN=true ./ntx-utility-menu.sh`) to preview commands
- Easy to customize — edit the script to add or remove menu items

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

## Menu highlights (v0.3-dev)

- System update: standard upgrade, upgrade + reboot-if-needed, unattended-upgrades enable/disable/status/run
- DNS: view/edit with automatic backups and restore
- Network/IP: public IP (with fallback), interfaces, routes, active connections
- Benchmarks: install/run Speedtest, manage Speedtest repo/key, run YABS
- Security/remote: UFW, Fail2ban, OpenSSH server, Tailscale install/up, Netmaker netclient install/remove repo/key, firewall/SSH status, failed logins
- Tools/environment: essentials, extended tools, ibramenu, QEMU guest agent
- Containers: Docker + Compose plugin
- Monitoring: node exporter, top CPU/mem processes, iostat summary, SMART health check
- System info: `/etc/os-release`, neofetch, memory info, VM check, link to project GitHub
- Maintenance/disks: cleanup, disks usage, largest `/var` dirs
- Users/time: create sudo user, time sync info, chrony install
- System control: reboot, power down
- Help/logs: Help/About screen, tail latest log lines

## Customization

- Open `ntx-utility-menu.sh` in your editor to change menu labels or add/remove functions.
- Keep a backup copy before changing behavior that performs destructive actions (e.g., disk operations, package removal).

Suggested quick edits:

- At the top of the script add a section for configurable variables (default packages, log path, dry-run flag).
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
