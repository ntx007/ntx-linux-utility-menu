# ntx Command Center

A small, portable, interactive Bash utility menu ("ntx Command Center") that bundles common Linux admin and maintenance tasks into a single script: `ntx-utility-menu.sh`.

This repository provides a menu-driven shell script you can run on Debian/Ubuntu and many other Linux distributions to perform system updates, quick diagnostics, networking helpers, install common tools, and more.

## Features

- Interactive, text-based menu (Bash/sh)
- Common sysadmin helpers (updates, package installs, networking tools)
- Quick system information and maintenance actions (reboot, shutdown)
- Easy to customize — edit the script to add or remove menu items

## Requirements

- A Unix-like system with Bash or POSIX sh
- Basic shell utilities available on most Linux systems (curl, wget, ip, ifconfig or iproute2)
- Run with a user account that can perform the chosen actions (some items require root)

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
./ntx-utility-menu.sh
```

- Or, if installed in your PATH:

```bash
ntx-utility-menu
```

The script shows a numbered interactive menu. Enter the number of the action you want to run and press Enter.

### Command-line (tested on Debian / Ubuntu)

You can download and run the script directly from the command line. This method has been tested and works on Debian and Ubuntu systems:

```bash
curl -fsSL -o ntx-utility-menu.sh https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/refs/heads/main/ntx-utility-menu.sh

bash ntx-utility-menu.sh
```

If you prefer to make the script executable and run it directly:

```bash
chmod +x ntx-utility-menu.sh
./ntx-utility-menu.sh
```

## Examples

Below are short examples of the most commonly used menu options and a sample interaction. Menu numbers in your copy may differ — use the on-screen numbers the script prints.

- Update system and installed packages (typical):

	1) Select "System update / upgrade" from the menu
	2) Confirm when prompted (or run with sudo to avoid extra prompts)

- Install common tools (curl, jq, htop):

	1) Select "Install essential tools" / "Install packages"
	2) Choose the recommended preset or enter package names when prompted

- View network configuration and active interfaces:

	1) Select "Network info / IP tools" → "Show interfaces" or "Show IPs"
	2) Use the displayed info to choose a specific interface for further actions

- Quick speed and connectivity check (Speedtest / YABS):

	1) Select "Run Speedtest" or "Run YABS" from the menu
	2) Wait for the test to finish and review latency / upload / download

- Enable SSH or set up Tailscale (when available):

	1) Select "SSH setup" to install/configure OpenSSH
	2) Select "Tailscale" to install and walk through authentication

Sample interaction (illustrative):

```text
Welcome to ntx Command Center
1) System update
2) Network tools
3) Install tools
4) Speedtest
5) SSH setup
6) Reboot
q) Quit

Enter choice: 1
Running apt update && apt upgrade -y...
Done. Packages upgraded.
Return to menu (press Enter)
```

These examples are intentionally short — open `ntx-utility-menu.sh` to see the exact menu labels and any additional submenus your copy provides.

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

---

If you want, I can also:

- Add a short example of the most commonly used menu options.
- Add a `LICENSE` file (MIT recommended for small utilities).
- Add a small test or a CI check that lints shell scripts (shellcheck) before merging.

Tell me which you'd like next and I'll apply it.
