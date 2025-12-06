# Changelog

<<<<<<< HEAD
<<<<<<< HEAD
## Unreleased
- Version: bumped to v0.3 (release branch).
- Menu/UX: switched to nested section menus; added Help/About, status dashboard shortcut, and log tail shortcut.
- Execution modes: added DRY_RUN (preview commands) and SAFE_MODE (skip destructive actions), exposed in Help/About.
- Logging: log rotation added for `/var/log/ntx-menu.log`; log tail view in main menu.
- Safety/maint: improved unattended-upgrades with disable option; kept DNS backups/restore; apt source list/removal added.
- Dependencies: preflight now installs correct packages (dnsutils, gnupg, etc.).
- Networking: added ping common endpoints and traceroute helpers.
- Security: added firewall/SSH status views, failed login summary, CrowdSec installer, and CrowdSec firewall bouncer.
- Repos: added repo/key removal for Speedtest and Netmaker.
- Docker: expanded menu with service status, short info, and running containers view.
- Status dashboard: now reports "not installed" cleanly when services/units are absent (avoids noisy errors).
- Status dashboard: added CPU/mem snapshot, public + private IPs, and Netmaker status.
- Security: added WireGuard install options (client and server).
- Docs: README refreshed with concise highlights, cleaned menu map, modes/shortcuts, service status caveats, and quick-start guidance.
- DNS: added an option to append Cloudflare/Google (1.1.1.1 + 8.8.8.8) without overwriting existing entries.
- DNS: added IPv6 Cloudflare/Google presets (overwrite or append) alongside the existing IPv4 options.
- Known behavior: status dashboard uses standard systemd unit names (e.g., ssh, docker); if your distro names services differently they may show as “not installed.”
- Config/UX: added unit name mapping, status dashboard extras (pending upgrades, kernel latest vs running, disk/inode summary), and menu search via `/keyword`.
- Security: added WireGuard sample config helper.
- Config/UX: exposed config/env in the menu, added wg-quick enable/disable actions, and show result lines after commands for clearer feedback.
- Docs: README expanded with search shortcut, config/env shortcut, dashboard details, and config edit guidance.
- Docs: cleaned menu map (removed duplicates) and added a pre-run checklist to review config paths, DNS presets, and unit names.
- Known behavior: pending update count uses `apt-get -s upgrade | grep '^Inst'` and may undercount on localized systems; WireGuard enable/disable assumes `/etc/wireguard/wg0.conf` exists; service status may show “not installed” if units use non-default names.

=======
>>>>>>> 40eec2c (...)
=======
## Unreleased
- Version: bumped to v0.3-dev (develop branch).
- Menu/UX: switched to nested section menus; added Help/About, status dashboard shortcut, and log tail shortcut.
- Execution modes: added DRY_RUN (preview commands) and SAFE_MODE (skip destructive actions), exposed in Help/About.
- Logging: log rotation added for `/var/log/ntx-menu.log`; log tail view in main menu.
- Safety/maint: improved unattended-upgrades with disable option; kept DNS backups/restore; apt source list/removal added.
- Dependencies: preflight now installs correct packages (dnsutils, gnupg, etc.).
- Networking: added ping common endpoints and traceroute helpers.
- Security: added firewall/SSH status views, failed login summary, CrowdSec installer, and CrowdSec firewall bouncer.
- Repos: added repo/key removal for Speedtest and Netmaker.
- Docker: expanded menu with service status, short info, and running containers view.
- Status dashboard: now reports "not installed" cleanly when services/units are absent (avoids noisy errors).
- Status dashboard: added CPU/mem snapshot, public + private IPs, and Netmaker status.
- Security: added WireGuard install options (client and server).
- Docs: README refreshed with concise highlights, cleaned menu map, modes/shortcuts, service status caveats, and quick-start guidance.

>>>>>>> b3bc974 (Update version to v0.3-dev in README, CHANGELOG, and script file)
## v0.2
- Added logging to `/var/log/ntx-menu.log` plus environment checks for Debian/Ubuntu and apt presence.
- Added backup/restore flow for `/etc/resolv.conf` and created shared backup directory `/var/backups/ntx-menu`.
- Expanded menu with routing/connection views, update-and-reboot-if-needed, unattended-upgrades toggle, and monitoring helpers (top processes, iostat, SMART check).
- Minor improvements to DNS edits (auto-backup), IP lookup fallbacks, and menu numbering to wire new actions.
- Version v0.2: added version tagging, unattended-upgrades status/run options, and menu renumbering to include the new features.
- Added Netmaker netclient installer for Debian-based distros (adds apt key/repo, updates, installs) and wired it into the Security/Remote Access menu.
- Added GitHub project link option in the System Information section.
