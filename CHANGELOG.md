# Changelog

## Unreleased
- Bumped development version to v0.3-dev on the develop branch.
- Added nested section-based menus, help/about screen, and log tail option for usability.
- Added DRY_RUN support, log rotation, and preflight dependency checks.
- Added repo/key removal for Speedtest and Netmaker, firewall/SSH status views, and failed login summary.
- Improved safety toggles (disable unattended-upgrades) and kept DNS backups/restore flow.
- Fixed preflight dependency installs to use correct package names (dnsutils, gnupg, etc.).

## v0.2
- Added logging to `/var/log/ntx-menu.log` plus environment checks for Debian/Ubuntu and apt presence.
- Added backup/restore flow for `/etc/resolv.conf` and created shared backup directory `/var/backups/ntx-menu`.
- Expanded menu with routing/connection views, update-and-reboot-if-needed, unattended-upgrades toggle, and monitoring helpers (top processes, iostat, SMART check).
- Minor improvements to DNS edits (auto-backup), IP lookup fallbacks, and menu numbering to wire new actions.
- Version v0.2: added version tagging, unattended-upgrades status/run options, and menu renumbering to include the new features.
- Added Netmaker netclient installer for Debian-based distros (adds apt key/repo, updates, installs) and wired it into the Security/Remote Access menu.
- Added GitHub project link option in the System Information section.
