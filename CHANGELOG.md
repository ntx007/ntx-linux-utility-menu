# Changelog

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

## v0.2
- Added logging to `/var/log/ntx-menu.log` plus environment checks for Debian/Ubuntu and apt presence.
- Added backup/restore flow for `/etc/resolv.conf` and created shared backup directory `/var/backups/ntx-menu`.
- Expanded menu with routing/connection views, update-and-reboot-if-needed, unattended-upgrades toggle, and monitoring helpers (top processes, iostat, SMART check).
- Minor improvements to DNS edits (auto-backup), IP lookup fallbacks, and menu numbering to wire new actions.
- Version v0.2: added version tagging, unattended-upgrades status/run options, and menu renumbering to include the new features.
- Added Netmaker netclient installer for Debian-based distros (adds apt key/repo, updates, installs) and wired it into the Security/Remote Access menu.
- Added GitHub project link option in the System Information section.
