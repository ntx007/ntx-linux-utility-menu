# Changelog 📝

## Unreleased (v1.3.0-dev) 🚧
- Version: bumped to v1.3.0-dev to start the next development cycle.
- Apt: added source validator for mismatched codenames and expanded apt lock waits on update flows.
- Monitoring: new `health_brief` non-interactive summary; added MTR and nmap quick scans in Network; added container log tail helper.
- Maintenance: journal vacuum with custom window, needrestart summary, and a config template writer.
- Security: SSH cipher/KEX/MAC audit helper.
- Proxmox: backup rotation helper for /var/lib/vz/dump.

### Known behaviors ⚠️
- Self-update needs the full script path when realpath/readlink -f is missing or it may write into the current directory.
- Service status assumes standard systemd unit names (ssh, docker, etc.); adjust unit variables if your distro differs.
- Pending update count (`apt-get -s upgrade | grep '^Inst'`) can undercount on localized systems.
- WireGuard enable/disable assumes `/etc/wireguard/wg0.conf`; QR rendering requires `qrencode`.
- ClamAV `freshclam` may fail if the daemon holds the DB lock; stop/reload `clamav-freshclam` first.
- SMART on virtio/atypical disks may require manual `smartctl` flags (e.g., `-d scsi`).
- Rootkit check installs `binutils` for `strings`; install manually if it’s still missing.
- Offline/proxy: upgrades depend on `apt-get update` succeeding; set `http_proxy/https_proxy` or skip update steps (they stop early on failure).
- Minimal envs: inode view can be skipped if `df -i` is unsupported; IP listing falls back to `ip addr` or `ifconfig` if `ip` is absent.
- MariaDB server install expects a systemd host; may fail in containers.
- Speedtest repo helper is pinned to Ubuntu jammy; on other releases it writes jammy entries, so add a distro-appropriate repo if needed.

## v1.2.1
- Network: VLAN and bond helpers (create/delete) plus an SSH key generator utility alongside the existing custom nameserver append/overwrite flow.
- Security: Fail2ban tuning shortcut (basic jail.local defaults) and auditd minimal ruleset installer.
- Monitoring: SMART batch check for all disks; new service uptime and hardware overview snapshots.
- Maintenance: added log cleanup preset, kernel list/purge helper, and /etc backup shortcut.
- Proxmox: LXC flow now lists VMIDs before entering; added qm VM helpers (list, start/stop/restart, snapshots create/list/rollback, backup/restore) and ISO downloader alongside existing community scripts.
- Tools: added Node/npm version check; essentials bundle now installs mariadb-client-core; MariaDB server installer (host install, systemd-based, not containerized).
- System update: added APT proxy toggle (set/remove).
- CLI: expanded `--run` support (status_report_json, apt_health, update_health, clamav_scan) and updated in-script help/usage to list them.
- Network: added “Top talkers (TCP)” view (ss/netstat).
- Containers: added prune helper, image scan helper (docker scan/trivy), a simple compose project manager, and Docker installers for Nginx Proxy Manager and Traefik.
- SSH: submenu now includes start/stop/restart and enable/disable controls for the SSH service.
- Users: added a menu option to change a user's password via `passwd`.
- Security: first-run checklist to install/enable Docker/Compose, SSH, UFW, and Fail2ban in one pass.
- DNS: add “restore backup + restart systemd-resolved.”
- Status exports: include running container count and SMART health (if available) in text/JSON; JSON gains a minimal schema with SMART/container info.
- Proxmox: task list (pvesh) and backup listing for quick checks.
- Header: shows apt index staleness when older than the configured threshold.
- Compose app installers: prompt for data paths and log post-install summaries to `POST_INSTALL_LOG`.
- UI: main menu grouped layout with refreshed header/footer styling and German labels updated.
- Versioning note: v1.2.0 was skipped during development; we moved directly to v1.2.1.

### Bug fixes 🐛
- Hemmelig installer now correctly checks for the Docker Compose plugin before deployment.

### Known behaviors ⚠️
- Same as v1.1.1; MariaDB server install expects systemd (host) and may fail in containers. Compose manager still requires the Docker Compose plugin.

## v1.1.1
- Header: fixed RAM detection fallback so systems without awk/PROC parsing quirks no longer show “unknown GiB”.
- Update check: only surfaces a notice when the remote tag is newer than the current version (prevents downgrades being shown as updates).

## v1.1.0
- System update: added Ubuntu do-release-upgrade option (installs update-manager-core, shows held packages, and runs do-release-upgrade per Ubuntu wiki guidance).
- Containers: added basic Docker controls (stop all containers, start via compose up -d, run custom docker command).
- Containers: added Portainer (CE) installer (pull image, create volume, run on 9443).
- Containers: added Nginx Proxy Manager installer (compose stack with ports 80/81/443, external network support).
- Containers: added Pi-hole (standalone) and Pi-hole + Unbound installers (compose stacks with defaults and optional custom network/password).
- Containers: added Nextcloud All-in-One installer (compose stack using nextcloud/all-in-one).
- Containers: added Tactical RMM installer (docker install script from upstream; requires DNS/FQDN prep).
- Containers: added Hemmelig.app installer (compose stack on port 3000).
- UI: header now shows host, CPU threads, RAM, IP, and a GitHub link; update notice shown if a newer release is detected.
- UI: cleaned and regrouped submenus for clearer spacing and task clustering across update/DNS/containers/monitoring.
- Docs: README/usage/installation refreshed for clearer install/run instructions and grouped menu overview.
- UI: main menu reorganized into Core / Operations / Shortcuts and aligned in both English and German layouts.
- Containers: Docker install now uses the official convenience script (get.docker.com) with a compose plugin fallback from GitHub releases.
- Agents: Netmaker netclient installer updated to follow official docs flow.
- Networking: ifconfig view now auto-installs net-tools when missing (falls back to ip addr).

## v1.0.0
- Semantic versioning adopted; canonical version string: v1.0.0.
- Self-update: version-aware updater lists GitHub releases (semantic sort) and allows rollbacks to a selected version or the latest dev build (GitHub raw URL).
- UX: security/remote split into clearer submenus; removed mandatory “Press Enter to continue” pauses.
- Proxmox: dedicated submenu for Proxmox helpers including `pct enter <vmid>`, LXC listing, and SSH config updater (PermitRootLogin yes); placed ahead of System control.
- Tools: added a separate submenu to install the essentials bundle; CLI wrapper `ntxmenu` plus installer `install_ntxmenu.sh`; in-menu install shortcut (`i`) downloads and installs to `/usr/local/bin`.

### Bug fixes
- Installer one-liner: updated `install_ntxmenu.sh` to download missing scripts from GitHub main when run outside the repo.
- Installer and in-app install now add a `/etc/profile.d/ntxmenu.sh` PATH snippet when `/usr/local/bin` is missing.
- Installer and in-app install also symlink `ntxmenu` to `/usr/bin` when `/usr/local/bin` is not in PATH to allow immediate use.
- Wrapper: `ntxmenu` now resolves to `/usr/local/bin/ntx-utility-menu` (or local copies) so it works even when symlinked from `/usr/bin`.
- Installer now creates a `/usr/local/bin/ntx-utility-menu.sh` symlink pointing to the installed script for older wrappers.
- Wrapper expanded to look for `/usr/local/bin` and `/usr/bin` variants of the script before falling back to its own directory, fixing missing-script errors when symlinked.
- Tools: added nvm installer to the Tools & environment menu.
- Installer now warns when `/usr/local/bin` is not in PATH after install.
- Containers menu: restored missing Docker helpers (install/status/ps/list/info) to prevent “command not found” errors.

### Known behaviors
- Same as v0.6: pending updates may undercount on localized systems; WireGuard assumes `/etc/wireguard/wg0.conf`; service units may differ per distro; `qrencode`/Docker Compose plugin required for their helpers; self-update needs full path if `realpath/readlink -f` are absent.

## v0.6
- Self-update: version-aware updater lists GitHub releases (semantic sort) and allows rollbacks to a selected version or the latest dev build (GitHub raw URL).
- UX: security/remote split into clearer submenus; removed mandatory “Press Enter to continue” pauses.
- Proxmox: dedicated submenu for Proxmox helpers including `pct enter <vmid>`, LXC listing, and SSH config updater (PermitRootLogin yes); placed ahead of System control.
- Tools: added a separate submenu to install the essentials bundle; CLI wrapper `ntxmenu` plus installer `install_ntxmenu.sh`; in-menu install shortcut (`i`) downloads and installs to `/usr/local/bin`.

### Bug fixes
- Replaced remote Proxmox SSH config updater with an inline PermitRootLogin yes helper (backs up sshd_config, edits locally, reloads SSH).
- German menu updated for Proxmox entry; removed unused install_tools helper.

### Known behaviors
- When realpath/readlink -f are unavailable and the script is invoked via $PATH, self-update may write to the current directory instead of the installed path; run with the full path to update in place.
- Status dashboard uses standard systemd unit names (e.g., ssh, docker); if your distro uses different names they may show as “not installed.”
- Pending update count uses `apt-get -s upgrade | grep '^Inst'` and may undercount on localized systems; WireGuard enable/disable assumes `/etc/wireguard/wg0.conf` exists; service status may show “not installed” if units use non-default names.
- WireGuard QR helper requires `qrencode`; Docker Compose health assumes the Compose plugin is present.

## v0.5
- Added language toggle (en/de) in the main menu and more translated labels.
- Status report export to JSON with optional copy to `STATUS_UPLOAD_PATH`; log rotation cleans old archives (`LOG_HISTORY`).
- System update: APT health/update health checks in `--run`; update cadence warning (`UPDATE_WARN_DAYS`) with optional auto-update in maintenance bundle (`AUTO_UPDATE_BEFORE_MAINT`).
- Security: ClamAV flow improved (daemon stop/start choice, target selection, report log); Fail2ban list/unban helpers; UFW presets snapshot current rules with revert; config backups can include Docker Compose path and restores allow selection; WireGuard actions accept interface choice and diff/validate new configs.
- Containers: added hardening checks for sensitive mounts, privileged containers, root user, and host network; menu expanded.
- Monitoring: status report export supports JSON; language toggle `d` added.
- Benchmarks: removed external option; YABS presets retained.
- Self-update: after updating, prompt to restart so the new script loads.
- Tools: essentials bundle now installs npm and iproute2 by default.
- DNS: Netcup presets now include 46.38.225.230 + 46.38.252.230 + 1.1.1.1 for append/overwrite options.
- Self-update: version-aware updater to pick/rollback to GitHub releases or the latest dev build.
- UX: Security menu split into submenus; removed mandatory “Press Enter to continue” prompt between actions.
- Tools: dedicated essentials submenu; Proxmox helpers submenu (pct list/enter).

### Bug fixes
- Restored missing monitoring functions (node exporter/top/iostat/SMART).
- Fixed `df` inode view clash in disk/inode summary.
- Display adapters view now auto-installs `lshw` if missing.
- SMART check now handles virtio disks by using `-d scsi` fallback and clearer guidance when detection fails.
- Rootkit check now installs `binutils` so `strings` is available, and surfaces a clearer note if it’s missing.
- Private IP listing now ensures `iproute2`/`ip` is present before running, avoiding failures on minimal systems.
- update_all now stops early with a clear hint when apt-get update fails (e.g., proxy/offline) instead of continuing.
- Inode summary falls back with a friendly note if `df -i` is unsupported; SSH audit skips cleanly if sshd is absent.
- German menu updated for Proxmox entry; removed unused install_tools helper.

### Known behaviors
- When realpath/readlink -f are unavailable and the script is invoked via $PATH, self-update may write to the current directory instead of the installed path; run with the full path to update in place.
- Status dashboard uses standard systemd unit names (e.g., ssh, docker); if your distro uses different names they may show as “not installed.”
- Pending update count uses `apt-get -s upgrade | grep '^Inst'` and may undercount on localized systems; WireGuard enable/disable assumes `/etc/wireguard/wg0.conf` exists; service status may show “not installed” if units use non-default names.
- WireGuard QR helper requires `qrencode`; Docker Compose health assumes the Compose plugin is present.

## v0.4
- Added in-menu self-update (main menu shortcut `u`) to download the latest NTX Command Center script from GitHub main: https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main/ntx-utility-menu.sh
- New non-interactive mode via `--run` (e.g., update_all, maintenance_bundle, status_report, ssh_audit, docker_compose_health, wireguard_qr).
- Added maintenance bundle (update + cleanup + log rotate + status report) and exportable status reports to `/var/log/ntx-menu-reports`.
- Introduced SSH hardening check and WireGuard QR helper; Docker Compose health view (ls/ps) added to containers menu.
- Enhanced menu search feedback for `/keyword` queries.
- Config overrides supported via `/etc/ntx-menu.conf` or `./ntx-menu.conf` for paths and unit names.
- Added rootkit check (chkrootkit installer/runner), video adapter info (lshw display), and all-containers listing in the Docker menu.
- Expanded essentials install to include unzip, python3-pip, gcc/python3-dev, psutil (pip), gdown, dos2unix, glances, tmux, zsh, and mc.
- Added YABS benchmark presets submenu under Speedtest/benchmarks.
- Added ClamAV install + quick scan option to Security/remote.
- Added APT health/update health checks; security enhancements (Fail2ban summary/reload, UFW presets, Google Authenticator install, config backup bundle, WireGuard validate/start/stop/restart, ClamAV improvements); container hardening checks (rootless, privileged containers); log integrity report in maintenance.
- ClamAV: `freshclam` may fail if the daemon holds the DB lock; stop/reload `clamav-freshclam` before updating if needed.

### Known behaviors
- When realpath/readlink -f are unavailable and the script is invoked via $PATH, self-update may write to the current directory instead of the installed path; run with the full path to update in place.
- Status dashboard uses standard systemd unit names (e.g., ssh, docker); if your distro uses different names they may show as “not installed.”
- Pending update count uses `apt-get -s upgrade | grep '^Inst'` and may undercount on localized systems; WireGuard enable/disable assumes `/etc/wireguard/wg0.conf` exists; service status may show “not installed” if units use non-default names.
- WireGuard QR helper requires `qrencode`; Docker Compose health assumes the Compose plugin is present.

## v0.3
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

## v0.2
- Added logging to `/var/log/ntx-menu.log` plus environment checks for Debian/Ubuntu and apt presence.
- Added backup/restore flow for `/etc/resolv.conf` and created shared backup directory `/var/backups/ntx-menu`.
- Expanded menu with routing/connection views, update-and-reboot-if-needed, unattended-upgrades toggle, and monitoring helpers (top processes, iostat, SMART check).
- Minor improvements to DNS edits (auto-backup), IP lookup fallbacks, and menu numbering to wire new actions.
- Version v0.2: added version tagging, unattended-upgrades status/run options, and menu renumbering to include the new features.
- Added Netmaker netclient installer for Debian-based distros (adds apt key/repo, updates, installs) and wired it into the Security/Remote Access menu.
- Added GitHub project link option in the System Information section.
