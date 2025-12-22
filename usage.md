# Usage

## Run the menu
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

## Non-interactive actions
```bash
sudo ./ntx-utility-menu.sh --run update_all
sudo ./ntx-utility-menu.sh --run maintenance_bundle
sudo ./ntx-utility-menu.sh --run status_report
sudo ./ntx-utility-menu.sh --run ssh_audit
sudo ./ntx-utility-menu.sh --run docker_compose_health
sudo ./ntx-utility-menu.sh --run wireguard_qr
```
Use `--help` for the supported list.

## Modes & shortcuts
- `DRY_RUN=true ./ntx-utility-menu.sh`: preview commands.
- `SAFE_MODE=true ./ntx-utility-menu.sh`: skip destructive actions.
- Shortcuts: `h` Help/About, `s` Status dashboard, `l` Tail logs, `c` Config/env, `u` Self-update, `i` Install to PATH, `q` Quit.
- Language toggle: `d` switches between English and German labels.

## Menu at a glance
- Core: updates (incl. unattended), do-release-upgrade, apt source hygiene + proxy toggle, APT/update health, self-update; DNS presets/backups + custom nameserver (append/overwrite); network views (incl. top talkers); Speedtest/YABS; security submenus (firewall, Fail2ban, SSH, WireGuard, agents, anti-malware, config backup).
- Operations: tools/essentials/nvm, MariaDB server (host install), Node/npm version check, containers (Docker/Compose, hardening checks, prune/scan/compose manager, app installers), monitoring (status dashboard, reports, node exporter), system info, maintenance (cleanup/bundle/log integrity), Proxmox helpers (start/stop/restart, storage, snapshots, backup/restore, resources, services/cluster, community post-install/templates scripts), users/time, system control.
- Shortcuts: `h` help, `s` dashboard, `l` logs, `c` config/env, `u` self-update, `d` language, `i` install to PATH, `q` quit.

## Known behaviors & caveats
- Self-update uses `https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main/ntx-utility-menu.sh` (GitHub main); use full path if `realpath`/`readlink -f` are absent to avoid writing to the current directory.
- Service status uses standard systemd unit names; adjust unit variables if your distro differs.
- Pending updates count may undercount on localized systems.
- WireGuard enable/disable assumes `/etc/wireguard/wg0.conf` exists; QR requires `qrencode`.
- ClamAV `freshclam` can fail if the daemon holds the DB lock; stop/reload `clamav-freshclam` before updating if needed.
- Display adapters view now auto-installs `lshw` if missing; monitoring functions (node exporter/top/iostat/SMART) are bundled in the current release.
- SMART checks: virtio disks may need `-d scsi`; the menu tries this fallback but unusual storage can require a manual `smartctl -a -d <type> /dev/<disk>`.
- Rootkit check installs `binutils` so `strings` is available; install binutils manually if it’s still missing.
- Offline/proxy: `apt-get update` must succeed for upgrades; if blocked, set `http_proxy/https_proxy` or skip update steps (they will stop early with a hint).
- Minimal envs: Inode view may be skipped if `df -i` is unsupported; IP listing falls back to `ip addr` or `ifconfig` if `ip` is absent.
