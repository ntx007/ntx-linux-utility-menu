# Usage

## Run the menu
From the project directory:
```bash
sudo ./ntx-utility-menu.sh
```
If installed to PATH:
```bash
sudo ntx-utility-menu
```

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

## Modes and shortcuts
- `DRY_RUN=true ./ntx-utility-menu.sh` to preview commands.
- `SAFE_MODE=true ./ntx-utility-menu.sh` to skip destructive actions.
- Shortcuts in the main menu: `h` Help/About, `s` Status dashboard, `l` Tail logs, `c` Config/env, `u` Self-update, `q` Quit.
- Language toggle: `d` switches between English and German labels (menus only).

- **System update**: updates, unattended-upgrades, apt source list/remove, APT health, update health (with stale-update warning support).
- **DNS**: view/edit with backups, IPv4/IPv6 presets, restore latest backup.
- **Network**: public IP, interfaces/routes/connections, ping/traceroute.
- **Benchmarks**: Speedtest install/run, YABS, YABS preset submenu.
- **Security**: UFW presets with snapshot/revert, Fail2ban (summary/reload/list/unban), SSH hardening, Tailscale, Netmaker, CrowdSec, WireGuard (install/QR/validate/start/stop/restart, interface choice), rootkit check, ClamAV install/scan, Google Authenticator install, config backup/restore (with optional Docker Compose include).
- **Containers**: Docker/Compose install, service/status/info, list running/all, Compose health, rootless check, list privileged containers, list containers with sensitive mounts, containers running as root, containers using host network.
- **Monitoring**: node exporter, top CPU/mem, iostat, SMART, status dashboard, export status report (text/JSON with optional upload path).
- **Maintenance**: cleanup, disks, largest `/var`, maintenance bundle (can auto-update first), log integrity.
- **System info**: `/etc/os-release`, neofetch, memory, VM check, display adapters.
- **Users/time**: create sudo user, time sync info, chrony install.
- **Control**: reboot, power down.

## Notes and caveats
- Self-update uses `https://ntx-menu.re-vent.de` (GitHub main); use full path if `realpath`/`readlink -f` are absent to avoid writing to the current directory.
- Service status uses standard systemd unit names; adjust unit variables if your distro differs.
- Pending updates count may undercount on localized systems.
- WireGuard enable/disable assumes `/etc/wireguard/wg0.conf` exists; QR requires `qrencode`.
- ClamAV `freshclam` can fail if the daemon holds the DB lock; stop/reload `clamav-freshclam` before updating if needed.
- Display adapters view now auto-installs `lshw` if missing; monitoring functions (node exporter/top/iostat/SMART) are bundled in the current release.
- SMART checks: virtio disks may need `-d scsi`; the menu tries this fallback but unusual storage can require a manual `smartctl -a -d <type> /dev/<disk>`.
- Rootkit check installs `binutils` so `strings` is available; install binutils manually if it’s still missing.
