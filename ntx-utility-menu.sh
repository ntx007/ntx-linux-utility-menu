#!/bin/bash

###############################################################################
# NTX Command Center - Simple server helper menu
# Version: v0.4-dev
###############################################################################

LOG_FILE="/var/log/ntx-menu.log"
BACKUP_DIR="/var/backups/ntx-menu"
REPORT_DIR="/var/log/ntx-menu-reports"
MAX_LOG_SIZE=$((1024 * 1024)) # 1 MiB
DRY_RUN=${DRY_RUN:-false}
SAFE_MODE=${SAFE_MODE:-false}
VERSION="v0.4-dev"
SCRIPT_PATH="$(command -v realpath >/dev/null 2>&1 && realpath "$0")"
if [[ -z "$SCRIPT_PATH" ]]; then
    SCRIPT_PATH="$(command -v readlink >/dev/null 2>&1 && readlink -f "$0")"
fi
# If neither realpath nor readlink -f is present and the script was invoked via $PATH,
# self-update will write to the current directory instead of the installed location.
SCRIPT_PATH="${SCRIPT_PATH:-$0}"

# Known behaviors:
# - Systemd unit names are assumed to be standard (ssh, docker, etc.); adjust variables if your distro differs.
# - Pending update count uses `apt-get -s upgrade | grep '^Inst'` and can undercount on localized systems.
# - WireGuard enable/disable assumes /etc/wireguard/wg0.conf exists.
# Service unit map (adjust if your distro uses different names)
SSH_UNIT="${SSH_UNIT:-ssh}"
UFW_UNIT="${UFW_UNIT:-ufw}"
FAIL2BAN_UNIT="${FAIL2BAN_UNIT:-fail2ban}"
TAILSCALE_UNIT="${TAILSCALE_UNIT:-tailscaled}"
DOCKER_UNIT="${DOCKER_UNIT:-docker}"
NETMAKER_UNIT="${NETMAKER_UNIT:-netclient}"
SCHROOT_UNIT="${SCHROOT_UNIT:-schroot}"
CROWDSEC_UNIT="${CROWDSEC_UNIT:-crowdsec}"
CROWDSEC_BOUNCER_UNIT="${CROWDSEC_BOUNCER_UNIT:-crowdsec-firewall-bouncer}"

# Colors (fall back to plain if not a TTY)
if [[ -t 1 ]]; then
    C_RED="\033[31m"; C_GRN="\033[32m"; C_YLW="\033[33m"; C_CYN="\033[36m"; C_RST="\033[0m"
else
    C_RED=""; C_GRN=""; C_YLW=""; C_CYN=""; C_RST=""
fi

ibralogo() {
    echo "=== NTX Command Center ==="
}

msgbox() {
    echo
    echo "=============================="
    echo "$1"
    echo "=============================="
    echo
}

log_line() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $message" | tee -a "$LOG_FILE"
}

load_config() {
    for cfg in /etc/ntx-menu.conf "./ntx-menu.conf"; do
        if [[ -f "$cfg" ]]; then
            # shellcheck disable=SC1090
            . "$cfg"
        fi
    done
}

rotate_log() {
    if [[ -f "$LOG_FILE" ]]; then
        local size
        size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if [[ "$size" -gt "$MAX_LOG_SIZE" ]]; then
            mv "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null || true
            if command -v gzip >/dev/null 2>&1; then
                gzip -f "${LOG_FILE}.1" 2>/dev/null || true
            fi
            touch "$LOG_FILE"
            log_line "Log rotated (previous -> ${LOG_FILE}.1)"
        fi
    fi
}

run_cmd() {
    local description="$1"; shift
    log_line "RUN: $description"
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY RUN] $*"
        log_line "OK : $description (dry run)"
        echo "Result: OK (dry run)"
        return 0
    fi
    if "$@"; then
        log_line "OK : $description"
        echo "Result: OK"
    else
        log_line "FAIL: $description"
        echo "Result: FAIL"
        return 1
    fi
}

ensure_dirs() {
    mkdir -p "$BACKUP_DIR"
    touch "$LOG_FILE"
    mkdir -p "$REPORT_DIR"
    rotate_log
}

self_update_script() {
    # Download URL points to the latest main branch script on GitHub
    local url="https://ntx-menu.re-vent.de"
    local target="$SCRIPT_PATH"
    local tmp="${target}.tmp"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY RUN] curl -fsSL \"$url\" -o \"$tmp\" && chmod +x \"$tmp\" && cp \"$target\" \"${target}.bak\" && mv \"$tmp\" \"$target\""
        log_line "OK : download latest NTX Command Center (dry run)"
        return 0
    fi

    log_line "RUN: download latest NTX Command Center from $url"
    if curl -fsSL "$url" -o "$tmp"; then
        chmod +x "$tmp" || true
        cp "$target" "${target}.bak" 2>/dev/null || true
        if mv "$tmp" "$target"; then
            log_line "OK : updated script from $url (backup: ${target}.bak)"
            echo "Updated script from $url (backup: ${target}.bak)"
        else
            log_line "FAIL: replace script with downloaded version"
            echo "Failed to replace existing script."
            rm -f "$tmp"
            return 1
        fi
    else
        log_line "FAIL: download latest NTX Command Center from $url"
        echo "Failed to download latest script from $url"
        rm -f "$tmp"
        return 1
    fi
}

ensure_cmd() {
    local binary="$1"
    local pkg="${2:-$1}"
    if ! command -v "$binary" >/dev/null 2>&1; then
        run_cmd "Installing missing dependency: $pkg" apt-get install -y "$pkg"
    fi
}

backup_file() {
    local target="$1"
    if [[ -f "$target" ]]; then
        local ts
        ts=$(date '+%Y%m%d-%H%M%S')
        local dest="$BACKUP_DIR/$(basename "$target").$ts"
        cp "$target" "$dest"
        log_line "Backup created: $dest"
    fi
}

restore_backup() {
    local target="$1"
    local latest
    latest=$(ls -1t "$BACKUP_DIR/$(basename "$target")."* 2>/dev/null | head -n 1)
    if [[ -z "$latest" ]]; then
        echo "No backup found for $target."
        return 1
    fi
    cp "$latest" "$target"
    log_line "Restored $target from $latest"
    echo "Restored $target from $latest"
}

check_environment() {
    if [[ ! -f /etc/os-release ]]; then
        echo "Cannot find /etc/os-release. Unsupported system."
        exit 1
    fi
    if ! grep -qiE 'debian|ubuntu|mint|pop' /etc/os-release; then
        echo "This script targets Debian/Ubuntu systems. Aborting."
        exit 1
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "apt-get not found. Aborting."
        exit 1
    fi
}

preflight_dependencies() {
    ensure_cmd curl curl
    ensure_cmd gpg gnupg
    ensure_cmd dig dnsutils
    ensure_cmd lsblk util-linux
    ensure_cmd df coreutils
    ensure_cmd ps procps
    ensure_cmd awk gawk
    ensure_cmd sed sed
    ensure_cmd ip iproute2
}

show_service_status() {
    local service="$1"
    local unit="$2"
    unit="${unit:-$service}"
    if ! systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q "$unit"; then
        echo -e "${C_YLW}$service: not installed${C_RST}"
        return 0
    fi
    if systemctl is-active --quiet "$unit"; then
        echo -e "${C_GRN}$service: active${C_RST}"
    else
        echo -e "${C_RED}$service: inactive${C_RST}"
    fi
}

heading() {
    echo -e "${C_CYN}$1${C_RST}"
}

cpu_mem_snapshot() {
    echo "Load / uptime: $(uptime | sed 's/^.*load average: //')"
    echo "Memory:"
    free -h
}

list_private_ips() {
    echo "IPs (IPv4) per interface:"
    ip -brief -family inet address 2>/dev/null || ip addr show
}

pending_updates_count() {
    local count
    count=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || echo 0)
    echo "Pending upgrades: ${count}"
}

kernel_version_summary() {
    local running latest
    running=$(uname -r)
    latest=$(dpkg -l 'linux-image-*' 2>/dev/null | awk '/^ii/{print $2,$3}' | sort | tail -1)
    echo "Kernel running: $running"
    echo "Kernel latest (installed): ${latest:-unknown}"
}

disk_inode_summary() {
    echo "Disk usage:"
    df -h --output=source,pcent,avail,target | sed '1d' | head -5
    echo
    echo "Inode usage:"
    df -ih --output=source,ipcent,iavail,target | sed '1d' | head -5
}

status_report_export() {
    mkdir -p "$REPORT_DIR"
    local ts
    ts=$(date '+%Y%m%d-%H%M%S')
    local report="$REPORT_DIR/status-$ts.txt"

    # Disable colors for report output
    local SAVED_RED="$C_RED" SAVED_GRN="$C_GRN" SAVED_YLW="$C_YLW" SAVED_CYN="$C_CYN" SAVED_RST="$C_RST"
    C_RED=""; C_GRN=""; C_YLW=""; C_CYN=""; C_RST=""

    {
        echo "NTX Command Center status report"
        echo "Version: $VERSION"
        echo "Timestamp: $ts"
        echo "Host: $(hostname)"
        echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
        echo
        echo "[Services]"
        show_service_status ssh "$SSH_UNIT"
        show_service_status ufw "$UFW_UNIT"
        show_service_status fail2ban "$FAIL2BAN_UNIT"
        show_service_status tailscale "$TAILSCALE_UNIT"
        show_service_status docker "$DOCKER_UNIT"
        show_service_status netmaker "$NETMAKER_UNIT"
        show_service_status crowdsec "$CROWDSEC_UNIT"
        show_service_status crowdsec-firewall-bouncer "$CROWDSEC_BOUNCER_UNIT"
        echo
        echo "[Network]"
        whats_my_ip
        list_private_ips
        echo
        echo "[Updates]"
        pending_updates_count
        kernel_version_summary
        echo
        echo "[CPU/Memory]"
        cpu_mem_snapshot
        echo
        echo "[Disk/Inodes]"
        disk_inode_summary
    } > "$report"

    # Restore colors
    C_RED="$SAVED_RED"; C_GRN="$SAVED_GRN"; C_YLW="$SAVED_YLW"; C_CYN="$SAVED_CYN"; C_RST="$SAVED_RST"

    log_line "Status report saved to $report"
    echo "Status report saved to $report"
}

maintenance_bundle() {
    echo "Running maintenance bundle (updates, cleanup, log rotate, status report)..."
    update_all
    system_cleanup
    rotate_log
    status_report_export
}

ssh_hardening_audit() {
    local cfg="/etc/ssh/sshd_config"
    if [[ ! -f "$cfg" ]]; then
        echo "sshd_config not found at $cfg"
        return 1
    fi
    echo "SSH hardening check ($cfg)"
    local pri par pwa
    pri=$(grep -Ei '^\s*PermitRootLogin' "$cfg" | tail -1 | awk '{print $2}')
    par=$(grep -Ei '^\s*PasswordAuthentication' "$cfg" | tail -1 | awk '{print $2}')
    pwa=$(grep -Ei '^\s*PubkeyAuthentication' "$cfg" | tail -1 | awk '{print $2}')
    echo "PermitRootLogin: ${pri:-default (yes on many distros)}"
    echo "PasswordAuthentication: ${par:-default (yes on many distros)}"
    echo "PubkeyAuthentication: ${pwa:-default (yes)}"
    if [[ "${pri,,}" != "no" ]]; then
        echo "Recommendation: set PermitRootLogin no"
    fi
    if [[ "${par,,}" != "no" ]]; then
        echo "Recommendation: set PasswordAuthentication no (if keys are configured)"
    fi
    if [[ -z "$pwa" || "${pwa,,}" == "yes" ]]; then
        echo "PubkeyAuthentication enabled (recommended)."
    else
        echo "Recommendation: enable PubkeyAuthentication yes"
    fi
}

docker_compose_health() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker is not installed."
        return 1
    fi
    echo "Docker info (compose plugin and services)"
    docker --version
    docker compose version 2>/dev/null || echo "docker compose plugin not found."
    echo
    echo "[Compose projects]"
    docker compose ls 2>/dev/null || echo "No compose projects or compose plugin unavailable."
    echo
    echo "[Compose services (ps --all)]"
    docker compose ps --all 2>/dev/null || echo "Compose ps not available."
}

wireguard_show_qr() {
    local cfg="${1:-/etc/wireguard/wg0.conf}"
    if [[ ! -f "$cfg" ]]; then
        echo "WireGuard config not found at $cfg"
        return 1
    fi
    if ! command -v qrencode >/dev/null 2>&1; then
        echo "qrencode not installed. Install it to render QR codes."
        return 1
    fi
    echo "Rendering QR for $cfg"
    qrencode -t ANSIUTF8 < "$cfg"
}

skip_if_safe() {
    local action="$1"
    if [[ "$SAFE_MODE" == "true" ]]; then
        echo "SAFE_MODE=true; skipping $action."
        return 1
    fi
    return 0
}

###############################################################################
# Functions
###############################################################################

# --- System update ---

update_all() {
    run_cmd "apt-get update" apt-get update
    run_cmd "apt-get upgrade" apt-get upgrade -y
}

update_all_with_sudo_reboot() {
    # keep sudo at the beginning as requested
    sudo apt install sudo && sudo apt-get update && sudo apt-get upgrade -y && sudo reboot
}

update_all_reboot_if_needed() {
    run_cmd "apt-get update" apt-get update
    run_cmd "apt-get upgrade" apt-get upgrade -y
    if [[ -f /var/run/reboot-required ]]; then
        msgbox "Reboot required after updates."
        read -p "Reboot now (y/N)? " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_line "Reboot requested after updates."
            reboot
        fi
    else
        echo "No reboot required."
    fi
}

enable_unattended_upgrades() {
    run_cmd "Install unattended-upgrades" apt-get install unattended-upgrades -y
    run_cmd "Enable unattended-upgrades service" systemctl enable --now unattended-upgrades
    echo "Unattended upgrades enabled."
}

disable_unattended_upgrades() {
    if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
        echo "unattended-upgrades is not installed."
        return 0
    fi
    run_cmd "Stop unattended-upgrades service" systemctl disable --now unattended-upgrades
    echo "Unattended upgrades disabled."
}

check_unattended_status() {
    if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
        echo "unattended-upgrades is not installed. Please enable it first."
        return 1
    fi
    echo "Service status:"
    systemctl status unattended-upgrades --no-pager || true
    echo
    echo "APT::Periodic settings:"
    apt-config dump APT::Periodic | sed 's/::/ - /'
    echo
    echo "Recent unattended-upgrades log:"
    tail -n 20 /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null || echo "No log entries found."
}

run_unattended_upgrade_now() {
    if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
        echo "unattended-upgrades is not installed. Please enable it first."
        return 1
    fi
    run_cmd "Run unattended-upgrade now" unattended-upgrade -v
}

list_custom_sources() {
    echo "Custom sources (.list) in /etc/apt/sources.list.d:"
    ls -1 /etc/apt/sources.list.d/*.list 2>/dev/null || echo "None found."
}

remove_custom_source() {
    read -p "Enter path to .list file to remove: " SRC_FILE
    [[ -z "$SRC_FILE" ]] && { echo "No file provided."; return 1; }
    if [[ ! -f "$SRC_FILE" ]]; then
        echo "File not found: $SRC_FILE"
        return 1
    fi
    if ! skip_if_safe "removing $SRC_FILE"; then return 1; fi
    read -p "Remove $SRC_FILE? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        run_cmd "Remove custom source $SRC_FILE" rm -f "$SRC_FILE"
        run_cmd "apt-get update after source removal" apt-get update
    else
        echo "Cancelled."
    fi
}

apt_health_check() {
    msgbox "APT health check"
    echo "[Held packages]"
    apt-mark showhold || true
    echo
    echo "[Broken deps check]"
    apt-get check || true
    echo
    echo "[Security updates (simulated)]"
    apt-get -s upgrade 2>/dev/null | grep -i security || echo "None detected (simulated)."
}

update_health_check() {
    echo "[Reboot required]"
    if [[ -f /var/run/reboot-required ]]; then
        echo "Yes"
    else
        echo "No"
    fi
    echo
    echo "[Last apt update timestamp]"
    if [[ -f /var/lib/apt/periodic/update-success-stamp ]]; then
        stat -c '%y' /var/lib/apt/periodic/update-success-stamp 2>/dev/null || stat -f '%Sm' /var/lib/apt/periodic/update-success-stamp 2>/dev/null
    else
        echo "No record found; run apt-get update."
    fi
}

# --- DNS management ---

show_dns() {
    cat /etc/resolv.conf
}

edit_dns() {
    backup_file /etc/resolv.conf
    nano /etc/resolv.conf
}

# Append Netcup DNS (46.38.225.230 + 1.1.1.1)
add_dns_netcup_append() {
    backup_file /etc/resolv.conf
    echo -e "nameserver 46.38.225.230\nnameserver 1.1.1.1" | tee -a /etc/resolv.conf > /dev/null
}

# Overwrite with Netcup DNS (46.38.225.230 + 1.1.1.1)
set_dns_netcup_overwrite() {
    backup_file /etc/resolv.conf
    cat <<EOF > /etc/resolv.conf
nameserver 46.38.225.230
nameserver 1.1.1.1
EOF
}

# Overwrite with Cloudflare + Google DNS (1.1.1.1 + 8.8.8.8)
set_dns_cloudflare_google() {
    backup_file /etc/resolv.conf
    cat <<EOF > /etc/resolv.conf
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
}

add_dns_cloudflare_google_append() {
    backup_file /etc/resolv.conf
    echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" | tee -a /etc/resolv.conf > /dev/null
}

set_dns_cloudflare_google_ipv6() {
    backup_file /etc/resolv.conf
    cat <<EOF > /etc/resolv.conf
nameserver 2606:4700:4700::1111
nameserver 2001:4860:4860::8888
EOF
}

add_dns_cloudflare_google_ipv6_append() {
    backup_file /etc/resolv.conf
    echo -e "nameserver 2606:4700:4700::1111\nnameserver 2001:4860:4860::8888" | tee -a /etc/resolv.conf > /dev/null
}

restore_dns_backup() {
    restore_backup /etc/resolv.conf
}

# --- Networking / IP ---

whats_my_ip() {
    ensure_cmd dig dnsutils
    if ! dig +short myip.opendns.com @resolver1.opendns.com; then
        echo "OpenDNS lookup failed, trying Cloudflare..."
        dig +short txt ch whoami.cloudflare @1.0.0.1
    fi
}

show_ifconfig() {
    ifconfig
}

show_routes() {
    if command -v ip >/dev/null 2>&1; then
        ip route show
    else
        netstat -rn
    fi
}

show_connections() {
    if command -v ss >/dev/null 2>&1; then
        ss -tup
    else
        netstat -tupn
    fi
}

ping_common() {
    ensure_cmd ping iputils-ping
    for host in 1.1.1.1 8.8.8.8 github.com; do
        echo "Pinging $host..."
        ping -c 3 -W 2 "$host" || true
        echo
    done
}

trace_route() {
    ensure_cmd traceroute traceroute
    read -p "Enter host/IP to traceroute: " TARGET
    [[ -z "$TARGET" ]] && { echo "No target provided."; return 1; }
    traceroute "$TARGET"
}

# --- Speedtest & benchmarks ---

install_speedtest_full() {
    apt-get install curl -y
    curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash
    apt-get install speedtest -y
}

change_speedtest_apt_list() {
    cat <<EOF > /etc/apt/sources.list.d/ookla_speedtest-cli.list
# this file was generated by packagecloud.io for
# the repository at https://packagecloud.io/ookla/speedtest-cli

deb [signed-by=/etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg] https://packagecloud.io/ookla/speedtest-cli/ubuntu/ jammy main
deb-src [signed-by=/etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg] https://packagecloud.io/ookla/speedtest-cli/ubuntu/ jammy main
EOF
}

install_speedtest_after_list() {
    apt-get update && apt-get install speedtest -y
}

run_speedtest() {
    speedtest
}

run_yabs() {
    curl -sL https://yabs.sh | bash
}

run_yabs_all() {
    msgbox "Benchmark - All Tests"
    curl -sL https://yabs.sh | bash
}

run_yabs_disk() {
    msgbox "Benchmark - Disk Performance"
    curl -sL https://yabs.sh | bash -s -- -ig
}

run_yabs_network() {
    msgbox "Benchmark - Network Performance"
    curl -sL https://yabs.sh | bash -s -- -fg
}

run_yabs_system_old() {
    msgbox "Benchmark - System Performance (older version)"
    curl -sL https://yabs.sh | bash -s -- -fi4
}

run_yabs_system() {
    msgbox "Benchmark - System Performance"
    curl -sL https://yabs.sh | bash -s -- -fi
}

remove_speedtest_repo() {
    if [[ -f /etc/apt/sources.list.d/ookla_speedtest-cli.list ]]; then
        run_cmd "Remove Speedtest repo list" rm -f /etc/apt/sources.list.d/ookla_speedtest-cli.list
    fi
    if [[ -f /etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg ]]; then
        run_cmd "Remove Speedtest keyring" rm -f /etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg
    fi
    run_cmd "apt-get update after Speedtest repo removal" apt-get update
}

# --- Security / remote access ---

change_ssh_proxmox() {
    curl -fsSL "https://cloud.io.anatolium.eu/s/jR9crxfoLHz5474/download" | bash
}

install_openssh() {
    apt update
    apt install openssh-server -y
    systemctl enable --now ssh
}

tailscale_install() {
    curl -fsSL https://tailscale.com/install.sh | sh
}

tailscale_up_qr() {
    tailscale up -qr
}

install_netclient() {
    run_cmd "Install dependencies for netclient" apt-get install -y curl gpg
    run_cmd "Add Netmaker GPG key" bash -c "curl -fsSL 'https://apt.netmaker.org/gpg.key' | gpg --dearmor -o /usr/share/keyrings/netmaker-keyring.gpg"
    run_cmd "Add Netmaker apt repository" bash -c "echo \"deb [signed-by=/usr/share/keyrings/netmaker-keyring.gpg] https://apt.netmaker.org stable main\" > /etc/apt/sources.list.d/netclient.list"
    run_cmd "apt-get update (netclient)" apt-get update
    run_cmd "Install netclient" apt-get install -y netclient
}

remove_netclient_repo() {
    if [[ -f /etc/apt/sources.list.d/netclient.list ]]; then
        run_cmd "Remove Netmaker repo list" rm -f /etc/apt/sources.list.d/netclient.list
    fi
    if [[ -f /usr/share/keyrings/netmaker-keyring.gpg ]]; then
        run_cmd "Remove Netmaker keyring" rm -f /usr/share/keyrings/netmaker-keyring.gpg
    fi
    run_cmd "apt-get update after Netmaker repo removal" apt-get update
}

install_wireguard_client() {
    run_cmd "Install WireGuard (client)" apt-get install -y wireguard wireguard-tools
}

install_wireguard_server() {
    run_cmd "Install WireGuard (server)" apt-get install -y wireguard wireguard-tools
    echo "Remember to configure /etc/wireguard/wg0.conf and enable via: systemctl enable --now wg-quick@wg0"
}

print_wireguard_sample() {
    cat <<'EOF'
[Interface]
PrivateKey = <server-private-key>
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = <client-public-key>
AllowedIPs = 10.0.0.2/32
EOF
    echo "Sample only. Replace keys/addresses and save as /etc/wireguard/wg0.conf, then run: systemctl enable --now wg-quick@wg0"
}

enable_wg_quick() {
    run_cmd "Enable and start wg-quick@wg0" systemctl enable --now wg-quick@wg0
}

disable_wg_quick() {
    run_cmd "Disable wg-quick@wg0" systemctl disable --now wg-quick@wg0
}

install_crowdsec() {
    run_cmd "Install CrowdSec repo" bash -c "curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"
    run_cmd "Install crowdsec" apt-get install -y crowdsec
    show_service_status crowdsec
}

install_crowdsec_firewall_bouncer() {
    run_cmd "Install CrowdSec firewall bouncer (iptables)" apt-get install -y crowdsec-firewall-bouncer-iptables
    show_service_status crowdsec-firewall-bouncer
}

install_ufw_basic() {
    apt update
    apt install ufw -y
    ufw allow 22/tcp
    echo "y" | ufw enable
    ufw status
}

install_fail2ban() {
    apt update
    apt install fail2ban -y
    systemctl enable --now fail2ban
}

show_firewall_status() {
    if command -v ufw >/dev/null 2>&1; then
        ufw status
    else
        echo "UFW not installed."
    fi
}

show_ssh_status() {
    if systemctl list-unit-files | grep -q ssh.service; then
        systemctl status ssh --no-pager || true
    else
        echo "SSH service not found."
    fi
}

install_and_scan_clamav() {
    msgbox "Installing ClamAV"
    apt update
    apt install clamav clamav-daemon -y
    msgbox "Updating virus definitions"
    # Note: freshclam may fail if the daemon holds the DB lock; consider stopping/reloading clamav-freshclam before updating.
    systemctl stop clamav-freshclam 2>/dev/null || true
    freshclam || echo "freshclam failed (may require service stop); continuing..."
    systemctl start clamav-freshclam 2>/dev/null || true
    read -p "Path to scan (default: /home): " CLAM_PATH
    CLAM_PATH=${CLAM_PATH:-/home}
    msgbox "Running ClamAV quick scan on $CLAM_PATH (ctrl+c to stop)"
    clamscan -r "$CLAM_PATH"
}

firewall_preset_ssh_only() {
    install_ufw_basic
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw --force enable
    msgbox "UFW preset applied: SSH only"
}

firewall_preset_web() {
    install_ufw_basic
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw --force enable
    msgbox "UFW preset applied: SSH + HTTP/HTTPS"
}

firewall_preset_deny_all_except_ssh() {
    install_ufw_basic
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw --force enable
    msgbox "UFW preset applied: deny all except SSH"
}

install_google_authenticator() {
    msgbox "Installing Google Authenticator PAM"
    apt update
    apt install libpam-google-authenticator -y
    echo "Run 'google-authenticator' as the target user to configure; update /etc/pam.d/sshd and /etc/ssh/sshd_config per your policy."
}

backup_config_bundle() {
    local ts
    ts=$(date '+%Y%m%d-%H%M%S')
    local dest="$BACKUP_DIR/config-backup-$ts.tar.gz"
    tar -czf "$dest" /etc/ssh/sshd_config /etc/wireguard 2>/dev/null /etc/fail2ban /etc/ufw/applications.d 2>/dev/null || true
    log_line "Config backup created: $dest"
    echo "Config backup saved to $dest"
}

fail2ban_summary() {
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        echo "Fail2ban not installed."
        return 1
    fi
    fail2ban-client status
    echo
    echo "Reloading jails..."
    fail2ban-client reload || true
    echo
    echo "Top offenders (auth.log):"
    if [[ -f /var/log/auth.log ]]; then
        grep 'Ban ' /var/log/auth.log | awk '{print $NF}' | sort | uniq -c | sort -nr | head
    else
        echo "auth.log not found."
    fi
}

wireguard_validate_config() {
    local cfg="/etc/wireguard/wg0.conf"
    if [[ ! -f "$cfg" ]]; then
        echo "WireGuard config not found at $cfg"
        return 1
    fi
    if wg-quick strip "$cfg" >/dev/null 2>&1; then
        echo "Config syntax looks OK ($cfg)"
    else
        echo "Config validation failed for $cfg"
        return 1
    fi
}

wireguard_start_wgquick() {
    systemctl start wg-quick@wg0
}

wireguard_stop_wgquick() {
    systemctl stop wg-quick@wg0
}

wireguard_reload_wgquick() {
    systemctl restart wg-quick@wg0
}

log_integrity_report() {
    local size sha
    if [[ -f "$LOG_FILE" ]]; then
        size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        sha=$(sha256sum "$LOG_FILE" 2>/dev/null | awk '{print $1}')
        echo "Log size: $size bytes"
        echo "SHA256 : ${sha:-unavailable}"
    else
        echo "Log file not found: $LOG_FILE"
    fi
    if compgen -G "${LOG_FILE}.1*" > /dev/null; then
        echo "Rotated logs present: $(ls -1 ${LOG_FILE}.1* | wc -l)"
    fi
}

docker_rootless_check() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    echo "Docker rootless info:"
    docker info --format 'Rootless: {{.SecurityOptions}}' 2>/dev/null || echo "Could not determine rootless status."
    loginctl show-user "$(whoami)" | grep Linger || true
    echo "Note: enable rootless per Docker docs if needed."
}

docker_privileged_containers() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    echo "Privileged containers:"
    docker ps --filter "status=running" --filter "status=exited" --format '{{.Names}} {{.ID}} {{.Status}}' | while read -r name id status; do
        if docker inspect --format '{{.HostConfig.Privileged}}' "$id" 2>/dev/null | grep -qi true; then
            echo "$name ($id) - $status"
        fi
    done
}

rootkit_check() {
    msgbox "Installing/Preparing Rootkit Check"
    run_cmd "Install chkrootkit" apt install chkrootkit -y
    ibralogo
    msgbox "Rootkit Check"
    chkrootkit
}

# --- System information ---

os_release_check() {
    cat /etc/os-release
}

visit_project_github() {
    msgbox "NTX Linux Utility Menu - GitHub"
    echo "https://github.com/ntx007/ntx-linux-utility-menu"
}

general_information() {
    apt install neofetch -y
    msgbox "Neofetch"
    neofetch
}

memory_information() {
    msgbox "Memory Information"
    free -h
    read -p "Press Enter to continue..."
    dmidecode -t memory
}

vm_check() {
    systemd-detect-virt
}

check_display() {
    sudo lshw -c display
}

# --- Maintenance / disks ---

system_cleanup() {
    if ! skip_if_safe "system cleanup"; then return 1; fi
    apt-get autoremove -y
    apt-get autoclean -y
    journalctl --vacuum-time=7d 2>/dev/null || true
}

show_disks() {
    echo "lsblk:"
    lsblk
    echo
    echo "df -h:"
    df -h
}

show_big_var_dirs() {
    echo "Largest directories in /var (top 10):"
    du -sh /var/* 2>/dev/null | sort -h | tail
}

show_failed_logins() {
    if command -v lastb >/dev/null 2>&1; then
        lastb | head
    else
        echo "lastb not available."
    fi
}

# --- Users & time ---

create_sudo_user() {
    read -p "Enter new username: " NEWUSER
    if id "$NEWUSER" &>/dev/null; then
        echo "User $NEWUSER already exists."
        return
    fi
    adduser "$NEWUSER"
    usermod -aG sudo "$NEWUSER"
    echo "User $NEWUSER created and added to sudo group."
}

show_time_sync() {
    timedatectl
}

install_chrony() {
    apt update
    apt install chrony -y
    systemctl enable --now chrony
    timedatectl
}

# --- System control ---

system_reboot() {
    if ! skip_if_safe "reboot"; then return 1; fi
    msgbox "System Reboot"
    read -p "Are you sure (y/N)? " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        reboot
    fi
}

system_powerdown() {
    if ! skip_if_safe "power down"; then return 1; fi
    msgbox "System Power Down"
    read -p "Are you sure (y/N)? " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        /sbin/shutdown -h now
    fi
}

tail_logs() {
    heading "Last 40 log lines ($LOG_FILE)"
    tail -n 40 "$LOG_FILE" 2>/dev/null || echo "Log file not found."
}

show_config() {
    heading "Config / Environment"
    cat <<EOF
Version:        $VERSION
Log file:       $LOG_FILE
Backup dir:     $BACKUP_DIR
DRY_RUN:        $DRY_RUN
SAFE_MODE:      $SAFE_MODE
Units:          SSH=$SSH_UNIT, UFW=$UFW_UNIT, Fail2ban=$FAIL2BAN_UNIT, Tailscale=$TAILSCALE_UNIT, Docker=$DOCKER_UNIT, Netmaker=$NETMAKER_UNIT, CrowdSec=$CROWDSEC_UNIT, Bouncer=$CROWDSEC_BOUNCER_UNIT
EOF
}

show_help_about() {
    heading "NTX Command Center ($VERSION)"
    cat <<EOF
Log file: $LOG_FILE (rotates at ~$(($MAX_LOG_SIZE/1024)) KiB)
Backups:  $BACKUP_DIR (resolv.conf snapshots)
Dry run:  $DRY_RUN (set DRY_RUN=true to preview commands)
Safe mode: $SAFE_MODE (set SAFE_MODE=true to skip destructive actions)
Repo:     https://github.com/ntx007/ntx-linux-utility-menu

Use the main menu to choose a section, then pick an action.
Shortcuts: h/help, l/log tail, q/quit.
Config:   see 'Show config/env' option.
EOF
}

status_dashboard() {
    heading "Status dashboard"
    show_service_status ssh "$SSH_UNIT"
    show_service_status ufw "$UFW_UNIT"
    show_service_status fail2ban "$FAIL2BAN_UNIT"
    show_service_status tailscale "$TAILSCALE_UNIT"
    show_service_status docker "$DOCKER_UNIT"
    show_service_status netmaker "$NETMAKER_UNIT"
    show_service_status crowdsec "$CROWDSEC_UNIT"
    show_service_status crowdsec-firewall-bouncer "$CROWDSEC_BOUNCER_UNIT"
    if [[ -f /var/run/reboot-required ]]; then
        echo -e "${C_YLW}Reboot required.${C_RST}"
    fi
    echo "Public IP:"
    whats_my_ip
    list_private_ips
    pending_updates_count
    kernel_version_summary
    disk_inode_summary
    cpu_mem_snapshot
}

###############################################################################
# Menus
###############################################################################

main_menu() {
    cat <<EOF
================= NTX COMMAND CENTER ($VERSION) =================
 1) System update
 2) DNS management
 3) Network / IP
 4) Speedtest & benchmarks
 5) Security / remote access
 6) Tools & environment
 7) Containers / Docker
 8) Monitoring
 9) System information
10) Maintenance / disks
11) Users & time
12) System control
h) Help / About
s) Status dashboard
l) Tail logs
c) Show config/env
u) Update NTX Command Center
q) Quit
================================================================
EOF
}

search_section() {
    local query="$1"
    local -a names=("system update" "dns" "network" "speedtest" "security" "tools" "containers" "monitoring" "system information" "maintenance" "users" "control" "help" "status" "logs" "config" "update")
    local -a targets=(1 2 3 4 5 6 7 8 9 10 11 12 h s l c u)
    local matches=()
    for i in "${!names[@]}"; do
        if [[ "${names[$i]}" == *"$query"* ]]; then
            matches+=("${targets[$i]}")
        fi
    done
    if [[ ${#matches[@]} -eq 1 ]]; then
        echo "${matches[0]}"
    elif [[ ${#matches[@]} -gt 1 ]]; then
        echo "Matches: ${matches[*]}"
    else
        echo ""
    fi
}

run_action_by_name() {
    local action="$1"
    case "$action" in
        update_all) update_all ;;
        maintenance_bundle) maintenance_bundle ;;
        status_report|status_report_export) status_report_export ;;
        status_dashboard) status_dashboard ;;
        ssh_audit|ssh_hardening) ssh_hardening_audit ;;
        docker_compose_health) docker_compose_health ;;
        wireguard_qr|wg_qr) wireguard_show_qr ;;
        *)
            echo "Unknown action: $action"
            echo "Supported: update_all, maintenance_bundle, status_report, status_dashboard, ssh_audit, docker_compose_health, wireguard_qr"
            return 1
            ;;
    esac
}

print_usage() {
    cat <<EOF
Usage: $0 [--run ACTION]

Actions (non-interactive):
  update_all            Run apt-get update && upgrade
  maintenance_bundle    Update, cleanup, rotate log, export status report
  status_report         Export status report to file
  status_dashboard      Print status dashboard
  ssh_audit             Run SSH hardening check
  docker_compose_health Show Docker Compose health (ls/ps)
  wireguard_qr          Render /etc/wireguard/wg0.conf as QR (requires qrencode)
EOF
}

menu_update() {
    while true; do
        cat <<EOF
[System update]
 1) Update all (apt-get update && upgrade)
 2) Update all with sudo and reboot
 3) Update all and reboot if required
 4) Enable unattended upgrades
 5) Disable unattended upgrades
 6) Check unattended upgrades status
 7) Run unattended upgrade now
 8) List custom apt sources
 9) Remove custom apt source (.list)
10) APT health check (held/broken/security)
11) Update health (reboot + last update)
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) update_all ;;
            2) update_all_with_sudo_reboot ;;
            3) update_all_reboot_if_needed ;;
            4) enable_unattended_upgrades ;;
            5) disable_unattended_upgrades ;;
            6) check_unattended_status ;;
            7) run_unattended_upgrade_now ;;
            8) list_custom_sources ;;
            9) remove_custom_source ;;
            10) apt_health_check ;;
            11) update_health_check ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_dns() {
    while true; do
        cat <<EOF
[DNS management]
 1) Show DNS (/etc/resolv.conf)
 2) Edit DNS (nano)
 3) Append Netcup DNS 46.38.225.230 + 1.1.1.1
 4) Overwrite Netcup DNS 46.38.225.230 + 1.1.1.1
 5) Overwrite DNS with 1.1.1.1 + 8.8.8.8
 6) Append DNS with 1.1.1.1 + 8.8.8.8
 7) Overwrite DNS with IPv6 (2606:4700:4700::1111 + 2001:4860:4860::8888)
 8) Append DNS with IPv6 (2606:4700:4700::1111 + 2001:4860:4860::8888)
 9) Restore DNS from latest backup
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) show_dns ;;
            2) edit_dns ;;
            3) add_dns_netcup_append ;;
            4) set_dns_netcup_overwrite ;;
            5) set_dns_cloudflare_google ;;
            6) add_dns_cloudflare_google_append ;;
            7) set_dns_cloudflare_google_ipv6 ;;
            8) add_dns_cloudflare_google_ipv6_append ;;
            9) restore_dns_backup ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_network() {
    while true; do
        cat <<EOF
[Network / IP]
 1) Show public IP
 2) Show ifconfig
 3) Show routing table
 4) Show active connections
 5) Ping common endpoints
 6) Traceroute to host
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) whats_my_ip ;;
            2) show_ifconfig ;;
            3) show_routes ;;
            4) show_connections ;;
            5) ping_common ;;
            6) trace_route ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_bench() {
    while true; do
        cat <<EOF
[Speedtest & benchmarks]
 1) Install Speedtest (repo + package)
 2) Update Speedtest repo list (jammy)
 3) Install Speedtest after repo update
 4) Run Speedtest
 5) Run YABS
 6) Remove Speedtest repo/key
 7) Benchmark presets (YABS submenu)
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) install_speedtest_full ;;
            2) change_speedtest_apt_list ;;
            3) install_speedtest_after_list ;;
            4) run_speedtest ;;
            5) run_yabs ;;
            6) remove_speedtest_repo ;;
            7) menu_yabs_presets ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_yabs_presets() {
    while true; do
        cat <<EOF
[YABS benchmark presets]
 1) Benchmark - All Tests
 2) Benchmark - Disk Performance
 3) Benchmark - Network Performance
 4) Benchmark - System Performance (older version)
 5) Benchmark - System Performance
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) run_yabs_all ;;
            2) run_yabs_disk ;;
            3) run_yabs_network ;;
            4) run_yabs_system_old ;;
            5) run_yabs_system ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_security() {
    while true; do
        cat <<EOF
[Security / remote access]
 1) Install UFW (allow SSH, enable)
 2) Install Fail2ban
 3) Update SSH config for Proxmox (remote script)
 4) Install OpenSSH server
 5) Install Tailscale
 6) Tailscale up (QR mode)
 7) Install Netmaker netclient
 8) Remove Netmaker repo/key
 9) Show firewall status
10) Show SSH status
11) Show recent failed logins
12) Install CrowdSec
13) Install CrowdSec firewall bouncer (iptables)
14) Install WireGuard (client)
15) Install WireGuard (server)
16) Show WireGuard sample config
17) Enable wg-quick@wg0
18) Disable wg-quick@wg0
19) SSH hardening check
20) Show WireGuard config as QR (wg0.conf)
21) Rootkit check (installs chkrootkit)
22) Install ClamAV + run quick scan
23) Fail2ban summary + reload
24) UFW preset: SSH only
25) UFW preset: SSH + HTTP/HTTPS
26) UFW preset: deny all except SSH
27) Install Google Authenticator (PAM)
28) Backup config bundle (SSH/WireGuard/Fail2ban/UFW)
29) WireGuard: validate config
30) WireGuard: start wg-quick@wg0
31) WireGuard: stop wg-quick@wg0
32) WireGuard: restart wg-quick@wg0
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) install_ufw_basic ;;
            2) install_fail2ban ;;
            3) change_ssh_proxmox ;;
            4) install_openssh ;;
            5) tailscale_install ;;
            6) tailscale_up_qr ;;
            7) install_netclient ;;
            8) remove_netclient_repo ;;
            9) show_firewall_status ;;
            10) show_ssh_status ;;
            11) show_failed_logins ;;
            12) install_crowdsec ;;
            13) install_crowdsec_firewall_bouncer ;;
            14) install_wireguard_client ;;
            15) install_wireguard_server ;;
            16) print_wireguard_sample ;;
            17) enable_wg_quick ;;
            18) disable_wg_quick ;;
            19) ssh_hardening_audit ;;
            20) wireguard_show_qr ;;
            21) rootkit_check ;;
            22) install_and_scan_clamav ;;
            23) fail2ban_summary ;;
            24) firewall_preset_ssh_only ;;
            25) firewall_preset_web ;;
            26) firewall_preset_deny_all_except_ssh ;;
            27) install_google_authenticator ;;
            28) backup_config_bundle ;;
            29) wireguard_validate_config ;;
            30) wireguard_start_wgquick ;;
            31) wireguard_stop_wgquick ;;
            32) wireguard_reload_wgquick ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_tools() {
    while true; do
        cat <<EOF
[Tools & environment]
 1) Install essentials (sudo, nano, curl, net-tools)
 2) Install extra tools (unzip, python, gdown, glances, tmux, zsh, mc)
 3) Install ibramenu
 4) Install QEMU guest agent
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) install_essentials ;;
            2) install_tools ;;
            3) install_ibramenu ;;
            4) install_qemu_guest_agent ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_containers() {
    while true; do
        cat <<EOF
[Containers / Docker]
 1) Install Docker & Docker Compose plugin
 2) Docker service status
 3) Docker info (short)
 4) Docker ps (running containers)
 5) Docker Compose health (ls/ps)
 6) List all Docker containers
 7) Docker rootless check
 8) List privileged containers
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) install_docker ;;
            2) docker_service_status ;;
            3) docker_info_short ;;
            4) docker_ps ;;
            5) docker_compose_health ;;
            6) docker_list_all ;;
            7) docker_rootless_check ;;
            8) docker_privileged_containers ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_monitoring() {
    while true; do
        cat <<EOF
[Monitoring]
 1) Install node exporter
 2) Show top CPU/mem processes
 3) Show IO stats (iostat)
 4) SMART health check (first disk)
 5) Status dashboard (services + IP)
 6) Export status report to file
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) install_node_exporter ;;
            2) show_top_processes ;;
            3) show_iostat_summary ;;
            4) smart_health_check ;;
            5) status_dashboard ;;
            6) status_report_export ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_sysinfo() {
    while true; do
        cat <<EOF
[System information]
 1) Show /etc/os-release
 2) General system info (neofetch)
 3) Memory information
 4) VM / virtualization check
 5) Visit project GitHub
 6) Show video adapters (lshw display)
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) os_release_check ;;
            2) general_information ;;
            3) memory_information ;;
            4) vm_check ;;
            5) visit_project_github ;;
            6) check_display ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_maintenance() {
    while true; do
        cat <<EOF
[Maintenance / disks]
 1) System cleanup (APT autoremove/autoclean, logs 7d)
 2) Show disks (lsblk + df -h)
 3) Show biggest /var directories
 4) Run maintenance bundle (update + cleanup + log rotate + status report)
 5) Log integrity (size + SHA256)
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) system_cleanup ;;
            2) show_disks ;;
            3) show_big_var_dirs ;;
            4) maintenance_bundle ;;
            5) log_integrity_report ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_users_time() {
    while true; do
        cat <<EOF
[Users & time]
 1) Create sudo user
 2) Show time sync (timedatectl)
 3) Install chrony (NTP) and show time status
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) create_sudo_user ;;
            2) show_time_sync ;;
            3) install_chrony ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_control() {
    while true; do
        cat <<EOF
[System control]
 1) Reboot
 2) Power down
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) system_reboot ;;
            2) system_powerdown ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

###############################################################################
# Main
###############################################################################

RUN_ACTION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --run)
            RUN_ACTION="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

# Root check
if [[ $EUID -ne 0 ]]; then
   echo "Please run as root (e.g. sudo bash $0)."
   exit 1
fi
load_config

check_environment
ensure_dirs
preflight_dependencies
log_line "Starting NTX Command Center..."

echo "Starting NTX Command Center $VERSION..."

if [[ -n "$RUN_ACTION" ]]; then
    run_action_by_name "$RUN_ACTION"
    exit $?
fi

while true; do
    main_menu
    read -p "Select a section: " choice
    if [[ "$choice" == /* ]]; then
        choice="${choice#/}"
        choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
        resolved=$(search_section "$choice")
        if [[ "$resolved" == Matches:* ]]; then
            echo "$resolved"
            continue
        elif [[ -n "$resolved" ]]; then
            choice="$resolved"
        else
            echo "No match for \"$choice\""
            continue
        fi
    fi
    case "$choice" in
        1) menu_update ;;
        2) menu_dns ;;
        3) menu_network ;;
        4) menu_bench ;;
        5) menu_security ;;
        6) menu_tools ;;
        7) menu_containers ;;
        8) menu_monitoring ;;
        9) menu_sysinfo ;;
        10) menu_maintenance ;;
        11) menu_users_time ;;
        12) menu_control ;;
        u|U) self_update_script ;;
        h|H) show_help_about ;;
        c|C) show_config ;;
        s|S) status_dashboard ;;
        l|L) tail_logs ;;
        q|Q|0) echo "Exiting NTX Command Center."; exit 0 ;;
        *)  echo "Invalid choice." ;;
    esac
    echo
    read -p "Press Enter to continue..."
done
