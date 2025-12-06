#!/bin/bash

###############################################################################
# NTX Command Center - Simple server helper menu
# Version: v0.3-dev
###############################################################################

LOG_FILE="/var/log/ntx-menu.log"
BACKUP_DIR="/var/backups/ntx-menu"
MAX_LOG_SIZE=$((1024 * 1024)) # 1 MiB
DRY_RUN=${DRY_RUN:-false}
SAFE_MODE=${SAFE_MODE:-false}
VERSION="v0.3-dev"

# Colors (fall back to plain if not a TTY)
if [[ -t 1 ]]; then
    C_RED="\033[31m"; C_GRN="\033[32m"; C_YLW="\033[33m"; C_CYN="\033[36m"; C_RST="\033[0m"
else
    C_RED=""; C_GRN=""; C_YLW=""; C_CYN=""; C_RST=""
fi

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

rotate_log() {
    if [[ -f "$LOG_FILE" ]]; then
        local size
        size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if [[ "$size" -gt "$MAX_LOG_SIZE" ]]; then
            mv "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null || true
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
        return 0
    fi
    if "$@"; then
        log_line "OK : $description"
    else
        log_line "FAIL: $description"
        return 1
    fi
}

ensure_dirs() {
    mkdir -p "$BACKUP_DIR"
    touch "$LOG_FILE"
    rotate_log
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
    if ! systemctl list-unit-files "$service" --no-legend 2>/dev/null | grep -q "$service"; then
        echo -e "${C_YLW}$service: not installed${C_RST}"
        return 0
    fi
    if systemctl is-active --quiet "$service"; then
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

remove_speedtest_repo() {
    if [[ -f /etc/apt/sources.list.d/ookla_speedtest-cli.list ]]; then
        run_cmd "Remove Speedtest repo list" rm -f /etc/apt/sources.list.d/ookla_speedtest-cli.list
    fi
    if [[ -f /etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg ]]; then
        run_cmd "Remove Speedtest keyring" rm -f /etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg
    fi
    run_cmd "apt-get update after Speedtest repo removal" apt-get update
}

# --- SSH / remote access / security ---

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

# --- Tools & environment ---

install_essentials() {
    apt update
    apt-get install sudo -y
    apt-get install nano -y
    apt-get install curl -y
    apt-get install net-tools -y
}

install_tools() {
    apt update
    apt-get install sudo curl net-tools -y
    apt install unzip -y
    apt install python3-pip -y
    apt-get install gcc python3-dev -y
    pip install --no-binary :all: psutil
    pip3 install gdown
    apt install dos2unix -y
    apt install glances -y
    apt install tmux -y
    apt install zsh -y
    apt install mc -y
}

install_ibramenu() {
    wget -qO ./i https://raw.githubusercontent.com/ibracorp/ibramenu/main/ibrainit.sh
    chmod +x i
    ./i
}

install_qemu_guest_agent() {
    apt update
    apt install qemu-guest-agent -y
    systemctl enable --now qemu-guest-agent
}

# --- Containers / Docker ---

install_docker() {
    apt update
    apt install ca-certificates curl gnupg -y
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo \$VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
    apt update
    apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
    systemctl enable --now docker
}

docker_service_status() {
    show_service_status docker
}

docker_ps() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
}

docker_info_short() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    docker info --format 'Server Version: {{.ServerVersion}}\nStorage Driver: {{.Driver}}\nCgroup Driver: {{.CgroupDriver}}'
}

# --- Monitoring ---

install_node_exporter() {
    apt update
    apt install prometheus-node-exporter -y
    systemctl enable --now prometheus-node-exporter
}

show_top_processes() {
    ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head
}

show_iostat_summary() {
    ensure_cmd iostat sysstat
    iostat -x 5 3
}

smart_health_check() {
    ensure_cmd smartctl smartmontools
    local disk
    disk=$(lsblk -ndo NAME,TYPE | awk '$2=="disk"{print "/dev/"$1; exit}')
    if [[ -z "$disk" ]]; then
        echo "No disk found for SMART check."
        return 1
    fi
    smartctl -H "$disk"
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
EOF
}

status_dashboard() {
    heading "Status dashboard"
    show_service_status ssh
    show_service_status ufw
    show_service_status fail2ban
    show_service_status tailscaled
    show_service_status docker
    show_service_status netclient
    show_service_status crowdsec
    show_service_status crowdsec-firewall-bouncer
    if [[ -f /var/run/reboot-required ]]; then
        echo -e "${C_YLW}Reboot required.${C_RST}"
    fi
    echo "Public IP:"
    whats_my_ip
    list_private_ips
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
q) Quit
================================================================
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
 6) Restore DNS from latest backup
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) show_dns ;;
            2) edit_dns ;;
            3) add_dns_netcup_append ;;
            4) set_dns_netcup_overwrite ;;
            5) set_dns_cloudflare_google ;;
            6) restore_dns_backup ;;
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
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) install_docker ;;
            2) docker_service_status ;;
            3) docker_info_short ;;
            4) docker_ps ;;
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
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) install_node_exporter ;;
            2) show_top_processes ;;
            3) show_iostat_summary ;;
            4) smart_health_check ;;
            5) status_dashboard ;;
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
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) os_release_check ;;
            2) general_information ;;
            3) memory_information ;;
            4) vm_check ;;
            5) visit_project_github ;;
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
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) system_cleanup ;;
            2) show_disks ;;
            3) show_big_var_dirs ;;
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

# Root check
if [[ $EUID -ne 0 ]]; then
   echo "Please run as root (e.g. sudo bash $0)."
   exit 1
fi

check_environment
ensure_dirs
preflight_dependencies
log_line "Starting NTX Command Center..."

echo "Starting NTX Command Center $VERSION..."

while true; do
    main_menu
    read -p "Select a section: " choice
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
        h|H) show_help_about ;;
        s|S) status_dashboard ;;
        l|L) tail_logs ;;
        q|Q|0) echo "Exiting NTX Command Center."; exit 0 ;;
        *)  echo "Invalid choice." ;;
    esac
    echo
    read -p "Press Enter to continue..."
done
