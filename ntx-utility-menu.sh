#!/bin/bash

###############################################################################
# NTX Command Center - Simple server helper menu
# Version: v0.2
###############################################################################

LOG_FILE="/var/log/ntx-menu.log"
BACKUP_DIR="/var/backups/ntx-menu"
VERSION="v0.2"

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

run_cmd() {
    local description="$1"; shift
    log_line "RUN: $description"
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
    if ! grep -qiE 'debian|ubuntu' /etc/os-release; then
        echo "This script targets Debian/Ubuntu systems. Aborting."
        exit 1
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "apt-get not found. Aborting."
        exit 1
    fi
}

show_service_status() {
    local service="$1"
    if systemctl is-active --quiet "$service"; then
        echo "$service: active"
    else
        echo "$service: inactive"
        systemctl status "$service" --no-pager || true
    fi
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
    msgbox "System Reboot"
    read -p "Are you sure (y/N)? " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        reboot
    fi
}

system_powerdown() {
    msgbox "System Power Down"
    read -p "Are you sure (y/N)? " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        /sbin/shutdown -h now
    fi
}

###############################################################################
# Menu
###############################################################################

show_menu() {
    echo "================= NTX COMMAND CENTER ================="
    echo "================= SYSTEM UPDATE ======================="
    echo " 1) Update all (apt-get update && upgrade)"
    echo " 2) Update all with sudo and reboot"
    echo " 3) Update all and reboot if required"
    echo " 4) Enable unattended upgrades"
    echo " 5) Check unattended upgrades status"
    echo " 6) Run unattended upgrade now"
    echo
    echo "================= DNS MANAGEMENT ======================"
    echo " 7) Show DNS (/etc/resolv.conf)"
    echo " 8) Edit DNS (/etc/resolv.conf in nano)"
    echo " 9) Append Netcup DNS 46.38.225.230 + 1.1.1.1"
    echo "10) Overwrite Netcup DNS 46.38.225.230 + 1.1.1.1"
    echo "11) Overwrite DNS with 1.1.1.1 + 8.8.8.8"
    echo "12) Restore DNS from latest backup"
    echo
    echo "================ NETWORK / IP ========================="
    echo "13) Show public IP (dig / OpenDNS)"
    echo "14) Show ifconfig"
    echo "15) Show routing table"
    echo "16) Show active connections"
    echo
    echo "============= SPEEDTEST & BENCHMARKS =================="
    echo "17) Install Speedtest (repo + package)"
    echo "18) Update Speedtest repo list (jammy)"
    echo "19) Install Speedtest after repo update"
    echo "20) Run Speedtest"
    echo "21) Run YABS (Yet-Another-Bench-Script)"
    echo
    echo "============= SECURITY / REMOTE ACCESS ================"
    echo "22) Install UFW (allow SSH, enable)"
    echo "23) Install Fail2ban"
    echo "24) Update SSH config for Proxmox (remote script)"
    echo "25) Install OpenSSH server"
    echo "26) Install Tailscale"
    echo "27) Tailscale up (QR mode)"
    echo "28) Install Netmaker netclient"
    echo
    echo "========== TOOLS & ENVIRONMENT SETUP =================="
    echo "29) Install essentials (sudo, nano, curl, net-tools)"
    echo "30) Install extra tools (unzip, python, gdown, glances, tmux, zsh, mc)"
    echo "31) Install ibramenu"
    echo "32) Install QEMU guest agent"
    echo
    echo "============= CONTAINERS / DOCKER ====================="
    echo "33) Install Docker & Docker Compose plugin"
    echo
    echo "================== MONITORING ========================="
    echo "34) Install node exporter (prometheus-node-exporter)"
    echo "35) Show top CPU/mem processes"
    echo "36) Show IO stats (iostat)"
    echo "37) SMART health check (first disk)"
    echo
    echo "============ SYSTEM INFORMATION ======================="
    echo "38) Show /etc/os-release"
    echo "39) General system info (neofetch)"
    echo "40) Memory information"
    echo "41) VM / virtualization check"
    echo "42) Visit project GitHub"
    echo
    echo "================= MAINTENANCE ========================="
    echo "43) System cleanup (APT autoremove/autoclean, logs 7d)"
    echo "44) Show disks (lsblk + df -h)"
    echo "45) Show biggest /var directories"
    echo
    echo "=============== USERS & TIME =========================="
    echo "46) Create sudo user"
    echo "47) Show time sync (timedatectl)"
    echo "48) Install chrony (NTP) and show time status"
    echo
    echo "================ SYSTEM CONTROL ======================="
    echo "49) Reboot"
    echo "50) Power down"
    echo
    echo " 0) Exit"
    echo "======================================================="
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
log_line "Starting NTX Command Center..."

echo "Starting NTX Command Center $VERSION..."

while true; do
    show_menu
    read -p "Select an option: " choice
    case "$choice" in
        1)  update_all ;;
        2)  update_all_with_sudo_reboot ;;
        3)  update_all_reboot_if_needed ;;
        4)  enable_unattended_upgrades ;;
        5)  check_unattended_status ;;
        6)  run_unattended_upgrade_now ;;
        7)  show_dns ;;
        8)  edit_dns ;;
        9)  add_dns_netcup_append ;;
        10) set_dns_netcup_overwrite ;;
        11) set_dns_cloudflare_google ;;
        12) restore_dns_backup ;;
        13) whats_my_ip ;;
        14) show_ifconfig ;;
        15) show_routes ;;
        16) show_connections ;;
        17) install_speedtest_full ;;
        18) change_speedtest_apt_list ;;
        19) install_speedtest_after_list ;;
        20) run_speedtest ;;
        21) run_yabs ;;
        22) install_ufw_basic ;;
        23) install_fail2ban ;;
        24) change_ssh_proxmox ;;
        25) install_openssh ;;
        26) tailscale_install ;;
        27) tailscale_up_qr ;;
        28) install_netclient ;;
        29) install_essentials ;;
        30) install_tools ;;
        31) install_ibramenu ;;
        32) install_qemu_guest_agent ;;
        33) install_docker ;;
        34) install_node_exporter ;;
        35) show_top_processes ;;
        36) show_iostat_summary ;;
        37) smart_health_check ;;
        38) os_release_check ;;
        39) general_information ;;
        40) memory_information ;;
        41) vm_check ;;
        42) visit_project_github ;;
        43) system_cleanup ;;
        44) show_disks ;;
        45) show_big_var_dirs ;;
        46) create_sudo_user ;;
        47) show_time_sync ;;
        48) install_chrony ;;
        49) system_reboot ;;
        50) system_powerdown ;;
        0)  echo "Exiting NTX Command Center."; exit 0 ;;
        *)  echo "Invalid choice." ;;
    esac
    echo
    read -p "Press Enter to continue..."
done
