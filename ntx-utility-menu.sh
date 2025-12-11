#!/bin/bash

###############################################################################
# NTX Command Center - Simple server helper menu
# Version: v0.7-dev
###############################################################################

LOG_FILE="/var/log/ntx-menu.log"
BACKUP_DIR="/var/backups/ntx-menu"
REPORT_DIR="/var/log/ntx-menu-reports"
MAX_LOG_SIZE=$((1024 * 1024)) # 1 MiB
LOG_HISTORY=${LOG_HISTORY:-3}
DRY_RUN=${DRY_RUN:-false}
SAFE_MODE=${SAFE_MODE:-false}
VERSION="v0.7-dev"
LANGUAGE="${LANGUAGE:-en}"
UPDATE_WARN_DAYS=${UPDATE_WARN_DAYS:-7}
AUTO_UPDATE_BEFORE_MAINT=${AUTO_UPDATE_BEFORE_MAINT:-false}
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

t() {
    local key="$1"
    case "$LANGUAGE:$key" in
        de:main.title) echo "================= NTX BEFEHLSZENTRALE ($VERSION) =================" ;;
        de:main.opts) cat <<'EOF'
 1) Systemupdate
 2) DNS Verwaltung
 3) Netzwerk / IP
 4) Speedtest & Benchmarks
 5) Sicherheit / Remote
 6) Tools & Umgebung
 7) Container / Docker
 8) Monitoring
 9) Systeminfo
10) Wartung / Disks
11) Benutzer & Zeit
12) Proxmox-Helfer
13) Systemsteuerung
h) Hilfe / Info
s) Status-Dashboard
l) Logs ansehen
c) Konfig/Umgebung anzeigen
u) NTX Command Center aktualisieren
d) Sprache umschalten (en/de)
q) Beenden
EOF
        ;;
        de:status.reboot) echo "Neustart erforderlich." ;;
        *) echo "================= NTX COMMAND CENTER ($VERSION) =================" ;;
    esac
}

toggle_language() {
    if [[ "$LANGUAGE" == "en" ]]; then
        LANGUAGE="de"
        echo "Sprache umgestellt auf Deutsch."
    else
        LANGUAGE="en"
        echo "Language switched to English."
    fi
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
            # Cleanup old rotations beyond LOG_HISTORY
            local keep=$LOG_HISTORY
            if [[ "$keep" -gt 0 ]]; then
                ls -1t ${LOG_FILE}.1* 2>/dev/null | tail -n +$((keep+1)) | xargs -r rm -f
            fi
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
    local target="$SCRIPT_PATH"
    local tmp="${target}.tmp"
    local choice tag url

    echo "[Self-update] Choose source:"
    echo " 1) Latest release (GitHub)"
    echo " 2) Pick a release tag (GitHub)"
    echo " 3) Latest dev (main branch)"
    echo " 0) Cancel"
    read -p "Select: " choice

    case "$choice" in
        1)
            tag=$(curl -fsSL "https://api.github.com/repos/ntx007/ntx-linux-utility-menu/releases?per_page=1" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | head -n1 | cut -d'"' -f4)
            if [[ -z "$tag" ]]; then
                echo "Could not determine latest release; falling back to main."
                url="https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main/ntx-utility-menu.sh"
            else
                url="https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/${tag}/ntx-utility-menu.sh"
            fi
            ;;
        2)
            echo "Fetching recent releases..."
            mapfile -t tags < <(curl -fsSL "https://api.github.com/repos/ntx007/ntx-linux-utility-menu/releases?per_page=15" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4)
            if [[ ${#tags[@]} -eq 0 ]]; then
                echo "No tags retrieved; falling back to main."
                url="https://ntx-menu.re-vent.de"
            else
                local i=1
                for t in "${tags[@]}"; do
                    echo " $i) $t"
                    i=$((i+1))
                done
                read -p "Select release (1-${#tags[@]}): " sel
                sel=${sel:-1}
                tag=${tags[$((sel-1))]}
                if [[ -z "$tag" ]]; then
                    echo "Invalid selection; cancelling."
                    return 1
                fi
                url="https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/${tag}/ntx-utility-menu.sh"
            fi
            ;;
        3)
            url="https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main/ntx-utility-menu.sh"
            ;;
        0)
            echo "Update cancelled."
            return 0
            ;;
        *)
            echo "Invalid choice; cancelling."
            return 1
            ;;
    esac

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY RUN] curl -fsSL \"$url\" -o \"$tmp\" && chmod +x \"$tmp\" && cp \"$target\" \"${target}.bak\" && mv \"$tmp\" \"$target\""
        log_line "OK : download NTX Command Center (dry run)"
        return 0
    fi

    log_line "RUN: download NTX Command Center from $url"
    if curl -fsSL "$url" -o "$tmp"; then
        chmod +x "$tmp" || true
        cp "$target" "${target}.bak" 2>/dev/null || true
        if mv "$tmp" "$target"; then
            log_line "OK : updated script from $url (backup: ${target}.bak)"
            echo "Updated script from $url (backup: ${target}.bak)"
            read -p "Restart NTX Command Center now to use the update? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                echo "Exiting so you can restart the updated script."
                exit 0
            else
                echo "Update applied. Restart manually to load the new version."
            fi
        else
            log_line "FAIL: replace script with downloaded version"
            echo "Failed to replace existing script."
            rm -f "$tmp"
            return 1
        fi
    else
        log_line "FAIL: download NTX Command Center from $url"
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
    ensure_cmd ip iproute2
    echo "IPs (IPv4) per interface:"
    if ! ip -brief -family inet address 2>/dev/null; then
        ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "No IP utility available (ip/ifconfig missing)."
    fi
}

update_cadence_warn() {
    local mode="${1:-prompt}"
    if [[ -f /var/lib/apt/periodic/update-success-stamp ]]; then
        local last
        last=$(stat -c '%Y' /var/lib/apt/periodic/update-success-stamp 2>/dev/null || stat -f '%m' /var/lib/apt/periodic/update-success-stamp 2>/dev/null)
        local now
        now=$(date +%s)
        local days=$(( (now - last) / 86400 ))
        if (( days > UPDATE_WARN_DAYS )); then
            if [[ "$mode" == "prompt" ]]; then
                echo "Warning: last apt-get update is ${days} days ago (threshold: ${UPDATE_WARN_DAYS}d)."
            fi
            return 0
        fi
    fi
    return 1
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
    df -h | head -20
    echo
    echo "Inode usage:"
    if ! df -ih | head -20; then
        echo "Inode view unavailable (df -i not supported in this environment)."
    fi
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

status_report_json() {
    mkdir -p "$REPORT_DIR"
    local ts
    ts=$(date '+%Y%m%d-%H%M%S')
    local report="$REPORT_DIR/status-$ts.json"
    {
        echo "{"
        echo "  \"version\": \"$VERSION\","
        echo "  \"timestamp\": \"$ts\","
        echo "  \"host\": \"$(hostname)\","
        echo "  \"uptime\": \"$(uptime -p 2>/dev/null || uptime)\","
        echo "  \"reboot_required\": \"$( [[ -f /var/run/reboot-required ]] && echo yes || echo no )\","
        echo "  \"pending_updates\": \"$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || echo 0)\","
        echo "  \"kernel_running\": \"$(uname -r)\","
        echo "  \"services\": {"
        echo "    \"ssh\": \"$(systemctl is-active ssh >/dev/null 2>&1 && echo active || echo inactive)\","
        echo "    \"ufw\": \"$(systemctl is-active ufw >/dev/null 2>&1 && echo active || echo inactive)\","
        echo "    \"fail2ban\": \"$(systemctl is-active fail2ban >/dev/null 2>&1 && echo active || echo inactive)\","
        echo "    \"tailscale\": \"$(systemctl is-active tailscaled >/dev/null 2>&1 && echo active || echo inactive)\","
        echo "    \"docker\": \"$(systemctl is-active docker >/dev/null 2>&1 && echo active || echo inactive)\""
        echo "  }"
        echo "}"
    } > "$report"
    log_line "Status report (json) saved to $report"
    echo "Status report (json) saved to $report"
    if [[ -n "$STATUS_UPLOAD_PATH" ]]; then
        mkdir -p "$STATUS_UPLOAD_PATH"
        cp "$report" "$STATUS_UPLOAD_PATH"/ 2>/dev/null || true
    fi
}

maintenance_bundle() {
    echo "Running maintenance bundle (updates, cleanup, log rotate, status report)..."
    if update_cadence_warn "silent"; then
        if [[ "$AUTO_UPDATE_BEFORE_MAINT" == "true" ]]; then
            echo "AUTO_UPDATE_BEFORE_MAINT=true, running apt-get update..."
            run_cmd "apt-get update (maintenance bundle)" apt-get update
        fi
    fi
    update_all
    system_cleanup
    rotate_log
    status_report_export
}

ssh_hardening_audit() {
    local cfg="/etc/ssh/sshd_config"
    if [[ ! -f "$cfg" ]]; then
        echo "sshd_config not found at $cfg (SSH not installed? skipping audit)"
        return 0
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
    if ! run_cmd "apt-get update" apt-get update; then
        echo "apt-get update failed (network/proxy?). Skipping upgrade."
        return 1
    fi
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
    echo -e "nameserver 46.38.225.230\nnameserver 46.38.252.230\nnameserver 1.1.1.1" | tee -a /etc/resolv.conf > /dev/null
}

# Overwrite with Netcup DNS (46.38.225.230 + 1.1.1.1)
set_dns_netcup_overwrite() {
    backup_file /etc/resolv.conf
    cat <<EOF > /etc/resolv.conf
nameserver 46.38.225.230
nameserver 46.38.252.230
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
    local file="/etc/ssh/sshd_config"
    backup_file "$file"
    if [[ ! -f "$file" ]]; then
        echo "sshd_config not found at $file"
        return 1
    fi
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' "$file"
    sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' "$file"
    systemctl reload sshd 2>/dev/null || systemctl restart sshd
    echo "sshd_config adjusted. Backup: ${file}.bak"
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

install_essentials() {
    apt update
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
    apt install iproute2 -y
    apt install npm -y
    apt-get install sudo -y
    apt-get install nano -y
    apt-get install curl -y
    apt-get install net-tools -y
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

install_ntxmenu_path() {
    local url_base="https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main"
    local tmpdir
    tmpdir=$(mktemp -d)
    local script_path="${tmpdir}/ntx-utility-menu.sh"
    local wrapper_path="${tmpdir}/ntxmenu"
    echo "Downloading latest scripts to install into /usr/local/bin..."
    if ! curl -fsSL "${url_base}/ntx-utility-menu.sh" -o "$script_path"; then
        echo "Failed to download ntx-utility-menu.sh"
        rm -rf "$tmpdir"
        return 1
    fi
    if ! curl -fsSL "${url_base}/ntxmenu" -o "$wrapper_path"; then
        echo "Failed to download ntxmenu wrapper"
        rm -rf "$tmpdir"
        return 1
    fi
    chmod +x "$script_path" "$wrapper_path"
    if install -m 0755 "$script_path" /usr/local/bin/ntx-utility-menu && install -m 0755 "$wrapper_path" /usr/local/bin/ntxmenu; then
        echo "Installed to /usr/local/bin: ntx-utility-menu and ntxmenu"
    else
        echo "Install failed. Do you have sufficient privileges?"
    fi
    rm -rf "$tmpdir"
}

menu_essentials() {
    while true; do
        cat <<EOF
[Essentials bundle]
 1) Install essentials bundle (sudo, nano, curl, net-tools, iproute2, unzip, python3-pip, gcc/python3-dev, psutil, gdown, dos2unix, glances, tmux, zsh, mc, npm)
 2) Re-run essentials bundle
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1|2) install_essentials ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
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
    msgbox "Virus definitions"
    echo "1) Stop freshclam, update, restart"
    echo "2) Update without touching daemon"
    read -p "Choice [1/2]: " CHOICE
    if [[ "$CHOICE" == "1" ]]; then
        systemctl stop clamav-freshclam 2>/dev/null || true
        freshclam || echo "freshclam failed"
        systemctl start clamav-freshclam 2>/dev/null || true
    else
        freshclam || echo "freshclam failed (may require service stop); continuing..."
    fi
    echo "Scan target:"
    echo "1) /home"
    echo "2) Custom path"
    echo "3) /media (removable)"
    read -p "Select: " target_choice
    case "$target_choice" in
        1) CLAM_PATH="/home" ;;
        2) read -p "Enter path: " CLAM_PATH ;;
        3) CLAM_PATH="/media" ;;
        *) CLAM_PATH="/home" ;;
    esac
    msgbox "Running ClamAV quick scan on $CLAM_PATH (ctrl+c to stop)"
    mkdir -p "$REPORT_DIR"
    local report="$REPORT_DIR/clamav-$(date '+%Y%m%d-%H%M%S').log"
    clamscan -r "$CLAM_PATH" | tee "$report"
    echo "ClamAV report saved to $report"
}

firewall_preset_ssh_only() {
    ufw_snapshot_rules
    install_ufw_basic
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw --force enable
    msgbox "UFW preset applied: SSH only"
}

firewall_preset_web() {
    ufw_snapshot_rules
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
    ufw_snapshot_rules
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

ufw_snapshot_rules() {
    mkdir -p "$BACKUP_DIR"
    local ts
    ts=$(date '+%Y%m%d-%H%M%S')
    local snap="$BACKUP_DIR/ufw-snapshot-$ts.rules"
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > "$snap" 2>/dev/null || true
    fi
    echo "UFW snapshot saved to $snap"
}

ufw_revert_snapshot() {
    local latest
    latest=$(ls -1t "$BACKUP_DIR"/ufw-snapshot-*.rules 2>/dev/null | head -n 1)
    if [[ -z "$latest" ]]; then
        echo "No UFW snapshot found in $BACKUP_DIR"
        return 1
    fi
    msgbox "Restoring UFW from snapshot $latest"
    if command -v iptables-restore >/dev/null 2>&1; then
        iptables-restore < "$latest" 2>/dev/null || echo "iptables-restore may have failed; check status."
        ufw reload 2>/dev/null || true
    else
        echo "iptables-restore not available; cannot restore snapshot."
        return 1
    fi
}

backup_config_bundle() {
    local ts
    ts=$(date '+%Y%m%d-%H%M%S')
    read -p "Optional: path to Docker Compose files to include (leave blank to skip): " COMPOSE_PATH
    local dest="$BACKUP_DIR/config-backup-$ts.tar.gz"
    tar -czf "$dest" /etc/ssh/sshd_config /etc/wireguard 2>/dev/null /etc/fail2ban /etc/ufw/applications.d 2>/dev/null || true
    if [[ -n "$COMPOSE_PATH" && -d "$COMPOSE_PATH" ]]; then
        tar -rf "$dest" -C "$COMPOSE_PATH" . 2>/dev/null || true
    fi
    log_line "Config backup created: $dest"
    echo "Config backup saved to $dest"
}

restore_config_bundle() {
    local latest
    latest=$(ls -1t "$BACKUP_DIR"/config-backup-*.tar.gz 2>/dev/null | head -n 1)
    if [[ -z "$latest" ]]; then
        echo "No config backup found in $BACKUP_DIR"
        return 1
    fi
    echo "Available backups:"
    ls -1t "$BACKUP_DIR"/config-backup-*.tar.gz 2>/dev/null | nl
    read -p "Select backup number (default 1): " sel
    sel=${sel:-1}
    local chosen
    chosen=$(ls -1t "$BACKUP_DIR"/config-backup-*.tar.gz 2>/dev/null | sed -n "${sel}p")
    if [[ -z "$chosen" ]]; then
        echo "Invalid selection."
        return 1
    fi
    msgbox "Restoring config backup: $chosen"
    tar -xzf "$chosen" -C / || { echo "Restore failed"; return 1; }
    echo "Restore completed from $chosen"
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

fail2ban_list_bans() {
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        echo "Fail2ban not installed."
        return 1
    fi
    fail2ban-client status || true
    fail2ban-client status | awk '/Jail list/{$1=$2=\"\"; gsub(/ /,\"\",$0); gsub(/,/,\" \",$0); print $0}' | while read -r jail; do
        [[ -z "$jail" ]] && continue
        echo "Banned IPs for $jail:"
        fail2ban-client status "$jail" | awk '/Banned IP list/{print $NF}'
    done
}

fail2ban_unban_ip() {
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        echo "Fail2ban not installed."
        return 1
    fi
    read -p "Enter jail name: " JAIL
    read -p "Enter IP to unban: " IP
    if [[ -z "$JAIL" || -z "$IP" ]]; then
        echo "Jail or IP missing."
        return 1
    fi
    fail2ban-client set "$JAIL" unbanip "$IP"
}

wireguard_validate_config() {
    read -p "WireGuard interface (default wg0): " IFACE
    IFACE=${IFACE:-wg0}
    local cfg="/etc/wireguard/${IFACE}.conf"
    if [[ ! -f "$cfg" ]]; then
        echo "WireGuard config not found at $cfg"
        return 1
    fi
    read -p "Optional new config to diff/validate (leave blank to use current): " NEWCFG
    if [[ -n "$NEWCFG" && -f "$NEWCFG" ]]; then
        diff -u "$cfg" "$NEWCFG" || true
        cfg="$NEWCFG"
    fi
    if wg-quick strip "$cfg" >/dev/null 2>&1; then
        echo "Config syntax looks OK ($cfg)"
    else
        echo "Config validation failed for $cfg"
        return 1
    fi
}

wireguard_start_wgquick() {
    read -p "WireGuard interface to start (default wg0): " IFACE
    IFACE=${IFACE:-wg0}
    systemctl start "wg-quick@${IFACE}"
}

wireguard_stop_wgquick() {
    read -p "WireGuard interface to stop (default wg0): " IFACE
    IFACE=${IFACE:-wg0}
    systemctl stop "wg-quick@${IFACE}"
}

wireguard_reload_wgquick() {
    read -p "WireGuard interface to restart (default wg0): " IFACE
    IFACE=${IFACE:-wg0}
    systemctl restart "wg-quick@${IFACE}"
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

dockers_with_host_network() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    echo "Containers using host network:"
    docker ps --format '{{.Names}} {{.ID}}' | while read -r name id; do
        if docker inspect --format '{{.HostConfig.NetworkMode}}' "$id" 2>/dev/null | grep -q "^host"; then
            echo "$name ($id)"
        fi
    done
}

docker_containers_running_as_root() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    echo "Containers running as root (User unset or 0):"
    docker ps --format '{{.Names}} {{.ID}}' | while read -r name id; do
        local user
        user=$(docker inspect --format '{{.Config.User}}' "$id" 2>/dev/null)
        if [[ -z "$user" || "$user" == "0" ]]; then
            echo "$name ($id) user=${user:-root}"
        fi
    done
}

docker_sensitive_mounts() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    echo "Containers with sensitive mounts (/var/run/docker.sock or /etc):"
    docker ps --filter "status=running" --format '{{.Names}} {{.ID}}' | while read -r name id; do
        if docker inspect --format '{{json .Mounts}}' "$id" 2>/dev/null | grep -E 'docker\.sock|/etc' >/dev/null; then
            echo "$name ($id)"
        fi
    done
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
    # Virtio disks often need -d scsi; fall back if plain check fails.
    if [[ "$disk" == /dev/vd* ]]; then
        smartctl -H -d scsi "$disk" || {
            echo "SMART check failed for $disk. Try: smartctl -a -d scsi $disk"
            return 1
        }
    else
        smartctl -H "$disk" || {
            echo "SMART check failed for $disk. Try: smartctl -a -d sat $disk"
            return 1
        }
    fi
}

rootkit_check() {
    msgbox "Installing/Preparing Rootkit Check"
    run_cmd "Install chkrootkit" apt install chkrootkit binutils -y
    ibralogo
    msgbox "Rootkit Check"
    if ! command -v strings >/dev/null 2>&1; then
        echo "'strings' not found; install binutils and re-run if this check fails."
    fi
    chkrootkit || echo "chkrootkit reported an issue (see above)."
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
    ensure_cmd lshw lshw
    sudo lshw -c display
}

list_pct_containers() {
    if ! command -v pct >/dev/null 2>&1; then
        echo "pct not found (Proxmox tools missing)."
        return 1
    fi
    pct list
}

pct_enter_shell() {
    if ! command -v pct >/dev/null 2>&1; then
        echo "pct not found (Proxmox tools missing)."
        return 1
    fi
    read -p "Enter VMID to enter: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    pct enter "$VMID"
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
        echo -e "${C_YLW}$( [[ "$LANGUAGE" == "de" ]] && echo "Neustart erforderlich." || echo "Reboot required.")${C_RST}"
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
    if [[ "$LANGUAGE" == "de" ]]; then
        t "main.title"
        t "main.opts"
    else
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
12) Proxmox helpers
13) System control
h) Help / About
s) Status dashboard
l) Tail logs
c) Show config/env
u) Update NTX Command Center
d) Toggle language (en/de)
i) Install ntxmenu to PATH
q) Quit
================================================================
EOF
    fi
}

search_section() {
    local query="$1"
    local -a names=("system update" "dns" "network" "speedtest" "security" "tools" "containers" "monitoring" "system information" "maintenance" "users" "proxmox" "control" "help" "status" "logs" "config" "update" "language" "install")
    local -a targets=(1 2 3 4 5 6 7 8 9 10 11 12 13 h s l c u d i)
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
        status_report_json) status_report_json ;;
        status_dashboard) status_dashboard ;;
        ssh_audit|ssh_hardening) ssh_hardening_audit ;;
        docker_compose_health) docker_compose_health ;;
        wireguard_qr|wg_qr) wireguard_show_qr ;;
        apt_health) apt_health_check ;;
        update_health) update_health_check ;;
        clamav_scan) install_and_scan_clamav ;;
        *)
            echo "Unknown action: $action"
            echo "Supported: update_all, maintenance_bundle, status_report, status_report_json, status_dashboard, ssh_audit, docker_compose_health, wireguard_qr, apt_health, update_health, clamav_scan"
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
 3) Append Netcup DNS 46.38.225.230 + 46.38.252.230 + 1.1.1.1
 4) Overwrite Netcup DNS 46.38.225.230 + 46.38.252.230 + 1.1.1.1
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
 1) Firewall (UFW) submenu
 2) Fail2ban submenu
 3) SSH / Access submenu
 4) WireGuard submenu
 5) CrowdSec / Netmaker / Tailscale submenu
 6) Anti-malware (ClamAV / Rootkit)
 7) Config backup/restore submenu
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) menu_firewall ;;
            2) menu_fail2ban ;;
            3) menu_ssh_access ;;
            4) menu_wireguard ;;
            5) menu_agents ;;
            6) menu_antimalware ;;
            7) menu_config_backup ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_firewall() {
    while true; do
        cat <<EOF
[Firewall / UFW]
 1) Show firewall status
 2) Install UFW (allow SSH, enable)
 3) UFW preset: SSH only
 4) UFW preset: SSH + HTTP/HTTPS
 5) UFW preset: deny all except SSH
 6) UFW: revert last snapshot
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) show_firewall_status ;;
            2) install_ufw_basic ;;
            3) firewall_preset_ssh_only ;;
            4) firewall_preset_web ;;
            5) firewall_preset_deny_all_except_ssh ;;
            6) ufw_revert_snapshot ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_fail2ban() {
    while true; do
        cat <<EOF
[Fail2ban]
 1) Install Fail2ban
 2) Fail2ban summary + reload
 3) Fail2ban: list banned IPs
 4) Fail2ban: unban IP
 5) Show recent failed logins
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) install_fail2ban ;;
            2) fail2ban_summary ;;
            3) fail2ban_list_bans ;;
            4) fail2ban_unban_ip ;;
            5) show_failed_logins ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_ssh_access() {
    while true; do
        cat <<EOF
[SSH / Access]
 1) Show SSH status
 2) SSH hardening check
 3) Update SSH config for Proxmox (PermitRootLogin yes)
 4) Install OpenSSH server
 5) Install Google Authenticator (PAM)
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) show_ssh_status ;;
            2) ssh_hardening_audit ;;
            3) change_ssh_proxmox ;;
            4) install_openssh ;;
            5) install_google_authenticator ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_wireguard() {
    while true; do
        cat <<EOF
[WireGuard]
 1) Install WireGuard (client)
 2) Install WireGuard (server)
 3) Show WireGuard sample config
 4) Validate config (choose interface, optional diff)
 5) Start interface (prompt, default wg0)
 6) Stop interface (prompt, default wg0)
 7) Restart interface (prompt, default wg0)
 8) Show WireGuard config as QR (wg0.conf)
 9) Enable wg-quick@wg0 (default; enable/start)
10) Disable wg-quick@wg0 (default)
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) install_wireguard_client ;;
            2) install_wireguard_server ;;
            3) print_wireguard_sample ;;
            4) wireguard_validate_config ;;
            5) wireguard_start_wgquick ;;
            6) wireguard_stop_wgquick ;;
            7) wireguard_reload_wgquick ;;
            8) wireguard_show_qr ;;
            9) enable_wg_quick ;;
            10) disable_wg_quick ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_agents() {
    while true; do
        cat <<EOF
[CrowdSec / Netmaker / Tailscale]
 1) Install Tailscale
 2) Tailscale up (QR mode)
 3) Install Netmaker netclient
 4) Remove Netmaker repo/key
 5) Install CrowdSec
 6) Install CrowdSec firewall bouncer (iptables)
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) tailscale_install ;;
            2) tailscale_up_qr ;;
            3) install_netclient ;;
            4) remove_netclient_repo ;;
            5) install_crowdsec ;;
            6) install_crowdsec_firewall_bouncer ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_antimalware() {
    while true; do
        cat <<EOF
[Anti-malware]
 1) Rootkit check (installs chkrootkit)
 2) Install ClamAV + run quick scan
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) rootkit_check ;;
            2) install_and_scan_clamav ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_config_backup() {
    while true; do
        cat <<EOF
[Config backup/restore]
 1) Backup config bundle (SSH/WireGuard/Fail2ban/UFW)
 2) Restore config bundle (choose backup)
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) backup_config_bundle ;;
            2) restore_config_bundle ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_tools() {
    while true; do
        cat <<EOF
[Tools & environment]
 1) Essentials bundle submenu
 2) Install ibramenu
 3) Install QEMU guest agent
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) menu_essentials ;;
            2) install_ibramenu ;;
            3) install_qemu_guest_agent ;;
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
 9) Containers with sensitive mounts
10) Containers running as root
11) Containers using host network
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
            9) docker_sensitive_mounts ;;
            10) docker_containers_running_as_root ;;
            11) dockers_with_host_network ;;
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
 7) Export status report to JSON
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
            7) status_report_json ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

menu_proxmox() {
    while true; do
        cat <<EOF
[Proxmox helpers]
 1) List containers (pct list)
 2) Enter container shell (pct enter <vmid>)
 3) Update SSH config for Proxmox (remote script)
 0) Back
EOF
        read -p "Select: " c
        case "$c" in
            1) list_pct_containers ;;
            2) pct_enter_shell ;;
            3) change_ssh_proxmox ;;
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
        12) menu_proxmox ;;
        13) menu_control ;;
        u|U) self_update_script ;;
        d|D) toggle_language ;;
        h|H) show_help_about ;;
        c|C) show_config ;;
        s|S) status_dashboard ;;
        l|L) tail_logs ;;
        i|I) install_ntxmenu_path ;;
        q|Q|0) echo "Exiting NTX Command Center."; exit 0 ;;
        *)  echo "Invalid choice." ;;
    esac
done
