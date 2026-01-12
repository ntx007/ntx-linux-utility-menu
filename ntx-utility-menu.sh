#!/bin/bash
set -eEuo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Dieses Skript muss als Root ausgeführt werden (sudo)."
   exit 1
fi

###############################################################################
# NTX Command Center - Simple server helper menu
# Version: v1.4.0-dev
###############################################################################

LOG_FILE="/var/log/ntx-menu.log"
ERROR_LOG="/var/log/ntx-utility.log"
BACKUP_DIR="/var/backups/ntx-menu"
REPORT_DIR="/var/log/ntx-menu-reports"
MAX_LOG_SIZE=$((1024 * 1024)) # 1 MiB
LOG_HISTORY=${LOG_HISTORY:-3}
BACKUP_COMPRESS=${BACKUP_COMPRESS:-gzip}
BACKUP_KEEP=${BACKUP_KEEP:-5}
DRY_RUN=${DRY_RUN:-false}
SAFE_MODE=${SAFE_MODE:-false}
CONFIRM=${CONFIRM:-true}
VERSION="v1.4.0-dev"
UPDATE_NOTICE=""
HEADER_CPU=""
HEADER_RAM=""
HEADER_HOST=""
HEADER_IP=""
HEADER_PUBLIC_IP=""
HEADER_PUBLIC_TIMEOUT="${HEADER_PUBLIC_TIMEOUT:-3}"
LANGUAGE="${LANGUAGE:-en}"
UPDATE_WARN_DAYS=${UPDATE_WARN_DAYS:-7}
POST_INSTALL_LOG="${POST_INSTALL_LOG:-/var/log/ntx-menu-app-installs.log}"
STATUS_UPLOAD_PATH="${STATUS_UPLOAD_PATH:-}"
AUTO_UPDATE_BEFORE_MAINT=${AUTO_UPDATE_BEFORE_MAINT:-false}
PKG_MGR=""
DISTRO_ID=""
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
SSH_UNIT_DEFAULT="ssh"
SSH_UNIT="${SSH_UNIT:-$SSH_UNIT_DEFAULT}"
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

confirm_prompt() {
    local prompt="$1"
    local default_no="${2:-true}"
    if [[ "$CONFIRM" != "true" ]]; then
        return 0
    fi
    if [[ "$default_no" == "true" ]]; then
        read -p "$prompt (y/N): " -n 1 -r
    else
        read -p "$prompt (Y/n): " -n 1 -r
    fi
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

log_line() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $message" | tee -a "$LOG_FILE"
}

log_error() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | ERROR | $message" >> "$ERROR_LOG" 2>/dev/null || true
}

trap 'rc=$?; log_error "line $LINENO: $BASH_COMMAND (exit $rc)"' ERR

render_header() {
    local title="$1"
    local bar="===============================================================================" 
    echo "$bar"
    echo " $title"
    echo " Host: ${HEADER_HOST:-unknown} | Threads: ${HEADER_CPU:-?} | RAM: ${HEADER_RAM:-?} GiB | LAN: ${HEADER_IP:-unknown} | WAN: ${HEADER_PUBLIC_IP:-unknown}"
    echo " Distro: ${DISTRO_ID:-unknown} | Package mgr: ${PKG_MGR:-unknown}"
    echo " Repo: https://github.com/ntx007/ntx-linux-utility-menu"
    [[ -n "$UPDATE_NOTICE" ]] && echo " Update: $UPDATE_NOTICE"
    echo "$bar"
}

render_footer() {
    local bar="===============================================================================" 
    echo "$bar"
    echo " Shortcuts: h=Help  s=Status  l=Logs  c=Config  u=Update  d=Lang  m=CMatrix  i=Install  q=Quit"
    echo "$bar"
}

t() {
    local key="$1"
    case "$LANGUAGE:$key" in
        de:main.title) echo "=========================== NTX BEFEHLSZENTRALE ($VERSION) ===========================" ;;
        de:main.opts) cat <<'EOF'
[Kern]
 1) Systemupdate
 2) DNS-Verwaltung
 3) Netzwerk / IP
 4) Speedtest & Benchmarks
 5) Sicherheit / Remote

[Betrieb]
 6) Tools & Umgebung
 7) Container / Docker
 8) Monitoring
 9) Systeminfo
10) Wartung / Disks
11) Benutzer & Zeit
12) Proxmox-Helfer
13) Systemsteuerung

[Schnellzugriff]
h) Hilfe / Info    s) Status-Dashboard    l) Logs ansehen
c) Konfig/Umgebung u) Self-Update         d) Sprache (en/de)
i) Installation    q) Beenden
EOF
        ;;
        de:status.reboot) echo "Neustart erforderlich." ;;
        *) echo "=========================== NTX COMMAND CENTER ($VERSION) ===========================" ;;
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
    touch "$ERROR_LOG"
    mkdir -p "$REPORT_DIR"
    rotate_log
}

wait_for_dpkg_lock() {
    if [[ "$PKG_MGR" != "apt" ]]; then
        return 0
    fi
    local timeout="${1:-60}"
    local start
    start=$(date +%s)
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        local now
        now=$(date +%s)
        if (( now - start >= timeout )); then
            echo "Package manager lock is still held (dpkg/apt busy). Try again shortly."
            return 1
        fi
        echo "Waiting for package manager lock to clear..."
        sleep 2
    done
    return 0
}

detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MGR="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
    elif command -v pacman >/dev/null 2>&1; then
        PKG_MGR="pacman"
    else
        PKG_MGR=""
    fi
    [[ -n "$PKG_MGR" ]]
}

map_pkg_name() {
    local pkg="$1"
    case "$PKG_MGR:$pkg" in
        pacman:openssh-server) echo "openssh" ;;
        dnf:prometheus-node-exporter) echo "node_exporter" ;;
        pacman:prometheus-node-exporter) echo "prometheus-node-exporter" ;;
        dnf:gnupg) echo "gnupg2" ;;
        pacman:dnsutils) echo "bind" ;;
        dnf:dnsutils) echo "bind-utils" ;;
        pacman:procps) echo "procps-ng" ;;
        dnf:procps) echo "procps-ng" ;;
        dnf:iproute2) echo "iproute" ;;
        dnf:python3-dev) echo "python3-devel" ;;
        pacman:python3-dev) echo "python" ;;
        pacman:python3-pip) echo "python-pip" ;;
        dnf:mariadb-client-core) echo "mariadb" ;;
        pacman:mariadb-client-core) echo "mariadb" ;;
        dnf:mariadb-server) echo "mariadb-server" ;;
        pacman:mariadb-server) echo "mariadb" ;;
        dnf:clamav-daemon) echo "clamav" ;;
        pacman:clamav-daemon) echo "clamav" ;;
        dnf:libpam-google-authenticator) echo "google-authenticator" ;;
        pacman:libpam-google-authenticator) echo "google-authenticator-libpam" ;;
        *) echo "$pkg" ;;
    esac
}

require_pkg_mgr() {
    local needed="$1"
    if [[ "$PKG_MGR" != "$needed" ]]; then
        echo "This action requires $needed (current: ${PKG_MGR:-unknown})."
        return 1
    fi
    return 0
}

pkg_update() {
    case "$PKG_MGR" in
        apt) apt-get update ;;
        dnf) dnf -y makecache ;;
        pacman) return 0 ;;
        *) return 1 ;;
    esac
}

pkg_upgrade() {
    case "$PKG_MGR" in
        apt) apt-get upgrade -y ;;
        dnf) dnf -y upgrade ;;
        pacman) pacman -Syu --noconfirm ;;
        *) return 1 ;;
    esac
}

pkg_install() {
    case "$PKG_MGR" in
        apt) apt-get install -y "$@" ;;
        dnf) dnf -y install "$@" ;;
        pacman) pacman -S --noconfirm --needed "$@" ;;
        *) return 1 ;;
    esac
}

check_updates() {
    local latest
    latest=$(curl -fsSL "https://api.github.com/repos/ntx007/ntx-linux-utility-menu/releases?per_page=1" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | head -n1 | cut -d'"' -f4 || true)
    if [[ -n "$latest" ]]; then
        local latest_clean="${latest#v}"
        local current_clean="${VERSION#v}"
        if [[ "$latest_clean" != "$current_clean" ]]; then
            local highest
            highest=$(printf "%s\n%s\n" "$current_clean" "$latest_clean" | sort -V | tail -1)
            if [[ "$highest" == "$latest_clean" ]]; then
                UPDATE_NOTICE="Update available: ${latest} (current ${VERSION})"
            fi
        fi
    fi
}

gather_header_info() {
    HEADER_CPU=$(nproc 2>/dev/null || echo "unknown")
    local mem_gib=""
    mem_gib=$(awk '/MemTotal/ {printf "%.1f", $2/1024/1024}' /proc/meminfo 2>/dev/null | head -n1)
    if [[ -z "$mem_gib" ]]; then
        mem_gib=$(free -m 2>/dev/null | awk 'NR==2 {printf "%.1f", $2/1024}')
    fi
    HEADER_RAM=${mem_gib:-unknown}
    HEADER_HOST=$(hostname 2>/dev/null || echo "unknown")
    HEADER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' | sed 's/[[:space:]]//g')
    HEADER_IP=${HEADER_IP:-unknown}
    # Public IP lookup with timeout to avoid hanging on slow/offline links
    if command -v dig >/dev/null 2>&1; then
        HEADER_PUBLIC_IP=$(timeout "${HEADER_PUBLIC_TIMEOUT}" dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null | head -n1)
    else
        HEADER_PUBLIC_IP="dig missing"
    fi
    HEADER_PUBLIC_IP=${HEADER_PUBLIC_IP:-unknown}
    if update_cadence_warn "silent"; then
        if [[ -n "$UPDATE_NOTICE" ]]; then
            UPDATE_NOTICE="$UPDATE_NOTICE; ${STALE_APT_MSG}"
        else
            UPDATE_NOTICE="$STALE_APT_MSG"
        fi
    fi
}

self_update_script() {
    local target="$SCRIPT_PATH"
    local tmp="${target}.tmp"
    local choice tag url branch

    echo "[Self-update] Choose source:"
    echo " 1) Update from main branch"
    echo " 2) Latest release"
    echo " 3) Select from branches"
    echo " 4) Update via git pull (if repo)"
    echo " 0) Cancel"
    read -p "Select: " choice

    case "$choice" in
        1)
            url="https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/main/ntx-utility-menu.sh"
            ;;
        2)
            echo "Fetching recent releases..."
            mapfile -t tags < <(curl -fsSL "https://api.github.com/repos/ntx007/ntx-linux-utility-menu/releases?per_page=15" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4 || true)
            if [[ ${#tags[@]} -eq 0 ]]; then
                echo "No tags retrieved (rate limit or network). Try again or pick main/dev manually."
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
            echo "Fetching branches..."
            mapfile -t branches < <(curl -fsSL "https://api.github.com/repos/ntx007/ntx-linux-utility-menu/branches?per_page=50" 2>/dev/null | grep -o '"name": *"[^"]*"' | cut -d'"' -f4 || true)
            if [[ ${#branches[@]} -gt 0 ]]; then
                local i=1
                for b in "${branches[@]}"; do
                    echo " $i) $b"
                    i=$((i+1))
                done
            else
                echo "No branches retrieved from GitHub (rate limit or network). Enter one manually or retry."
            fi
            echo " 0) Cancel"
            echo " M) Manual branch name"
            read -p "Select branch (1-${#branches[@]} or M): " selb
            if [[ "$selb" == "M" || "$selb" == "m" ]]; then
                read -p "Enter branch name: " branch
            elif [[ "$selb" =~ ^[0-9]+$ && "$selb" -ge 1 && "$selb" -le ${#branches[@]} ]]; then
                branch=${branches[$((selb-1))]}
            else
                echo "Cancelled."
                return 0
            fi
            if [[ -z "$branch" ]]; then
                echo "Invalid selection; cancelling."
                return 1
            fi
            url="https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/${branch}/ntx-utility-menu.sh"
            ;;
        4)
            self_update_git
            return $?
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

self_update_git() {
    local repo_dir
    repo_dir="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
    if [[ ! -d "$repo_dir/.git" ]]; then
        echo "No git repository found at $repo_dir."
        return 1
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY RUN] git -C \"$repo_dir\" pull --ff-only"
        log_line "OK : git pull (dry run)"
        return 0
    fi
    log_line "RUN: git pull in $repo_dir"
    if git -C "$repo_dir" pull --ff-only; then
        log_line "OK : git pull in $repo_dir"
        echo "Updated repository in $repo_dir."
    else
        log_line "FAIL: git pull in $repo_dir"
        echo "Failed to update repository in $repo_dir."
        return 1
    fi
}

ensure_cmd() {
    local binary="$1"
    local pkg="${2:-$1}"
    if ! command -v "$binary" >/dev/null 2>&1; then
        if [[ "$PKG_MGR" == "apt" ]]; then
            if ! wait_for_dpkg_lock 90; then
                return 1
            fi
        fi
        local mapped_pkg
        mapped_pkg=$(map_pkg_name "$pkg")
        run_cmd "Installing missing dependency: $mapped_pkg" pkg_install "$mapped_pkg"
    fi
}

backup_finalize() {
    local tarfile="$1"
    local base="${tarfile%.tar}"
    local outfile=""
    case "$BACKUP_COMPRESS" in
        zstd)
            if command -v zstd >/dev/null 2>&1; then
                zstd -T0 -q -f "$tarfile"
                outfile="${base}.tar.zst"
                mv "${tarfile}.zst" "$outfile" 2>/dev/null || true
            else
                if command -v gzip >/dev/null 2>&1; then
                    gzip -f "$tarfile"
                    outfile="${base}.tar.gz"
                else
                    outfile="$tarfile"
                fi
            fi
            ;;
        gzip|*)
            if command -v gzip >/dev/null 2>&1; then
                gzip -f "$tarfile"
                outfile="${base}.tar.gz"
            else
                outfile="$tarfile"
            fi
            ;;
    esac
    echo "$outfile"
}

backup_cleanup() {
    local pattern="$1"
    local keep="${BACKUP_KEEP:-0}"
    if [[ "$keep" -le 0 ]]; then
        return 0
    fi
    ls -1t $pattern 2>/dev/null | tail -n +$((keep+1)) | xargs -r rm -f || true
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

log_app_summary() {
    mkdir -p "$(dirname "$POST_INSTALL_LOG")"
    {
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    } >> "$POST_INSTALL_LOG"
}

check_environment() {
    if [[ ! -f /etc/os-release ]]; then
        echo "Cannot find /etc/os-release. Unsupported system."
        exit 1
    fi
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    if ! detect_package_manager; then
        echo "No supported package manager detected (apt, dnf, pacman). Aborting."
        exit 1
    fi
    if [[ "$PKG_MGR" != "apt" && "$SSH_UNIT" == "$SSH_UNIT_DEFAULT" ]]; then
        SSH_UNIT="sshd"
    fi
    if [[ "$PKG_MGR" != "apt" ]]; then
        echo "Note: detected $PKG_MGR on ${DISTRO_ID}; some apt-only features are unavailable."
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

netstat_top_talkers() {
    if command -v ss >/dev/null 2>&1; then
        ss -ntp | awk 'NR>1 {split($5,a,":"); host=a[1]; cnt[host]++} END {for(h in cnt) printf "%-25s %d\n", h, cnt[h]}' | sort -k2 -nr | head
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ntp 2>/dev/null | awk 'NR>2 {split($5,a,":"); host=a[1]; cnt[host]++} END {for(h in cnt) printf "%-25s %d\n", h, cnt[h]}' | sort -k2 -nr | head
    else
        echo "Neither ss nor netstat available."
    fi
}

update_cadence_warn() {
    if [[ "$PKG_MGR" != "apt" ]]; then
        return 1
    fi
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
            STALE_APT_MSG="apt index stale (${days}d old)"
            return 0
        fi
    fi
    return 1
}

pending_updates_count() {
    local count
    case "$PKG_MGR" in
        apt)
            count=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || true)
            count=${count:-0}
            ;;
        pacman)
            count=$(pacman -Qu 2>/dev/null | wc -l | tr -d ' ')
            ;;
        dnf)
            count=$(dnf -q check-update 2>/dev/null | awk 'NF && $1 !~ /^Last/ {c++} END{print c+0}' || true)
            ;;
        *)
            count=0
            ;;
    esac
    echo "Pending upgrades: ${count}"
}

kernel_version_summary() {
    local running latest
    running=$(uname -r)
    if [[ "$PKG_MGR" == "apt" ]]; then
        latest=$(dpkg -l 'linux-image-*' 2>/dev/null | awk '/^ii/{print $2,$3}' | sort | tail -1)
    else
        latest=""
    fi
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
    local smart_summary=""
    if command -v smartctl >/dev/null 2>&1; then
        local disk
        disk=$(lsblk -ndo NAME,TYPE | awk '$2=="disk"{print "/dev/"$1; exit}')
        if [[ -n "$disk" ]]; then
            smart_summary=$(smartctl -H "$disk" 2>/dev/null | grep -E "SMART overall-health|SMART overall-health self-assessment" || true)
        fi
    fi
    local container_count=""
    if command -v docker >/dev/null 2>&1; then
        container_count=$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')
    fi

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
        if [[ -n "$smart_summary" ]]; then
            echo
            echo "[SMART]"
            echo "$smart_summary"
        fi
        if [[ -n "$container_count" ]]; then
            echo
            echo "[Containers]"
            echo "Running containers: $container_count"
        fi
    } > "$report"

    # Restore colors
    C_RED="$SAVED_RED"; C_GRN="$SAVED_GRN"; C_YLW="$SAVED_YLW"; C_CYN="$SAVED_CYN"; C_RST="$SAVED_RST"

    log_line "Status report saved to $report"
    echo "Status report saved to $report"
}

health_brief() {
    local public_ip reboot_needed updates
    public_ip=$(whats_my_ip 2>/dev/null | head -n1)
    updates=$(pending_updates_count | awk '{print $3}')
    updates=${updates:-0}
    if [[ "$PKG_MGR" == "apt" ]]; then
        reboot_needed=$( [[ -f /var/run/reboot-required ]] && echo yes || echo no )
    else
        reboot_needed="unknown"
    fi
    echo "Host: $(hostname)"
    echo "Public IP: ${public_ip:-unknown}"
    echo "Pending updates: ${updates}"
    echo "Reboot required: ${reboot_needed}"
    echo "Services:"
    printf "  ssh: %s\n" "$(systemctl is-active "$SSH_UNIT" >/dev/null 2>&1 && echo active || echo inactive)"
    printf "  docker: %s\n" "$(systemctl is-active "$DOCKER_UNIT" >/dev/null 2>&1 && echo active || echo inactive)"
    printf "  ufw: %s\n" "$(systemctl is-active "$UFW_UNIT" >/dev/null 2>&1 && echo active || echo inactive)"
}

status_report_json() {
    mkdir -p "$REPORT_DIR"
    local ts
    ts=$(date '+%Y%m%d-%H%M%S')
    local report="$REPORT_DIR/status-$ts.json"
    local container_count=""
    if command -v docker >/dev/null 2>&1; then
        container_count=$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')
    fi
    local smart_disk=""
    local smart_health=""
    if command -v smartctl >/dev/null 2>&1; then
        smart_disk=$(lsblk -ndo NAME,TYPE | awk '$2=="disk"{print "/dev/"$1; exit}')
        if [[ -n "$smart_disk" ]]; then
            smart_health=$(smartctl -H "$smart_disk" 2>/dev/null | grep -E "SMART overall-health|SMART overall-health self-assessment" | head -1 | sed 's/.*: //' || true)
        fi
    fi
    {
        echo "{"
        echo "  \"version\": \"$VERSION\","
        echo "  \"timestamp\": \"$ts\","
        echo "  \"host\": \"$(hostname)\","
        echo "  \"uptime\": \"$(uptime -p 2>/dev/null || uptime)\","
        echo "  \"reboot_required\": \"$( [[ -f /var/run/reboot-required ]] && echo yes || echo no )\","
        echo "  \"pending_updates\": \"$(pending_updates_count | awk '{print $3}' || true)\","
        echo "  \"kernel_running\": \"$(uname -r)\","
        echo "  \"containers_running\": \"${container_count:-unknown}\","
        if [[ -n "$smart_disk" ]]; then
            echo "  \"smart\": {\"disk\": \"$smart_disk\", \"health\": \"${smart_health:-unknown}\"},"
        fi
        echo "  \"services\": {"
        printf '    "ssh": "%s",\n' "$(systemctl is-active "$SSH_UNIT" >/dev/null 2>&1 && echo active || echo inactive)"
        printf '    "ufw": "%s",\n' "$(systemctl is-active "$UFW_UNIT" >/dev/null 2>&1 && echo active || echo inactive)"
        printf '    "fail2ban": "%s",\n' "$(systemctl is-active "$FAIL2BAN_UNIT" >/dev/null 2>&1 && echo active || echo inactive)"
        printf '    "tailscale": "%s",\n' "$(systemctl is-active "$TAILSCALE_UNIT" >/dev/null 2>&1 && echo active || echo inactive)"
        printf '    "docker": "%s"\n' "$(systemctl is-active "$DOCKER_UNIT" >/dev/null 2>&1 && echo active || echo inactive)"
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
            echo "AUTO_UPDATE_BEFORE_MAINT=true, running package update..."
            run_cmd "Package update (maintenance bundle)" pkg_update
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
    pri=$(grep -Ei '^\s*PermitRootLogin' "$cfg" | tail -1 | awk '{print $2}' || true)
    par=$(grep -Ei '^\s*PasswordAuthentication' "$cfg" | tail -1 | awk '{print $2}' || true)
    pwa=$(grep -Ei '^\s*PubkeyAuthentication' "$cfg" | tail -1 | awk '{print $2}' || true)
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

ssh_cipher_audit() {
    local cfg="/etc/ssh/sshd_config"
    if [[ ! -f "$cfg" ]]; then
        echo "sshd_config not found at $cfg"
        return 1
    fi
    echo "SSH ciphers/KEX/MAC audit ($cfg)"
    local ciphers kex macs
    ciphers=$(grep -i '^[[:space:]]*Ciphers' "$cfg" | tail -1 | cut -d' ' -f2- || true)
    kex=$(grep -i '^[[:space:]]*KexAlgorithms' "$cfg" | tail -1 | cut -d' ' -f2- || true)
    macs=$(grep -i '^[[:space:]]*MACs' "$cfg" | tail -1 | cut -d' ' -f2- || true)
    echo "Ciphers: ${ciphers:-default (OpenSSH defaults)}"
    echo "KexAlgorithms: ${kex:-default (OpenSSH defaults)}"
    echo "MACs: ${macs:-default (OpenSSH defaults)}"
    echo "Recommendation: prefer modern defaults (chacha20-poly1305, aes256-gcm, curve25519-sha256, sntrup/curve combos on newer OpenSSH)."
}

generate_ssh_key() {
    local key="${HOME}/.ssh/id_ed25519"
    read -r -p "Key path [${key}]: " KEY_PATH
    KEY_PATH=${KEY_PATH:-$key}
    read -r -p "Key comment [ntx-key]: " COMM
    COMM=${COMM:-ntx-key}
    if [[ -f "$KEY_PATH" ]]; then
        echo "Key already exists at $KEY_PATH"
    else
        mkdir -p "$(dirname "$KEY_PATH")"
        ssh-keygen -t ed25519 -f "$KEY_PATH" -C "$COMM" -N ""
    fi
    echo "Public key:"
    cat "${KEY_PATH}.pub"
    read -r -p "Copy to remote (user@host)? Leave blank to skip: " REM
    if [[ -n "$REM" ]]; then
        ssh-copy-id -i "${KEY_PATH}.pub" "$REM" || echo "ssh-copy-id failed."
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

install_docker() {
    # Use the official Docker convenience script (https://github.com/docker/docker-install)
    run_cmd "Download Docker install script" bash -c "curl -fsSL https://get.docker.com -o /tmp/get-docker.sh"
    run_cmd "Run Docker install script" bash -c "sh /tmp/get-docker.sh"
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker installation failed (docker not found)."
        return 1
    fi
    # Ensure compose plugin is present; try package manager first, then binary fallback from GitHub Compose releases.
    if ! docker compose version >/dev/null 2>&1; then
        if ! run_cmd "Install docker compose plugin" pkg_install docker-compose-plugin; then
            local plugin_dir="/usr/local/lib/docker/cli-plugins"
            local compose_bin="${plugin_dir}/docker-compose"
            mkdir -p "$plugin_dir"
            run_cmd "Download docker compose CLI plugin" bash -c "curl -fsSL https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m) -o \"$compose_bin\""
            run_cmd "Make docker compose executable" chmod +x "$compose_bin"
        fi
    fi
    run_cmd "Enable and start Docker" systemctl enable --now docker
}

docker_service_status() {
    show_service_status docker "$DOCKER_UNIT"
}

docker_ps() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
}

docker_logs_follow() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    read -r -p "Container name/ID: " cname
    [[ -z "$cname" ]] && { echo "No container provided."; return 1; }
    docker logs -f --tail 200 "$cname"
}

docker_list_all() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    msgbox "Alle Docker Container"
    docker container ls -a --format "table {{.Names}}\t{{.Image}}\t{{.ID}}\t{{.Size}}\t{{.Networks}}"
}

docker_info_short() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    docker info --format 'Server Version: {{.ServerVersion}}\nStorage Driver: {{.Driver}}\nCgroup Driver: {{.CgroupDriver}}'
}

docker_prune_safe() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    run_cmd "Docker prune unused resources" docker system prune -af --volumes
}

docker_scan_images() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    local scanner=""
    if docker scan --help >/dev/null 2>&1; then
        scanner="docker scan"
    elif command -v trivy >/dev/null 2>&1; then
        scanner="trivy image"
    fi
    if [[ -z "$scanner" ]]; then
        echo "No scanner found (docker scan or trivy)."
        return 1
    fi
    docker images --format '{{.Repository}}:{{.Tag}}' | while read -r img; do
        [[ -z "$img" || "$img" == ":" ]] && continue
        echo "Scanning $img ..."
        $scanner "$img" || true
    done
}

docker_compose_manage() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        echo "Docker Compose plugin not found."
        return 1
    fi
    read -r -p "Path to compose project (directory with compose file): " CPATH
    [[ -z "$CPATH" ]] && { echo "No path provided."; return 1; }
    if [[ ! -f "$CPATH/docker-compose.yml" && ! -f "$CPATH/compose.yaml" && ! -f "$CPATH/compose.yml" ]]; then
        echo "No compose file found in $CPATH"
        return 1
    fi
    echo "Actions: 1) up -d  2) down  3) restart"
    read -r -p "Select: " ACT
    case "$ACT" in
        1) (cd "$CPATH" && run_cmd "docker compose up -d ($CPATH)" docker compose up -d) ;;
        2) (cd "$CPATH" && run_cmd "docker compose down ($CPATH)" docker compose down) ;;
        3) (cd "$CPATH" && run_cmd "docker compose restart ($CPATH)" docker compose restart) ;;
        *) echo "Invalid choice." ;;
    esac
}

create_vlan() {
    read -r -p "Base interface (e.g., eth0): " IFACE
    read -r -p "VLAN ID: " VID
    [[ -z "$IFACE" || -z "$VID" ]] && { echo "Interface or VLAN ID missing."; return 1; }
    run_cmd "Create VLAN ${IFACE}.${VID}" ip link add link "$IFACE" name "${IFACE}.${VID}" type vlan id "$VID"
    run_cmd "Bring up ${IFACE}.${VID}" ip link set up dev "${IFACE}.${VID}"
}

delete_vlan() {
    read -r -p "VLAN interface to delete (e.g., eth0.10): " VIF
    [[ -z "$VIF" ]] && { echo "No interface provided."; return 1; }
    run_cmd "Delete VLAN $VIF" ip link delete "$VIF"
}

create_bond() {
    read -r -p "Bond name (e.g., bond0): " BOND
    read -r -p "Mode (default 802.3ad): " MODE
    MODE=${MODE:-802.3ad}
    read -r -p "Slave interfaces (space separated, e.g., eth0 eth1): " SLAVES
    [[ -z "$BOND" || -z "$SLAVES" ]] && { echo "Bond name or slaves missing."; return 1; }
    run_cmd "Create bond $BOND" ip link add "$BOND" type bond mode "$MODE"
    for s in $SLAVES; do
        run_cmd "Set $s master $BOND" ip link set "$s" master "$BOND"
    done
    run_cmd "Bring up $BOND" ip link set "$BOND" up
}

delete_bond() {
    read -r -p "Bond interface to delete (e.g., bond0): " BOND
    [[ -z "$BOND" ]] && { echo "No bond provided."; return 1; }
    run_cmd "Delete bond $BOND" ip link delete "$BOND" type bond
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

pause_prompt() {
    echo
    read -p "Press Enter to continue..."
}

should_pause_after() {
    local choice="$1"
    case "$choice" in
        ""|0) return 1 ;; # empty or back/quit
        *) return 0 ;;
    esac
}

###############################################################################
# Functions
###############################################################################

# --- System update ---

update_all() {
    if [[ "$PKG_MGR" == "apt" ]]; then
        if ! wait_for_dpkg_lock 90; then
            return 1
        fi
    fi
    if ! run_cmd "Package update" pkg_update; then
        echo "Package update failed (network/proxy?). Skipping upgrade."
        return 1
    fi
    run_cmd "Package upgrade" pkg_upgrade
}

update_all_with_sudo_reboot() {
    # keep sudo at the beginning as requested
    if ! require_pkg_mgr apt; then
        return 1
    fi
    sudo apt install sudo && sudo apt-get update && sudo apt-get upgrade -y && sudo reboot
}

update_all_reboot_if_needed() {
    if [[ "$PKG_MGR" == "apt" ]]; then
        if ! wait_for_dpkg_lock 90; then
            return 1
        fi
    fi
    if ! run_cmd "Package update" pkg_update; then
        echo "Skipping upgrade and reboot check because package update failed."
        return 1
    fi
    if ! run_cmd "Package upgrade" pkg_upgrade; then
        echo "Skipping reboot check because package upgrade failed."
        return 1
    fi
    if [[ "$PKG_MGR" == "apt" ]]; then
        if [[ -f /var/run/reboot-required ]]; then
            msgbox "Reboot required after updates."
            if confirm_prompt "Reboot now?"; then
                log_line "Reboot requested after updates."
                reboot
            fi
        else
            echo "No reboot required."
        fi
    else
        echo "Reboot check not available for ${PKG_MGR}."
    fi
}

do_release_upgrade() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    echo "Ubuntu release upgrade: checks performed per https://wiki.ubuntuusers.de/Upgrade/"
    run_cmd "Install update-manager-core" apt-get install -y update-manager-core
    run_cmd "List held packages" apt-mark showhold
    echo "Recommended: ensure backups and remove EOL third-party repositories before upgrading."
    run_cmd "Run do-release-upgrade (non-interactive prompt will follow)" do-release-upgrade
}

enable_unattended_upgrades() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    run_cmd "Install unattended-upgrades" apt-get install unattended-upgrades -y
    run_cmd "Enable unattended-upgrades service" systemctl enable --now unattended-upgrades
    echo "Unattended upgrades enabled."
}

disable_unattended_upgrades() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
        echo "unattended-upgrades is not installed."
        return 0
    fi
    run_cmd "Stop unattended-upgrades service" systemctl disable --now unattended-upgrades
    echo "Unattended upgrades disabled."
}

check_unattended_status() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
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
    if ! require_pkg_mgr apt; then
        return 1
    fi
    if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
        echo "unattended-upgrades is not installed. Please enable it first."
        return 1
    fi
    run_cmd "Run unattended-upgrade now" unattended-upgrade -v
}

list_custom_sources() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    echo "Custom sources (.list) in /etc/apt/sources.list.d:"
    ls -1 /etc/apt/sources.list.d/*.list 2>/dev/null || echo "None found."
}

toggle_apt_proxy() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    local proxy_file="/etc/apt/apt.conf.d/99proxy"
    if [[ -f "$proxy_file" ]]; then
        echo "APT proxy currently enabled:"
        cat "$proxy_file"
        if confirm_prompt "Disable and remove proxy file?"; then
            run_cmd "Remove APT proxy config" rm -f "$proxy_file"
        fi
    else
        read -p "Enter http(s) proxy (e.g., http://user:pass@host:port): " proxy
        [[ -z "$proxy" ]] && { echo "No proxy provided."; return; }
        cat <<EOF > "$proxy_file"
Acquire::http::Proxy "$proxy";
Acquire::https::Proxy "$proxy";
EOF
        echo "Proxy written to $proxy_file"
    fi
}

apt_source_validator() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    local codename=""
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        codename="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
    fi
    echo "Checking /etc/apt/sources.list and /etc/apt/sources.list.d/*.list for mismatched codenames..."
    local mismatches=0
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        [[ "$line" =~ ^[[:space:]]*deb[[:space:]] ]] || continue
        local trimmed="${line%%#*}"
        local dist=""
        read -r -a tokens <<< "$trimmed"
        if [[ ${#tokens[@]} -lt 3 ]]; then
            continue
        fi
        local idx=0
        if [[ "${tokens[0]}" == "deb" ]]; then
            idx=1
        fi
        if [[ "${tokens[$idx]}" == \[* ]]; then
            while [[ $idx -lt ${#tokens[@]} && "${tokens[$idx]}" != *"]" ]]; do
                idx=$((idx+1))
            done
            idx=$((idx+1))
        fi
        dist="${tokens[$((idx+1))]}"
        [[ -z "$dist" || -z "$codename" ]] && continue
        case "$dist" in
            "$codename"|"$codename"-*) ;;
            stable|stable-*|testing|testing-*|unstable|unstable-*|sid|oldstable|oldstable-*) ;;
            *)
                echo "Possible mismatch: $line"
                mismatches=$((mismatches+1))
                ;;
        esac
    done < <(shopt -s nullglob; cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true)
    if [[ "$mismatches" -eq 0 ]]; then
        echo "No mismatched codenames detected."
    else
        echo "Found $mismatches potential mismatches. Review above entries."
    fi
}

remove_custom_source() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    read -p "Enter path to .list file to remove: " SRC_FILE
    [[ -z "$SRC_FILE" ]] && { echo "No file provided."; return 1; }
    if [[ ! -f "$SRC_FILE" ]]; then
        echo "File not found: $SRC_FILE"
        return 1
    fi
    if ! skip_if_safe "removing $SRC_FILE"; then return 1; fi
    if confirm_prompt "Remove $SRC_FILE?"; then
        run_cmd "Remove custom source $SRC_FILE" rm -f "$SRC_FILE"
        run_cmd "Package update after source removal" pkg_update
    else
        echo "Cancelled."
    fi
}

apt_health_check() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
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
    if ! require_pkg_mgr apt; then
        return 1
    fi
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

add_custom_dns() {
    backup_file /etc/resolv.conf
    read -p "Enter nameserver IP (e.g., 9.9.9.9): " CUSTOM_NS
    if [[ -z "$CUSTOM_NS" ]]; then
        echo "No nameserver provided; nothing changed."
        return 0
    fi
    echo "Choose mode:"
    echo " 1) Append"
    echo " 2) Overwrite (replace current resolv.conf with only this nameserver)"
    read -p "Select: " MODE
    case "$MODE" in
        2)
            cat <<EOF > /etc/resolv.conf
nameserver $CUSTOM_NS
EOF
            echo "Overwrote /etc/resolv.conf with $CUSTOM_NS"
            ;;
        *)
            echo "nameserver $CUSTOM_NS" | tee -a /etc/resolv.conf > /dev/null
            echo "Appended nameserver $CUSTOM_NS to /etc/resolv.conf"
            ;;
    esac
}

restore_dns_backup() {
    restore_backup /etc/resolv.conf
}

restore_dns_and_restart() {
    if restore_backup /etc/resolv.conf; then
        if systemctl is-active systemd-resolved >/dev/null 2>&1; then
            run_cmd "Restart systemd-resolved" systemctl restart systemd-resolved
        else
            echo "systemd-resolved not active; skipped restart."
        fi
    fi
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
    ensure_cmd ifconfig net-tools
    ifconfig || ip addr show
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

show_top_talkers() {
    echo "Top TCP talkers:"
    netstat_top_talkers
}

smart_health_batch() {
    ensure_cmd smartctl smartmontools
    lsblk -ndo NAME,TYPE | awk '$2=="disk"{print "/dev/"$1}' | while read -r disk; do
        [[ -z "$disk" ]] && continue
        echo "== $disk =="
        smartctl -H "$disk" 2>/dev/null || smartctl -H -d scsi "$disk" 2>/dev/null || echo "SMART check failed for $disk"
    done
}

service_uptime_summary() {
    echo "Boot time: $(uptime -s 2>/dev/null || who -b)"
    systemctl list-units --type=service --state=running --no-pager --plain 2>/dev/null | head -n 20
}

hardware_overview() {
    echo "CPU model:"
    lscpu 2>/dev/null | grep -E 'Model name|CPU\\(s\\)' || cat /proc/cpuinfo 2>/dev/null | grep -m1 'model name'
    echo
    echo "Memory total:"
    free -h 2>/dev/null || cat /proc/meminfo 2>/dev/null | head -n 2
    echo
    echo "Disks:"
    lsblk -ndo NAME,SIZE,MODEL,TYPE 2>/dev/null | awk '$4=="disk"{print $0}' || lsblk
}

auditd_minimal_rules() {
    run_cmd "Install auditd" pkg_install auditd
    cat <<'EOF' > /etc/audit/rules.d/99-minimal.rules
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /var/log/lastlog -p wa -k logins
EOF
    run_cmd "Reload audit rules" augenrules --load
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

run_mtr_quick() {
    ensure_cmd mtr mtr
    read -p "Enter host/IP for MTR: " TARGET
    [[ -z "$TARGET" ]] && { echo "No target provided."; return 1; }
    mtr -rwzc 10 "$TARGET"
}

nmap_top_ports() {
    ensure_cmd nmap nmap
    read -p "Enter host/IP to scan: " TARGET
    [[ -z "$TARGET" ]] && { echo "No target provided."; return 1; }
    nmap -Pn --top-ports 50 "$TARGET"
}

# --- Speedtest & benchmarks ---

install_speedtest_full() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    if ! wait_for_dpkg_lock 90; then
        return 1
    fi
    run_cmd "Install curl" pkg_install curl
    curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash
    pkg_install speedtest
}

change_speedtest_apt_list() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    cat <<EOF > /etc/apt/sources.list.d/ookla_speedtest-cli.list
# this file was generated by packagecloud.io for
# the repository at https://packagecloud.io/ookla/speedtest-cli

deb [signed-by=/etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg] https://packagecloud.io/ookla/speedtest-cli/ubuntu/ jammy main
deb-src [signed-by=/etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg] https://packagecloud.io/ookla/speedtest-cli/ubuntu/ jammy main
EOF
}

install_speedtest_after_list() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    if ! wait_for_dpkg_lock 90; then
        return 1
    fi
    run_cmd "Package update" pkg_update
    run_cmd "Install speedtest" pkg_install speedtest
}

run_cmatrix() {
    if ! command -v cmatrix >/dev/null 2>&1; then
        if ! wait_for_dpkg_lock 90; then
            return 1
        fi
        run_cmd "Install cmatrix" pkg_install cmatrix
    fi
    cmatrix
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
    if ! require_pkg_mgr apt; then
        return 1
    fi
    if [[ -f /etc/apt/sources.list.d/ookla_speedtest-cli.list ]]; then
        run_cmd "Remove Speedtest repo list" rm -f /etc/apt/sources.list.d/ookla_speedtest-cli.list
    fi
    if [[ -f /etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg ]]; then
        run_cmd "Remove Speedtest keyring" rm -f /etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg
    fi
    run_cmd "Package update after Speedtest repo removal" pkg_update
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
    systemctl reload "$SSH_UNIT" 2>/dev/null || systemctl restart "$SSH_UNIT"
    echo "sshd_config adjusted. Backup: ${file}.bak"
}

install_openssh() {
    run_cmd "Package update" pkg_update
    run_cmd "Install OpenSSH server" pkg_install openssh-server
    systemctl enable --now "$SSH_UNIT"
}

tailscale_install() {
    curl -fsSL https://tailscale.com/install.sh | sh
}

tailscale_up_qr() {
    tailscale up -qr
}

install_netclient() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    # Based on https://docs.netmaker.io/docs/client-installation/netclient#installation
    run_cmd "Install dependencies for netclient" pkg_install curl gpg
    run_cmd "Add Netmaker GPG key" bash -c "curl -fsSL 'https://apt.netmaker.org/gpg.key' | gpg --dearmor -o /usr/share/keyrings/netmaker-keyring.gpg"
    run_cmd "Add Netmaker apt repository" bash -c "echo \"deb [signed-by=/usr/share/keyrings/netmaker-keyring.gpg] https://apt.netmaker.org stable main\" > /etc/apt/sources.list.d/netclient.list"
    run_cmd "apt-get update (netclient)" apt-get update
    run_cmd "Install netclient" pkg_install netclient
    echo "Netmaker netclient installed. Join commands per https://docs.netmaker.io/docs/client-installation/netclient#installation"
}

remove_netclient_repo() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    if [[ -f /etc/apt/sources.list.d/netclient.list ]]; then
        run_cmd "Remove Netmaker repo list" rm -f /etc/apt/sources.list.d/netclient.list
    fi
    if [[ -f /usr/share/keyrings/netmaker-keyring.gpg ]]; then
        run_cmd "Remove Netmaker keyring" rm -f /usr/share/keyrings/netmaker-keyring.gpg
    fi
    run_cmd "Package update after Netmaker repo removal" pkg_update
}

install_wireguard_client() {
    run_cmd "Install WireGuard (client)" pkg_install wireguard wireguard-tools
}

install_wireguard_server() {
    run_cmd "Install WireGuard (server)" pkg_install wireguard wireguard-tools
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
    if ! require_pkg_mgr apt; then
        return 1
    fi
    run_cmd "Install CrowdSec repo" bash -c "curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"
    run_cmd "Install crowdsec" pkg_install crowdsec
    show_service_status crowdsec
}

install_crowdsec_firewall_bouncer() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    run_cmd "Install CrowdSec firewall bouncer (iptables)" pkg_install crowdsec-firewall-bouncer-iptables
    show_service_status crowdsec-firewall-bouncer
}

install_essentials() {
    run_cmd "Package update" pkg_update
    run_cmd "Install essentials bundle" pkg_install unzip python3-pip gcc python3-dev mariadb-client-core dos2unix glances tmux zsh mc iproute2 npm sudo nano curl net-tools
    pip install --no-binary :all: psutil
    pip3 install gdown
}

install_ibramenu() {
    wget -qO ./i https://raw.githubusercontent.com/ibracorp/ibramenu/main/ibrainit.sh
    chmod +x i
    ./i
}

install_qemu_guest_agent() {
    run_cmd "Package update" pkg_update
    run_cmd "Install QEMU guest agent" pkg_install qemu-guest-agent
    systemctl enable --now qemu-guest-agent
}

install_nvm() {
    echo "Installing nvm (Node Version Manager)..."
    if command -v curl >/dev/null 2>&1; then
        bash -c "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash"
    elif command -v wget >/dev/null 2>&1; then
        bash -c "wget -qO- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash"
    else
        echo "Neither curl nor wget is available; cannot install nvm."
        return 1
    fi
    echo "nvm install script executed. Open a new shell or source ~/.nvm/nvm.sh to use nvm."
}

install_mariadb_server() {
    # Based on https://mariadb.com/docs/server/mariadb-quickstart-guides/installing-mariadb-server-guide
    if ! pidof systemd >/dev/null 2>&1; then
        echo "Systemd not detected; MariaDB service enable/start may fail in this environment."
    fi
    run_cmd "Package update" pkg_update
    run_cmd "Install MariaDB server" pkg_install mariadb-server
    run_cmd "Enable and start MariaDB" systemctl enable --now mariadb
    echo
    echo "MariaDB installed (host install, not containerized). For post-install hardening, run: mysql_secure_installation"
    echo "Default auth on Debian/Ubuntu uses unix_socket; log in as root with: sudo mariadb"
}

show_node_npm_versions() {
    if command -v node >/dev/null 2>&1; then
        echo "Node.js: $(node -v 2>/dev/null)"
    else
        echo "Node.js: not installed"
    fi
    if command -v npm >/dev/null 2>&1; then
        echo "npm: $(npm -v 2>/dev/null)"
    else
        echo "npm: not installed"
    fi
}

install_ntxmenu_path() {
    local ref="${NTX_VERSION:-main}"
    local url_base="https://raw.githubusercontent.com/ntx007/ntx-linux-utility-menu/${ref}"
    local tmpdir
    tmpdir=$(mktemp -d)
    local script_path="${tmpdir}/ntx-utility-menu.sh"
    local wrapper_path="${tmpdir}/ntxmenu"
    local link_target="/usr/bin/ntxmenu"
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
        if [[ ":$PATH:" != *":/usr/local/bin:"* ]]; then
            if [[ -w /etc/profile.d ]]; then
                cat <<'EOF' > /etc/profile.d/ntxmenu.sh
# Added by NTX installer
case ":\$PATH:" in
    *:/usr/local/bin:*) ;;
    *) export PATH=/usr/local/bin:\$PATH ;;
esac
EOF
                echo "/usr/local/bin not in PATH. Added /etc/profile.d/ntxmenu.sh; re-login or export PATH=/usr/local/bin:\$PATH for current shell."
            else
                echo "/usr/local/bin not in PATH. Add it (export PATH=/usr/local/bin:\$PATH) or re-login."
            fi
        fi
        if [[ ":$PATH:" != *":/usr/local/bin:"* && -d /usr/bin && -w /usr/bin ]]; then
            ln -sf /usr/local/bin/ntxmenu "$link_target"
            echo "Symlinked ntxmenu to $link_target for immediate use in current PATH."
        fi
    else
        echo "Install failed. Do you have sufficient privileges?"
    fi
    rm -rf "$tmpdir"
}

menu_essentials() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Essentials-Paket]
 1) Essentials installieren (sudo, nano, curl, net-tools, iproute2, unzip, python3-pip, gcc/python3-dev, psutil, gdown, dos2unix, glances, tmux, zsh, mc, npm)
 2) Essentials erneut ausführen
 0) Zurück
EOF
        else
            cat <<EOF
[Essentials bundle]
 1) Install essentials bundle (sudo, nano, curl, net-tools, iproute2, unzip, python3-pip, gcc/python3-dev, psutil, gdown, dos2unix, glances, tmux, zsh, mc, npm)
 2) Re-run essentials bundle
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1|2) install_essentials ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

install_ufw_basic() {
    run_cmd "Package update" pkg_update
    run_cmd "Install UFW" pkg_install ufw
    ufw allow 22/tcp
    echo "y" | ufw enable
    ufw status
}

install_fail2ban() {
    run_cmd "Package update" pkg_update
    run_cmd "Install Fail2ban" pkg_install fail2ban
    systemctl enable --now fail2ban
}

first_run_checklist() {
    echo "First-run checklist: detect core services and offer to install/enable."
    local missing=()
    local actions=()

    # Docker / Compose
    if ! command -v docker >/dev/null 2>&1; then
        missing+=("Docker + Compose plugin")
        actions+=("install_docker")
    else
        if ! docker compose version >/dev/null 2>&1; then
            missing+=("Docker Compose plugin")
            actions+=("install_docker")
        fi
    fi

    # SSH
    if ! systemctl list-unit-files | grep -q ssh.service; then
        missing+=("OpenSSH server")
        actions+=("install_openssh")
    fi

    # UFW
    if ! command -v ufw >/dev/null 2>&1; then
        missing+=("UFW firewall")
        actions+=("install_ufw_basic")
    fi

    # Fail2ban
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        missing+=("Fail2ban")
        actions+=("install_fail2ban")
    fi

    if [[ ${#missing[@]} -eq 0 ]]; then
        echo "Looks good: Docker/Compose, SSH, UFW, and Fail2ban are present."
        return 0
    fi

    echo "Missing/needs attention: ${missing[*]}"
    read -p "Install/enable these now? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Skipped."
        return 0
    fi

    for action in "${actions[@]}"; do
        case "$action" in
            install_docker) install_docker ;;
            install_openssh) install_openssh ;;
            install_ufw_basic) install_ufw_basic ;;
            install_fail2ban) install_fail2ban ;;
        esac
    done
    echo "First-run checklist completed."
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
    run_cmd "Package update" pkg_update
    run_cmd "Install ClamAV" pkg_install clamav clamav-daemon
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
    run_cmd "Package update" pkg_update
    run_cmd "Install Google Authenticator PAM" pkg_install libpam-google-authenticator
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
    local base="$BACKUP_DIR/config-backup-$ts"
    local tarfile="${base}.tar"
    tar -cf "$tarfile" /etc/ssh/sshd_config /etc/wireguard 2>/dev/null /etc/fail2ban /etc/ufw/applications.d 2>/dev/null || true
    if [[ -n "$COMPOSE_PATH" && -d "$COMPOSE_PATH" ]]; then
        tar -rf "$tarfile" -C "$COMPOSE_PATH" . 2>/dev/null || true
    fi
    local dest
    dest=$(backup_finalize "$tarfile")
    log_line "Config backup created: $dest"
    echo "Config backup saved to $dest"
    backup_cleanup "$BACKUP_DIR/config-backup-*.tar.*"
}

backup_etc_bundle() {
    local ts
    ts=$(date '+%Y%m%d-%H%M%S')
    local base="$BACKUP_DIR/etc-backup-$ts"
    local tarfile="${base}.tar"
    tar -cf "$tarfile" /etc 2>/dev/null || true
    local dest
    dest=$(backup_finalize "$tarfile")
    log_line "Etc backup created: $dest"
    echo "Etc backup saved to $dest"
    backup_cleanup "$BACKUP_DIR/etc-backup-*.tar.*"
}

backup_routine_quick() {
    msgbox "Backup routine (etc + config)"
    backup_etc_bundle
    backup_config_bundle
}

restore_config_bundle() {
    local latest
    latest=$(ls -1t "$BACKUP_DIR"/config-backup-*.tar.* 2>/dev/null | head -n 1)
    if [[ -z "$latest" ]]; then
        echo "No config backup found in $BACKUP_DIR"
        return 1
    fi
    echo "Available backups:"
    ls -1t "$BACKUP_DIR"/config-backup-*.tar.* 2>/dev/null | nl
    read -p "Select backup number (default 1): " sel
    sel=${sel:-1}
    local chosen
    chosen=$(ls -1t "$BACKUP_DIR"/config-backup-*.tar.* 2>/dev/null | sed -n "${sel}p")
    if [[ -z "$chosen" ]]; then
        echo "Invalid selection."
        return 1
    fi
    msgbox "Restoring config backup: $chosen"
    if [[ "$chosen" == *.tar.zst ]]; then
        if command -v zstd >/dev/null 2>&1; then
            zstd -dc "$chosen" | tar -xf - -C / || { echo "Restore failed"; return 1; }
        else
            echo "zstd not available to extract $chosen"
            return 1
        fi
    else
        tar -xzf "$chosen" -C / || { echo "Restore failed"; return 1; }
    fi
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
        grep 'Ban ' /var/log/auth.log | awk '{print $NF}' | sort | uniq -c | sort -nr | head || true
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
    fail2ban-client status | awk '/Jail list/{$1=$2=""; gsub(/ /,"",$0); gsub(/,/," ",$0); print $0}' | while read -r jail; do
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

fail2ban_tune_basics() {
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        echo "Fail2ban not installed."
        return 1
    fi
    local jail="/etc/fail2ban/jail.local"
    backup_file "$jail"
    read -r -p "maxretry [5]: " MAXR
    read -r -p "findtime (seconds) [600]: " FND
    read -r -p "bantime (seconds) [600]: " BAN
    MAXR=${MAXR:-5}; FND=${FND:-600}; BAN=${BAN:-600}
    cat > "$jail" <<EOF
[DEFAULT]
maxretry = $MAXR
findtime = $FND
bantime  = $BAN
EOF
    echo "Updated $jail with maxretry=$MAXR, findtime=$FND, bantime=$BAN"
    fail2ban-client reload || true
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

docker_socket_warning() {
    if ! command -v docker >/dev/null 2>&1; then
        return 0
    fi
    local id
    for id in $(docker ps -q 2>/dev/null || true); do
        if docker inspect --format '{{range .Mounts}}{{println .Source}}{{end}}' "$id" 2>/dev/null | grep -q "/var/run/docker.sock"; then
            echo "Warning: /var/run/docker.sock is mounted in a container. Consider a socket proxy."
            return 0
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

kernel_list_installed() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    echo "Running kernel: $(uname -r)"
    echo "Installed kernel packages (linux-image):"
    dpkg -l 'linux-image-*' 2>/dev/null | awk '/^ii/{print $2,$3}' | column -t
}

kernel_purge_package() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    kernel_list_installed
    read -r -p "Package name to purge (exact, e.g., linux-image-5.15.0-88-generic): " KP
    [[ -z "$KP" ]] && { echo "No package provided."; return 1; }
    warn_if_remote_no_tmux "Purging kernels can impact remote sessions."
    if [[ "$KP" == *"$(uname -r)"* ]]; then
        echo "Refusing to purge the running kernel."
        return 1
    fi
    run_cmd "Purge kernel package $KP" apt-get purge -y "$KP"
}

log_cleanup_preset() {
    echo "Journal vacuum (7d) and largest /var/log files (top 10):"
    run_cmd "journalctl vacuum-time=7d" journalctl --vacuum-time=7d
    find /var/log -type f -printf '%s %p\n' 2>/dev/null | sort -nr | head -n 10 | awk '{printf "%7.1f MiB  %s\n", $1/1024/1024, $2}'
}

journal_vacuum_custom() {
    read -r -p "Vacuum journal to time window (e.g., 14d, 1G) [7d]: " JWIN
    JWIN=${JWIN:-7d}
    run_cmd "journalctl vacuum-time=${JWIN}" journalctl --vacuum-time="$JWIN"
}

needrestart_summary() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
    if ! command -v needrestart >/dev/null 2>&1; then
        if ! wait_for_dpkg_lock 90; then
            return 1
        fi
        run_cmd "Install needrestart" pkg_install needrestart
    fi
    needrestart -b || true
}

kernel_manage_menu() {
    kernel_list_installed
    read -r -p "Purge a kernel package? (leave blank to skip): " DO_PURGE
    if [[ -n "$DO_PURGE" ]]; then
        kernel_purge_package
    fi
}

# --- Monitoring ---

install_node_exporter() {
    run_cmd "Package update" pkg_update
    run_cmd "Install node exporter" pkg_install prometheus-node-exporter
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
    run_cmd "Install chkrootkit" pkg_install chkrootkit binutils
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

start_ssh_service() {
    run_cmd "Start SSH service (${SSH_UNIT})" systemctl start "$SSH_UNIT"
}

stop_ssh_service() {
    if ! skip_if_safe "stop SSH service"; then return 1; fi
    run_cmd "Stop SSH service (${SSH_UNIT})" systemctl stop "$SSH_UNIT"
}

restart_ssh_service() {
    run_cmd "Restart SSH service (${SSH_UNIT})" systemctl restart "$SSH_UNIT"
}

enable_ssh_service() {
    run_cmd "Enable SSH service (${SSH_UNIT})" systemctl enable --now "$SSH_UNIT"
}

disable_ssh_service() {
    if ! skip_if_safe "disable SSH service"; then return 1; fi
    run_cmd "Disable SSH service (${SSH_UNIT})" systemctl disable --now "$SSH_UNIT"
}

warn_if_remote_no_tmux() {
    local msg="$1"
    if [[ -n "${SSH_TTY:-}" ]] && [[ -z "${TMUX:-}" && -z "${STY:-}" ]]; then
        echo "Note: remote session without tmux/screen. $msg"
    fi
}

qm_list_vms() {
    if ! command -v qm >/dev/null 2>&1; then
        echo "qm not found (Proxmox tools missing)."
        return 1
    fi
    qm list
}

general_information() {
    run_cmd "Install neofetch" pkg_install neofetch
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
    lshw -c display
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
    echo "Available containers:"
    pct list || true
    read -r -p "Enter VMID to enter: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    pct enter "$VMID"
}

pct_start_container() {
    if ! command -v pct >/dev/null 2>&1; then
        echo "pct not found (Proxmox tools missing)."
        return 1
    fi
    read -r -p "Enter VMID to start: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    run_cmd "Start LXC $VMID" pct start "$VMID"
}

pct_stop_container() {
    if ! command -v pct >/dev/null 2>&1; then
        echo "pct not found (Proxmox tools missing)."
        return 1
    fi
    read -r -p "Enter VMID to stop: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    run_cmd "Stop LXC $VMID" pct stop "$VMID"
}

pct_restart_container() {
    if ! command -v pct >/dev/null 2>&1; then
        echo "pct not found (Proxmox tools missing)."
        return 1
    fi
    read -r -p "Enter VMID to restart: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    run_cmd "Restart LXC $VMID" pct restart "$VMID"
}

proxmox_list_storage() {
    if command -v pvesm >/dev/null 2>&1; then
        pvesm status
    else
        echo "pvesm not found (host may not be Proxmox)."
    fi
}

proxmox_snapshot_create() {
    if ! command -v pct >/dev/null 2>&1; then
        echo "pct not found (Proxmox tools missing)."
        return 1
    fi
    read -r -p "Enter VMID to snapshot: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    local SNAP
    SNAP="snap-$(date +%Y%m%d-%H%M%S)"
    read -r -p "Snapshot name [${SNAP}]: " USER_SNAP
    SNAP=${USER_SNAP:-$SNAP}
    run_cmd "Create snapshot $SNAP on $VMID" pct snapshot "$VMID" "$SNAP"
}

proxmox_snapshot_list() {
    if ! command -v pct >/dev/null 2>&1; then
        echo "pct not found (Proxmox tools missing)."
        return 1
    fi
    read -r -p "Enter VMID to list snapshots: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    pct listsnapshot "$VMID"
}

proxmox_snapshot_rollback() {
    if ! command -v pct >/dev/null 2>&1; then
        echo "pct not found (Proxmox tools missing)."
        return 1
    fi
    read -r -p "Enter VMID to rollback: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    read -r -p "Snapshot name to rollback to: " SNAP
    [[ -z "$SNAP" ]] && { echo "No snapshot provided."; return 1; }
    run_cmd "Rollback $VMID to snapshot $SNAP" pct rollback "$VMID" "$SNAP"
}

proxmox_backup_lxc() {
    if ! command -v vzdump >/dev/null 2>&1; then
        echo "vzdump not found (Proxmox tools missing)."
        return 1
    fi
    read -r -p "Enter VMID to back up: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    read -r -p "Backup directory [/var/lib/vz/dump]: " BDIR
    BDIR=${BDIR:-/var/lib/vz/dump}
    read -r -p "Mode (snapshot/stop) [snapshot]: " MODE
    MODE=${MODE:-snapshot}
    run_cmd "Backup LXC $VMID to $BDIR (mode=$MODE)" vzdump "$VMID" --mode "$MODE" --dumpdir "$BDIR" --compress zstd
}

proxmox_restore_lxc() {
    if ! command -v pct >/dev/null 2>&1; then
        echo "pct not found (Proxmox tools missing)."
        return 1
    fi
    read -r -p "Backup file path (e.g., /var/lib/vz/dump/vzdump-lxc-100-*.tar.zst): " BFILE
    [[ -z "$BFILE" ]] && { echo "No backup file provided."; return 1; }
    read -r -p "Target VMID to restore into: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    read -r -p "Storage (optional, e.g., local-lvm) [leave blank to default]: " STOR
    if [[ -n "$STOR" ]]; then
        run_cmd "Restore $BFILE to VMID $VMID (storage $STOR)" pct restore "$VMID" "$BFILE" --storage "$STOR"
    else
        run_cmd "Restore $BFILE to VMID $VMID" pct restore "$VMID" "$BFILE"
    fi
}

proxmox_rotate_backups() {
    local dump_dir="/var/lib/vz/dump"
    read -r -p "Backup directory [$dump_dir]: " USER_DIR
    dump_dir=${USER_DIR:-$dump_dir}
    read -r -p "Keep how many newest backups? [5]: " KEEP
    KEEP=${KEEP:-5}
    if [[ ! -d "$dump_dir" ]]; then
        echo "Directory not found: $dump_dir"
        return 1
    fi
    echo "Rotating backups in $dump_dir (keeping $KEEP newest files)..."
    local removed=0
    while IFS= read -r file; do
        echo "Removing $file"
        rm -f -- "$file"
        removed=$((removed+1))
    done < <(find "$dump_dir" -maxdepth 1 -type f \( -name 'vzdump-*.vma*' -o -name 'vzdump-*.tar.*' \) | sort -r | tail -n +$((KEEP+1)))
    echo "Removed $removed old backup(s) from $dump_dir"
}

proxmox_tune_resources() {
    if ! command -v pct >/dev/null 2>&1; then
        echo "pct not found (Proxmox tools missing)."
        return 1
    fi
    read -r -p "Enter VMID to tune: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    read -r -p "CPU cores (leave blank to skip): " CORES
    read -r -p "Memory MB (leave blank to skip): " MEM
    local args=()
    [[ -n "$CORES" ]] && args+=("--cores" "$CORES")
    [[ -n "$MEM" ]] && args+=("--memory" "$MEM")
    if [[ ${#args[@]} -eq 0 ]]; then
        echo "No changes provided."
        return 0
    fi
    run_cmd "Set resources for $VMID" pct set "$VMID" "${args[@]}"
}

proxmox_health() {
    echo "[Proxmox services]"
    systemctl status pveproxy --no-pager 2>/dev/null || echo "pveproxy status unavailable."
    systemctl status pvedaemon --no-pager 2>/dev/null || echo "pvedaemon status unavailable."
    systemctl status pvescheduler --no-pager 2>/dev/null || echo "pvescheduler status unavailable."
    echo
    if command -v pvesm >/dev/null 2>&1; then
        echo "[Storage status]"
        pvesm status
    fi
    if command -v pvecm >/dev/null 2>&1; then
        echo
        echo "[Cluster status]"
        pvecm status
    fi
}

proxmox_post_install() {
    if ! command -v bash >/dev/null 2>&1; then
        echo "bash not found; cannot run post-install script."
        return 1
    fi
    echo "Running PVE Post Install script from community-scripts (https://community-scripts.github.io/ProxmoxVE)..."
    run_cmd "Execute post-pve-install.sh" bash -c "curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/tools/pve/post-pve-install.sh | bash"
    echo "Post-install script execution finished. Review output above for details."
}

proxmox_download_templates() {
    if ! command -v bash >/dev/null 2>&1; then
        echo "bash not found; cannot run template script."
        return 1
    fi
    echo "Running community 'all-templates' script to download Proxmox templates..."
    run_cmd "Execute all-templates" bash -c "curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/tools/pve/all-templates.sh | bash"
    echo "Template script execution finished. Review output above for details."
}

proxmox_list_tasks() {
    if command -v pvesh >/dev/null 2>&1; then
        echo "Recent tasks (pvesh /cluster/tasks --limit 15):"
        pvesh get /cluster/tasks --limit 15 2>/dev/null | head -n 200 || echo "Unable to list tasks."
    else
        echo "pvesh not found; skipping task list."
    fi
}

proxmox_list_backups() {
    local dumpdir="/var/lib/vz/dump"
    if [[ -d "$dumpdir" ]]; then
        echo "Backups in $dumpdir:"
        ls -lh "$dumpdir" 2>/dev/null | tail -n +1
    else
        echo "Backup directory $dumpdir not found."
    fi
}

qm_start_vm() {
    if ! command -v qm >/dev/null 2>&1; then
        echo "qm not found."
        return 1
    fi
    read -r -p "VMID to start: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    run_cmd "Start VM $VMID" qm start "$VMID"
}

qm_stop_vm() {
    if ! command -v qm >/dev/null 2>&1; then
        echo "qm not found."
        return 1
    fi
    read -r -p "VMID to stop: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    run_cmd "Stop VM $VMID" qm stop "$VMID"
}

qm_restart_vm() {
    if ! command -v qm >/dev/null 2>&1; then
        echo "qm not found."
        return 1
    fi
    read -r -p "VMID to restart: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    run_cmd "Restart VM $VMID" qm reset "$VMID"
}

qm_snapshot_create() {
    if ! command -v qm >/dev/null 2>&1; then
        echo "qm not found."
        return 1
    fi
    read -r -p "VMID to snapshot: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    local SNAP="snap-$(date +%Y%m%d-%H%M%S)"
    read -r -p "Snapshot name [${SNAP}]: " USER_SNAP
    SNAP=${USER_SNAP:-$SNAP}
    run_cmd "Create VM snapshot $SNAP on $VMID" qm snapshot "$VMID" "$SNAP"
}

qm_snapshot_list() {
    if ! command -v qm >/dev/null 2>&1; then
        echo "qm not found."
        return 1
    fi
    read -r -p "VMID to list snapshots: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    qm listsnapshot "$VMID"
}

qm_snapshot_rollback() {
    if ! command -v qm >/dev/null 2>&1; then
        echo "qm not found."
        return 1
    fi
    read -r -p "VMID to rollback: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    read -r -p "Snapshot name to rollback to: " SNAP
    [[ -z "$SNAP" ]] && { echo "No snapshot provided."; return 1; }
    run_cmd "Rollback VM $VMID to snapshot $SNAP" qm rollback "$VMID" "$SNAP"
}

qm_backup_vm() {
    if ! command -v vzdump >/dev/null 2>&1; then
        echo "vzdump not found."
        return 1
    fi
    read -r -p "VMID to back up: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    read -r -p "Backup directory [/var/lib/vz/dump]: " BDIR
    BDIR=${BDIR:-/var/lib/vz/dump}
    read -r -p "Mode (snapshot/stop) [snapshot]: " MODE
    MODE=${MODE:-snapshot}
    run_cmd "Backup VM $VMID to $BDIR (mode=$MODE)" vzdump "$VMID" --mode "$MODE" --dumpdir "$BDIR" --compress zstd
}

qm_restore_vm() {
    if ! command -v qmrestore >/dev/null 2>&1 && ! command -v qm >/dev/null 2>&1; then
        echo "qm/qmrestore not found."
        return 1
    fi
    read -r -p "Backup file path (e.g., /var/lib/vz/dump/vzdump-qemu-100-*.vma.zst): " BFILE
    [[ -z "$BFILE" ]] && { echo "No backup file provided."; return 1; }
    read -r -p "Target VMID to restore into: " VMID
    [[ -z "$VMID" ]] && { echo "No VMID provided."; return 1; }
    read -r -p "Storage (optional, e.g., local-lvm) [leave blank to default]: " STOR
    local cmd="qmrestore"
    [[ ! -x "$(command -v qmrestore)" ]] && cmd="qm restore"
    if [[ -n "$STOR" ]]; then
        run_cmd "Restore $BFILE to VMID $VMID (storage $STOR)" $cmd "$BFILE" "$VMID" --storage "$STOR"
    else
        run_cmd "Restore $BFILE to VMID $VMID" $cmd "$BFILE" "$VMID"
    fi
}

qm_download_iso() {
    read -r -p "ISO URL: " ISOURL
    [[ -z "$ISOURL" ]] && { echo "No URL provided."; return 1; }
    read -r -p "Target directory [/var/lib/vz/template/iso]: " TDIR
    TDIR=${TDIR:-/var/lib/vz/template/iso}
    mkdir -p "$TDIR"
    run_cmd "Download ISO to $TDIR" bash -c "cd \"$TDIR\" && wget -q --show-progress \"$ISOURL\""
    echo "Downloaded to $TDIR"
}

# --- Maintenance / disks ---

system_cleanup() {
    if ! require_pkg_mgr apt; then
        return 1
    fi
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

change_user_password() {
    read -p "Enter username to change password: " TARGETUSER
    if ! id "$TARGETUSER" &>/dev/null; then
        echo "User $TARGETUSER does not exist."
        return 1
    fi
    passwd "$TARGETUSER"
}

show_time_sync() {
    timedatectl
}

install_chrony() {
    run_cmd "Package update" pkg_update
    run_cmd "Install chrony" pkg_install chrony
    systemctl enable --now chrony
    timedatectl
}

# --- System control ---

system_reboot() {
    if ! skip_if_safe "reboot"; then return 1; fi
    warn_if_remote_no_tmux "Rebooting over SSH without tmux/screen may drop your session."
    msgbox "System Reboot"
    if confirm_prompt "Are you sure?"; then
        reboot
    fi
}

system_powerdown() {
    if ! skip_if_safe "power down"; then return 1; fi
    warn_if_remote_no_tmux "Powering down over SSH without tmux/screen may drop your session."
    msgbox "System Power Down"
    if confirm_prompt "Are you sure?"; then
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
Error log:      $ERROR_LOG
Backup dir:     $BACKUP_DIR
Backup keep:    $BACKUP_KEEP
Backup comp:    $BACKUP_COMPRESS
DRY_RUN:        $DRY_RUN
SAFE_MODE:      $SAFE_MODE
CONFIRM:        $CONFIRM
PKG_MGR:        ${PKG_MGR:-unknown}
DISTRO_ID:      ${DISTRO_ID:-unknown}
Units:          SSH=$SSH_UNIT, UFW=$UFW_UNIT, Fail2ban=$FAIL2BAN_UNIT, Tailscale=$TAILSCALE_UNIT, Docker=$DOCKER_UNIT, Netmaker=$NETMAKER_UNIT, CrowdSec=$CROWDSEC_UNIT, Bouncer=$CROWDSEC_BOUNCER_UNIT
EOF
}

config_json() {
    echo "{"
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "log_file": "%s",\n' "$LOG_FILE"
    printf '  "error_log": "%s",\n' "$ERROR_LOG"
    printf '  "backup_dir": "%s",\n' "$BACKUP_DIR"
    printf '  "backup_keep": "%s",\n' "$BACKUP_KEEP"
    printf '  "backup_compress": "%s",\n' "$BACKUP_COMPRESS"
    printf '  "report_dir": "%s",\n' "$REPORT_DIR"
    printf '  "dry_run": "%s",\n' "$DRY_RUN"
    printf '  "safe_mode": "%s",\n' "$SAFE_MODE"
    printf '  "confirm": "%s",\n' "$CONFIRM"
    printf '  "pkg_mgr": "%s",\n' "${PKG_MGR:-unknown}"
    printf '  "distro_id": "%s",\n' "${DISTRO_ID:-unknown}"
    printf '  "units": {"ssh": "%s", "ufw": "%s", "fail2ban": "%s", "tailscale": "%s", "docker": "%s", "netmaker": "%s", "crowdsec": "%s", "bouncer": "%s"}\n' \
        "$SSH_UNIT" "$UFW_UNIT" "$FAIL2BAN_UNIT" "$TAILSCALE_UNIT" "$DOCKER_UNIT" "$NETMAKER_UNIT" "$CROWDSEC_UNIT" "$CROWDSEC_BOUNCER_UNIT"
    echo "}"
}

write_config_template() {
    local target="${1:-/etc/ntx-menu.conf}"
    if [[ -f "$target" ]]; then
        echo "Config already exists at $target"
        return 0
    fi
    cat <<EOF > "$target"
# ntx-menu config override
LOG_FILE="${LOG_FILE}"
BACKUP_DIR="${BACKUP_DIR}"
REPORT_DIR="${REPORT_DIR}"
SSH_UNIT="${SSH_UNIT}"
UFW_UNIT="${UFW_UNIT}"
FAIL2BAN_UNIT="${FAIL2BAN_UNIT}"
TAILSCALE_UNIT="${TAILSCALE_UNIT}"
DOCKER_UNIT="${DOCKER_UNIT}"
NETMAKER_UNIT="${NETMAKER_UNIT}"
SCHROOT_UNIT="${SCHROOT_UNIT}"
CROWDSEC_UNIT="${CROWDSEC_UNIT}"
CROWDSEC_BOUNCER_UNIT="${CROWDSEC_BOUNCER_UNIT}"
# Language: en|de
LANGUAGE="${LANGUAGE}"
# Update cadence warning (days)
UPDATE_WARN_DAYS="${UPDATE_WARN_DAYS}"
EOF
    echo "Wrote template to $target"
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
        render_header "NTX BEFEHLSZENTRALE ($VERSION)"
        cat <<EOF
[Kern]
 1) Systemupdate        2) DNS-Verwaltung      3) Netzwerk / IP
 4) Speedtest & Bench   5) Sicherheit / Remote

[Betrieb]
 6) Tools & Umgebung    7) Container / Docker  8) Monitoring
 9) Systeminfo         10) Wartung / Disks    11) Benutzer & Zeit
12) Proxmox-Helfer     13) Systemsteuerung     m) CMatrix

[Schnellzugriff]
h) Hilfe / Info    s) Status-Dashboard    l) Logs ansehen
c) Konfig/Umgebung u) Self-Update        d) Sprache (en/de)
i) Installation    q) Beenden
EOF
        render_footer
    else
        render_header "NTX COMMAND CENTER ($VERSION)"
        cat <<EOF
[Core]
 1) System update       2) DNS management      3) Network / IP
 4) Speedtest & bench   5) Security / remote

[Operations]
 6) Tools & environment 7) Containers / Docker 8) Monitoring
 9) System info        10) Maintenance / disks 11) Users & time
12) Proxmox helpers    13) System control      m) CMatrix
EOF
        render_footer
    fi
}

search_section() {
    local query="$1"
    local -a names=("system update" "dns" "network" "speedtest" "security" "tools" "containers" "monitoring" "system information" "maintenance" "users" "proxmox" "control" "cmatrix" "help" "status" "logs" "config" "update" "language" "install")
    local -a targets=(1 2 3 4 5 6 7 8 9 10 11 12 13 m h s l c u d i)
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
        ssh_start) start_ssh_service ;;
        ssh_stop) stop_ssh_service ;;
        ssh_restart) restart_ssh_service ;;
        ssh_enable) enable_ssh_service ;;
        ssh_disable) disable_ssh_service ;;
        change_password) change_user_password ;;
        health_brief) health_brief ;;
        cmatrix) run_cmatrix ;;
        config_json) config_json ;;
        *)
            echo "Unknown action: $action"
            echo "Supported: update_all, maintenance_bundle, status_report, status_report_json, status_dashboard, health_brief, ssh_audit, docker_compose_health, wireguard_qr, apt_health, update_health, clamav_scan, ssh_start, ssh_stop, ssh_restart, ssh_enable, ssh_disable, change_password, cmatrix, config_json"
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
  status_report_json    Export status report to JSON
  config_json           Print config/environment as JSON
  status_dashboard      Print status dashboard
  health_brief          Print a short text-only health summary
  ssh_audit             Run SSH hardening check
  docker_compose_health Show Docker Compose health (ls/ps)
  wireguard_qr          Render /etc/wireguard/wg0.conf as QR (requires qrencode)
  apt_health            Show held/broken/security updates
  update_health         Show reboot requirement + last update timestamp
  clamav_scan           Install ClamAV and run a quick recursive scan
  ssh_start             Start SSH service
  ssh_stop              Stop SSH service
  ssh_restart           Restart SSH service
  ssh_enable            Enable SSH service (enable --now)
  ssh_disable           Disable SSH service
  change_password       Prompt to change a user's password
  cmatrix               Run cmatrix (installs if missing)
EOF
}

menu_update() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Systemupdate]
 1) Alles aktualisieren (apt-get update && upgrade)
 2) Aktualisieren und bei Bedarf neu starten
 3) Aktualisieren mit sudo und neu starten (nur apt)
 4) do-release-upgrade (Ubuntu, nur apt)

 5) Automatische Updates aktivieren (nur apt)
 6) Automatische Updates deaktivieren (nur apt)
 7) Automatische Updates: Status (nur apt)
 8) Automatische Updates jetzt ausführen (nur apt)

 9) Benutzerdefinierte apt-Quellen auflisten (nur apt)
10) Benutzerdefinierte apt-Quelle entfernen (.list, nur apt)
11) APT-Gesundheit (gehalten/defekt/Security, nur apt)
12) Update-Status (Reboot + Zeitstempel, nur apt)
13) APT Proxy setzen/entfernen (nur apt)
14) APT-Quellen auf mismatched Codenames prüfen (nur apt)
 0) Zurück
EOF
        else
            cat <<EOF
[System update]
 1) Update all (apt-get update && upgrade)
 2) Update all and reboot if required
 3) Update all with sudo and reboot (apt-only)
 4) do-release-upgrade (Ubuntu, apt-only)

 5) Unattended upgrades: enable (apt-only)
 6) Unattended upgrades: disable (apt-only)
 7) Unattended upgrades: status (apt-only)
 8) Unattended upgrades: run now (apt-only)

 9) List custom apt sources (apt-only)
10) Remove custom apt source (.list, apt-only)
11) APT health check (held/broken/security, apt-only)
12) Update health (reboot + last update, apt-only)
13) APT proxy toggle (set/remove, apt-only)
14) Validate apt sources for mismatched codenames (apt-only)
 0) Back
EOF
        fi
        if [[ "$PKG_MGR" != "apt" ]]; then
            if [[ "$LANGUAGE" == "de" ]]; then
                echo "Hinweis: Optionen mit 'nur apt' sind markiert und auf ${PKG_MGR} nicht verfugbar."
            else
                echo "Note: apt-only options are labeled and unavailable on ${PKG_MGR}."
            fi
        fi
        read -p "Select: " c
        case "$c" in
            1) update_all ;;
            2) update_all_reboot_if_needed ;;
            3) update_all_with_sudo_reboot ;;
            4) do_release_upgrade ;;
            5) enable_unattended_upgrades ;;
            6) disable_unattended_upgrades ;;
            7) check_unattended_status ;;
            8) run_unattended_upgrade_now ;;
            9) list_custom_sources ;;
            10) remove_custom_source ;;
            11) apt_health_check ;;
            12) update_health_check ;;
            13) toggle_apt_proxy ;;
            14) apt_source_validator ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_dns() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[DNS-Verwaltung]
 1) DNS anzeigen (/etc/resolv.conf)
 2) DNS bearbeiten (nano)

 3) Netcup anhängen: 46.38.225.230 + 46.38.252.230 + 1.1.1.1
 4) Netcup überschreiben: 46.38.225.230 + 46.38.252.230 + 1.1.1.1
 5) Überschreiben: 1.1.1.1 + 8.8.8.8
 6) Anhängen: 1.1.1.1 + 8.8.8.8

 7) IPv6 überschreiben: 2606:4700:4700::1111 + 2001:4860:4860::8888
 8) IPv6 anhängen: 2606:4700:4700::1111 + 2001:4860:4860::8888

 9) DNS aus letztem Backup wiederherstellen
10) Benutzerdefinierten Nameserver hinzufügen
11) Backup wiederherstellen + systemd-resolved neu starten
 0) Zurück
EOF
        else
            cat <<EOF
[DNS management]
 1) Show DNS (/etc/resolv.conf)
 2) Edit DNS (nano)

 3) Netcup append: 46.38.225.230 + 46.38.252.230 + 1.1.1.1
 4) Netcup overwrite: 46.38.225.230 + 46.38.252.230 + 1.1.1.1
 5) Overwrite: 1.1.1.1 + 8.8.8.8
 6) Append: 1.1.1.1 + 8.8.8.8

 7) Overwrite IPv6: 2606:4700:4700::1111 + 2001:4860:4860::8888
 8) Append IPv6: 2606:4700:4700::1111 + 2001:4860:4860::8888

 9) Restore DNS from latest backup
10) Add custom nameserver (prompt)
11) Restore DNS backup and restart systemd-resolved
 0) Back
EOF
        fi
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
            10) add_custom_dns ;;
            11) restore_dns_and_restart ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_network() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Netzwerk / IP]
 1) Öffentliche IP anzeigen
 2) Schnittstellen (ifconfig)
 3) Routing-Tabelle
 4) Aktive Verbindungen

 5) Häufige Ziele anpingen
 6) Traceroute zu Host
 7) Top-Talkers (TCP)
 8) VLAN anlegen
 9) VLAN löschen
10) Bond anlegen
11) Bond löschen
12) SSH-Key erzeugen + optional kopieren
13) MTR (kurzer Lauf)
14) Nmap Top Ports (50)
 0) Zurück
EOF
        else
            cat <<EOF
[Network / IP]
 1) Show public IP
 2) Show ifconfig
 3) Show routing table
 4) Show active connections

 5) Ping common endpoints
 6) Traceroute to host
 7) Top talkers (TCP)
 8) Create VLAN
 9) Delete VLAN
10) Create bond
11) Delete bond
12) Generate SSH key (+ optional ssh-copy-id)
13) Run MTR (short)
14) Quick nmap top 50 ports
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) whats_my_ip ;;
            2) show_ifconfig ;;
            3) show_routes ;;
            4) show_connections ;;
            5) ping_common ;;
            6) trace_route ;;
            7) show_top_talkers ;;
            8) create_vlan ;;
            9) delete_vlan ;;
            10) create_bond ;;
            11) delete_bond ;;
            12) generate_ssh_key ;;
            13) run_mtr_quick ;;
            14) nmap_top_ports ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_bench() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Speedtest & Benchmarks]
 1) Speedtest installieren (Repo + Paket, nur apt)
 2) Speedtest-Repo-Liste aktualisieren (jammy, nur apt)
 3) Speedtest nach Repo-Update installieren (nur apt)
 4) Speedtest ausführen

 5) YABS ausführen
 6) Speedtest Repo/Key entfernen (nur apt)
 7) Benchmark-Presets (YABS Untermenü)
 0) Zurück
EOF
        else
            cat <<EOF
[Speedtest & benchmarks]
 1) Install Speedtest (repo + package, apt-only)
 2) Update Speedtest repo list (jammy, apt-only)
 3) Install Speedtest after repo update (apt-only)
 4) Run Speedtest

 5) Run YABS
 6) Remove Speedtest repo/key (apt-only)
 7) Benchmark presets (YABS submenu)
 0) Back
EOF
        fi
        if [[ "$PKG_MGR" != "apt" ]]; then
            if [[ "$LANGUAGE" == "de" ]]; then
                echo "Hinweis: Optionen mit 'nur apt' sind markiert und auf ${PKG_MGR} nicht verfugbar."
            else
                echo "Note: apt-only options are labeled and unavailable on ${PKG_MGR}."
            fi
        fi
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
        should_pause_after "$c" && pause_prompt
    done
}

menu_yabs_presets() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[YABS Benchmark-Presets]
 1) Benchmark - Alle Tests
 2) Benchmark - Disk Performance
 3) Benchmark - Netzwerk Performance
 4) Benchmark - System Performance (ältere Version)
 5) Benchmark - System Performance
 0) Zurück
EOF
        else
            cat <<EOF
[YABS benchmark presets]
 1) Benchmark - All Tests
 2) Benchmark - Disk Performance
 3) Benchmark - Network Performance
 4) Benchmark - System Performance (older version)
 5) Benchmark - System Performance
 0) Back
EOF
        fi
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
        should_pause_after "$c" && pause_prompt
    done
}

menu_security() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Sicherheit / Remote]
 1) Firewall (UFW) Untermenü
 2) Fail2ban Untermenü
 3) SSH / Zugriff Untermenü
 4) WireGuard Untermenü
 5) CrowdSec / Netmaker / Tailscale Untermenü
 6) Anti-Malware (ClamAV / Rootkit)
 7) Config-Backup/Wiederherstellung
 8) Auditd Minimal-Profile anwenden
 9) Erst-Setup-Checkliste (Docker/Compose, SSH, UFW, Fail2ban)
10) SSH Cipher/KEX/MAC Audit
 0) Zurück
EOF
        else
            cat <<EOF
[Security / remote access]
 1) Firewall (UFW) submenu
 2) Fail2ban submenu
 3) SSH / Access submenu
 4) WireGuard submenu
 5) CrowdSec / Netmaker / Tailscale submenu
 6) Anti-malware (ClamAV / Rootkit)
 7) Config backup/restore submenu
 8) Auditd minimal ruleset
 9) First-run checklist (Docker/Compose, SSH, UFW, Fail2ban)
10) SSH cipher/KEX/MAC audit
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) menu_firewall ;;
            2) menu_fail2ban ;;
            3) menu_ssh_access ;;
            4) menu_wireguard ;;
            5) menu_agents ;;
            6) menu_antimalware ;;
            7) menu_config_backup ;;
            8) auditd_minimal_rules ;;
            9) first_run_checklist ;;
            10) ssh_cipher_audit ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_firewall() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Firewall / UFW]
 1) Firewall-Status anzeigen
 2) UFW installieren (SSH erlauben, aktivieren)
 3) UFW Preset: nur SSH
 4) UFW Preset: SSH + HTTP/HTTPS
 5) UFW Preset: alles außer SSH blocken
 6) UFW: letztes Snapshot zurückrollen
 0) Zurück
EOF
        else
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
        fi
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
        should_pause_after "$c" && pause_prompt
    done
}

menu_fail2ban() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Fail2ban]
 1) Fail2ban installieren
 2) Fail2ban Übersicht + Reload
 3) Gebannte IPs auflisten
 4) IP entbannen
 5) Letzte fehlgeschlagene Logins
 6) Basis-Parameter setzen (maxretry/findtime/bantime)
 0) Zurück
EOF
        else
            cat <<EOF
[Fail2ban]
 1) Install Fail2ban
 2) Fail2ban summary + reload
 3) Fail2ban: list banned IPs
 4) Fail2ban: unban IP
 5) Show recent failed logins
 6) Tune basics (maxretry/findtime/bantime)
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) install_fail2ban ;;
            2) fail2ban_summary ;;
            3) fail2ban_list_bans ;;
            4) fail2ban_unban_ip ;;
            5) show_failed_logins ;;
            6) fail2ban_tune_basics ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_ssh_access() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[SSH / Zugriff]
 1) SSH-Status anzeigen
 2) SSH-Hardening-Check
 3) SSH-Konfig für Proxmox (PermitRootLogin yes)
 4) OpenSSH-Server installieren
 5) Google Authenticator (PAM) installieren
 6) SSH-Dienst starten
 7) SSH-Dienst stoppen
 8) SSH-Dienst neu starten
 9) SSH-Dienst aktivieren (enable)
10) SSH-Dienst deaktivieren (disable)
 0) Zurück
EOF
        else
            cat <<EOF
[SSH / Access]
 1) Show SSH status
 2) SSH hardening check
 3) Update SSH config for Proxmox (PermitRootLogin yes)
 4) Install OpenSSH server
 5) Install Google Authenticator (PAM)
 6) Start SSH service
 7) Stop SSH service
 8) Restart SSH service
 9) Enable SSH service
10) Disable SSH service
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) show_ssh_status ;;
            2) ssh_hardening_audit ;;
            3) change_ssh_proxmox ;;
            4) install_openssh ;;
            5) install_google_authenticator ;;
            6) start_ssh_service ;;
            7) stop_ssh_service ;;
            8) restart_ssh_service ;;
            9) enable_ssh_service ;;
            10) disable_ssh_service ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_wireguard() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[WireGuard]
 1) WireGuard installieren (Client)
 2) WireGuard installieren (Server)
 3) Beispielkonfiguration anzeigen
 4) Konfig validieren (Interface wählen, optional Diff)
 5) Interface starten (Standard wg0)
 6) Interface stoppen (Standard wg0)
 7) Interface neu starten (Standard wg0)
 8) Konfig als QR anzeigen (wg0.conf)
 9) wg-quick@wg0 aktivieren
10) wg-quick@wg0 deaktivieren
 0) Zurück
EOF
        else
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
        fi
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
        should_pause_after "$c" && pause_prompt
    done
}

menu_agents() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[CrowdSec / Netmaker / Tailscale]
 1) Tailscale installieren
 2) Tailscale up (QR-Modus)
 3) Netmaker netclient installieren (nur apt)
 4) Netmaker Repo/Key entfernen (nur apt)
 5) CrowdSec installieren (nur apt)
 6) CrowdSec Firewall Bouncer (iptables) installieren (nur apt)
 0) Zurück
EOF
        else
            cat <<EOF
[CrowdSec / Netmaker / Tailscale]
 1) Install Tailscale
 2) Tailscale up (QR mode)
 3) Install Netmaker netclient (apt-only)
 4) Remove Netmaker repo/key (apt-only)
 5) Install CrowdSec (apt-only)
 6) Install CrowdSec firewall bouncer (iptables) (apt-only)
 0) Back
EOF
        fi
        if [[ "$PKG_MGR" != "apt" ]]; then
            if [[ "$LANGUAGE" == "de" ]]; then
                echo "Hinweis: Optionen mit 'nur apt' sind markiert und auf ${PKG_MGR} nicht verfugbar."
            else
                echo "Note: apt-only options are labeled and unavailable on ${PKG_MGR}."
            fi
        fi
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
        should_pause_after "$c" && pause_prompt
    done
}

menu_antimalware() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Anti-Malware]
 1) Rootkit-Check (installiert chkrootkit)
 2) ClamAV installieren + Schnellscan
 0) Zurück
EOF
        else
            cat <<EOF
[Anti-malware]
 1) Rootkit check (installs chkrootkit)
 2) Install ClamAV + run quick scan
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) rootkit_check ;;
            2) install_and_scan_clamav ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_config_backup() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Config-Backup/Wiederherstellung]
 1) Config-Bundle sichern (SSH/WireGuard/Fail2ban/UFW)
 2) Config-Bundle wiederherstellen (Auswahl)
 0) Zurück
EOF
        else
            cat <<EOF
[Config backup/restore]
 1) Backup config bundle (SSH/WireGuard/Fail2ban/UFW)
 2) Restore config bundle (choose backup)
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) backup_config_bundle ;;
            2) restore_config_bundle ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_tools() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Tools & Umgebung]
 1) Essentials-Bundle Untermenü

 2) ibramenu installieren
 3) QEMU Guest Agent installieren
 4) nvm (Node Version Manager) installieren
 5) MariaDB Server installieren
 6) Node/npm Version anzeigen
 0) Zurück
EOF
        else
            cat <<EOF
[Tools & environment]
 1) Essentials bundle submenu

 2) Install ibramenu
 3) Install QEMU guest agent
 4) Install nvm (Node Version Manager)
 5) Install MariaDB Server
 6) Show Node/npm versions
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) menu_essentials ;;
            2) install_ibramenu ;;
            3) install_qemu_guest_agent ;;
            4) install_nvm ;;
            5) install_mariadb_server ;;
            6) show_node_npm_versions ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_containers() {
    while true; do
        docker_socket_warning
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Container / Docker]
 1) Docker & Compose-Plugin installieren
 2) Docker Dienst-Status
 3) Docker Info (kurz)
 4) Docker ps (laufende Container)
 5) Docker Compose Health (ls/ps)
 6) Alle Container auflisten

 7) Rootless-Check
 8) Privilegierte Container
 9) Sensible Mounts
10) Container als Root
11) Host-Netzwerk-Container

12) Alle Container stoppen
13) Alle Container starten (compose up -d)
14) Einzelnen Container stoppen
15) Container entfernen (rm -f)
16) Image entfernen (rmi -f)
17) Eigenen Docker-Befehl ausführen

18) Docker aufräumen (prune)
19) Images scannen (docker scan/trivy)
20) Compose-Projekt verwalten (up/down/restart)

21) Portainer installieren
22) Nginx Proxy Manager installieren
23) Traefik installieren
24) Pi-hole installieren
25) Pi-hole + Unbound installieren
26) Nextcloud All-in-One installieren
27) Tactical RMM installieren
28) Hemmelig.app installieren
29) Pangolin installieren (native installer)
30) Arcane installieren (Installer)
31) Arcane installieren (Docker Compose)
32) Docker-Logs anzeigen (tail -f)
 0) Zurück
EOF
        else
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

12) Stop all Docker containers
13) Start all containers (compose up -d)
14) Stop one container
15) Remove container (rm -f)
16) Remove image (rmi -f)
17) Run custom docker command

18) Docker prune (safe)
19) Scan images (docker scan/trivy)
20) Manage Docker Compose project (up/down/restart)

21) Install Portainer (CE)
22) Install Nginx Proxy Manager
23) Install Traefik
24) Install Pi-hole
25) Install Pi-hole + Unbound
26) Install Nextcloud All-in-One
27) Install Tactical RMM
28) Install Hemmelig.app
29) Install Pangolin (native installer)
30) Install Arcane (installer script)
31) Install Arcane (Docker Compose)
32) Tail Docker container logs (follow)
 0) Back
EOF
        fi
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
            12) docker_stop_all ;;
            13) docker_start_all_compose ;;
            14) docker_stop_one ;;
            15) docker_remove_container ;;
            16) docker_remove_image ;;
            17) docker_run_custom ;;
            18) docker_prune_safe ;;
            19) docker_scan_images ;;
            20) docker_compose_manage ;;
            21) install_portainer ;;
            22) install_nginx_proxy_manager ;;
            23) install_traefik ;;
            24) install_pihole_only ;;
            25) install_pihole_unbound ;;
            26) install_nextcloud_aio ;;
            27) install_tactical_rmm ;;
            28) install_hemmelig ;;
            29) install_pangolin_native ;;
            30) install_arcane_script ;;
            31) install_arcane_compose ;;
            32) docker_logs_follow ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

docker_stop_all() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    local ids
    ids=$(docker ps -q)
    if [[ -z "$ids" ]]; then
        echo "No running containers to stop."
        return 0
    fi
    run_cmd "Stop all Docker containers" docker stop $ids
}

docker_stop_one() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    read -r -p "Container name/ID to stop: " cname
    [[ -z "$cname" ]] && { echo "No container provided."; return 1; }
    run_cmd "Stop Docker container $cname" docker stop "$cname"
}

docker_remove_container() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    read -r -p "Container name/ID to remove: " cname
    [[ -z "$cname" ]] && { echo "No container provided."; return 1; }
    run_cmd "Remove Docker container $cname" docker rm -f "$cname"
}

docker_remove_image() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    read -r -p "Image name/ID to remove: " img
    [[ -z "$img" ]] && { echo "No image provided."; return 1; }
    run_cmd "Remove Docker image $img" docker rmi -f "$img"
}

docker_start_all_compose() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    run_cmd "Start all containers (compose up -d)" docker compose up -d
}

docker_run_custom() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    read -p "Enter docker command (after 'docker '): " CMD
    [[ -z "$CMD" ]] && { echo "No command provided."; return 1; }
    run_cmd "docker $CMD" docker $CMD
}

install_portainer() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    run_cmd "Pull Portainer image" docker pull portainer/portainer-ce:latest
    run_cmd "Create Portainer data volume" docker volume create portainer_data
    run_cmd "Run Portainer" docker run -d -p 8000:8000 -p 9443:9443 --name portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:latest
    echo "Portainer running on https://<host>:9443"
    log_app_summary "Portainer: https://<host>:9443 (admin setup on first login)"
}

install_nginx_proxy_manager() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        echo "Docker Compose plugin not found. Install it first (Containers menu option 1)."
        return 1
    fi
    local app="npm"
    local image="jc21/nginx-proxy-manager:latest"
    local base="/opt/appdata/${app}"
    read -p "Docker network to use/create (default npm_proxy): " dockernet
    dockernet=${dockernet:-npm_proxy}

    run_cmd "Create app directory" mkdir -p "$base"
    read -p "Data path for NPM (default ${base}): " base_override
    base=${base_override:-$base}
    cat > "${base}/.env" <<EOF
APP_NAME=${app}
IMAGE=${image}
EOF
    cat > "${base}/compose.yaml" <<EOF
services:
  nginx-proxy-manager:
    image: \${IMAGE:?err}
    container_name: \${APP_NAME:?err}
    ports:
      - "80:80"
      - "81:81"
      - "443:443"
    networks:
      - ${dockernet}
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined

networks:
  ${dockernet}:
    driver: bridge
    external: true
EOF
    if ! docker network inspect "$dockernet" >/dev/null 2>&1; then
        run_cmd "Create Docker network ${dockernet}" docker network create "$dockernet"
    fi
    (cd "$base" && run_cmd "Deploy Nginx Proxy Manager" docker compose up -d --force-recreate)
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo
    echo "Nginx Proxy Manager deployed."
    echo "URL   : http://${ip:-<host>}:81"
    echo "User  : admin@example.com"
    echo "Pass  : changeme"
    log_app_summary "NPM: http://${ip:-<host>}:81 (admin@example.com / changeme) data=${base}"
}

install_traefik() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        echo "Docker Compose plugin not found. Install it first (Containers menu option 1)."
        return 1
    fi
    local base="/opt/appdata/traefik"
    read -p "Data path for Traefik (default ${base}): " base_override
    base=${base_override:-$base}
    read -p "Docker network to use/create (default traefik_proxy): " dockernet
    dockernet=${dockernet:-traefik_proxy}
    read -p "ACME email for certificates (optional): " acme_email

    run_cmd "Create app directory" mkdir -p "$base"
    cat > "${base}/traefik.yml" <<EOF
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

providers:
  file:
    filename: /etc/traefik/dynamic.yml
  docker:
    exposedByDefault: false

certificatesResolvers:
  letsencrypt:
    acme:
      email: ${acme_email}
      storage: /etc/traefik/acme.json
      httpChallenge:
        entryPoint: web
EOF
    cat > "${base}/dynamic.yml" <<'EOF'
http:
  middlewares:
    https-redirect:
      redirectScheme:
        scheme: https
  routers:
    api:
      rule: Host(`traefik.local`)
      service: api@internal
      entryPoints: websecure
      tls: {}
EOF
    touch "${base}/acme.json"
    chmod 600 "${base}/acme.json"
    cat > "${base}/docker-compose.yml" <<EOF
services:
  traefik:
    image: traefik:latest
    container_name: traefik
    restart: unless-stopped
    command:
      - --providers.file.filename=/etc/traefik/traefik.yml
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik.yml:/etc/traefik/traefik.yml:ro
      - ./dynamic.yml:/etc/traefik/dynamic.yml:ro
      - ./acme.json:/etc/traefik/acme.json
    networks:
      - ${dockernet}

networks:
  ${dockernet}:
    external: true
EOF
    if ! docker network inspect "$dockernet" >/dev/null 2>&1; then
        run_cmd "Create Docker network ${dockernet}" docker network create "$dockernet"
    fi
    (cd "$base" && run_cmd "Deploy Traefik" docker compose up -d --force-recreate)
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo
    echo "Traefik deployed."
    echo "Dashboard (insecure example): http://${ip:-<host>}/dashboard/ (enable via labels as needed)."
    echo "Default router example uses host rule traefik.local in dynamic.yml; adjust to your domains and add certificates per your needs."
    log_app_summary "Traefik: http://${ip:-<host>}:80/443 (configure routers) data=${base} network=${dockernet}"
}

install_pihole_unbound() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        echo "Docker Compose plugin not found. Install it first (Containers menu option 1)."
        return 1
    fi
    local base="/opt/appdata/pihole-unbound"
    read -p "Data path for Pi-hole+Unbound (default ${base}): " base_override
    base=${base_override:-$base}
    local tz
    tz=$(cat /etc/timezone 2>/dev/null || echo "UTC")
    read -p "Set Pi-hole WEBPASSWORD (leave blank for default changeme): " webpw
    webpw=${webpw:-changeme}
    run_cmd "Create app directory" mkdir -p "$base"
    cat > "${base}/.env" <<EOF
TZ=${tz}
WEBPASSWORD=${webpw}
PIHOLE_IMAGE=pihole/pihole:latest
UNBOUND_IMAGE=mvance/unbound:latest
EOF
    cat > "${base}/docker-compose.yml" <<'EOF'
services:
  unbound:
    image: ${UNBOUND_IMAGE:?err}
    container_name: unbound
    restart: unless-stopped
    ports:
      - "5335:5335/tcp"
      - "5335:5335/udp"
    volumes:
      - ./unbound:/opt/unbound/etc/unbound

  pihole:
    image: ${PIHOLE_IMAGE:?err}
    container_name: pihole
    depends_on:
      - unbound
    environment:
      TZ: ${TZ}
      WEBPASSWORD: ${WEBPASSWORD}
      DNS1: 127.0.0.1#5335
      DNS2: 127.0.0.1#5335
      REV_SERVER: "false"
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "80:80/tcp"
    volumes:
      - ./etc-pihole:/etc/pihole
      - ./dnsmasq.d:/etc/dnsmasq.d
    restart: unless-stopped
EOF
    (cd "$base" && run_cmd "Deploy Pi-hole + Unbound" docker compose up -d --force-recreate)
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo
    echo "Pi-hole + Unbound deployed."
    echo "Pi-hole UI: http://${ip:-<host>}/ (default user: admin, password: ${webpw})"
    echo "DNS: ${ip:-<host>} on port 53"
    log_app_summary "Pi-hole+Unbound: http://${ip:-<host>}/ (admin/${webpw}) DNS=${ip:-<host>}:53 data=${base}"
}
install_pihole_only() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        echo "Docker Compose plugin not found. Install it first (Containers menu option 1)."
        return 1
    fi
    local base="/opt/appdata/pihole"
    read -p "Data path for Pi-hole (default ${base}): " base_override
    base=${base_override:-$base}
    local tz
    tz=$(cat /etc/timezone 2>/dev/null || echo "UTC")
    read -p "Set Pi-hole WEBPASSWORD (leave blank for default changeme): " webpw
    webpw=${webpw:-changeme}
    run_cmd "Create app directory" mkdir -p "$base"
    cat > "${base}/docker-compose.yml" <<EOF
version: "3"

services:
  pihole:
    image: pihole/pihole:latest
    container_name: pihole
    environment:
      TZ: ${tz}
      WEBPASSWORD: ${webpw}
      DNS1: 1.1.1.1
      DNS2: 8.8.8.8
      REV_SERVER: "false"
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "80:80/tcp"
    volumes:
      - ./etc-pihole:/etc/pihole
      - ./dnsmasq.d:/etc/dnsmasq.d
    restart: unless-stopped
EOF
    (cd "$base" && run_cmd "Deploy Pi-hole" docker compose up -d --force-recreate)
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo
    echo "Pi-hole deployed."
    echo "Pi-hole UI: http://${ip:-<host>}/ (default user: admin, password: ${webpw})"
    echo "DNS: ${ip:-<host>} on port 53"
    log_app_summary "Pi-hole: http://${ip:-<host>}/ (admin/${webpw}) DNS=${ip:-<host>}:53 data=${base}"
}

install_nextcloud_aio() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        echo "Docker Compose plugin not found. Install it first (Containers menu option 1)."
        return 1
    fi
    local base="/opt/appdata/nextcloud-aio"
    read -p "Data path for Nextcloud AIO (default ${base}): " base_override
    base=${base_override:-$base}
    run_cmd "Create app directory" mkdir -p "$base"
    cat > "${base}/docker-compose.yml" <<'EOF'
services:
  nextcloud-aio-mastercontainer:
    image: nextcloud/all-in-one:latest
    container_name: nextcloud-aio-mastercontainer
    restart: always
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - nextcloud_aio_mastercontainer:/mnt/docker-aio-config
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - APACHE_PORT=11000
      - APACHE_IP_BINDING=0.0.0.0
      - NEXTCLOUD_DATADIR=/mnt/ncdata

volumes:
  nextcloud_aio_mastercontainer:
EOF
    (cd "$base" && run_cmd "Deploy Nextcloud All-in-One" docker compose up -d --force-recreate)
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo
    echo "Nextcloud All-in-One deployed."
    echo "Access the AIO interface: https://${ip:-<host>}:8080"
    log_app_summary "Nextcloud AIO: https://${ip:-<host>}:8080 data=${base}"
}

install_tactical_rmm() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        echo "Docker Compose plugin not found. Install it first (Containers menu option 1)."
        return 1
    fi
    echo "Tactical RMM install (Docker) per https://docs.tacticalrmm.com/install_docker/"
    echo "Ensure DNS (FQDN) is configured per their docs before proceeding."
    if [[ "$SAFE_MODE" == "true" ]]; then
        echo "SAFE_MODE=true; skipping install."
        return 1
    fi
    run_cmd "Download Tactical RMM docker installer" bash -c "curl -fsSL https://raw.githubusercontent.com/amidaware/tacticalrmm/master/docker_install.sh -o /tmp/trmm_install.sh"
    run_cmd "Run Tactical RMM docker installer" bash -c "bash /tmp/trmm_install.sh"
    echo "Tactical RMM installer executed. Review output for URLs and credentials."
    log_app_summary "Tactical RMM installer executed; check output for URLs/credentials."
}

install_hemmelig() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        echo "Docker Compose plugin not found. Install it first (Containers menu option 1)."
        return 1
    fi
    local base="/opt/appdata/hemmelig"
    run_cmd "Create app directory" mkdir -p "$base"
    cat > "${base}/docker-compose.yml" <<'EOF'
version: "3.7"

services:
  hemmelig:
    image: hemmeligapp/hemmelig
    container_name: hemmelig
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    volumes:
      - ./uploads:/var/app/uploads
EOF
    (cd "$base" && run_cmd "Deploy Hemmelig.app" docker compose up -d --force-recreate)
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo
    echo "Hemmelig.app deployed."
    echo "URL: http://${ip:-<host>}:3000"
    log_app_summary "Hemmelig: http://${ip:-<host>}:3000 data=${base}"
}

install_pangolin_native() {
    if ! command -v curl >/dev/null 2>&1; then
        echo "curl not installed."
        return 1
    fi
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed (required by Pangolin installer)."
        return 1
    fi
    local base="/opt/pangolin"
    read -r -p "Install directory for Pangolin [${base}]: " base_override
    base=${base_override:-$base}
    run_cmd "Create Pangolin directory" mkdir -p "$base"
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY RUN] curl -fsSL https://static.pangolin.net/get-installer.sh | bash"
        echo "[DRY RUN] (cd \"$base\" && ./installer)"
        log_line "OK : Pangolin installer (dry run)"
        return 0
    fi
    run_cmd "Download Pangolin installer" bash -c "cd \"$base\" && curl -fsSL https://static.pangolin.net/get-installer.sh | bash"
    if [[ ! -x "$base/installer" ]]; then
        echo "Installer not found at $base/installer."
        return 1
    fi
    run_cmd "Run Pangolin installer" bash -c "cd \"$base\" && ./installer"
    log_app_summary "Pangolin: installer run in ${base}"
}

install_arcane_script() {
    if ! command -v curl >/dev/null 2>&1; then
        echo "curl not installed."
        return 1
    fi
    echo "Arcane installer will set up dependencies (Docker, Node.js, Go)."
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY RUN] curl -fsSL https://getarcane.app/install.sh | bash"
        log_line "OK : Arcane installer (dry run)"
        return 0
    fi
    run_cmd "Run Arcane installer" bash -c "curl -fsSL https://getarcane.app/install.sh | bash"
    log_app_summary "Arcane: installer script executed"
}

install_arcane_compose() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not installed."
        return 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        echo "Docker Compose plugin not found."
        return 1
    fi
    local base="/opt/appdata/arcane"
    read -r -p "Install directory for Arcane [${base}]: " base_override
    base=${base_override:-$base}
    local projects_dir="/opt/docker"
    read -r -p "Projects directory to mount (absolute path) [${projects_dir}]: " projects_override
    projects_dir=${projects_override:-$projects_dir}
    if [[ "$projects_dir" != /* ]]; then
        echo "Projects directory must be an absolute path."
        return 1
    fi
    local app_url="http://localhost:3552"
    read -r -p "APP_URL [${app_url}]: " app_url_override
    app_url=${app_url_override:-$app_url}
    local puid="${PUID:-$(id -u)}"
    local pgid="${PGID:-$(id -g)}"
    read -r -p "PUID [${puid}]: " puid_override
    read -r -p "PGID [${pgid}]: " pgid_override
    puid=${puid_override:-$puid}
    pgid=${pgid_override:-$pgid}
    local enc_key=""
    local jwt_secret=""
    if command -v openssl >/dev/null 2>&1; then
        enc_key=$(openssl rand -base64 32 | tr -d '\n' 2>/dev/null || true)
        jwt_secret=$(openssl rand -base64 32 | tr -d '\n' 2>/dev/null || true)
    fi
    read -r -p "ENCRYPTION_KEY (32 bytes, base64 ok) [auto-generate]: " enc_override
    read -r -p "JWT_SECRET (32 bytes, base64 ok) [auto-generate]: " jwt_override
    enc_key=${enc_override:-$enc_key}
    jwt_secret=${jwt_override:-$jwt_secret}
    if [[ -z "$enc_key" || -z "$jwt_secret" ]]; then
        echo "Missing ENCRYPTION_KEY or JWT_SECRET. Generate via:"
        echo "  docker run --rm ghcr.io/getarcaneapp/arcane:latest /app/arcane generate secret"
        echo "  or: openssl rand -base64 32"
        return 1
    fi
    run_cmd "Create Arcane directory" mkdir -p "$base"
    cat > "${base}/compose.yaml" <<EOF
services:
  arcane:
    image: ghcr.io/getarcaneapp/arcane:latest
    container_name: arcane
    ports:
      - "3552:3552"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - arcane-data:/app/data
      - ${projects_dir}:${projects_dir}
    environment:
      - APP_URL=${app_url}
      - PUID=${puid}
      - PGID=${pgid}
      - ENCRYPTION_KEY=${enc_key}
      - JWT_SECRET=${jwt_secret}
      - PROJECTS_DIRECTORY=${projects_dir}
    restart: unless-stopped

volumes:
  arcane-data:
EOF
    (cd "$base" && run_cmd "Deploy Arcane" docker compose up -d --force-recreate)
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo "Arcane deployed."
    echo "URL: ${app_url} (default: http://${ip:-<host>}:3552)"
    echo "Default login: arcane / arcane-admin (change on first login)."
    log_app_summary "Arcane: ${app_url} data=${base}"
}

menu_monitoring() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Monitoring]
 1) Node Exporter installieren
 2) Top CPU/Memory Prozesse
 3) IO-Statistiken (iostat)
 4) SMART-Check (erste Platte)
 5) SMART-Check (alle Platten)
 6) Status-Dashboard (Dienste + IP)

 7) Statusreport als Datei
 8) Statusreport als JSON
 0) Zurück
EOF
        else
            cat <<EOF
[Monitoring]
 1) Install node exporter
 2) Show top CPU/mem processes
 3) Show IO stats (iostat)
 4) SMART health check (first disk)
 5) SMART health check (all disks)
 6) Status dashboard (services + IP)

 7) Export status report to file
 8) Export status report to JSON
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) install_node_exporter ;;
            2) show_top_processes ;;
            3) show_iostat_summary ;;
            4) smart_health_check ;;
            5) smart_health_batch ;;
            6) status_dashboard ;;
            7) status_report_export ;;
            8) status_report_json ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_proxmox() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Proxmox-Helfer]
 1) LXC Untermenü
 2) VM Untermenü
 3) Backups/Storage/Tasks
 4) Tools & Skripte
 0) Zurück
EOF
        else
            cat <<EOF
[Proxmox helpers]
 1) LXC submenu
 2) VM submenu
 3) Backups / storage / tasks
 4) Tools & scripts
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) proxmox_menu_lxc ;;
            2) proxmox_menu_vm ;;
            3) proxmox_menu_backups ;;
            4) proxmox_menu_tools ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

proxmox_menu_lxc() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Proxmox LXC]
 1) Container auflisten (pct list)
 2) Container-Shell betreten (pct enter <vmid>)
 3) Container starten (pct start)
 4) Container stoppen (pct stop)
 5) Container neu starten (pct restart)
 6) LXC Snapshot erstellen
 7) LXC Snapshots anzeigen
 8) LXC Snapshot zurückrollen
 9) LXC Backup (vzdump)
10) LXC Wiederherstellen (Backup)
11) LXC Ressourcen anpassen (CPU/Memory)
 0) Zurück
EOF
        else
            cat <<EOF
[Proxmox LXC]
 1) List containers (pct list)
 2) Enter container shell (pct enter <vmid>)
 3) Start container (pct start)
 4) Stop container (pct stop)
 5) Restart container (pct restart)
 6) Create LXC snapshot
 7) List LXC snapshots
 8) Rollback LXC snapshot
 9) Backup LXC (vzdump)
10) Restore LXC from backup
11) Tune LXC resources (CPU/Memory)
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) list_pct_containers ;;
            2) pct_enter_shell ;;
            3) pct_start_container ;;
            4) pct_stop_container ;;
            5) pct_restart_container ;;
            6) proxmox_snapshot_create ;;
            7) proxmox_snapshot_list ;;
            8) proxmox_snapshot_rollback ;;
            9) proxmox_backup_lxc ;;
            10) proxmox_restore_lxc ;;
            11) proxmox_tune_resources ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

proxmox_menu_vm() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Proxmox VMs]
 1) VMs auflisten (qm list)
 2) VM starten (qm start)
 3) VM stoppen (qm stop)
 4) VM neu starten (qm reset)
 5) VM Snapshot erstellen
 6) VM Snapshots anzeigen
 7) VM Snapshot zurückrollen
 8) VM Backup (vzdump)
 9) VM Wiederherstellen (qmrestore)
10) ISO herunterladen (Templates-Verzeichnis)
 0) Zurück
EOF
        else
            cat <<EOF
[Proxmox VMs]
 1) List VMs (qm list)
 2) Start VM (qm start)
 3) Stop VM (qm stop)
 4) Restart VM (qm reset)
 5) Create VM snapshot
 6) List VM snapshots
 7) Rollback VM snapshot
 8) Backup VM (vzdump)
 9) Restore VM (qmrestore)
10) Download ISO (template dir)
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) qm_list_vms ;;
            2) qm_start_vm ;;
            3) qm_stop_vm ;;
            4) qm_restart_vm ;;
            5) qm_snapshot_create ;;
            6) qm_snapshot_list ;;
            7) qm_snapshot_rollback ;;
            8) qm_backup_vm ;;
            9) qm_restore_vm ;;
            10) qm_download_iso ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

proxmox_menu_backups() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Backups / Storage / Tasks]
 1) Speicher anzeigen (pvesm status)
 2) Backups in /var/lib/vz/dump anzeigen
 3) Backups rotieren (ältere löschen)
 4) Letzte Tasks anzeigen (pvesh)
 5) Proxmox Dienste / Cluster-Status
 0) Zurück
EOF
        else
            cat <<EOF
[Backups / Storage / Tasks]
 1) List storage (pvesm status)
 2) List backups in /var/lib/vz/dump
 3) Rotate backups (delete older files)
 4) List recent tasks (pvesh)
 5) Proxmox services / cluster status
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) proxmox_list_storage ;;
            2) proxmox_list_backups ;;
            3) proxmox_rotate_backups ;;
            4) proxmox_list_tasks ;;
            5) proxmox_health ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

proxmox_menu_tools() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Proxmox Tools & Skripte]
 1) SSH-Konfig anpassen (PermitRootLogin yes)
 2) PVE Post Install Script (community)
 3) PVE All Templates Script (community)
 0) Zurück
EOF
        else
            cat <<EOF
[Proxmox Tools & Scripts]
 1) Update SSH config (PermitRootLogin yes)
 2) PVE Post Install Script (community)
 3) PVE All Templates Script (community)
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) change_ssh_proxmox ;;
            2) proxmox_post_install ;;
            3) proxmox_download_templates ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_sysinfo() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Systeminformationen]
 1) /etc/os-release anzeigen
 2) Allgemeine Systeminfo (neofetch)
 3) Speicherinformationen
 4) VM / Virtualisierungscheck
 5) Projekt-GitHub öffnen
 6) Grafikkarten anzeigen (lshw display)
 7) Dienste-Uptime-Übersicht
 8) Hardware-Überblick
 0) Zurück
EOF
        else
            cat <<EOF
[System information]
 1) Show /etc/os-release
 2) General system info (neofetch)
 3) Memory information
 4) VM / virtualization check
 5) Visit project GitHub
 6) Show video adapters (lshw display)
 7) Service uptime summary
 8) Hardware overview
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) os_release_check ;;
            2) general_information ;;
            3) memory_information ;;
            4) vm_check ;;
            5) visit_project_github ;;
            6) check_display ;;
            7) service_uptime_summary ;;
            8) hardware_overview ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_maintenance() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Wartung / Disks]
 1) System bereinigen (APT autoremove/autoclean, Logs 7d)
 2) Datenträger anzeigen (lsblk + df -h)
 3) Größte /var Verzeichnisse
 4) Wartungspaket ausführen (Update + Cleanup + Logrotate + Statusreport)
 5) Log-Integrität (Größe + SHA256)
 6) Log-Cleanup (Journal 7d + größte /var/log)
 7) Kernel-Liste / optional Paket entfernen (nur apt)
 8) Backup-Routine (etc + config)
 9) /etc Backup erstellen
 0) Zurück
EOF
        else
            cat <<EOF
[Maintenance / disks]
 1) System cleanup (APT autoremove/autoclean, logs 7d)
 2) Show disks (lsblk + df -h)
 3) Show biggest /var directories
 4) Run maintenance bundle (update + cleanup + log rotate + status report)
 5) Log integrity (size + SHA256)
 6) Log cleanup preset (journal 7d + top /var/log files)
 7) Kernel list / optional purge package (apt-only)
 8) Backup routine (etc + config)
 9) Create /etc backup
10) Write /etc/ntx-menu.conf template
11) Journal vacuum (custom window)
12) needrestart summary (apt-only)
 0) Back
EOF
        fi
        if [[ "$PKG_MGR" != "apt" ]]; then
            if [[ "$LANGUAGE" == "de" ]]; then
                echo "Hinweis: Optionen mit 'nur apt' sind markiert und auf ${PKG_MGR} nicht verfugbar."
            else
                echo "Note: apt-only options are labeled and unavailable on ${PKG_MGR}."
            fi
        fi
        read -p "Select: " c
        case "$c" in
            1) system_cleanup ;;
            2) show_disks ;;
            3) show_big_var_dirs ;;
            4) maintenance_bundle ;;
            5) log_integrity_report ;;
            6) log_cleanup_preset ;;
            7) kernel_manage_menu ;;
            8) backup_routine_quick ;;
            9) backup_etc_bundle ;;
            10) write_config_template ;;
            11) journal_vacuum_custom ;;
            12) needrestart_summary ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_users_time() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Benutzer & Zeit]
 1) Sudo-Benutzer anlegen
 2) Zeitsynchronisation anzeigen (timedatectl)
 3) Chrony (NTP) installieren und Zeitstatus anzeigen
 4) Passwort für Benutzer ändern
 0) Zurück
EOF
        else
            cat <<EOF
[Users & time]
 1) Create sudo user
 2) Show time sync (timedatectl)
 3) Install chrony (NTP) and show time status
 4) Change user password
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) create_sudo_user ;;
            2) show_time_sync ;;
            3) install_chrony ;;
            4) change_user_password ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
    done
}

menu_control() {
    while true; do
        if [[ "$LANGUAGE" == "de" ]]; then
            cat <<EOF
[Systemsteuerung]
 1) Neustarten
 2) Herunterfahren
 0) Zurück
EOF
        else
            cat <<EOF
[System control]
 1) Reboot
 2) Power down
 0) Back
EOF
        fi
        read -p "Select: " c
        case "$c" in
            1) system_reboot ;;
            2) system_powerdown ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
        should_pause_after "$c" && pause_prompt
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

load_config

check_environment
ensure_dirs
preflight_dependencies
gather_header_info
check_updates
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
        m|M) run_cmatrix ;;
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
