#!/usr/bin/env bash
# 11.SH — Kaokab5G Core Installer (EPC + 5GC) for Ubuntu 22.04
# Block01: Foundation (safety, logging, UX, OS checks)

set -Eeuo pipefail
IFS=$'\n\t'

# ----------------------------
# Global constants / paths
# ----------------------------
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/kaokab-install-$(date +%F_%H%M%S).log"

# ----------------------------
# Colors (professional output)
# ----------------------------
GREEN="\e[32m"
RED="\e[31m"
BLUE="\e[34m"
YELLOW="\e[33m"
BOLD="\e[1m"
RESET="\e[0m"

# ----------------------------
# Logging helpers
# ----------------------------
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

log()   { echo -e "$*" | tee -a "$LOG_FILE" >/dev/null; }
info()  { log "${BOLD}${BLUE}[INFO]${RESET} $*"; }
ok()    { log "${BOLD}${GREEN}[OK]${RESET}   $*"; }
warn()  { log "${BOLD}${YELLOW}[WARN]${RESET} $*"; }
fail()  { log "${BOLD}${RED}[FAIL]${RESET} $*"; }

# Print last command on error
on_error() {
  local exit_code=$?
  local line_no=${BASH_LINENO[0]:-unknown}
  local cmd=${BASH_COMMAND:-unknown}
  fail "Error on line ${line_no}: ${cmd}"
  fail "Installer log: ${LOG_FILE}"
  exit "$exit_code"
}
trap on_error ERR

# ----------------------------
# Privilege check
# ----------------------------
require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Please run as root: sudo ./${SCRIPT_NAME}"
    exit 1
  fi
}

# ----------------------------
# OS check (Ubuntu 22.04 only)
# ----------------------------
check_os_ubuntu_2204() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "22.04" ]]; then
      fail "Unsupported OS. Required: Ubuntu 22.04. Detected: ${PRETTY_NAME:-unknown}"
      exit 1
    fi
  else
    fail "Cannot detect OS (missing /etc/os-release)."
    exit 1
  fi
  ok "OS check passed: Ubuntu 22.04"
}

# ----------------------------
# Basic package installer
# ----------------------------
apt_install() {
  local pkgs=("$@")
  info "Installing packages: ${pkgs[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" >>"$LOG_FILE" 2>&1
  ok "Packages installed: ${pkgs[*]}"
}

# ----------------------------
# Optional UX tools (figlet/toilet/dialog)
# ----------------------------
ensure_ux_tools() {
  local need=()
  command -v dialog >/dev/null 2>&1 || need+=("dialog")
  command -v figlet >/dev/null 2>&1 || need+=("figlet")
  command -v toilet >/dev/null 2>&1 || need+=("toilet")
  if (( ${#need[@]} )); then
    apt_install "${need[@]}"
  else
    ok "UX tools already present (dialog/figlet/toilet)"
  fi
}

show_banner() {
  clear || true
  local term_width
  term_width="$(tput cols 2>/dev/null || echo 120)"
  echo -e "${BOLD}${BLUE}"
  if command -v figlet >/dev/null 2>&1; then
    figlet -c -w "$term_width" "KAOKAB5G CORE"
    figlet -c -w "$term_width" "EPC + 5GC INSTALLER"
  else
    echo "KAOKAB5G CORE — EPC + 5GC INSTALLER"
  fi
  echo -e "${RESET}"
  info "Log file: ${LOG_FILE}"
}

# ----------------------------
# Block01 entry
# ----------------------------
block01_foundation() {
  require_root
  check_os_ubuntu_2204

  # Base utilities used by later blocks
  apt_install ca-certificates curl gnupg lsb-release software-properties-common

  # Nice-to-have UX tools
  ensure_ux_tools
  show_banner

  ok "Block01 complete: foundation ready."
}

# Execute Block01 only (for now)
block01_foundation
# ============================================================
# Block02: Collect & validate deployment parameters (dialog)
# - Saves config to: /etc/kaokab/kaokab.env
# ============================================================

KAOKAB_CFG_DIR="/etc/kaokab"
KAOKAB_CFG_FILE="${KAOKAB_CFG_DIR}/kaokab.env"

ensure_dialog() {
  command -v dialog >/dev/null 2>&1 || apt_install dialog
}

dialog_input() {
  local title="$1"
  local prompt="$2"
  local default="${3:-}"
  local out

  out=$(dialog --clear --stdout --title "$title" \
      --inputbox "$prompt" 10 70 "$default") || {
        clear || true
        fail "Cancelled by user."
        exit 1
      }
  echo "$out"
}

dialog_msg() {
  local title="$1"
  local msg="$2"
  dialog --clear --title "$title" --msgbox "$msg" 12 70
}

is_iface() {
  local ifc="$1"
  ip link show "$ifc" &>/dev/null
}

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r a b c d <<<"$ip"
  [[ "$a" -le 255 && "$b" -le 255 && "$c" -le 255 && "$d" -le 255 ]]
}

is_cidr() {
  local cidr="$1"
  [[ "$cidr" =~ ^[0-9]{1,2}$ ]] && [[ "$cidr" -ge 1 && "$cidr" -le 32 ]]
}

is_mcc() { [[ "$1" =~ ^[0-9]{3}$ ]]; }
is_mnc() { [[ "$1" =~ ^[0-9]{2,3}$ ]]; }
is_tac() { [[ "$1" =~ ^[0-9]{1,5}$ ]]; }
is_sst() { [[ "$1" =~ ^[0-9]{1,3}$ ]]; }   # 1..255 typical, keep flexible
is_sd()  { [[ "$1" =~ ^[0-9A-Fa-f]{6}$ ]]; } # 3 bytes hex (e.g., 010203)

write_cfg() {
  mkdir -p "$KAOKAB_CFG_DIR"
  chmod 700 "$KAOKAB_CFG_DIR"
  cat >"$KAOKAB_CFG_FILE" <<EOF
# Kaokab5G Installer Config
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
INTERFACE="${INTERFACE}"
S1AP_IP="${S1AP_IP}"
GTPU_IP="${GTPU_IP}"
UPF_IP="${UPF_IP}"
CIDR="${CIDR}"
GATEWAY="${GATEWAY}"
DNS1="${DNS1}"
DNS2="${DNS2}"
APN_POOL="${APN_POOL}"
APN_GW="${APN_GW}"
MCC="${MCC}"
MNC="${MNC}"
SST="${SST}"
SD="${SD}"
TAC="${TAC}"
GUAMI_REGION="${GUAMI_REGION}"
GUAMI_SET="${GUAMI_SET}"
EOF
  chmod 600 "$KAOKAB_CFG_FILE"
  ok "Saved config to ${KAOKAB_CFG_FILE}"
}

block02_collect_config() {
  ensure_dialog

  # Suggest defaults from current system
  local default_iface
  default_iface="$(ip -br link | awk '$1!="lo"{print $1; exit}')"
  local default_gw
  default_gw="$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')"
  local default_dns1="1.1.1.1"
  local default_dns2="1.0.0.1"

  while :; do
    INTERFACE="$(dialog_input "Kaokab5G Setup" "Enter network interface name (e.g., ens160, eth0)" "$default_iface")"
    if is_iface "$INTERFACE"; then break; fi
    dialog_msg "Invalid" "Interface '$INTERFACE' not found. Check: ip -br link"
  done

  # Control/User-plane IPs (you can keep these on same NIC as you do now)
  while :; do
    S1AP_IP="$(dialog_input "IP Plan" "Enter S1AP/N2 (Control Plane) IPv4 (e.g., 192.168.178.80)" "")"
    is_ipv4 "$S1AP_IP" && break
    dialog_msg "Invalid" "Invalid IPv4 address."
  done

  while :; do
    GTPU_IP="$(dialog_input "IP Plan" "Enter GTP-U/N3 (User Plane) IPv4 (e.g., 192.168.178.81)" "")"
    is_ipv4 "$GTPU_IP" && break
    dialog_msg "Invalid" "Invalid IPv4 address."
  done

  while :; do
    UPF_IP="$(dialog_input "IP Plan" "Enter UPF GTP-U bind IPv4 (e.g., 192.168.178.82)" "")"
    is_ipv4 "$UPF_IP" && break
    dialog_msg "Invalid" "Invalid IPv4 address."
  done

  while :; do
    CIDR="$(dialog_input "IP Plan" "Enter CIDR mask (1-32) (e.g., 24)" "24")"
    is_cidr "$CIDR" && break
    dialog_msg "Invalid" "CIDR must be 1..32"
  done

  while :; do
    GATEWAY="$(dialog_input "Routing" "Enter default gateway IPv4" "$default_gw")"
    is_ipv4 "$GATEWAY" && break
    dialog_msg "Invalid" "Invalid IPv4 address."
  done

  while :; do
    DNS1="$(dialog_input "DNS" "Enter DNS1 IPv4" "$default_dns1")"
    is_ipv4 "$DNS1" && break
    dialog_msg "Invalid" "Invalid IPv4 address."
  done

  while :; do
    DNS2="$(dialog_input "DNS" "Enter DNS2 IPv4" "$default_dns2")"
    is_ipv4 "$DNS2" && break
    dialog_msg "Invalid" "Invalid IPv4 address."
  done

  # Subscriber pool
  while :; do
    APN_POOL="$(dialog_input "Subscriber Pool" "Enter APN pool in CIDR (e.g., 10.45.0.0/16)" "10.45.0.0/16")"
    [[ "$APN_POOL" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] && break
    dialog_msg "Invalid" "Format must be like 10.45.0.0/16"
  done

  while :; do
    APN_GW="$(dialog_input "Subscriber Pool" "Enter APN gateway IPv4 (e.g., 10.45.0.1)" "10.45.0.1")"
    is_ipv4 "$APN_GW" && break
    dialog_msg "Invalid" "Invalid IPv4 address."
  done

  # PLMN / Slice
  while :; do
    MCC="$(dialog_input "PLMN" "Enter MCC (3 digits) e.g., 204" "204")"
    is_mcc "$MCC" && break
    dialog_msg "Invalid" "MCC must be exactly 3 digits."
  done

  while :; do
    MNC="$(dialog_input "PLMN" "Enter MNC (2 or 3 digits) e.g., 61 or 025" "61")"
    is_mnc "$MNC" && break
    dialog_msg "Invalid" "MNC must be 2 or 3 digits."
  done

  while :; do
    SST="$(dialog_input "Slice" "Enter SST (e.g., 1)" "1")"
    is_sst "$SST" && break
    dialog_msg "Invalid" "SST must be numeric."
  done

  while :; do
    SD="$(dialog_input "Slice" "Enter SD (6 hex digits) e.g., 010203" "010203")"
    is_sd "$SD" && break
    dialog_msg "Invalid" "SD must be 6 hex digits."
  done

  while :; do
    TAC="$(dialog_input "Tracking Area" "Enter TAC (e.g., 1)" "1")"
    is_tac "$TAC" && break
    dialog_msg "Invalid" "TAC must be numeric."
  done

  GUAMI_REGION="$(dialog_input "GUAMI" "Enter AMF GUAMI region (numeric) e.g., 2" "2")"
  GUAMI_SET="$(dialog_input "GUAMI" "Enter AMF GUAMI set (numeric) e.g., 1" "1")"

  # Show summary (review)
  local summary
  summary=$(
    cat <<EOS
Interface:   ${INTERFACE}

S1AP/N2:     ${S1AP_IP}/${CIDR}
GTPU/N3:     ${GTPU_IP}/${CIDR}
UPF GTPU:    ${UPF_IP}/${CIDR}
Gateway:     ${GATEWAY}
DNS:         ${DNS1}, ${DNS2}

APN Pool:    ${APN_POOL}
APN GW:      ${APN_GW}

PLMN:        MCC ${MCC} / MNC ${MNC}
Slice:       SST ${SST} / SD ${SD}
TAC:         ${TAC}
GUAMI:       region ${GUAMI_REGION} / set ${GUAMI_SET}
EOS
  )

  dialog --clear --title "Review Configuration" --yesno "$summary" 22 72
  if [[ $? -ne 0 ]]; then
    clear || true
    warn "User chose to re-enter values."
    block02_collect_config
    return
  fi

  clear || true
  write_cfg
  ok "Block02 complete: parameters collected & saved."
}

# Run Block02 (uncomment when ready to execute)
block02_collect_config
# ============================================================
# Block03: Netplan generation, apply & validation
# - Reads config from /etc/kaokab/kaokab.env
# ============================================================

block03_netplan() {
  info "Starting Block03: Netplan configuration"

  # ----------------------------
  # Load configuration
  # ----------------------------
  if [[ ! -f /etc/kaokab/kaokab.env ]]; then
    fail "Missing config file /etc/kaokab/kaokab.env (run Block02 first)"
    exit 1
  fi
  # shellcheck disable=SC1091
  source /etc/kaokab/kaokab.env
  ok "Loaded configuration from /etc/kaokab/kaokab.env"

  # ----------------------------
  # Validate interface exists
  # ----------------------------
  if ! ip link show "$INTERFACE" &>/dev/null; then
    fail "Interface $INTERFACE does not exist"
    exit 1
  fi

  # ----------------------------
  # Backup existing netplan
  # ----------------------------
  NETPLAN_DIR="/etc/netplan"
  BACKUP_DIR="/etc/netplan/backup-$(date +%F_%H%M%S)"
  mkdir -p "$BACKUP_DIR"
  cp -a ${NETPLAN_DIR}/*.yaml "$BACKUP_DIR"/ 2>/dev/null || true
  ok "Netplan backup created at $BACKUP_DIR"

  # ----------------------------
  # Generate Kaokab netplan
  # ----------------------------
  KAOKAB_NETPLAN="${NETPLAN_DIR}/01-kaokab.yaml"
  info "Generating Netplan file: $KAOKAB_NETPLAN"

  cat >"$KAOKAB_NETPLAN" <<EOF
network:
  version: 2
  ethernets:
    ${INTERFACE}:
      dhcp4: no
      addresses:
        - ${S1AP_IP}/${CIDR}
        - ${GTPU_IP}/${CIDR}
        - ${UPF_IP}/${CIDR}
      routes:
        - to: default
          via: ${GATEWAY}
      nameservers:
        addresses:
          - ${DNS1}
          - ${DNS2}
EOF

  chmod 600 "$KAOKAB_NETPLAN"
  ok "Netplan file written"

  # ----------------------------
  # Apply netplan safely
  # ----------------------------
  info "Applying Netplan configuration"
  netplan generate >>"$LOG_FILE" 2>&1
  netplan apply >>"$LOG_FILE" 2>&1
  sleep 3
  ok "Netplan applied"

  # ----------------------------
  # Validation checks
  # ----------------------------
  info "Validating network state"

  # Interface UP
  ip link show "$INTERFACE" | grep -q "state UP" || {
    fail "Interface $INTERFACE is not UP"
    exit 1
  }

  # IPs present
  ip -4 addr show "$INTERFACE" | grep -q "$S1AP_IP" || fail "Missing S1AP IP"
  ip -4 addr show "$INTERFACE" | grep -q "$GTPU_IP" || fail "Missing GTPU IP"
  ip -4 addr show "$INTERFACE" | grep -q "$UPF_IP"  || fail "Missing UPF IP"

  # Default route
  ip route | grep -q "default via ${GATEWAY}" || {
    fail "Default route via ${GATEWAY} not present"
    exit 1
  }

  # DNS resolution test
  if ! getent hosts ubuntu.com &>/dev/null; then
    fail "DNS resolution failed"
    exit 1
  fi

  ok "Network validation successful"
  ok "Block03 complete: Netplan configured and validated"
}

# Run Block03
block03_netplan

