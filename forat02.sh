#!/usr/bin/env bash
# =============================================================================
# KAOKAB5GC – Unified Installer
# Block01: Foundation & Safety
# =============================================================================

# ----------------------------
# Strict shell behavior
# ----------------------------
set -Eeuo pipefail

# ----------------------------
# Colors & formatting
# ----------------------------
RESET="\033[0m"
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"

# ----------------------------
# Logging
# ----------------------------
LOG_DIR="/var/log/kaokab"
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

LOG_FILE="${LOG_DIR}/forat01-install-$(date +%F_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

# ----------------------------
# Helper functions
# ----------------------------
block() {
  echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}${BLUE}║ ▶▶ $1${RESET}"
  echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════════════╝${RESET}"
}

info() { echo -e "${BLUE}[INFO]${RESET} $*"; }
ok()   { echo -e "${GREEN}[OK]${RESET}   $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
fail() { echo -e "${RED}[FAIL]${RESET} $*"; exit 1; }

# ----------------------------
# Error trap (never fail silently)
# ----------------------------
trap 'fail "Unexpected error on line $LINENO. Check log: $LOG_FILE"' ERR

# ----------------------------
# Banner
# ----------------------------
clear || true
cat <<'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║ ✅ KAOKAB5GC UNIFIED INSTALLER                                             ║
║    Single Node • EPC + 5GC • SCP-Based                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF

info "Zero-interaction supported (interactive only if config missing)"
info "Log file: $LOG_FILE"

# ----------------------------
# Root check
# ----------------------------
block "Block01 – Safety & Environment"

if [[ "$EUID" -ne 0 ]]; then
  fail "This installer must be run as root"
fi
ok "Running as root"

# ----------------------------
# OS validation
# ----------------------------
if [[ ! -f /etc/os-release ]]; then
  fail "Cannot detect OS (missing /etc/os-release)"
fi

# shellcheck disable=SC1091
source /etc/os-release

if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "22.04" ]]; then
  fail "Unsupported OS: ${PRETTY_NAME:-unknown}. Ubuntu 22.04 required."
fi

ok "OS verified: Ubuntu 22.04 (Jammy)"

# ----------------------------
# Directory structure
# ----------------------------
CFG_DIR="/etc/kaokab"
CFG_FILE="${CFG_DIR}/kaokab.env"

mkdir -p "$CFG_DIR"
chmod 700 "$CFG_DIR"

ok "Kaokab configuration directory ready: $CFG_DIR"

# ----------------------------
# Summary
# ----------------------------
ok "Block01 complete"
info "What we did:"
info "- Enabled strict error handling"
info "- Initialized logging & UX helpers"
info "- Verified root privileges"
info "- Verified OS compatibility"
info "- Prepared Kaokab directory structure"
# =============================================================================
# Block02 – Deployment Parameters (interactive if missing)
# =============================================================================
block "Block02 – Deployment Parameters"

CFG_DIR="/etc/kaokab"
CFG_FILE="${CFG_DIR}/kaokab.env"

mkdir -p "$CFG_DIR"
chmod 700 "$CFG_DIR"

# ----------------------------
# Helper validation functions
# ----------------------------
is_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r a b c d <<<"$1"
  [[ $a -le 255 && $b -le 255 && $c -le 255 && $d -le 255 ]]
}

is_iface() {
  ip link show "$1" &>/dev/null
}

cidr_netmask() {
  echo "${1##*/}"
}

calc_gateway() {
  local cidr="$1"
  local net="${cidr%/*}"
  IFS=. read -r a b c d <<<"$net"
  echo "$a.$b.$c.1"
}

# ----------------------------
# Load existing config if present
# ----------------------------
if [[ -f "$CFG_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CFG_FILE"
  ok "Existing configuration loaded: $CFG_FILE"
else
  info "No configuration found – starting interactive setup"

  # Ensure dialog exists
  command -v dialog &>/dev/null || apt-get install -y dialog

  iface_default="$(ip -br link | awk '$1!="lo"{print $1; exit}')"
  gw_default="$(ip route show default | awk '{print $3}')"

  INTERFACE="$(dialog --stdout --inputbox "Network interface (e.g. ens160)" 8 60 "$iface_default")" || fail "Cancelled"
  is_iface "$INTERFACE" || fail "Interface $INTERFACE not found"

  N2_IP="$(dialog --stdout --inputbox "N2 / S1AP IPv4" 8 60 "")" || fail "Cancelled"
  is_ipv4 "$N2_IP" || fail "Invalid N2 IP"

  N3_IP="$(dialog --stdout --inputbox "N3 / GTP-U IPv4" 8 60 "")" || fail "Cancelled"
  is_ipv4 "$N3_IP" || fail "Invalid N3 IP"

  UPF_GTPU_IP="$(dialog --stdout --inputbox "UPF GTP-U IPv4" 8 60 "")" || fail "Cancelled"
  is_ipv4 "$UPF_GTPU_IP" || fail "Invalid UPF GTP-U IP"

  GW_IP="$(dialog --stdout --inputbox "Default Gateway" 8 60 "$gw_default")" || fail "Cancelled"
  is_ipv4 "$GW_IP" || fail "Invalid Gateway"

  DNS1="$(dialog --stdout --inputbox "DNS 1" 8 60 "1.1.1.1")" || fail "Cancelled"
  DNS2="$(dialog --stdout --inputbox "DNS 2" 8 60 "1.0.0.1")" || fail "Cancelled"

  UE_POOL1="$(dialog --stdout --inputbox "UE Pool (Internet) CIDR" 8 60 "10.45.0.0/16")" || fail "Cancelled"
  UE_POOL2="$(dialog --stdout --inputbox "UE Pool (IMS) CIDR" 8 60 "10.46.0.0/16")" || fail "Cancelled"

  UE_GW1="$(calc_gateway "$UE_POOL1")"
  UE_GW2="$(calc_gateway "$UE_POOL2")"

  MCC="$(dialog --stdout --inputbox "MCC (3 digits)" 8 60 "204")" || fail "Cancelled"
  MNC="$(dialog --stdout --inputbox "MNC (2–3 digits)" 8 60 "61")" || fail "Cancelled"
  TAC="$(dialog --stdout --inputbox "TAC" 8 60 "1")" || fail "Cancelled"
  SST="$(dialog --stdout --inputbox "Slice SST" 8 60 "1")" || fail "Cancelled"
  SD="$(dialog --stdout --inputbox "Slice SD (hex)" 8 60 "010203")" || fail "Cancelled"

  clear || true

  cat >"$CFG_FILE" <<EOF
# KAOKAB5GC Deployment Configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Network
IFACE=${INTERFACE}
N2_IP=${N2_IP}
N3_IP=${N3_IP}
UPF_GTPU_IP=${UPF_GTPU_IP}
GW_IP=${GW_IP}
DNS1=${DNS1}
DNS2=${DNS2}

# UE Pools
UE_POOL1=${UE_POOL1}
UE_GW1=${UE_GW1}
UE_POOL2=${UE_POOL2}
UE_GW2=${UE_GW2}

# PLMN / Slice
MCC=${MCC}
MNC=${MNC}
TAC=${TAC}
SST=${SST}
SD=${SD}

# Behavior
MANAGE_NETPLAN=false
EOF

  chmod 600 "$CFG_FILE"
  ok "Configuration saved to $CFG_FILE"
fi

# ----------------------------
# Final summary
# ----------------------------
info "What we did:"
info "- Loaded or collected deployment parameters"
info "- Validated interface and IPs"
info "- Derived UE gateways safely"
info "- Stored single source of truth in kaokab.env"
ok "Block02 complete"
# =============================================================================
# Block03 – Network validation + optional netplan
# =============================================================================
block "Block03 – Network validation"

CFG_FILE="/etc/kaokab/kaokab.env"
[[ -f "$CFG_FILE" ]] || fail "Missing config: $CFG_FILE (run Block02 first)"

# shellcheck disable=SC1090
source "$CFG_FILE"

# ----------------------------
# Normalize variable naming
# ----------------------------
# Block02 writes IFACE; some older snippets used INTERFACE. Support both.
IFACE="${IFACE:-${INTERFACE:-}}"
[[ -n "${IFACE}" ]] || fail "Missing IFACE in $CFG_FILE"

# Required keys for Block03
need_var() { [[ -n "${!1:-}" ]] || fail "Missing required variable: $1"; }
need_var IFACE
need_var N2_IP
need_var N3_IP
need_var UPF_GTPU_IP
need_var GW_IP
need_var DNS1
need_var DNS2
need_var MANAGE_NETPLAN

# ----------------------------
# Basic interface checks
# ----------------------------
ip link show "$IFACE" &>/dev/null || fail "Interface not found: $IFACE"

# Ensure interface is UP (don’t force it here; just validate)
ip -br link show "$IFACE" | grep -q "UP" || fail "Interface is not UP: $IFACE"

# ----------------------------
# Validate IP presence on IFACE
# ----------------------------
ip_on_iface() {
  local ifc="$1" ip="$2"
  ip -4 addr show dev "$ifc" | grep -q "inet ${ip}/"
}

ip_on_iface "$IFACE" "$N2_IP"       || fail "N2_IP ($N2_IP) not configured on $IFACE"
ip_on_iface "$IFACE" "$N3_IP"       || fail "N3_IP ($N3_IP) not configured on $IFACE"
ip_on_iface "$IFACE" "$UPF_GTPU_IP" || fail "UPF_GTPU_IP ($UPF_GTPU_IP) not configured on $IFACE"

# ----------------------------
# Default route validation
# ----------------------------
ip route | grep -q "^default via ${GW_IP} " || fail "Default route via GW_IP ($GW_IP) not present"

# ----------------------------
# DNS resolution validation
# ----------------------------
getent hosts ubuntu.com &>/dev/null || fail "DNS resolution failed (check DNS1/DNS2 + routing)"

ok "Network validation passed"
info "IFACE=$IFACE"
info "N2_IP=$N2_IP"
info "N3_IP=$N3_IP"
info "UPF_GTPU_IP=$UPF_GTPU_IP"
info "GW_IP=$GW_IP"
info "DNS=${DNS1}, ${DNS2}"

# =============================================================================
# Optional: manage netplan (only if enabled)
# =============================================================================
if [[ "${MANAGE_NETPLAN}" == "true" ]]; then
  block "Block03b – Netplan apply (MANAGE_NETPLAN=true)"

  NETPLAN_DIR="/etc/netplan"
  TS="$(date +%F_%H%M%S)"
  BACKUP_DIR="${NETPLAN_DIR}/backup-${TS}"

  mkdir -p "$BACKUP_DIR"
  cp -a ${NETPLAN_DIR}/*.yaml "$BACKUP_DIR"/ 2>/dev/null || true
  ok "Netplan backup created: $BACKUP_DIR"

  # If you want static netplan from env, you MUST also have CIDR in env.
  # We'll infer CIDR from IFACE current addresses to avoid asking again.
  CIDR_N2="$(ip -4 addr show dev "$IFACE" | awk -v ip="$N2_IP" '$0 ~ ip {print $2}' | head -n1 | cut -d/ -f2)"
  [[ -n "$CIDR_N2" ]] || CIDR_N2="24"

  KAOKAB_NETPLAN="${NETPLAN_DIR}/01-kaokab.yaml"
  cat >"$KAOKAB_NETPLAN" <<EOF
network:
  version: 2
  ethernets:
    ${IFACE}:
      dhcp4: no
      addresses:
        - ${N2_IP}/${CIDR_N2}
        - ${N3_IP}/${CIDR_N2}
        - ${UPF_GTPU_IP}/${CIDR_N2}
      routes:
        - to: default
          via: ${GW_IP}
      nameservers:
        addresses:
          - ${DNS1}
          - ${DNS2}
EOF

  chmod 600 "$KAOKAB_NETPLAN"
  ok "Netplan file written: $KAOKAB_NETPLAN"

  info "Applying netplan..."
  netplan generate >>"$LOG_FILE" 2>&1 || fail "netplan generate failed (see log)"
  netplan apply >>"$LOG_FILE" 2>&1 || fail "netplan apply failed (see log)"
  sleep 2
  ok "Netplan applied"

  # Re-validate quickly
  ip_on_iface "$IFACE" "$N2_IP" || fail "After netplan: missing N2_IP on $IFACE"
  ip route | grep -q "^default via ${GW_IP} " || fail "After netplan: default route missing"
  ok "Netplan validation passed"
fi

info "What we did: validated interface/IPs/default-route/DNS${MANAGE_NETPLAN:+ and optionally applied netplan}."
ok "Block03 complete"
############################################
# Block04 – IP forwarding & NAT (WORKING VM MODEL)
############################################
block "Block04" "Enable IP forwarding & NAT for UE subnets"

info "Enabling IPv4 forwarding (working VM behavior)"

mkdir -p /etc/sysctl.d
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-kaokab5gc.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null

[[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]] \
  || die "IPv4 forwarding could not be enabled"

ok "IPv4 forwarding enabled"

info "Installing iptables persistence"
apt-get install -y iptables-persistent netfilter-persistent

info "Applying NAT rules (MASQUERADE -s POOL ! -o ogstun)"

iptables -t nat -C POSTROUTING -s "$UE_POOL1" ! -o ogstun -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$UE_POOL1" ! -o ogstun -j MASQUERADE

iptables -t nat -C POSTROUTING -s "$UE_POOL2" ! -o ogstun -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$UE_POOL2" ! -o ogstun -j MASQUERADE

netfilter-persistent save >/dev/null

ok "NAT rules installed and persisted"
iptables -t nat -S POSTROUTING | grep -E "$UE_POOL1|$UE_POOL2" || true

############################################
# Block05 – Loopback validation (NO aliases)
############################################
block "Block05" "Loopback model validation (match working VM)"

ip -4 addr show lo | grep -q "127.0.0.1/8" \
  || die "Loopback /8 not present"

ip route show table local | grep -q "127.0.0.0/8" \
  || die "Local 127/8 route missing"

ok "Loopback model validated (127.0.0.1/8 only)"
info "No loopback aliases created (correct for Open5GS)"

############################################
# Block06 – MongoDB 6.0
############################################
block "Block06" "Install MongoDB 6.0 (non-interactive)"

if ! systemctl is-active --quiet mongod; then
  curl -fsSL https://pgp.mongodb.com/server-6.0.asc \
    | gpg --dearmor -o /etc/apt/keyrings/mongodb-server-6.0.gpg

  echo "deb [signed-by=/etc/apt/keyrings/mongodb-server-6.0.gpg] \
https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" \
    > /etc/apt/sources.list.d/mongodb-org-6.0.list

  apt-get update -y
  apt-get install -y mongodb-org
  systemctl enable --now mongod
fi

systemctl is-active --quiet mongod || die "MongoDB not running"
ok "MongoDB 6.0 installed and running"

############################################
# Block07 – Open5GS core (NO WebUI)
############################################
block "Block07" "Install Open5GS core (PPA, no WebUI)"

add-apt-repository -y ppa:open5gs/latest
apt-get update -y
apt-get install -y open5gs

ok "Open5GS core packages installed"

info "WebUI not installed automatically (recommended for production)"
info "If needed, install WebUI separately using NodeJS"

############################################
# Final summary
############################################
echo
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ ✅ KAOKAB5GC BASE SYSTEM READY                                              ║"
echo "╠══════════════════════════════════════════════════════════════════════════════╣"
echo "║ ✔ OS verified                                                             ║"
echo "║ ✔ Networking prepared                                                     ║"
echo "║ ✔ NAT + forwarding active                                                 ║"
echo "║ ✔ MongoDB running                                                         ║"
echo "║ ✔ Open5GS installed                                                       ║"
echo "║ ✖ WebUI intentionally skipped                                             ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"

ok "You may now proceed to Open5GS configuration & production GUI work"
