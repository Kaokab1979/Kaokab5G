#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# KAOKAB5GC – PRODUCTION INSTALLER
# install01.sh
# ============================================================

VERSION="1.0"
CFG_DIR="/etc/kaokab"
CFG_FILE="${CFG_DIR}/kaokab.env"
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/kaokab-install-$(date +%F_%H%M%S).log"

# ---------- Colors ----------
BOLD="\033[1m"
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

# ---------- Logging ----------
mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

info() { echo -e "${BLUE}[INFO]${RESET} $*"; }
ok()   { echo -e "${GREEN}[OK]${RESET}   $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
fail() { echo -e "${RED}[FAIL]${RESET} $*"; exit 1; }

# ============================================================
# Banner
# ============================================================
clear
cat <<EOF
╔══════════════════════════════════════════════════════════════════════════════╗
║ ✅ KAOKAB5GC PRODUCTION INSTALLER (EPC + 5GC FOUNDATION)                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Version: ${VERSION}                                                         ║
║ Mode: Interactive-once, deterministic thereafter                            ║
║ Log:  ${LOG_FILE}                                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF

# ============================================================
# Block01: System foundation
# ============================================================
echo -e "\n${BOLD}▶▶ Block01: System foundation${RESET}"

[[ $EUID -eq 0 ]] || fail "Run as root"

. /etc/os-release
[[ "$VERSION_ID" == "22.04" ]] || fail "Ubuntu 22.04 required"

apt-get update -y
apt-get install -y \
  ca-certificates curl gnupg jq iproute2 net-tools \
  software-properties-common iptables-persistent dialog

ok "Base OS verified and required packages installed"

# ============================================================
# Block02: Deployment parameters (interactive if missing)
# ============================================================
echo -e "\n${BOLD}▶▶ Block02: Deployment parameters${RESET}"

mkdir -p "$CFG_DIR"
chmod 700 "$CFG_DIR"

# ---- helpers (CIDR -> first host .1 for IPv4 pools) ----
ipv4_from_cidr() { echo "${1%%/*}"; }

guess_pool_gw_v4() {
  local cidr="$1"
  local ip; ip="$(ipv4_from_cidr "$cidr")"
  # replace last octet with 1 (works for typical 10.x/16, /24, etc.)
  echo "$ip" | awk -F. 'NF==4{print $1"."$2"."$3".1"; exit} {print ""}'
}

if [[ -f "$CFG_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CFG_FILE"
  ok "Existing configuration detected: $CFG_FILE"

  # If old env exists but gateways missing, backfill safely (no prompts)
  if [[ -z "${UE_GW1:-}" && -n "${UE_POOL1:-}" ]]; then
    UE_GW1="$(guess_pool_gw_v4 "$UE_POOL1")"
    warn "UE_GW1 missing in env → auto-set to ${UE_GW1}"
  fi
  if [[ -z "${UE_GW2:-}" && -n "${UE_POOL2:-}" ]]; then
    UE_GW2="$(guess_pool_gw_v4 "$UE_POOL2")"
    warn "UE_GW2 missing in env → auto-set to ${UE_GW2}"
  fi

else
  info "No config found – starting interactive setup"

  iface_default="$(ip -br link | awk '$1!="lo"{print $1; exit}')"
  gw_default="$(ip route show default | awk '{print $3}')"

  INTERFACE="$(dialog --stdout --inputbox "Network interface" 8 60 "$iface_default")"
  N2_IP="$(dialog --stdout --inputbox "N2 / S1AP IPv4" 8 60 "")"
  N3_IP="$(dialog --stdout --inputbox "N3 / GTP-U IPv4" 8 60 "")"
  UPF_GTPU_IP="$(dialog --stdout --inputbox "UPF GTP-U IPv4" 8 60 "")"
  GATEWAY="$(dialog --stdout --inputbox "Default gateway" 8 60 "$gw_default")"
  DNS1="$(dialog --stdout --inputbox "DNS 1" 8 60 "1.1.1.1")"
  DNS2="$(dialog --stdout --inputbox "DNS 2" 8 60 "1.0.0.1")"

  UE_POOL1="$(dialog --stdout --inputbox "UE pool (internet) CIDR" 8 60 "10.45.0.0/16")"
  UE_POOL2="$(dialog --stdout --inputbox "UE pool (IMS) CIDR" 8 60 "10.46.0.0/16")"

  # Suggested gateways from pools (editable)
  UE_GW1_DEFAULT="$(guess_pool_gw_v4 "$UE_POOL1")"
  UE_GW2_DEFAULT="$(guess_pool_gw_v4 "$UE_POOL2")"

  UE_GW1="$(dialog --stdout --inputbox "UE gateway for internet pool (usually x.x.x.1)" 8 60 "${UE_GW1_DEFAULT:-10.45.0.1}")"
  UE_GW2="$(dialog --stdout --inputbox "UE gateway for IMS pool (usually x.x.x.1)" 8 60 "${UE_GW2_DEFAULT:-10.46.0.1}")"

  MCC="$(dialog --stdout --inputbox "MCC (3 digits)" 8 60 "204")"
  MNC="$(dialog --stdout --inputbox "MNC (2–3 digits)" 8 60 "61")"
  TAC="$(dialog --stdout --inputbox "TAC" 8 60 "1")"
  SST="$(dialog --stdout --inputbox "Slice SST" 8 60 "1")"
  SD="$(dialog --stdout --inputbox "Slice SD (hex)" 8 60 "010203")"

fi

# Always (re)write env in a normalized way so all vars exist
cat >"$CFG_FILE" <<EOF
# KAOKAB5GC deployment configuration
IFACE=${IFACE:-$INTERFACE}
N2_IP=${N2_IP}
N3_IP=${N3_IP}
UPF_GTPU_IP=${UPF_GTPU_IP}
GW_IP=${GW_IP:-$GATEWAY}
DNS1=${DNS1}
DNS2=${DNS2}

# UE pools + gateways (used by UPF session blocks)
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

info "What we did: collected/loaded N2,N3,UPF IPs + UE pools and gateways (UE_GW1/UE_GW2) + PLMN/Slice parameters."


# ============================================================
# Block03: Networking validation (no netplan modification)
# ============================================================
echo -e "\n${BOLD}▶▶ Block03: Network validation${RESET}"

ip link show "$IFACE" >/dev/null || fail "Interface $IFACE not found"
ok "Interface $IFACE exists"

# ============================================================
# Block04: Kernel forwarding & NAT
# ============================================================
echo -e "\n${BOLD}▶▶ Block04: Kernel forwarding & NAT${RESET}"

sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/99-kaokab5gc.conf
ok "IPv4 forwarding enabled"

iptables -t nat -C POSTROUTING -s "$UE_POOL1" ! -o ogstun -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$UE_POOL1" ! -o ogstun -j MASQUERADE

iptables -t nat -C POSTROUTING -s "$UE_POOL2" ! -o ogstun -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$UE_POOL2" ! -o ogstun -j MASQUERADE

netfilter-persistent save
ok "NAT rules applied and persisted"

# ============================================================
# Block05: Loopback validation
# ============================================================
echo -e "\n${BOLD}▶▶ Block05: Loopback validation${RESET}"

ip -4 addr show lo | grep -q "127.0.0.1/8" || fail "Loopback misconfigured"
ok "Loopback model validated (127.0.0.1/8 only)"

# ============================================================
# Block06: MongoDB installation
# ============================================================
echo -e "\n${BOLD}▶▶ Block06: MongoDB installation${RESET}"

if ! command -v mongod >/dev/null; then
  curl -fsSL https://pgp.mongodb.com/server-6.0.asc |
    gpg --dearmor -o /etc/apt/keyrings/mongodb-6.gpg

  echo "deb [signed-by=/etc/apt/keyrings/mongodb-6.gpg] \
https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" \
> /etc/apt/sources.list.d/mongodb-org-6.0.list

  apt-get update -y
  apt-get install -y mongodb-org
fi

systemctl enable --now mongod
systemctl is-active mongod >/dev/null || fail "MongoDB not running"
ok "MongoDB installed and running"

# ============================================================
# Block07: Open5GS installation
# ============================================================
echo -e "\n${BOLD}▶▶ Block07: Open5GS installation${RESET}"

add-apt-repository -y ppa:open5gs/latest
apt-get update -y
apt-get install -y open5gs

systemctl daemon-reexec
systemctl daemon-reload

ok "Open5GS core packages installed"
info "WebUI intentionally NOT installed (production recommendation)"

# ============================================================
# Final: Core readiness
# ============================================================
echo -e "\n${BOLD}▶▶ Final: Core readiness validation${RESET}"

systemctl is-active mongod >/dev/null || fail "MongoDB inactive"
systemctl list-unit-files | grep -q open5gs-amfd.service || fail "Open5GS units missing"

ok "All prerequisites satisfied"

cat <<EOF

╔══════════════════════════════════════════════════════════════════════════════╗
║ ✅ KAOKAB5GC INSTALLATION COMPLETE                                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ ✔ OS prepared                                                              ║
║ ✔ Network validated                                                        ║
║ ✔ NAT + forwarding active                                                  ║
║ ✔ MongoDB running                                                          ║
║ ✔ Open5GS installed                                                        ║
║ ✖ No configuration applied (by design)                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

NEXT STEP:
  → Run ./777.sh to configure EPC + 5GC

EOF

exit 0
