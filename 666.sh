#!/usr/bin/env bash
set -euo pipefail

############################################
# KAOKAB5GC – Unified Core Bootstrap (666)
# Single Node EPC + 5GC (SCP-based)
# Ubuntu 22.04 (Jammy)
############################################

### ---------- UX helpers ----------
LOG_DIR="/var/log/kaokab"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/kaokab5gc-install-$(date +%F_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

info() { echo "[INFO] $*"; }
ok()   { echo "[OK]   $*"; }
warn() { echo "[WARN] $*"; }
die()  { echo "[FAIL] $*" ; exit 1; }

block() {
  echo
  echo "╔══════════════════════════════════════════════════════════════════════════════╗"
  printf "║ ▶▶ %-72s ║\n" "$1"
  echo "╠══════════════════════════════════════════════════════════════════════════════╣"
  printf "║ %-72s ║\n" "$2"
  echo "╚══════════════════════════════════════════════════════════════════════════════╝"
}

############################################
# Banner
############################################
echo
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ ✅ KAOKAB5GC UNIFIED INSTALLER (SINGLE NODE: EPC + 5GC, SCP-BASED)            ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
info "Zero-interaction: enabled (no prompts)"
info "Log file: $LOG_FILE"
info "Config file: /etc/kaokab/kaokab.env"

############################################
# Block01 – Base system tooling
############################################
block "Block01" "System checks + base tooling"

lsb_release -cs | grep -q jammy || die "Ubuntu 22.04 (Jammy) required"

apt-get update -y
apt-get install -y \
  ca-certificates curl gnupg jq net-tools \
  iproute2 software-properties-common

ok "Base OS verified (Ubuntu Jammy)"
ok "Required system tools installed"

############################################
# Block02 – Load or generate config
############################################
block "Block02" "Load or auto-generate deployment parameters"

CFG="/etc/kaokab/kaokab.env"
mkdir -p /etc/kaokab

if [[ ! -f "$CFG" ]]; then
  warn "Config not found – generating defaults"
  cat > "$CFG" <<EOF
# Network
IFACE=ens160
N2_IP=192.168.178.80
N3_IP=192.168.178.81
UPF_GTPU_IP=192.168.178.82
GW_IP=192.168.178.1
DNS1=1.1.1.1
DNS2=1.0.0.1

# UE pools
UE_POOL1=10.45.0.0/16
UE_POOL2=10.46.0.0/16

# PLMN / Slice
MCC=204
MNC=61
TAC=1
SST=1
SD=010203

# Behavior
MANAGE_NETPLAN=false
EOF
fi

# shellcheck disable=SC1090
source "$CFG"

echo
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║ CONFIG SUMMARY                                                               ║"
echo "╠══════════════════════════════════════════════════════════════════════════════╣"
printf "║ Interface: %-62s ║\n" "$IFACE"
printf "║ S1AP/N2:   %-62s ║\n" "$N2_IP"
printf "║ GTPU/N3:   %-62s ║\n" "$N3_IP"
printf "║ UPF GTPU:  %-62s ║\n" "$UPF_GTPU_IP"
printf "║ GW/DNS:    %-62s ║\n" "$GW_IP | $DNS1, $DNS2"
printf "║ UE pools:  %-62s ║\n" "$UE_POOL1 , $UE_POOL2"
printf "║ PLMN:      %-62s ║\n" "$MCC/$MNC  TAC:$TAC  Slice:$SST/$SD"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"

ok "Deployment parameters loaded"

############################################
# Block03 – Netplan (optional)
############################################
block "Block03" "Netplan management (optional)"

if [[ "$MANAGE_NETPLAN" == "true" ]]; then
  warn "Netplan automation requested but intentionally not implemented"
else
  ok "Netplan untouched (MANAGE_NETPLAN=false)"
fi

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
