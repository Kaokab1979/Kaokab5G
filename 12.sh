#!/usr/bin/env bash
# 12.sh — Kaokab5G Post-Network Enablement
# Block04 only: IP forwarding + persistent NAT for UE traffic (APN pool)

set -Eeuo pipefail
IFS=$'\n\t'

# ----------------------------
# Globals / logging
# ----------------------------
SCRIPT_NAME="$(basename "$0")"
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/kaokab-postnet-$(date +%F_%H%M%S).log"

GREEN="\e[32m"; RED="\e[31m"; BLUE="\e[34m"; YELLOW="\e[33m"; BOLD="\e[1m"; RESET="\e[0m"

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

log()   { echo -e "$*" | tee -a "$LOG_FILE" >/dev/null; }
info()  { log "${BOLD}${BLUE}[INFO]${RESET} $*"; }
ok()    { log "${BOLD}${GREEN}[OK]${RESET}   $*"; }
warn()  { log "${BOLD}${YELLOW}[WARN]${RESET} $*"; }
fail()  { log "${BOLD}${RED}[FAIL]${RESET} $*"; }

on_error() {
  local exit_code=$?
  local line_no=${BASH_LINENO[0]:-unknown}
  local cmd=${BASH_COMMAND:-unknown}
  fail "Error on line ${line_no}: ${cmd}"
  fail "Log: ${LOG_FILE}"
  exit "$exit_code"
}
trap on_error ERR

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Please run as root: sudo ./${SCRIPT_NAME}"
    exit 1
  fi
}

apt_install() {
  local pkgs=("$@")
  info "Installing packages: ${pkgs[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" >>"$LOG_FILE" 2>&1
  ok "Packages installed: ${pkgs[*]}"
}

load_cfg() {
  local cfg="/etc/kaokab/kaokab.env"
  if [[ ! -f "$cfg" ]]; then
    fail "Missing config file: $cfg"
    fail "Run 11.sh (Block02) first to generate it."
    exit 1
  fi
  # shellcheck disable=SC1091
  source "$cfg"
  ok "Loaded config: $cfg"
}

# ============================================================
# Block04: IP forwarding & persistent NAT (UE traffic)
# ============================================================
block04_forwarding_nat() {
  echo -e "${BOLD}${BLUE}▶▶ Block04: Enabling IP Forwarding & NAT${RESET}"
  info "Starting Block04: forwarding + NAT"

  load_cfg

  # ----------------------------
  # Enable forwarding (runtime)
  # ----------------------------
  info "Enabling IPv4/IPv6 forwarding (runtime)"
  sysctl -w net.ipv4.ip_forward=1 >>"$LOG_FILE" 2>&1
  sysctl -w net.ipv6.conf.all.forwarding=1 >>"$LOG_FILE" 2>&1
  ok "Forwarding enabled (runtime)"

  # ----------------------------
  # Persist forwarding
  # ----------------------------
  local sysctl_file="/etc/sysctl.d/99-kaokab-forwarding.conf"
  cat >"$sysctl_file" <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
  sysctl --system >>"$LOG_FILE" 2>&1
  ok "Forwarding persisted: $sysctl_file"

  # ----------------------------
  # Firewall persistence tools
  # ----------------------------
  apt_install iptables iptables-persistent netfilter-persistent

  # ----------------------------
  # NAT rule (idempotent)
  # ----------------------------
  # APN_POOL comes from /etc/kaokab/kaokab.env (e.g., 10.45.0.0/16)
  local apn_subnet_v4="${APN_POOL}"

  info "Ensuring NAT rule exists for UE subnet: $apn_subnet_v4"
  if ! iptables -t nat -C POSTROUTING -s "$apn_subnet_v4" ! -o ogstun -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s "$apn_subnet_v4" ! -o ogstun -j MASQUERADE
    ok "Added NAT rule for $apn_subnet_v4"
  else
    ok "NAT rule already present for $apn_subnet_v4"
  fi

  # Optional IPv6 NAT (kept consistent with your earlier deployments)
  if ip6tables -t nat -L &>/dev/null; then
    if ! ip6tables -t nat -C POSTROUTING -s 2001:db8:cafe::/48 ! -o ogstun -j MASQUERADE 2>/dev/null; then
      ip6tables -t nat -A POSTROUTING -s 2001:db8:cafe::/48 ! -o ogstun -j MASQUERADE
      ok "Added IPv6 NAT rule (2001:db8:cafe::/48)"
    else
      ok "IPv6 NAT rule already present"
    fi
  else
    warn "ip6tables NAT table not available; skipping IPv6 NAT"
  fi

  # ----------------------------
  # Persist firewall rules
  # ----------------------------
  netfilter-persistent save >>"$LOG_FILE" 2>&1
  netfilter-persistent reload >>"$LOG_FILE" 2>&1
  ok "Saved/reloaded persistent firewall rules"

  # ----------------------------
  # Validate
  # ----------------------------
  info "Validating forwarding & NAT"

  sysctl net.ipv4.ip_forward | grep -q "= 1" || { fail "IPv4 forwarding not enabled"; exit 1; }
  sysctl net.ipv6.conf.all.forwarding | grep -q "= 1" || { fail "IPv6 forwarding not enabled"; exit 1; }

  iptables -t nat -S | grep -q "$apn_subnet_v4" || { fail "NAT rule missing for $apn_subnet_v4"; exit 1; }

  ok "Forwarding + NAT validation successful"
  echo -e "${BOLD}${GREEN}✔ Block04 completed successfully${RESET}"
  info "Log saved at: $LOG_FILE"
}

# ----------------------------
# Main
# ----------------------------
main() {
  require_root
  block04_forwarding_nat
}

main "$@"
