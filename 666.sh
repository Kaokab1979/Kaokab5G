#!/usr/bin/env bash
# 555.sh — Kaokab5GC Unified Installer (Single Node: EPC + 5GC, SCP-based)
# Ubuntu 22.04 LTS (jammy) — production-grade, non-interactive, idempotent-ish
#
# Zero interaction policy:
# - NO prompts, NO "Overwrite? (y/N)", NO read -p.
# - Uses /etc/kaokab/kaokab.env if present; otherwise auto-generates sane defaults and continues.
#
# Logs:
# - /var/log/kaokab/kaokab5gc-install-YYYY-MM-DD_HHMMSS.log
#
# NOTE:
# - If you want to change values, edit /etc/kaokab/kaokab.env and re-run.

set -Eeuo pipefail
IFS=$'\n\t'

# ============================================================
# Globals / Logging / UX
# ============================================================
SCRIPT_NAME="$(basename "$0")"
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/kaokab5gc-install-$(date +%F_%H%M%S).log"

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

# Colors
GREEN="\e[32m"; RED="\e[31m"; YELLOW="\e[33m"; BLUE="\e[34m"; BOLD="\e[1m"; RESET="\e[0m"

log_raw() { echo -e "$*" | tee -a "$LOG_FILE" >/dev/null; }
info()    { log_raw "${BOLD}${BLUE}[INFO]${RESET}  $*"; }
ok()      { log_raw "${BOLD}${GREEN}[OK]${RESET}    $*"; }
warn()    { log_raw "${BOLD}${YELLOW}[WARN]${RESET}  $*"; }
fail()    { log_raw "${BOLD}${RED}[FAIL]${RESET}  $*"; }

die() { fail "$*"; fail "Log: $LOG_FILE"; exit 1; }

on_error() {
  local ec=$?
  local ln=${BASH_LINENO[0]:-unknown}
  local cmd=${BASH_COMMAND:-unknown}
  fail "Error on line ${ln}: ${cmd}"
  fail "Log: $LOG_FILE"
  exit "$ec"
}
trap on_error ERR

hr() { printf "%*s\n" "$(tput cols 2>/dev/null || echo 120)" "" | tr ' ' '='; }

box() {
  # box "TITLE" "line1" "line2" ...
  local title="$1"; shift || true
  local width=118
  local top="╔"; local mid="╠"; local bot="╚"
  local h="▒"
  local l="║"; local r="║"
  local line
  echo -e "${BOLD}${BLUE}${top}$(printf '%*s' $((width-2)) '' | tr ' ' "${h}")${top/${top}/${top/${top}/╗}}${RESET}" 2>/dev/null || true
  # Simpler: draw a consistent box without depending on locale tricks
  echo -e "${BOLD}${BLUE}╔$(printf '%*s' $((width-2)) '' | tr ' ' '▒')╗${RESET}"
  printf "${BOLD}${BLUE}║ %-*s ║${RESET}\n" $((width-4)) "$title"
  echo -e "${BOLD}${BLUE}╠$(printf '%*s' $((width-2)) '' | tr ' ' '▒')╣${RESET}"
  for line in "$@"; do
    printf "${BOLD}${BLUE}║${RESET} %-*s ${BOLD}${BLUE}║${RESET}\n" $((width-4)) "$line"
  done
  echo -e "${BOLD}${BLUE}╚$(printf '%*s' $((width-2)) '' | tr ' ' '▒')╝${RESET}"
}

banner() {
  clear || true
  cat <<'EOF'
         _  __    _    ___  _  __    _    ____ ____   ____  ____
        | |/ /   / \  / _ \| |/ /   / \  | __ ) ___| / ___|/ ___|
        | ' /   / _ \| | | | ' /   / _ \ |  _ \___ \| |  _| |
        | . \  / ___ \ |_| | . \  / ___ \| |_) |__) | |_| | |___
        |_|\_\/_/   \_\___/|_|\_\/_/   \_\____/____/ \____|\____|

              ___ _   _ ____ _____  _    _     _     _____ ____
             |_ _| \ | / ___|_   _|/ \  | |   | |   | ____|  _ \
              | ||  \| \___ \ | | / _ \ | |   | |   |  _| | |_) |
              | || |\  |___) || |/ ___ \| |___| |___| |___|  _ <
             |___|_| \_|____/ |_/_/   \_\_____|_____|_____|_| \_\
EOF
  echo
  box "✅ KAOKAB5GC UNIFIED INSTALLER (SINGLE NODE: EPC + 5GC, SCP-BASED)" \
      "OS: Ubuntu 22.04 (jammy) only" \
      "Zero-interaction: enabled (no prompts)" \
      "Log: ${LOG_FILE}" \
      "Config: /etc/kaokab/kaokab.env (auto-generated if missing)"
  echo
}

# ============================================================
# Helpers
# ============================================================
require_root() { [[ ${EUID:-0} -eq 0 ]] || die "Run as root: sudo ./${SCRIPT_NAME}"; }

check_os() {
  [[ -r /etc/os-release ]] || die "Missing /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "22.04" ]] || die "Unsupported OS: ${PRETTY_NAME:-unknown} (need Ubuntu 22.04)"
  ok "OS check passed: Ubuntu 22.04"
}

apt_update_once() {
  if [[ ! -f /var/lib/apt/periodic/update-success-stamp ]]; then
    info "Updating apt metadata..."
    DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1
  else
    # Still refresh (quietly) to reduce stale repo issues
    DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1 || true
  fi
}

apt_install() {
  local pkgs=("$@")
  info "Installing packages: ${pkgs[*]}"
  apt_update_once
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" >>"$LOG_FILE" 2>&1
  ok "Packages installed: ${pkgs[*]}"
}

file_backup_dir() {
  local base="$1"
  local ts
  ts="$(date +%F_%H%M%S)"
  echo "${base}/backup-${ts}"
}

# ============================================================
# Block01 — Foundation
# ============================================================
block01_foundation() {
  box "▶▶ Block01" \
      "System checks + base tooling + clean logging"

  require_root
  check_os

  apt_install ca-certificates curl gnupg lsb-release software-properties-common iproute2 iptables jq net-tools dnsutils
  apt_install dialog figlet toilet || true

  ok "System foundation ready"
}

# ============================================================
# Block02 — Config (zero interaction)
#   - Uses /etc/kaokab/kaokab.env if present
#   - Otherwise auto-generates defaults from system and continues
# ============================================================
CFG_DIR="/etc/kaokab"
CFG_FILE="${CFG_DIR}/kaokab.env"

detect_default_iface() { ip -br link | awk '$1!="lo"{print $1; exit}'; }
detect_default_gw()    { ip route show default 2>/dev/null | awk '/default/{print $3; exit}'; }
detect_dns_fallback()  { echo "1.1.1.1 1.0.0.1"; }

block02_config() {
  box "▶▶ Block02" \
      "Load or auto-generate deployment parameters (non-interactive)" \
      "Tip: Edit ${CFG_FILE} before re-running to customize"

  mkdir -p "$CFG_DIR"
  chmod 700 "$CFG_DIR"

  if [[ ! -f "$CFG_FILE" ]]; then
    info "Config not found; auto-generating ${CFG_FILE} from system defaults"

    local iface gw dns1 dns2
    iface="$(detect_default_iface)"
    gw="$(detect_default_gw)"
    read -r dns1 dns2 < <(detect_dns_fallback)

    # Best-effort: detect first IPv4 on iface; if missing, fallback to examples
    local ip0
    ip0="$(ip -4 -br addr show "$iface" | awk '{print $3}' | cut -d/ -f1 | head -n1 || true)"
    [[ -n "${ip0:-}" ]] || ip0="192.168.178.80"

    cat >"$CFG_FILE" <<EOF
# Kaokab5GC Installer Config — generated $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Edit and re-run 555.sh anytime.

# Primary interface and host IP plan
INTERFACE="${iface}"
S1AP_IP="${ip0}"
GTPU_IP="192.168.178.81"
UPF_IP="192.168.178.82"
CIDR="24"
GATEWAY="${gw:-192.168.178.1}"
DNS1="${dns1}"
DNS2="${dns2}"

# UE pools and DNNs
UE_POOL1="10.45.0.0/16"
UE_GW1="10.45.0.1"
DNN1="internet"
UE_POOL2="10.46.0.0/16"
UE_GW2="10.46.0.1"
DNN2="ims"

# PLMN / Slice
MCC="204"
MNC="61"
TAC="1"
SST="1"
SD="010203"

# Names (match your working VM pattern)
NETWORK_FULL="Kaokab"
NETWORK_SHORT="Kaokab"
AMF_NAME="kaokab-amf0"
MME_NAME="kaokab-mme0"

# Optional: manage netplan (true/false)
MANAGE_NETPLAN="false"
EOF

    chmod 600 "$CFG_FILE"
    ok "Config generated: ${CFG_FILE}"
  else
    ok "Config found: ${CFG_FILE}"
  fi

  # shellcheck disable=SC1090
  source "$CFG_FILE"

  # Minimal sanity checks
  [[ -n "${INTERFACE:-}" ]] || die "INTERFACE missing in ${CFG_FILE}"
  ip link show "$INTERFACE" &>/dev/null || die "Interface not found: ${INTERFACE}"
  [[ -n "${S1AP_IP:-}" && -n "${UPF_IP:-}" && -n "${CIDR:-}" ]] || die "IP plan incomplete in ${CFG_FILE}"
  [[ -n "${GATEWAY:-}" ]] || die "GATEWAY missing in ${CFG_FILE}"

  box "CONFIG SUMMARY" \
      "Interface: ${INTERFACE}" \
      "S1AP/N2:   ${S1AP_IP}/${CIDR}" \
      "GTPU/N3:   ${GTPU_IP}/${CIDR}" \
      "UPF GTPU:  ${UPF_IP}/${CIDR}" \
      "GW/DNS:    ${GATEWAY} | ${DNS1}, ${DNS2}" \
      "UE pools:  ${UE_POOL1}(${DNN1}) , ${UE_POOL2}(${DNN2})" \
      "PLMN:      ${MCC}/${MNC}  TAC:${TAC}  Slice:${SST}/${SD}" \
      "Names:     ${NETWORK_FULL}/${NETWORK_SHORT} AMF:${AMF_NAME} MME:${MME_NAME}"

  ok "Parameters loaded"
}

# ============================================================
# Block03 — Netplan (optional)
# ============================================================
block03_netplan_optional() {
  box "▶▶ Block03" \
      "Netplan management (optional)" \
      "Controlled by MANAGE_NETPLAN=${MANAGE_NETPLAN}"

  if [[ "${MANAGE_NETPLAN,,}" != "true" ]]; then
    ok "Netplan management disabled; skipping"
    return
  fi

  info "Backing up current netplan YAMLs"
  local backup_dir
  backup_dir="$(file_backup_dir "/etc/netplan")"
  mkdir -p "$backup_dir"
  cp -a /etc/netplan/*.yaml "$backup_dir"/ 2>/dev/null || true
  ok "Netplan backup: ${backup_dir}"

  local np="/etc/netplan/01-kaokab.yaml"
  info "Writing netplan: ${np}"
  cat >"$np" <<EOF
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
  chmod 600 "$np"

  info "Applying netplan (may briefly interrupt network on this host)"
  netplan generate >>"$LOG_FILE" 2>&1
  netplan apply >>"$LOG_FILE" 2>&1
  sleep 3

  # Validate
  ip -4 addr show "$INTERFACE" | grep -q "${S1AP_IP}" || die "Netplan: missing ${S1AP_IP} on ${INTERFACE}"
  ip route | grep -q "default via ${GATEWAY}" || die "Netplan: default route via ${GATEWAY} missing"
  getent hosts ubuntu.com >/dev/null 2>&1 || die "DNS resolution failed after netplan apply"

  ok "Netplan configured and validated"
}

# ============================================================
# Block04 — IP forwarding + NAT (persistent, clean output)
# ============================================================
block04_nat() {
  box "▶▶ Block04" \
      "Enable IP forwarding & NAT for UE subnets" \
      "Persistent via /etc/sysctl.d and netfilter-persistent"

  apt_install iptables-persistent netfilter-persistent

  info "Enabling IPv4 forwarding (persistent)"
  cat >/etc/sysctl.d/99-kaokab-ipforward.conf <<EOF
net.ipv4.ip_forward=1
EOF
  sysctl -p /etc/sysctl.d/99-kaokab-ipforward.conf >>"$LOG_FILE" 2>&1 || true

  info "Applying NAT rules for UE pools (idempotent)"
  # Helper: add rule only if missing
  ipt_add() {
    local table="$1"; shift
    if ! iptables -t "$table" -C "$@" >/dev/null 2>&1; then
      iptables -t "$table" -A "$@"
    fi
  }

  # Forward allow
  ipt_add filter FORWARD -i ogstun -o "$INTERFACE" -j ACCEPT
  ipt_add filter FORWARD -i "$INTERFACE" -o ogstun -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

  # NAT per pool
  ipt_add nat POSTROUTING -s "$UE_POOL1" -o "$INTERFACE" -j MASQUERADE
  if [[ -n "${UE_POOL2:-}" && -n "${DNN2:-}" ]]; then
    ipt_add nat POSTROUTING -s "$UE_POOL2" -o "$INTERFACE" -j MASQUERADE
  fi

  info "Saving firewall rules (persistent)"
  netfilter-persistent save >>"$LOG_FILE" 2>&1 || true
  netfilter-persistent reload >>"$LOG_FILE" 2>&1 || true

  ok "IP forwarding & NAT enabled (persistent)"
}

# ============================================================
# Block05 — Loopback aliases (persistent via systemd)
# ============================================================
block05_loopback() {
  box "▶▶ Block05" \
      "Install persistent loopback aliases (single-node NFs)" \
      "Provides 127.0.0.2..15, 127.0.0.20, 127.0.0.200"

  local unit="/etc/systemd/system/kaokab-loopback.service"
  cat >"$unit" <<'EOF'
[Unit]
Description=Kaokab Open5GS Loopback Aliases (Single Node)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ip addr add 127.0.0.2/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.3/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.4/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.5/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.6/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.7/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.8/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.9/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.10/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.11/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.12/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.13/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.14/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.15/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.20/8 dev lo
ExecStart=/usr/sbin/ip addr add 127.0.0.200/8 dev lo
ExecStart=/usr/sbin/ip link set lo up

# Idempotency: ignore "File exists" errors
ExecStartPost=/bin/true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >>"$LOG_FILE" 2>&1
  systemctl enable --now kaokab-loopback.service >>"$LOG_FILE" 2>&1 || true

  # Ensure addresses exist now (idempotent adds)
  for ip in {2..15} 20 200; do
    ip addr add "127.0.0.${ip}/8" dev lo 2>/dev/null || true
  done

  ip -4 addr show lo >>"$LOG_FILE" 2>&1 || true
  ok "Loopback aliases installed and active"
}

# ============================================================
# Block06 — MongoDB 6.0 (non-interactive)
# ============================================================
block06_mongodb() {
  box "▶▶ Block06" \
      "Install MongoDB 6.0 (repo + key, non-interactive)" \
      "Service: mongod"

  apt_install gnupg curl

  info "Configuring MongoDB apt repository"
  install -d -m 0755 /etc/apt/keyrings
  # Force overwrite key WITHOUT prompting
  rm -f /etc/apt/keyrings/mongodb-server-6.0.gpg
  curl -fsSL https://pgp.mongodb.com/server-6.0.asc \
    | gpg --dearmor -o /etc/apt/keyrings/mongodb-server-6.0.gpg
  chmod 0644 /etc/apt/keyrings/mongodb-server-6.0.gpg

  cat >/etc/apt/sources.list.d/mongodb-org-6.0.list <<EOF
deb [ arch=amd64,arm64 signed-by=/etc/apt/keyrings/mongodb-server-6.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse
EOF

  apt_update_once

  info "Installing MongoDB packages (this may take a minute)..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y mongodb-org >>"$LOG_FILE" 2>&1

  systemctl enable --now mongod >>"$LOG_FILE" 2>&1
  systemctl is-active --quiet mongod || die "MongoDB did not start (mongod)"
  ok "MongoDB installed & running"
}

# ============================================================
# Block07 — Open5GS install (repo + packages)
# ============================================================
block07_open5gs_install() {
  box "▶▶ Block07" \
      "Install Open5GS (EPC + 5GC) from apt repo" \
      "Target: single node with SCP-based SBI"

  info "Configuring Open5GS apt repository"
  install -d -m 0755 /etc/apt/keyrings
  rm -f /etc/apt/keyrings/open5gs.gpg
  curl -fsSL https://download.opensuse.org/repositories/home:/acetcom:/open5gs/xUbuntu_22.04/Release.key \
    | gpg --dearmor -o /etc/apt/keyrings/open5gs.gpg
  chmod 0644 /etc/apt/keyrings/open5gs.gpg

  cat >/etc/apt/sources.list.d/open5gs.list <<'EOF'
deb [signed-by=/etc/apt/keyrings/open5gs.gpg] https://download.opensuse.org/repositories/home:/acetcom:/open5gs/xUbuntu_22.04/ /
EOF

  apt_update_once

  info "Installing Open5GS packages (this may take a minute)..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y open5gs >>"$LOG_FILE" 2>&1

  ok "Open5GS installed"
}

# ============================================================
# Block08 — Open5GS configuration (match your working VM style)
# ============================================================
block08_open5gs_config() {
  box "▶▶ Block08" \
      "Configure Open5GS (Single Node)" \
      "SCP-based SBI (like your working VM)" \
      "Writes YAML under /etc/open5gs and backs up existing configs"

  local etcdir="/etc/open5gs"
  [[ -d "$etcdir" ]] || mkdir -p "$etcdir"

  local bdir
  bdir="$(file_backup_dir "$etcdir")"
  mkdir -p "$bdir"
  cp -a "$etcdir"/*.yaml "$bdir"/ 2>/dev/null || true
  ok "Backup created: ${bdir}"

  # Some values normalization (Open5GS often expects MNC without leading zeros in YAML, but both can work)
  local mnc_yaml="$MNC"
  # Keep as-is; user uses "61" not "061" in working VM.
  # If you ever need 3-digit, set MNC="025" and it will be written as 025 (string-like).

  # --- amf.yaml ---
  cat >"${etcdir}/amf.yaml" <<EOF
logger:
  file:
    path: /var/log/open5gs/amf.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024

amf:
  sbi:
    server:
      - address: 127.0.0.5
        port: 7777
    client:
      scp:
        - uri: http://127.0.0.200:7777
  ngap:
    server:
      - address: ${S1AP_IP}
  metrics:
    server:
      - address: 127.0.0.5
        port: 9090
  guami:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${mnc_yaml}
      amf_id:
        region: 1
        set: 1
  tai:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${mnc_yaml}
      tac: ${TAC}
  plmn_support:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${mnc_yaml}
      s_nssai:
          sst: ${SST}
          sd: ${SD}
  security:
    integrity_order : [ NIA2, NIA1, NIA0 ]
    ciphering_order : [ NEA0, NEA1, NEA2 ]
  network_name:
    full: ${NETWORK_FULL}
    short: ${NETWORK_SHORT}
  amf_name: ${AMF_NAME}
  time:
    t3512:
      value: 540
EOF

  # --- mme.yaml ---
  cat >"${etcdir}/mme.yaml" <<EOF
logger:
  file:
    path: /var/log/open5gs/mme.log
    level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024

mme:
  freeDiameter: /etc/freeDiameter/mme.conf
  s1ap:
    server:
      - address: ${S1AP_IP}
  gtpc:
    server:
      - address: 127.0.0.2
    client:
      sgwc:
        - address: 127.0.0.3
      smf:
        - address: 127.0.0.4
  metrics:
    server:
      - address: 127.0.0.2
        port: 9090
  gummei:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${mnc_yaml}
      mme_gid: 2
      mme_code: 1
  tai:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${mnc_yaml}
      tac: ${TAC}
  security:
    integrity_order : [ EIA2, EIA1, EIA0 ]
    ciphering_order : [ EEA0, EEA1, EEA2 ]
  network_name:
    full: ${NETWORK_FULL}
    short: ${NETWORK_SHORT}
  mme_name: ${MME_NAME}
  time:
EOF

  # --- nrf.yaml ---
  cat >"${etcdir}/nrf.yaml" <<EOF
logger:
  file:
    path: /var/log/open5gs/nrf.log
#  level: info

global:
  max:
    ue: 1024

nrf:
  serving:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${mnc_yaml}
  sbi:
    server:
      - address: 127.0.0.10
        port: 7777
EOF

  # --- scp.yaml ---
  cat >"${etcdir}/scp.yaml" <<'EOF'
logger:
  file:
    path: /var/log/open5gs/scp.log
#  level: info

global:
  max:
    ue: 1024

scp:
  sbi:
    server:
      - address: 127.0.0.200
        port: 7777
EOF

  # --- ausf.yaml ---
  cat >"${etcdir}/ausf.yaml" <<EOF
logger:
  file:
    path: /var/log/open5gs/ausf.log
#  level: info

global:
  max:
    ue: 1024

ausf:
  sbi:
    server:
      - address: 127.0.0.11
        port: 7777
    client:
      scp:
        - uri: http://127.0.0.200:7777
EOF

  # --- udm.yaml ---
  cat >"${etcdir}/udm.yaml" <<EOF
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/udm.log
#  level: info

global:
  max:
    ue: 1024

udm:
  sbi:
    server:
      - address: 127.0.0.12
        port: 7777
    client:
      scp:
        - uri: http://127.0.0.200:7777
EOF

  # --- udr.yaml ---
  cat >"${etcdir}/udr.yaml" <<EOF
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/udr.log
#  level: info

global:
  max:
    ue: 1024

udr:
  sbi:
    server:
      - address: 127.0.0.14
        port: 7777
    client:
      scp:
        - uri: http://127.0.0.200:7777
EOF

  # --- pcf.yaml ---
  cat >"${etcdir}/pcf.yaml" <<EOF
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/pcf.log
#  level: info

global:
  max:
    ue: 1024

pcf:
  sbi:
    server:
      - address: 127.0.0.13
        port: 7777
    client:
      scp:
        - uri: http://127.0.0.200:7777
  metrics:
    server:
      - address: 127.0.0.13
        port: 9090
EOF

  # --- nssf.yaml ---
  cat >"${etcdir}/nssf.yaml" <<EOF
logger:
  file:
    path: /var/log/open5gs/nssf.log
#  level: info

global:
  max:
    ue: 1024

nssf:
  sbi:
    server:
      - address: 127.0.0.20
        port: 7777
    client:
      scp:
        - uri: http://127.0.0.200:7777
  nsi:
    - name: ${DNN1}
      s_nssai:
        sst: ${SST}
        sd: ${SD}
EOF

  # --- bsf.yaml ---
  cat >"${etcdir}/bsf.yaml" <<EOF
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/bsf.log
#  level: info

global:
  max:
    ue: 1024

bsf:
  sbi:
    server:
      - address: 127.0.0.15
        port: 7777
    client:
      scp:
        - uri: http://127.0.0.200:7777
EOF

  # --- smf.yaml ---
  cat >"${etcdir}/smf.yaml" <<EOF
logger:
  file:
    path: /var/log/open5gs/smf.log
#  level: info

global:
  max:
    ue: 1024

smf:
  sbi:
    server:
      - address: 127.0.0.4
        port: 7777
    client:
      scp:
        - uri: http://127.0.0.200:7777
  pfcp:
    server:
      - address: 127.0.0.4
    client:
      upf:
        - address: 127.0.0.7
  gtpc:
    server:
      - address: 127.0.0.4
  gtpu:
    server:
      - address: 127.0.0.4
  metrics:
    server:
      - address: 127.0.0.4
        port: 9090
  session:
    - subnet: ${UE_POOL1}
      gateway: ${UE_GW1}
      dnn: ${DNN1}
    - subnet: ${UE_POOL2}
      gateway: ${UE_GW2}
      dnn: ${DNN2}
  dns:
    - ${DNS2}
    - ${DNS1}
  mtu: 1500
  freeDiameter: /etc/freeDiameter/smf.conf
EOF

  # --- upf.yaml ---
  cat >"${etcdir}/upf.yaml" <<EOF
logger:
  file:
    path: /var/log/open5gs/upf.log
#  level: info

global:
  max:
    ue: 1024

upf:
  pfcp:
    server:
      - address: 127.0.0.7
  gtpu:
    server:
      - address: ${UPF_IP}
  session:
    - subnet: ${UE_POOL1}
      dnn: ${DNN1}
    - subnet: ${UE_POOL2}
      dnn: ${DNN2}
EOF

  # --- sgwc.yaml ---
  cat >"${etcdir}/sgwc.yaml" <<EOF
logger:
  file:
    path: /var/log/open5gs/sgwc.log
#  level: info

global:
  max:
    ue: 1024

sgwc:
  gtpc:
    server:
      - address: 127.0.0.3
  pfcp:
    server:
      - address: 127.0.0.3
    client:
      sgwu:
        - address: 127.0.0.6
EOF

  # --- sgwu.yaml ---
  cat >"${etcdir}/sgwu.yaml" <<EOF
logger:
  file:
    path: /var/log/open5gs/sgwu.log
#  level: info

global:
  max:
    ue: 1024

sgwu:
  pfcp:
    server:
      - address: 127.0.0.6
  gtpu:
    server:
      - address: ${GTPU_IP}
EOF

  # --- hss.yaml / pcrf.yaml / sepp1.yaml / sepp2.yaml ---
  # Keep minimal presence to avoid breaking package expectations; these are optional for your core flow.
  cat >"${etcdir}/hss.yaml" <<'EOF'
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/hss.log
#  level: info
global:
  max:
    ue: 1024
hss:
  freeDiameter: /etc/freeDiameter/hss.conf
EOF

  cat >"${etcdir}/pcrf.yaml" <<'EOF'
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/pcrf.log
#  level: info
global:
  max:
    ue: 1024
pcrf:
  freeDiameter: /etc/freeDiameter/pcrf.conf
EOF

  cat >"${etcdir}/sepp1.yaml" <<'EOF'
logger:
  file:
    path: /var/log/open5gs/sepp1.log
#  level: info
global:
  max:
    ue: 1024
sepp:
  sbi:
    server:
      - address: 127.0.0.9
        port: 7777
EOF

  cat >"${etcdir}/sepp2.yaml" <<'EOF'
logger:
  file:
    path: /var/log/open5gs/sepp2.log
#  level: info
global:
  max:
    ue: 1024
sepp:
  sbi:
    server:
      - address: 127.0.0.8
        port: 7777
EOF

  # Permissions: Open5GS service runs as open5gs user
  chown -R open5gs:open5gs "$etcdir" 2>/dev/null || true
  chmod 640 "$etcdir"/*.yaml 2>/dev/null || true

  ok "Open5GS configuration written"
}

# ============================================================
# Block09 — Start services (correct order, stable)
# ============================================================
block09_start() {
  box "▶▶ Block09" \
      "Start MongoDB + Open5GS services" \
      "Order: mongod → nrf/scp → core NFs → access/UPF"

  info "Starting MongoDB (mongod)"
  systemctl enable --now mongod >>"$LOG_FILE" 2>&1 || true
  systemctl is-active --quiet mongod || die "mongod is not active"

  # Clean any fast-fail loops from previous runs
  systemctl reset-failed open5gs-* >>"$LOG_FILE" 2>&1 || true

  info "Starting NRF + SCP"
  systemctl enable --now open5gs-nrfd open5gs-scpd >>"$LOG_FILE" 2>&1 || true
  sleep 2

  info "Starting AUSF/UDM/UDR/PCF/NSSF/BSF/HSS"
  systemctl enable --now open5gs-ausfd open5gs-udmd open5gs-udrd open5gs-pcfd open5gs-nssfd open5gs-bsfd open5gs-hssd >>"$LOG_FILE" 2>&1 || true
  sleep 2

  info "Starting AMF/SMF/UPF/MME/SGW-C/SGW-U/PCRF"
  systemctl enable --now open5gs-amfd open5gs-smfd open5gs-upfd open5gs-mmed open5gs-sgwcd open5gs-sgwud open5gs-pcrfd >>"$LOG_FILE" 2>&1 || true
  sleep 2

  ok "Open5GS services start sequence issued"
}

# ============================================================
# Block10 — Health check (clean, explicit)
# ============================================================
block10_health() {
  box "▶▶ Block10" \
      "Health check" \
      "Validates SBI port 7777 listeners and core systemd units"

  info "Checking SBI listeners (port 7777)"
  local listeners
  listeners="$(ss -tuln 2>/dev/null | awk '$1 ~ /^tcp/ && $5 ~ /:7777$/ {print $5}' | sort -u | tr '\n' ' ' || true)"
  if [[ -z "${listeners// }" ]]; then
    ss -tuln >>"$LOG_FILE" 2>&1 || true
    die "No SBI port 7777 listening"
  fi
  ok "SBI ports listening: ${listeners}"

  info "Checking core services state"
  local must=(open5gs-nrfd open5gs-scpd open5gs-amfd open5gs-smfd open5gs-upfd)
  local s
  for s in "${must[@]}"; do
    if systemctl is-active --quiet "$s"; then
      ok "Service active: $s"
    else
      systemctl status "$s" --no-pager >>"$LOG_FILE" 2>&1 || true
      die "Service not active: $s"
    fi
  done

  ok "Core services running"
}

# ============================================================
# Main
# ============================================================
main() {
  banner

  block01_foundation
  block02_config
  block03_netplan_optional
  block04_nat
  block05_loopback
  block06_mongodb
  block07_open5gs_install
  block08_open5gs_config
  block09_start
  block10_health

  hr
  box "✅ KAOKAB5GC INSTALLATION COMPLETE" \
      "Single-node Open5GS (EPC + 5GC) is installed and running" \
      "Next: add subscribers via WebUI/DB as needed" \
      "Log: ${LOG_FILE}" \
      "Config: ${CFG_FILE}"
  hr
}

main "$@"
