#!/usr/bin/env bash
# ============================================================
# 555.sh — KAOKAB5GC Unified Installer (Single Node: EPC + 5GC)
# Ubuntu 22.04 | Open5GS + MongoDB | SCP-based architecture
# ============================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ----------------------------
# Constants
# ----------------------------
SCRIPT_NAME="$(basename "$0")"
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/kaokab5gc-install-$(date +%F_%H%M%S).log"
CFG_DIR="/etc/kaokab"
CFG_FILE="${CFG_DIR}/kaokab.env"
NETPLAN_DIR="/etc/netplan"
NETPLAN_FILE="${NETPLAN_DIR}/01-kaokab.yaml"
OPEN5GS_DIR="/etc/open5gs"
LOOP_SVC="/etc/systemd/system/kaokab-loopback.service"
LOOP_SVC_NAME="kaokab-loopback.service"

# ----------------------------
# Colors
# ----------------------------
BOLD="\e[1m"
RESET="\e[0m"
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
CYAN="\e[36m"
MAGENTA="\e[35m"

# ----------------------------
# Logging
# ----------------------------
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

log()   { echo -e "$*" | tee -a "$LOG_FILE" >/dev/null; }
info()  { log "${BOLD}${BLUE}[INFO]${RESET}  $*"; }
ok()    { log "${BOLD}${GREEN}[OK]${RESET}    $*"; }
warn()  { log "${BOLD}${YELLOW}[WARN]${RESET}  $*"; }
fail()  { log "${BOLD}${RED}[FAIL]${RESET}  $*"; }

on_error() {
  local code=$?
  fail "Installer failed at line ${BASH_LINENO[0]}: ${BASH_COMMAND}"
  fail "Log: ${LOG_FILE}"
  exit "$code"
}
trap on_error ERR

# ----------------------------
# UI helpers (Boxes + Progress)
# ----------------------------
term_cols() { tput cols 2>/dev/null || echo 100; }

hr() {
  local w; w="$(term_cols)"
  printf "%*s\n" "$w" "" | tr " " "="
}

box() {
  # box "TITLE" "line1" "line2" ...
  local title="$1"; shift || true
  local w; w="$(term_cols)"
  local inner=$(( w-4 ))
  echo -e "${BOLD}${CYAN}"
  printf "╔%*s╗\n" $((w-2)) "" | tr " " "═"
  printf "║ %-*s ║\n" "$inner" "$title"
  printf "╠%*s╣\n" $((w-2)) "" | tr " " "═"
  if (( $# == 0 )); then
    printf "║ %-*s ║\n" "$inner" ""
  else
    for line in "$@"; do
      printf "║ %-*s ║\n" "$inner" "$line"
    done
  fi
  printf "╚%*s╝\n" $((w-2)) "" | tr " " "═"
  echo -e "${RESET}"
}

banner() {
  clear || true
  echo -e "${BOLD}${CYAN}"
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
  echo -e "${RESET}"
}

spinner() {
  # spinner <seconds> <message>
  local seconds="${1:-3}"; shift || true
  local msg="${1:-Working...}"
  local i=0
  local spin='|/-\'
  echo -ne "${BOLD}${MAGENTA}${msg}${RESET} "
  while (( i < seconds*10 )); do
    echo -ne "${spin:i%4:1}\r${BOLD}${MAGENTA}${msg}${RESET} "
    sleep 0.1
    ((i++))
  done
  echo -e "✔"
}

step() {
  # step "BlockXX" "Description"
  local s="$1"; local d="$2"
  box "▶▶ ${s}" "${d}" "Log: ${LOG_FILE}"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${RED}Run as root: sudo ./${SCRIPT_NAME}${RESET}"
    exit 1
  fi
}

check_os() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "22.04" ]]; then
      fail "Unsupported OS. Required Ubuntu 22.04, detected: ${PRETTY_NAME:-unknown}"
      exit 1
    fi
  else
    fail "Cannot detect OS (/etc/os-release missing)."
    exit 1
  fi
}

apt_update_once() {
  # Run update only once per execution
  if [[ -z "${_APT_UPDATED:-}" ]]; then
    info "Refreshing apt index"
    DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1
    _APT_UPDATED=1
  fi
}

apt_install() {
  apt_update_once
  local pkgs=("$@")
  info "Installing: ${pkgs[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" >>"$LOG_FILE" 2>&1
}

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# ----------------------------
# Block01 — System checks + base tools
# ----------------------------
block01() {
  step "Block01" "System check + base dependencies"

  check_os
  ok "OS check passed: Ubuntu 22.04"

  apt_install ca-certificates curl gnupg lsb-release software-properties-common iproute2 iptables net-tools jq
  ok "Base tools installed"

  banner
  box "✅ SYSTEM CHECK PASSED" \
      "- OS            : Ubuntu 22.04" \
      "- Privileges    : root" \
      "- Network tools : ready" \
      "- Installer log : ${LOG_FILE}"
}

# ----------------------------
# Block02 — Collect inputs (dialog rectangles + fallback CLI)
# ----------------------------
ensure_dialog() {
  if ! cmd_exists dialog; then
    apt_install dialog
  fi
}

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r a b c d <<<"$ip"
  [[ "$a" -le 255 && "$b" -le 255 && "$c" -le 255 && "$d" -le 255 ]]
}

is_iface() { ip link show "$1" &>/dev/null; }

prompt_cli() {
  local var="$1"; local msg="$2"; local def="${3:-}"
  local val
  read -r -p "$(echo -e "${BOLD}${CYAN}${msg}${RESET} [${def}]: ")" val
  val="${val:-$def}"
  printf -v "$var" '%s' "$val"
}

dialog_input() {
  local title="$1" prompt="$2" def="${3:-}"
  dialog --clear --stdout --title "$title" --inputbox "$prompt" 10 74 "$def"
}

block02() {
  step "Block02" "Collect deployment parameters (nice rectangles)"

  mkdir -p "$CFG_DIR"
  chmod 700 "$CFG_DIR"

  local default_iface default_gw default_ip0
  default_iface="$(ip -br link | awk '$1!="lo"{print $1; exit}')"
  default_gw="$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')"
  default_ip0="$(ip -4 addr show "$default_iface" 2>/dev/null | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"

  local use_dialog="false"
  if [[ -t 1 ]]; then
    # interactive TTY
    ensure_dialog
    use_dialog="true"
  fi

  if [[ "$use_dialog" == "true" ]]; then
    # dialog mode
    local tmp

    tmp="$(dialog_input "Kaokab5GC" "Interface name (e.g., ens160)" "$default_iface")" || exit 1
    INTERFACE="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "S1AP/N2 IPv4 (Control) e.g. 192.168.178.80" "${default_ip0:-192.168.178.80}")" || exit 1
    S1AP_IP="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "GTPU/N3 IPv4 (optional) e.g. 192.168.178.81" "192.168.178.81")" || exit 1
    GTPU_IP="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "UPF GTPU bind IPv4 e.g. 192.168.178.82" "192.168.178.82")" || exit 1
    UPF_IP="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "CIDR mask (1-32)" "24")" || exit 1
    CIDR="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "Gateway IPv4" "${default_gw:-192.168.178.1}")" || exit 1
    GATEWAY="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "DNS1 IPv4" "1.1.1.1")" || exit 1
    DNS1="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "DNS2 IPv4" "1.0.0.1")" || exit 1
    DNS2="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "UE pool #1 (CIDR) e.g. 10.45.0.0/16" "10.45.0.0/16")" || exit 1
    UE_POOL1="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "UE gateway #1 e.g. 10.45.0.1" "10.45.0.1")" || exit 1
    UE_GW1="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "DNN #1 (APN) e.g. internet" "internet")" || exit 1
    DNN1="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "UE pool #2 (CIDR) optional" "10.46.0.0/16")" || exit 1
    UE_POOL2="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "UE gateway #2 optional" "10.46.0.1")" || exit 1
    UE_GW2="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "DNN #2 optional (e.g. ims)" "ims")" || exit 1
    DNN2="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "MCC (3 digits)" "204")" || exit 1
    MCC="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "MNC (2-3 digits)" "61")" || exit 1
    MNC="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "TAC" "1")" || exit 1
    TAC="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "SST" "1")" || exit 1
    SST="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "SD (6 hex digits) e.g. 010203" "010203")" || exit 1
    SD="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "Network name (full)" "Kaokab")" || exit 1
    NET_FULL="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "Network name (short)" "Kaokab")" || exit 1
    NET_SHORT="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "AMF name" "kaokab-amf0")" || exit 1
    AMF_NAME="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "MME name" "kaokab-mme0")" || exit 1
    MME_NAME="$tmp"

    tmp="$(dialog_input "Kaokab5GC" "Manage Netplan now? true/false" "false")" || exit 1
    MANAGE_NETPLAN="$tmp"

    clear || true
  else
    # CLI mode (still neat)
    box "CONFIG INPUT" "Enter values (press Enter to accept default)."
    prompt_cli INTERFACE "Interface name" "$default_iface"
    prompt_cli S1AP_IP "S1AP/N2 IPv4 (Control) e.g. 192.168.178.80" "${default_ip0:-192.168.178.80}"
    prompt_cli GTPU_IP "GTPU/N3 IPv4 (optional) e.g. 192.168.178.81" "192.168.178.81"
    prompt_cli UPF_IP "UPF GTPU bind IPv4 e.g. 192.168.178.82" "192.168.178.82"
    prompt_cli CIDR "CIDR mask" "24"
    prompt_cli GATEWAY "Gateway" "${default_gw:-192.168.178.1}"
    prompt_cli DNS1 "DNS1" "1.1.1.1"
    prompt_cli DNS2 "DNS2" "1.0.0.1"
    prompt_cli UE_POOL1 "UE pool #1 (CIDR) e.g. 10.45.0.0/16" "10.45.0.0/16"
    prompt_cli UE_GW1 "UE gateway #1 e.g. 10.45.0.1" "10.45.0.1"
    prompt_cli DNN1 "DNN #1 (APN) e.g. internet" "internet"
    prompt_cli UE_POOL2 "UE pool #2 (CIDR) optional" "10.46.0.0/16"
    prompt_cli UE_GW2 "UE gateway #2 optional" "10.46.0.1"
    prompt_cli DNN2 "DNN #2 optional" "ims"
    prompt_cli MCC "MCC (3 digits)" "204"
    prompt_cli MNC "MNC (2-3 digits)" "61"
    prompt_cli TAC "TAC" "1"
    prompt_cli SST "SST" "1"
    prompt_cli SD "SD (6 hex digits) e.g. 010203" "010203"
    prompt_cli NET_FULL "Network name (full)" "Kaokab"
    prompt_cli NET_SHORT "Network name (short)" "Kaokab"
    prompt_cli AMF_NAME "AMF name" "kaokab-amf0"
    prompt_cli MME_NAME "MME name" "kaokab-mme0"
    prompt_cli MANAGE_NETPLAN "Manage Netplan now? true/false" "false"
  fi

  # validate important fields
  is_iface "$INTERFACE" || { fail "Interface not found: $INTERFACE"; exit 1; }
  is_ipv4 "$S1AP_IP" || { fail "Invalid S1AP_IP: $S1AP_IP"; exit 1; }
  is_ipv4 "$UPF_IP"  || { fail "Invalid UPF_IP: $UPF_IP"; exit 1; }
  is_ipv4 "$GATEWAY" || { fail "Invalid GATEWAY: $GATEWAY"; exit 1; }
  is_ipv4 "$DNS1"    || { fail "Invalid DNS1: $DNS1"; exit 1; }
  is_ipv4 "$DNS2"    || { fail "Invalid DNS2: $DNS2"; exit 1; }

  cat >"$CFG_FILE" <<EOF
# Kaokab5GC Installer Config
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

INTERFACE="${INTERFACE}"
S1AP_IP="${S1AP_IP}"
GTPU_IP="${GTPU_IP}"
UPF_IP="${UPF_IP}"
CIDR="${CIDR}"
GATEWAY="${GATEWAY}"
DNS1="${DNS1}"
DNS2="${DNS2}"

UE_POOL1="${UE_POOL1}"
UE_GW1="${UE_GW1}"
DNN1="${DNN1}"

UE_POOL2="${UE_POOL2}"
UE_GW2="${UE_GW2}"
DNN2="${DNN2}"

MCC="${MCC}"
MNC="${MNC}"
TAC="${TAC}"
SST="${SST}"
SD="${SD}"

NET_FULL="${NET_FULL}"
NET_SHORT="${NET_SHORT}"
AMF_NAME="${AMF_NAME}"
MME_NAME="${MME_NAME}"

MANAGE_NETPLAN="${MANAGE_NETPLAN}"
EOF
  chmod 600 "$CFG_FILE"
  ok "Saved config: $CFG_FILE"

  box "CONFIG SUMMARY" \
      "Interface: ${INTERFACE}" \
      "S1AP/N2:   ${S1AP_IP}/${CIDR}" \
      "GTPU/N3:   ${GTPU_IP}/${CIDR}" \
      "UPF GTPU:  ${UPF_IP}/${CIDR}" \
      "GW/DNS:    ${GATEWAY} | ${DNS1}, ${DNS2}" \
      "UE pools:  ${UE_POOL1}(${DNN1}) , ${UE_POOL2}(${DNN2})" \
      "PLMN:      ${MCC}/${MNC}  TAC:${TAC}  Slice:${SST}/${SD}" \
      "Names:     ${NET_FULL}/${NET_SHORT} AMF:${AMF_NAME} MME:${MME_NAME}"
}

# ----------------------------
# Block03 — Netplan (optional)
# ----------------------------
block03_netplan() {
  step "Block03" "Netplan management (optional)"

  # shellcheck disable=SC1091
  source "$CFG_FILE"

  if [[ "${MANAGE_NETPLAN}" != "true" ]]; then
    warn "Netplan management skipped (MANAGE_NETPLAN=false)"
    return 0
  fi

  local backup="${NETPLAN_DIR}/backup-$(date +%F_%H%M%S)"
  mkdir -p "$backup"
  cp -a "${NETPLAN_DIR}"/*.yaml "$backup"/ 2>/dev/null || true
  ok "Netplan backup: $backup"

  cat >"$NETPLAN_FILE" <<EOF
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
  chmod 600 "$NETPLAN_FILE"
  ok "Netplan written: $NETPLAN_FILE"

  spinner 3 "Applying netplan (do not disconnect)..."
  netplan generate >>"$LOG_FILE" 2>&1
  netplan apply >>"$LOG_FILE" 2>&1
  sleep 2

  ip route | grep -q "default via ${GATEWAY}" || { fail "Default route missing after netplan"; exit 1; }
  getent hosts ubuntu.com >/dev/null 2>&1 || { fail "DNS check failed after netplan"; exit 1; }

  ok "Netplan applied + validated"
}

# ----------------------------
# Block04 — IP Forwarding + NAT
# ----------------------------
block04_nat() {
  step "Block04" "Enable IP forwarding & NAT for UE subnets"

  # shellcheck disable=SC1091
  source "$CFG_FILE"

  # kernel forwarding
  cat >/etc/sysctl.d/99-kaokab-ipforward.conf <<EOF
net.ipv4.ip_forward=1
EOF
  sysctl -p /etc/sysctl.d/99-kaokab-ipforward.conf >>"$LOG_FILE" 2>&1

  # NAT rules (idempotent)
  iptables -t nat -C POSTROUTING -s "${UE_POOL1}" -o "${INTERFACE}" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "${UE_POOL1}" -o "${INTERFACE}" -j MASQUERADE

  if [[ -n "${UE_POOL2}" ]]; then
    iptables -t nat -C POSTROUTING -s "${UE_POOL2}" -o "${INTERFACE}" -j MASQUERADE 2>/dev/null \
      || iptables -t nat -A POSTROUTING -s "${UE_POOL2}" -o "${INTERFACE}" -j MASQUERADE
  fi

  # persist iptables
  apt_install iptables-persistent
  netfilter-persistent save >>"$LOG_FILE" 2>&1 || true

  ok "IP forwarding & NAT enabled"
  iptables -t nat -S POSTROUTING | grep MASQUERADE | tee -a "$LOG_FILE" >/dev/null || true
}

# ----------------------------
# Block05 — Loopback aliases (single-node NF IPs)
# ----------------------------
block05_loopbacks() {
  step "Block05" "Install persistent loopback aliases (single-node NFs)"

  # Create systemd oneshot to add loopback IPs on boot
  cat >"$LOOP_SVC" <<'EOF'
[Unit]
Description=Kaokab Open5GS Loopback Aliases (single node)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '\
set -e; \
for ip in 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5 127.0.0.6 127.0.0.7 127.0.0.8 127.0.0.9 127.0.0.10 127.0.0.11 127.0.0.12 127.0.0.13 127.0.0.14 127.0.0.15 127.0.0.20 127.0.0.200; do \
  /sbin/ip -4 addr show lo | grep -q "$ip/8" || /sbin/ip addr add "$ip/8" dev lo; \
done'
ExecStop=/bin/bash -c '\
set -e; \
for ip in 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5 127.0.0.6 127.0.0.7 127.0.0.8 127.0.0.9 127.0.0.10 127.0.0.11 127.0.0.12 127.0.0.13 127.0.0.14 127.0.0.15 127.0.0.20 127.0.0.200; do \
  /sbin/ip addr del "$ip/8" dev lo 2>/dev/null || true; \
done'

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "$LOOP_SVC_NAME" >>"$LOG_FILE" 2>&1

  ip -4 addr show lo | grep -q "127.0.0.200/8" || { fail "Loopback aliases not applied"; exit 1; }
  ok "Loopback aliases installed"
}

# ----------------------------
# Block06 — MongoDB install (non-interactive keys)
# ----------------------------
block06_mongodb() {
  step "Block06" "Install MongoDB 6.0 (repo + key, non-interactive)"

  apt_install curl gnupg

  install -d -m 0755 /etc/apt/keyrings

  # key (non-interactive overwrite)
  curl -fsSL https://pgp.mongodb.com/server-6.0.asc \
    | gpg --dearmor --yes -o /etc/apt/keyrings/mongodb-server-6.0.gpg
  chmod 0644 /etc/apt/keyrings/mongodb-server-6.0.gpg

  # repo
  cat >/etc/apt/sources.list.d/mongodb-org-6.0.list <<EOF
deb [arch=amd64,arm64 signed-by=/etc/apt/keyrings/mongodb-server-6.0.gpg] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse
EOF

  apt_update_once
  apt_install mongodb-org

  systemctl enable --now mongod >>"$LOG_FILE" 2>&1
  spinner 2 "Waiting for MongoDB to become ready..."
  systemctl is-active --quiet mongod || { fail "MongoDB is not running"; exit 1; }

  ok "MongoDB installed & running (mongod)"
}

# ----------------------------
# Block07 — Open5GS install
# ----------------------------
block07_open5gs_install() {
  step "Block07" "Install Open5GS (latest PPA)"

  apt_install software-properties-common
  add-apt-repository -y ppa:open5gs/latest >>"$LOG_FILE" 2>&1 || true

  apt_update_once
  apt_install open5gs

  ok "Open5GS installed"
}

# ----------------------------
# Block08 — Open5GS configuration (SCP-based, like working VM)
# ----------------------------
backup_open5gs() {
  local backup="${OPEN5GS_DIR}/backup-$(date +%F_%H%M%S)"
  mkdir -p "$backup"
  cp -a "${OPEN5GS_DIR}"/*.yaml "$backup"/ 2>/dev/null || true
  ok "Backup created: $backup"
}

write_yaml() {
  # write_yaml <path> <content>
  local p="$1"
  local c="$2"
  install -o open5gs -g open5gs -m 0640 /dev/null "$p"
  printf "%s\n" "$c" >"$p"
  chown open5gs:open5gs "$p"
  chmod 0640 "$p"
}

block08_open5gs_config() {
  step "Block08" "Configure Open5GS (Single Node, SCP-based)"

  # shellcheck disable=SC1091
  source "$CFG_FILE"
  backup_open5gs

  # Normalize MNC: keep numeric, no leading zeros needed in YAML (Open5GS accepts "61")
  # We'll write exactly as provided.

  # --- amf.yaml (include network_name like your working VM)
  write_yaml "${OPEN5GS_DIR}/amf.yaml" "$(cat <<EOF
logger:
  file:
    path: /var/log/open5gs/amf.log
#  level: info

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
        mnc: ${MNC}
      amf_id:
        region: 1
        set: 1
  tai:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${MNC}
      tac: ${TAC}
  plmn_support:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${MNC}
      s_nssai:
        sst: ${SST}
        sd: ${SD}
  security:
    integrity_order : [ NIA2, NIA1, NIA0 ]
    ciphering_order : [ NEA0, NEA1, NEA2 ]
  network_name:
    full: ${NET_FULL}
    short: ${NET_SHORT}
  amf_name: ${AMF_NAME}
  time:
    t3512:
      value: 540
EOF
)"

  # --- nrf.yaml
  write_yaml "${OPEN5GS_DIR}/nrf.yaml" "$(cat <<EOF
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
        mnc: ${MNC}
  sbi:
    server:
      - address: 127.0.0.10
        port: 7777
EOF
)"

  # --- scp.yaml (core of SCP-based)
  write_yaml "${OPEN5GS_DIR}/scp.yaml" "$(cat <<'EOF'
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
)"

  # --- ausf.yaml
  write_yaml "${OPEN5GS_DIR}/ausf.yaml" "$(cat <<EOF
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
)"

  # --- udm.yaml
  write_yaml "${OPEN5GS_DIR}/udm.yaml" "$(cat <<EOF
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
)"

  # --- udr.yaml
  write_yaml "${OPEN5GS_DIR}/udr.yaml" "$(cat <<EOF
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
      - address: 127.0.0.20
        port: 7777
    client:
      scp:
        - uri: http://127.0.0.200:7777
EOF
)"

  # --- pcf.yaml (must include db_uri)
  write_yaml "${OPEN5GS_DIR}/pcf.yaml" "$(cat <<EOF
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
)"

  # --- nssf.yaml
  write_yaml "${OPEN5GS_DIR}/nssf.yaml" "$(cat <<EOF
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
      - address: 127.0.0.14
        port: 7777
    client:
      scp:
        - uri: http://127.0.0.200:7777
  nsi:
    - name: nsi-1
      s_nssai:
        sst: ${SST}
        sd: ${SD}
EOF
)"

  # --- smf.yaml (includes dns section required in your working VM for 2.7.6)
  # Always include at least one session (DNN1). Optionally include DNN2.
  SMF_SESSIONS="    - subnet: ${UE_POOL1}
      gateway: ${UE_GW1}
      dnn: ${DNN1}"
  if [[ -n "${UE_POOL2}" && -n "${UE_GW2}" && -n "${DNN2}" ]]; then
    SMF_SESSIONS="${SMF_SESSIONS}
    - subnet: ${UE_POOL2}
      gateway: ${UE_GW2}
      dnn: ${DNN2}"
  fi

  write_yaml "${OPEN5GS_DIR}/smf.yaml" "$(cat <<EOF
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
${SMF_SESSIONS}

  dns:
    - ${DNS2}
    - ${DNS1}

  mtu: 1500
  freeDiameter: /etc/freeDiameter/smf.conf
EOF
)"

  # --- upf.yaml (bind gtp on UPF_IP, pfcp on 127.0.0.7)
  write_yaml "${OPEN5GS_DIR}/upf.yaml" "$(cat <<EOF
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
EOF
)"

  # --- EPC: mme.yaml, sgwc.yaml, sgwu.yaml, hss.yaml, pcrf.yaml (basic single node)
  write_yaml "${OPEN5GS_DIR}/mme.yaml" "$(cat <<EOF
logger:
  file:
    path: /var/log/open5gs/mme.log
#    level: debug

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
        mnc: ${MNC}
      mme_gid: 2
      mme_code: 1
  tai:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${MNC}
      tac: ${TAC}
  security:
    integrity_order : [ EIA2, EIA1, EIA0 ]
    ciphering_order : [ EEA0, EEA1, EEA2 ]
  network_name:
    full: ${NET_FULL}
    short: ${NET_SHORT}
  mme_name: ${MME_NAME}
EOF
)"

  write_yaml "${OPEN5GS_DIR}/sgwc.yaml" "$(cat <<'EOF'
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
)"

  write_yaml "${OPEN5GS_DIR}/sgwu.yaml" "$(cat <<EOF
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
)"

  write_yaml "${OPEN5GS_DIR}/hss.yaml" "$(cat <<'EOF'
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
)"

  write_yaml "${OPEN5GS_DIR}/pcrf.yaml" "$(cat <<'EOF'
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
)"

  ok "Open5GS configuration written"
}

# ----------------------------
# Block09 — Start services in strict order + health checks
# ----------------------------
block09_start() {
  step "Block09" "Start Open5GS (strict order) + health check"

  systemctl enable --now mongod >>"$LOG_FILE" 2>&1 || true
  spinner 2 "Ensuring MongoDB is running..."
  systemctl is-active --quiet mongod || { fail "mongod not running"; exit 1; }

  # Start core in recommended order
  info "Starting NRF + SCP"
  systemctl restart open5gs-nrfd open5gs-scpd >>"$LOG_FILE" 2>&1 || true
  sleep 2

  info "Starting AUSF/UDM/UDR/PCF/NSSF/BSF/HSS"
  systemctl restart open5gs-ausfd open5gs-udmd open5gs-udrd open5gs-pcfd open5gs-nssfd open5gs-bsfd open5gs-hssd >>"$LOG_FILE" 2>&1 || true
  sleep 2

  info "Starting AMF/SMF/UPF + EPC components"
  systemctl restart open5gs-amfd open5gs-smfd open5gs-upfd open5gs-mmed open5gs-sgwcd open5gs-sgwud open5gs-pcrfd >>"$LOG_FILE" 2>&1 || true
  sleep 2

  ok "Open5GS services started"
}

health_ports() {
  # expects various 7777 listeners
  ss -tuln | grep -q ":7777" || return 1
  return 0
}

health_services() {
  local bad
  bad="$(systemctl list-units --all --plain --no-pager | awk '/open5gs-.*service/{print $1,$4}' | grep -E 'failed|inactive' || true)"
  [[ -z "$bad" ]]
}

block10_health() {
  step "Block10" "Health check (ports + services)"

  spinner 2 "Checking SBI ports (7777)..."
  if health_ports; then
    ok "SBI ports listening"
  else
    fail "No SBI port 7777 listening"
    ss -tuln | grep 7777 || true
    exit 1
  fi

  spinner 2 "Checking Open5GS service status..."
  if health_services; then
    ok "Core services running"
  else
    fail "Some Open5GS services are not running"
    systemctl list-units --all --plain --no-pager | grep 'open5gs-' || true
    exit 1
  fi

  box "✅ KAOKAB5GC INSTALLATION COMPLETE" \
      "Core is up (EPC + 5GC) in single-node SCP architecture." \
      "Config: ${CFG_FILE}" \
      "Logs:   ${LOG_FILE}" \
      "" \
      "Next: WebUI + Subscriber Provisioning (we can add as Block11)."
}

# ----------------------------
# Main
# ----------------------------
main() {
  require_root
  banner

  block01

  # If config exists, allow re-use (no forced re-entry).
  if [[ -f "$CFG_FILE" ]]; then
    box "CONFIG FOUND" \
        "Existing config detected:" \
        "${CFG_FILE}" \
        "" \
        "Installer will reuse it (delete it to re-enter values)."
  else
    block02
  fi

  # Ensure config loaded for later steps
  # shellcheck disable=SC1091
  source "$CFG_FILE"

  block03_netplan
  block04_nat
  block05_loopbacks
  block06_mongodb
  block07_open5gs_install
  block08_open5gs_config
  block09_start
  block10_health
}

main "$@"
