#!/usr/bin/env bash
# ============================================================
# 555.sh — KAOKAB5GC Unified Installer (Ubuntu 22.04)
# Single-node Open5GS (EPC + 5GC) + SCP-based architecture
#
# Design goals (met):
# ✅ One file, one entry point
# ✅ Strict execution order
# ✅ Single-node Open5GS (EPC + 5GC)
# ✅ SCP-based architecture (as in your working VM)
# ✅ Safe logging, clear banners, explicit steps
# ✅ Re-runnable (idempotent where possible)
# ✅ Production-grade structure
# ============================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ----------------------------
# Globals
# ----------------------------
SCRIPT_NAME="$(basename "$0")"
LOG_DIR="/var/log/kaokab"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/kaokab5gc-install-$(date +%F_%H%M%S).log"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

KAOKAB_CFG_DIR="/etc/kaokab"
KAOKAB_CFG_FILE="${KAOKAB_CFG_DIR}/kaokab.env"

OPEN5GS_DIR="/etc/open5gs"
OPEN5GS_BACKUP_DIR="${OPEN5GS_DIR}/backup-$(date +%F_%H%M%S)"

# ----------------------------
# Colors
# ----------------------------
GREEN="\e[32m"; RED="\e[31m"; BLUE="\e[34m"; YELLOW="\e[33m"
BOLD="\e[1m"; RESET="\e[0m"

# ----------------------------
# Logging
# ----------------------------
log()   { echo -e "$*" | tee -a "$LOG_FILE" >/dev/null; }
info()  { log "${BOLD}${BLUE}[INFO]${RESET}  $*"; }
ok()    { log "${BOLD}${GREEN}[OK]${RESET}    $*"; }
warn()  { log "${BOLD}${YELLOW}[WARN]${RESET}  $*"; }
fail()  { log "${BOLD}${RED}[FAIL]${RESET}  $*"; }

on_error() {
  local ec=$?
  local line="${BASH_LINENO[0]:-unknown}"
  local cmd="${BASH_COMMAND:-unknown}"
  fail "Error on line ${line}: ${cmd}"
  fail "Log: ${LOG_FILE}"
  exit "$ec"
}
trap on_error ERR

# ----------------------------
# Helpers
# ----------------------------
need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Run as root: sudo ./${SCRIPT_NAME}"
    exit 1
  fi
}

check_os() {
  if [[ ! -r /etc/os-release ]]; then
    fail "Cannot detect OS (missing /etc/os-release)"
    exit 1
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "22.04" ]]; then
    fail "Unsupported OS. Required Ubuntu 22.04. Detected: ${PRETTY_NAME:-unknown}"
    exit 1
  fi
  ok "OS: Ubuntu 22.04"
}

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

apt_update_once() {
  if [[ -f /var/lib/apt/periodic/update-success-stamp ]]; then
    ok "APT update stamp present (skipping update)"
    return
  fi
  info "APT update"
  DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1
  ok "APT updated"
}

apt_install() {
  local pkgs=("$@")
  info "Installing packages: ${pkgs[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" >>"$LOG_FILE" 2>&1
  ok "Installed: ${pkgs[*]}"
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
  log "${BOLD}${BLUE}==================================================${RESET}"
  log "${BOLD}${GREEN} ✅ KAOKAB5GC UNIFIED INSTALLER (555.sh)${RESET}"
  log "${BOLD}${BLUE}==================================================${RESET}"
  log "${BOLD}${BLUE}Log file:${RESET} ${LOG_FILE}"
  echo
}

# ----------------------------
# Config collection (non-distructive)
# ----------------------------
is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r a b c d <<<"$ip"
  [[ "$a" -le 255 && "$b" -le 255 && "$c" -le 255 && "$d" -le 255 ]]
}

prompt_default() {
  local prompt="$1"; local def="$2"
  local ans=""
  read -r -p "${prompt} [${def}]: " ans || true
  if [[ -z "${ans}" ]]; then ans="$def"; fi
  echo "$ans"
}

save_cfg() {
  mkdir -p "$KAOKAB_CFG_DIR"
  chmod 700 "$KAOKAB_CFG_DIR"
  cat >"$KAOKAB_CFG_FILE" <<EOF
# Kaokab5G Installer Config
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

# External / RAN-facing addresses (single NIC but multiple IPs ok)
INTERFACE="${INTERFACE}"
S1AP_IP="${S1AP_IP}"     # N2/S1AP (Control)
GTPU_IP="${GTPU_IP}"     # N3 (User plane on SMF if needed, kept for compatibility)
UPF_IP="${UPF_IP}"       # UPF GTPU bind

CIDR="${CIDR}"
GATEWAY="${GATEWAY}"
DNS1="${DNS1}"
DNS2="${DNS2}"

# UE pools
APN_POOL_1="${APN_POOL_1}"   # e.g. 10.45.0.0/16
APN_GW_1="${APN_GW_1}"       # e.g. 10.45.0.1
DNN_1="${DNN_1}"             # e.g. internet

APN_POOL_2="${APN_POOL_2}"   # optional (can be empty)
APN_GW_2="${APN_GW_2}"       # optional
DNN_2="${DNN_2}"             # optional

# PLMN / Slice
MCC="${MCC}"                 # 3 digits e.g. 204
MNC="${MNC}"                 # 2 or 3 digits e.g. 61
TAC="${TAC}"                 # e.g. 1
SST="${SST}"                 # e.g. 1
SD="${SD}"                   # 6 hex digits without 0x, e.g. 010203

# Display / names
NETWORK_NAME_FULL="${NETWORK_NAME_FULL}"
NETWORK_NAME_SHORT="${NETWORK_NAME_SHORT}"
AMF_NAME="${AMF_NAME}"
MME_NAME="${MME_NAME}"

# Behavior toggles
MANAGE_NETPLAN="${MANAGE_NETPLAN}"   # "true" to generate/apply netplan (default false)
EOF
  chmod 600 "$KAOKAB_CFG_FILE"
  ok "Config saved: ${KAOKAB_CFG_FILE}"
}

load_or_collect_cfg() {
  if [[ -f "$KAOKAB_CFG_FILE" ]]; then
    # shellcheck disable=SC1091
    source "$KAOKAB_CFG_FILE"
    ok "Loaded config: ${KAOKAB_CFG_FILE}"
    return
  fi

  info "No ${KAOKAB_CFG_FILE} found. Collecting minimal parameters (safe; no net changes unless MANAGE_NETPLAN=true)."

  local def_iface def_gw
  def_iface="$(ip -br link | awk '$1!="lo"{print $1; exit}')"
  def_gw="$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')"

  INTERFACE="$(prompt_default "Interface name" "${def_iface:-ens160}")"

  while :; do
    S1AP_IP="$(prompt_default "S1AP/N2 IPv4 (Control) e.g. 192.168.178.80" "192.168.178.80")"
    is_ipv4 "$S1AP_IP" && break
    echo "Invalid IPv4. Try again."
  done

  while :; do
    GTPU_IP="$(prompt_default "GTPU/N3 IPv4 (optional) e.g. 192.168.178.81" "192.168.178.81")"
    is_ipv4 "$GTPU_IP" && break
    echo "Invalid IPv4. Try again."
  done

  while :; do
    UPF_IP="$(prompt_default "UPF GTPU bind IPv4 e.g. 192.168.178.82" "192.168.178.82")"
    is_ipv4 "$UPF_IP" && break
    echo "Invalid IPv4. Try again."
  done

  CIDR="$(prompt_default "CIDR mask" "24")"
  GATEWAY="$(prompt_default "Gateway" "${def_gw:-192.168.178.1}")"
  DNS1="$(prompt_default "DNS1" "1.1.1.1")"
  DNS2="$(prompt_default "DNS2" "1.0.0.1")"

  APN_POOL_1="$(prompt_default "UE pool #1 (CIDR) e.g. 10.45.0.0/16" "10.45.0.0/16")"
  APN_GW_1="$(prompt_default "UE gateway #1 e.g. 10.45.0.1" "10.45.0.1")"
  DNN_1="$(prompt_default "DNN #1 (APN) e.g. internet" "internet")"

  APN_POOL_2="$(prompt_default "UE pool #2 (CIDR) optional" "10.46.0.0/16")"
  APN_GW_2="$(prompt_default "UE gateway #2 optional" "10.46.0.1")"
  DNN_2="$(prompt_default "DNN #2 optional" "ims")"

  MCC="$(prompt_default "MCC (3 digits)" "204")"
  MNC="$(prompt_default "MNC (2-3 digits)" "61")"
  TAC="$(prompt_default "TAC" "1")"
  SST="$(prompt_default "SST" "1")"
  SD="$(prompt_default "SD (6 hex digits) e.g. 010203" "010203")"

  NETWORK_NAME_FULL="$(prompt_default "Network name (full)" "Kaokab")"
  NETWORK_NAME_SHORT="$(prompt_default "Network name (short)" "Kaokab")"
  AMF_NAME="$(prompt_default "AMF name" "kaokab-amf0")"
  MME_NAME="$(prompt_default "MME name" "kaokab-mme0")"

  MANAGE_NETPLAN="$(prompt_default "Manage Netplan now? (true/false)" "false")"

  save_cfg
}

# ----------------------------
# (Optional) Netplan management
# ----------------------------
apply_netplan_if_enabled() {
  if [[ "${MANAGE_NETPLAN,,}" != "true" ]]; then
    ok "Netplan management disabled (MANAGE_NETPLAN=false). Skipping."
    return
  fi

  info "Netplan management enabled: generating /etc/netplan/01-kaokab.yaml"
  apt_install netplan.io

  local netplan_dir="/etc/netplan"
  local backup_dir="/etc/netplan/backup-$(date +%F_%H%M%S)"
  mkdir -p "$backup_dir"
  cp -a "$netplan_dir"/*.yaml "$backup_dir"/ 2>/dev/null || true
  ok "Netplan backup: ${backup_dir}"

  cat >"${netplan_dir}/01-kaokab.yaml" <<EOF
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
  chmod 600 "${netplan_dir}/01-kaokab.yaml"

  info "Applying netplan"
  netplan generate >>"$LOG_FILE" 2>&1
  netplan apply >>"$LOG_FILE" 2>&1
  sleep 3

  # minimal validation
  ip -4 addr show "$INTERFACE" | grep -q "$S1AP_IP" || fail "Netplan: missing ${S1AP_IP} on ${INTERFACE}"
  ip route | grep -q "default via ${GATEWAY}" || fail "Netplan: default route missing via ${GATEWAY}"
  ok "Netplan applied & validated"
}

# ----------------------------
# IP forwarding + NAT (persisted)
# ----------------------------
ensure_forwarding_and_nat() {
  info "Block03: Enabling IP forwarding & NAT (persisted)"

  # sysctl persistent
  cat >/etc/sysctl.d/99-kaokab.conf <<EOF
net.ipv4.ip_forward=1
EOF
  sysctl --system >>"$LOG_FILE" 2>&1
  ok "IPv4 forwarding enabled + persisted"

  # NAT rules (idempotent)
  apt_install iptables iptables-persistent netfilter-persistent

  # UE pools NAT through ${INTERFACE} (exclude ogstun)
  # Use -C then -A to make idempotent
  iptables -t nat -C POSTROUTING -s "${APN_POOL_1}" -o "${INTERFACE}" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "${APN_POOL_1}" -o "${INTERFACE}" -j MASQUERADE

  if [[ -n "${APN_POOL_2}" ]]; then
    iptables -t nat -C POSTROUTING -s "${APN_POOL_2}" -o "${INTERFACE}" -j MASQUERADE 2>/dev/null \
      || iptables -t nat -A POSTROUTING -s "${APN_POOL_2}" -o "${INTERFACE}" -j MASQUERADE
  fi

  netfilter-persistent save >>"$LOG_FILE" 2>&1
  ok "IP forwarding & NAT enabled (and persisted)"
}

# ----------------------------
# Loopback aliases (SCP/NRF + NFs) — persistent via systemd
# ----------------------------
install_loopback_aliases() {
  info "Block04: Installing loopback aliases (persistent)"

  mkdir -p /usr/local/sbin

  cat >/usr/local/sbin/kaokab-loopback.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

add_ip() {
  local ip="$1"
  ip -4 addr show lo | grep -q " ${ip}/8" 2>/dev/null || ip addr add "${ip}/8" dev lo
}

# Standard Open5GS single-node loopback map
# EPC/Evolved + 5GC + SCP-based
for ip in \
  127.0.0.2  127.0.0.3  127.0.0.4  127.0.0.5  127.0.0.6  127.0.0.7  127.0.0.8  127.0.0.9 \
  127.0.0.10 127.0.0.11 127.0.0.12 127.0.0.13 127.0.0.14 127.0.0.15 127.0.0.20 127.0.0.200
do
  add_ip "$ip"
done
EOF
  chmod 755 /usr/local/sbin/kaokab-loopback.sh

  cat >/etc/systemd/system/kaokab-loopback.service <<'EOF'
[Unit]
Description=KAOKAB Loopback IP Aliases for Open5GS (single node)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/kaokab-loopback.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >>"$LOG_FILE" 2>&1
  systemctl enable --now kaokab-loopback.service >>"$LOG_FILE" 2>&1
  ok "Loopback aliases installed (kaokab-loopback.service)"

  # validation
  ip -4 addr show lo | grep -q "127.0.0.200/8" || fail "Loopback validation failed (missing 127.0.0.200)"
  ok "Loopback alias validation OK"
}

# ----------------------------
# MongoDB install (official repo) — service: mongod
# ----------------------------
install_mongodb() {
  info "Block05: Installing MongoDB (mongod)"

  apt_update_once
  apt_install ca-certificates curl gnupg lsb-release

  mkdir -p /etc/apt/keyrings
  chmod 755 /etc/apt/keyrings

  # MongoDB 6.0 (jammy)
  local keyring="/etc/apt/keyrings/mongodb-server-6.0.gpg"
  curl -fsSL https://pgp.mongodb.com/server-6.0.asc | gpg --dearmor -o "$keyring" >>"$LOG_FILE" 2>&1
  chmod 644 "$keyring"

  local listfile="/etc/apt/sources.list.d/mongodb-org-6.0.list"
  if [[ ! -f "$listfile" ]]; then
    echo "deb [ arch=amd64,arm64 signed-by=${keyring} ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" \
      > "$listfile"
  fi

  DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y mongodb-org >>"$LOG_FILE" 2>&1

  systemctl enable --now mongod >>"$LOG_FILE" 2>&1
  systemctl is-active --quiet mongod && ok "MongoDB installed & running (mongod)" || fail "MongoDB failed to start"
}

# ----------------------------
# Open5GS install (PPA)
# ----------------------------
install_open5gs() {
  info "Block06: Installing Open5GS (EPC + 5GC)"

  apt_update_once
  apt_install software-properties-common ca-certificates curl

  # Add Open5GS PPA idempotently
  if ! grep -R "ppa.launchpadcontent.net/open5gs/latest" -n /etc/apt/sources.list /etc/apt/sources.list.d/* >/dev/null 2>&1; then
    add-apt-repository -y ppa:open5gs/latest >>"$LOG_FILE" 2>&1
    ok "Added Open5GS PPA: ppa:open5gs/latest"
  else
    ok "Open5GS PPA already present"
  fi

  DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y open5gs >>"$LOG_FILE" 2>&1

  ok "Open5GS installed"
}

# ----------------------------
# Write Open5GS configs (SCP-based, like your working VM)
# ----------------------------
backup_open5gs_configs() {
  mkdir -p "$OPEN5GS_DIR"
  if compgen -G "${OPEN5GS_DIR}/*.yaml" >/dev/null 2>&1; then
    mkdir -p "$OPEN5GS_BACKUP_DIR"
    cp -a "${OPEN5GS_DIR}"/*.yaml "$OPEN5GS_BACKUP_DIR"/ 2>/dev/null || true
    ok "Backup created: ${OPEN5GS_BACKUP_DIR}"
  else
    ok "No existing Open5GS YAMLs found (no backup needed)"
  fi
}

write_open5gs_yaml() {
  local file="$1"
  local content="$2"
  install -d -m 0750 -o open5gs -g open5gs "$OPEN5GS_DIR"
  printf "%s\n" "$content" > "${OPEN5GS_DIR}/${file}"
  chown open5gs:open5gs "${OPEN5GS_DIR}/${file}"
  chmod 0640 "${OPEN5GS_DIR}/${file}"
}

configure_open5gs_single_node_scp() {
  info "Block07: Configuring Open5GS (Single Node, SCP-based)"
  backup_open5gs_configs

  # Normalize MNC to no-leading-zero style for 5GC configs (Open5GS examples commonly use "61" not "061")
  # Keep exactly what user enters for MME gummei if they want; but for simplicity use same MNC in all.
  local MNC_NORM="${MNC#0}"

  # Common DNS list for SMF (required in 2.7.6+; your working VM includes it)
  local SMF_DNS_1="${DNS2}"
  local SMF_DNS_2="${DNS1}"

  # AMF
  write_open5gs_yaml "amf.yaml" "$(cat <<EOF
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
        mnc: ${MNC_NORM}
      amf_id:
        region: 1
        set: 1
  tai:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${MNC_NORM}
      tac: ${TAC}
  plmn_support:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${MNC_NORM}
      s_nssai:
          sst: ${SST}
          sd: ${SD}
  security:
    integrity_order : [ NIA2, NIA1, NIA0 ]
    ciphering_order : [ NEA0, NEA1, NEA2 ]
  network_name:
    full: ${NETWORK_NAME_FULL}
    short: ${NETWORK_NAME_SHORT}
  amf_name: ${AMF_NAME}
  time:
    t3512:
      value: 540
EOF
)"

  # NRF
  write_open5gs_yaml "nrf.yaml" "$(cat <<EOF
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
        mnc: ${MNC_NORM}
  sbi:
    server:
      - address: 127.0.0.10
        port: 7777
EOF
)"

  # SCP
  write_open5gs_yaml "scp.yaml" "$(cat <<'EOF'
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
    client:
      nrf:
        - uri: http://127.0.0.10:7777
EOF
)"

  # AUSF
  write_open5gs_yaml "ausf.yaml" "$(cat <<EOF
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

  # UDM
  write_open5gs_yaml "udm.yaml" "$(cat <<EOF
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

  # UDR
  write_open5gs_yaml "udr.yaml" "$(cat <<EOF
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

  # PCF
  write_open5gs_yaml "pcf.yaml" "$(cat <<EOF
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

  # NSSF
  write_open5gs_yaml "nssf.yaml" "$(cat <<EOF
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
    - name: "default"
      s_nssai:
        - sst: ${SST}
          sd: ${SD}
EOF
)"

  # BSF
  write_open5gs_yaml "bsf.yaml" "$(cat <<EOF
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
)"

  # SMF (SCP-based + sessions + DNS required)
  # Includes 2 sessions if APN_POOL_2 is set; otherwise only #1.
  local sessions="  session:
    - subnet: ${APN_POOL_1}
      gateway: ${APN_GW_1}
      dnn: ${DNN_1}"
  if [[ -n "${APN_POOL_2}" && -n "${APN_GW_2}" && -n "${DNN_2}" ]]; then
    sessions="${sessions}
    - subnet: ${APN_POOL_2}
      gateway: ${APN_GW_2}
      dnn: ${DNN_2}"
  fi

  write_open5gs_yaml "smf.yaml" "$(cat <<EOF
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
${sessions}

  dns:
    - ${SMF_DNS_1}
    - ${SMF_DNS_2}

  mtu: 1500
  freeDiameter: /etc/freeDiameter/smf.conf
EOF
)"

  # UPF
  write_open5gs_yaml "upf.yaml" "$(cat <<EOF
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
    - name: ogstun
      subnet: ${APN_POOL_1}
EOF
)"

  # EPC side configs (MME/SGWC/SGWU/PCRF/HSS) — keep minimal but working
  write_open5gs_yaml "mme.yaml" "$(cat <<EOF
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
        mnc: ${MNC_NORM}
      mme_gid: 2
      mme_code: 1
  tai:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${MNC_NORM}
      tac: ${TAC}
  security:
    integrity_order : [ EIA2, EIA1, EIA0 ]
    ciphering_order : [ EEA0, EEA1, EEA2 ]
  network_name:
    full: ${NETWORK_NAME_FULL}
    short: ${NETWORK_NAME_SHORT}
  mme_name: ${MME_NAME}
EOF
)"

  write_open5gs_yaml "sgwc.yaml" "$(cat <<'EOF'
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

  write_open5gs_yaml "sgwu.yaml" "$(cat <<EOF
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

  write_open5gs_yaml "pcrf.yaml" "$(cat <<'EOF'
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

  # Minimal HSS (many deployments need more; this is a safe baseline)
  write_open5gs_yaml "hss.yaml" "$(cat <<'EOF'
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

  # SEPP placeholders (safe minimal)
  write_open5gs_yaml "sepp1.yaml" "$(cat <<'EOF'
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
      - address: 127.0.0.8
        port: 7777
EOF
)"
  write_open5gs_yaml "sepp2.yaml" "$(cat <<'EOF'
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
      - address: 127.0.0.9
        port: 7777
EOF
)"

  ok "Open5GS configuration written"
}

# ----------------------------
# Start Open5GS (correct order)
# ----------------------------
start_open5gs_services() {
  info "Block08: Starting Open5GS (MongoDB → NRF/SCP → others)"

  systemctl enable --now mongod >>"$LOG_FILE" 2>&1 || true
  systemctl restart mongod >>"$LOG_FILE" 2>&1

  # Core discovery/mesh first
  systemctl enable open5gs-nrfd open5gs-scpd >>"$LOG_FILE" 2>&1 || true
  systemctl restart open5gs-nrfd open5gs-scpd >>"$LOG_FILE" 2>&1
  sleep 2

  # Next: database-backed control functions
  systemctl enable open5gs-ausfd open5gs-udmd open5gs-udrd open5gs-pcfd open5gs-nssfd open5gs-bsfd >>"$LOG_FILE" 2>&1 || true
  systemctl restart open5gs-ausfd open5gs-udmd open5gs-udrd open5gs-pcfd open5gs-nssfd open5gs-bsfd >>"$LOG_FILE" 2>&1
  sleep 2

  # Finally: AMF/SMF/UPF + EPC daemons
  systemctl enable open5gs-amfd open5gs-smfd open5gs-upfd open5gs-mmed open5gs-sgwcd open5gs-sgwud open5gs-pcrfd open5gs-hssd >>"$LOG_FILE" 2>&1 || true
  systemctl restart open5gs-amfd open5gs-smfd open5gs-upfd open5gs-mmed open5gs-sgwcd open5gs-sgwud open5gs-pcrfd open5gs-hssd >>"$LOG_FILE" 2>&1
  sleep 2

  ok "Open5GS services start sequence issued"
}

# ----------------------------
# Health checks
# ----------------------------
health_check() {
  info "Block09: Health check"

  # Services
  local services=(
    mongod
    open5gs-nrfd open5gs-scpd
    open5gs-ausfd open5gs-udmd open5gs-udrd open5gs-pcfd open5gs-nssfd open5gs-bsfd
    open5gs-amfd open5gs-smfd open5gs-upfd
  )

  local bad=0
  for s in "${services[@]}"; do
    if systemctl is-active --quiet "$s"; then
      :
    else
      warn "Service not active: $s"
      bad=1
    fi
  done

  # SBI endpoints (must match SCP-based architecture)
  ss -tuln | grep -q "127.0.0.200:7777" || { fail "SCP not listening on 127.0.0.200:7777"; bad=1; }
  ss -tuln | grep -q "127.0.0.10:7777"  || { fail "NRF not listening on 127.0.0.10:7777";  bad=1; }
  ss -tuln | grep -q "127.0.0.5:7777"   || { fail "AMF not listening on 127.0.0.5:7777";   bad=1; }
  ss -tuln | grep -q "127.0.0.4:7777"   || { fail "SMF not listening on 127.0.0.4:7777";   bad=1; }

  if [[ "$bad" -ne 0 ]]; then
    fail "Health check failed. See log: ${LOG_FILE}"
    info "Useful commands:"
    log "  journalctl -u open5gs-amfd -n 80 --no-pager"
    log "  journalctl -u open5gs-smfd -n 80 --no-pager"
    log "  journalctl -u open5gs-nrfd -n 80 --no-pager"
    log "  journalctl -u open5gs-scpd -n 80 --no-pager"
    exit 1
  fi

  ok "SBI ports listening"
  ok "Core services running"
}

# ----------------------------
# System check summary
# ----------------------------
system_check_summary() {
  log "=================================================="
  log " ✅ SYSTEM CHECK PASSED"
  log " - OS            : Ubuntu 22.04"
  log " - Privileges    : root"
  log " - Installer log : ${LOG_FILE}"
  log "=================================================="
}

# ----------------------------
# Main (strict order)
# ----------------------------
main() {
  need_root
  check_os
  banner

  # Base tools (stable CLI only; no apt warnings)
  info "Block01: Base prerequisites"
  apt_update_once
  apt_install ca-certificates curl gnupg lsb-release software-properties-common iproute2 iputils-ping net-tools jq
  ok "Base prerequisites ready"

  load_or_collect_cfg
  system_check_summary

  # Optional netplan (off by default)
  apply_netplan_if_enabled

  ensure_forwarding_and_nat
  install_loopback_aliases
  install_mongodb
  install_open5gs
  configure_open5gs_single_node_scp
  start_open5gs_services
  health_check

  echo
  log "================================================="
  log " ✅ KAOKAB5GC INSTALLATION COMPLETE"
  log "================================================="
  log " Next: WebUI + subscriber provisioning can be added as a separate final block."
  log " Log file: ${LOG_FILE}"
  echo
}

main "$@"
