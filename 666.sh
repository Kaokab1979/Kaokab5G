#!/usr/bin/env bash
# ============================================================
#  KAOKAB5GC UNIFIED INSTALLER (SINGLE NODE: EPC + 5GC, SCP)
#  File: 666.sh
#  OS: Ubuntu 22.04 (Jammy)
#  Mode: Zero-interaction / non-interactive
# ============================================================

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# -------------------------
# UX helpers (colors/boxes)
# -------------------------
if command -v tput >/dev/null 2>&1; then
  C_RESET="$(tput sgr0)"
  C_BOLD="$(tput bold)"
  C_RED="$(tput setaf 1)"
  C_GRN="$(tput setaf 2)"
  C_YLW="$(tput setaf 3)"
  C_BLU="$(tput setaf 4)"
  C_CYN="$(tput setaf 6)"
else
  C_RESET="" C_BOLD="" C_RED="" C_GRN="" C_YLW="" C_BLU="" C_CYN=""
fi

banner() {
  echo
  echo "${C_CYN}${C_BOLD}          _  __    _    ___  _  __    _    ____ ____   ____  ____"
  echo "         | |/ /   / \\  / _ \\| |/ /   / \\  | __ ) ___| / ___|/ ___|"
  echo "         | ' /   / _ \\| | | | ' /   / _ \\ |  _ \\___ \\| |  _| |"
  echo "         | . \\  / ___ \\ |_| | . \\  / ___ \\| |_) |__) | |_| | |___"
  echo "         |_|\\_\\/_/   \\_\\___/|_|\\_\\/_/   \\_\\____/____/ \\____|\\____|"
  echo
  echo "              ___ _   _ ____ _____  _    _     _     _____ ____"
  echo "             |_ _| \\ | / ___|_   _|/ \\  | |   | |   | ____|  _ \\"
  echo "              | ||  \\| \\___ \\ | | / _ \\ | |   | |   |  _| | |_) |"
  echo "              | || |\\  |___) || |/ ___ \\| |___| |___| |___|  _ <"
  echo "             |___|_| \\_|____/ |_/_/   \\_\\_____|_____|_____|_| \\_\\"
  echo "${C_RESET}"
}

box() {
  local title="$1"
  local msg="$2"
  echo
  echo "${C_BLU}${C_BOLD}╔══════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
  printf "${C_BLU}${C_BOLD}║ %-76s ║${C_RESET}\n" "${title}"
  echo "${C_BLU}${C_BOLD}╠══════════════════════════════════════════════════════════════════════════════╣${C_RESET}"
  while IFS= read -r line; do
    printf "${C_BLU}${C_BOLD}║${C_RESET} %-76s ${C_BLU}${C_BOLD}║${C_RESET}\n" "${line:0:76}"
  done <<< "$msg"
  echo "${C_BLU}${C_BOLD}╚══════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
}

ok()   { echo "${C_GRN}${C_BOLD}[OK]${C_RESET} $*"; }
info() { echo "${C_CYN}${C_BOLD}[INFO]${C_RESET} $*"; }
warn() { echo "${C_YLW}${C_BOLD}[WARN]${C_RESET} $*"; }
die()  { echo "${C_RED}${C_BOLD}[FAIL]${C_RESET} $*" >&2; exit 1; }

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo ./666.sh"
}

is_jammy() {
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" && "${VERSION_CODENAME:-}" == "jammy" ]]
}

# -------------------------
# Logging
# -------------------------
TS="$(date +%F_%H%M%S)"
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/kaokab5gc-install-${TS}.log"
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

# -------------------------
# Config (.env)
# -------------------------
ENV_DIR="/etc/kaokab"
ENV_FILE="${ENV_DIR}/kaokab.env"

autodetect_iface() {
  # default route interface
  ip route show default 0.0.0.0/0 2>/dev/null | awk '{print $5}' | head -n1
}
autodetect_ip() {
  local iface="$1"
  ip -4 -o addr show dev "$iface" | awk '{print $4}' | cut -d/ -f1 | head -n1
}
autodetect_gw() {
  ip route show default 0.0.0.0/0 2>/dev/null | awk '{print $3}' | head -n1
}

write_default_env() {
  mkdir -p "$ENV_DIR"
  local iface ip gw
  iface="$(autodetect_iface)"
  [[ -n "$iface" ]] || iface="ens160"
  ip="$(autodetect_ip "$iface" || true)"
  [[ -n "$ip" ]] || ip="192.168.178.80"
  gw="$(autodetect_gw || true)"
  [[ -n "$gw" ]] || gw="192.168.178.1"

  cat > "$ENV_FILE" <<EOF
# KAOKAB5GC deployment parameters (single node)
# Edit this file and re-run ./666.sh to apply.

# OS / behavior
MANAGE_NETPLAN=false

# Interface + addressing
IFACE=${iface}
CIDR=24
GW=${gw}
DNS1=1.1.1.1
DNS2=1.0.0.1

# Control-plane (S1AP/N2) IP
S1AP_N2_IP=${ip}

# (Optional) GTPU/N3 IP for gNB/eNB plane (can equal S1AP_N2_IP)
GTPU_N3_IP=192.168.178.81

# UPF GTPU bind IP (often same host)
UPF_GTPU_IP=192.168.178.82

# UE pools + DNN/APN
UE_POOL1=10.45.0.0/16
UE_GW1=10.45.0.1
DNN1=internet

UE_POOL2=10.46.0.0/16
UE_GW2=10.46.0.1
DNN2=ims

# PLMN / slice
MCC=204
MNC=61
TAC=1
SST=1
SD=010203

# Names
NW_FULL=Kaokab
NW_SHORT=Kaokab
AMF_NAME=kaokab-amf0
MME_NAME=kaokab-mme0
EOF
  chmod 600 "$ENV_FILE"
}

load_env() {
  mkdir -p "$ENV_DIR"
  if [[ ! -f "$ENV_FILE" ]]; then
    warn "Config not found: $ENV_FILE → generating defaults (zero-interaction)"
    write_default_env
  fi
  # shellcheck disable=SC1090
  source "$ENV_FILE"

  # Basic validation (non-empty)
  : "${IFACE:?}" "${CIDR:?}" "${GW:?}" "${DNS1:?}" "${DNS2:?}"
  : "${S1AP_N2_IP:?}" "${GTPU_N3_IP:?}" "${UPF_GTPU_IP:?}"
  : "${UE_POOL1:?}" "${UE_GW1:?}" "${DNN1:?}"
  : "${MCC:?}" "${MNC:?}" "${TAC:?}" "${SST:?}" "${SD:?}"
  : "${NW_FULL:?}" "${NW_SHORT:?}" "${AMF_NAME:?}" "${MME_NAME:?}"

  # Optional pool2
  : "${UE_POOL2:=}" "${UE_GW2:=}" "${DNN2:=}"

  # Boolean normalize
  MANAGE_NETPLAN="${MANAGE_NETPLAN,,}"
  [[ "$MANAGE_NETPLAN" == "true" || "$MANAGE_NETPLAN" == "false" ]] || MANAGE_NETPLAN="false"
}

# -------------------------
# System helpers
# -------------------------
apt_quiet_install() {
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

service_enable_start() {
  local s="$1"
  systemctl enable --now "$s" >/dev/null 2>&1 || {
    systemctl daemon-reload || true
    systemctl enable --now "$s"
  }
}

# -------------------------
# Block actions
# -------------------------
block01_prereqs() {
  box "▶▶ Block01" "System checks + base tooling + clean logging\nLog: ${LOG_FILE}"
  need_root
  is_jammy || die "This installer targets Ubuntu 22.04 (Jammy) only."
  ok "Running on Ubuntu Jammy"

  info "Installing base packages (curl, gpg, repo tools, netfilter persistence)"
  apt_quiet_install ca-certificates curl gnupg lsb-release software-properties-common \
                    iptables iproute2 net-tools jq \
                    netfilter-persistent iptables-persistent
  ok "Base tooling installed"
}

block02_load_config() {
  box "▶▶ Block02" "Load or auto-generate deployment parameters (non-interactive)\nConfig: ${ENV_FILE}"
  load_env

  # Print summary
  local pools="${UE_POOL1}(${DNN1})"
  if [[ -n "${UE_POOL2}" && -n "${DNN2}" ]]; then
    pools="${pools} , ${UE_POOL2}(${DNN2})"
  fi

  echo
  echo "${C_BOLD}╔══════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
  echo "${C_BOLD}║ CONFIG SUMMARY                                                               ║${C_RESET}"
  echo "${C_BOLD}╠══════════════════════════════════════════════════════════════════════════════╣${C_RESET}"
  printf "${C_BOLD}║${C_RESET} Interface: %-66s ${C_BOLD}║${C_RESET}\n" "${IFACE}"
  printf "${C_BOLD}║${C_RESET} S1AP/N2:   %-66s ${C_BOLD}║${C_RESET}\n" "${S1AP_N2_IP}/${CIDR}"
  printf "${C_BOLD}║${C_RESET} GTPU/N3:   %-66s ${C_BOLD}║${C_RESET}\n" "${GTPU_N3_IP}/${CIDR}"
  printf "${C_BOLD}║${C_RESET} UPF GTPU:  %-66s ${C_BOLD}║${C_RESET}\n" "${UPF_GTPU_IP}/${CIDR}"
  printf "${C_BOLD}║${C_RESET} GW/DNS:    %-66s ${C_BOLD}║${C_RESET}\n" "${GW} | ${DNS1}, ${DNS2}"
  printf "${C_BOLD}║${C_RESET} UE pools:  %-66s ${C_BOLD}║${C_RESET}\n" "${pools}"
  printf "${C_BOLD}║${C_RESET} PLMN:      %-66s ${C_BOLD}║${C_RESET}\n" "${MCC}/${MNC}  TAC:${TAC}  Slice:${SST}/${SD}"
  printf "${C_BOLD}║${C_RESET} Names:     %-66s ${C_BOLD}║${C_RESET}\n" "${NW_FULL}/${NW_SHORT} AMF:${AMF_NAME} MME:${MME_NAME}"
  echo "${C_BOLD}╚══════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
  ok "Parameters loaded"
}

block03_netplan_optional() {
  box "▶▶ Block03" "Netplan management (optional)\nControlled by MANAGE_NETPLAN=${MANAGE_NETPLAN}"
  if [[ "$MANAGE_NETPLAN" != "true" ]]; then
    ok "Skipping netplan changes (MANAGE_NETPLAN=false)"
    return
  fi

  info "Backing up current netplan and applying static config"
  local np_dir="/etc/netplan"
  local backup="${np_dir}/backup-${TS}"
  mkdir -p "$backup"
  cp -a "${np_dir}/"*.yaml "$backup/" 2>/dev/null || true
  ok "Netplan backup: $backup"

  cat > "${np_dir}/99-kaokab.yaml" <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${IFACE}:
      dhcp4: no
      addresses: [${S1AP_N2_IP}/${CIDR}]
      routes:
        - to: default
          via: ${GW}
      nameservers:
        addresses: [${DNS1}, ${DNS2}]
EOF

  netplan generate
  netplan apply
  ok "Netplan applied"
}

block04_ip_forward_nat() {
  box "▶▶ Block04" "Enable IP forwarding & NAT for UE subnets\nPersistent via /etc/sysctl.d and netfilter-persistent"
  info "Enabling IPv4 forwarding"
  cat > /etc/sysctl.d/99-kaokab5gc.conf <<EOF
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null
  ok "IP forwarding enabled"

  info "Ensuring NAT masquerade for UE pools via ${IFACE}"
  iptables -t nat -C POSTROUTING -s "${UE_POOL1}" -o "${IFACE}" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "${UE_POOL1}" -o "${IFACE}" -j MASQUERADE

  if [[ -n "${UE_POOL2}" ]]; then
    iptables -t nat -C POSTROUTING -s "${UE_POOL2}" -o "${IFACE}" -j MASQUERADE 2>/dev/null \
      || iptables -t nat -A POSTROUTING -s "${UE_POOL2}" -o "${IFACE}" -j MASQUERADE
  fi

  netfilter-persistent save >/dev/null
  ok "NAT rules set & persisted"
}

block05_loopback_aliases() {
  box "▶▶ Block05" "Install persistent loopback aliases (single-node NFs)\nProvides 127.0.0.2..15, 127.0.0.20, 127.0.0.200"
  info "Writing systemd service: kaokab-loopback.service"
  cat > /etc/systemd/system/kaokab-loopback.service <<'EOF'
[Unit]
Description=Kaokab Open5GS Loopback Aliases
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '\
  for ip in {2..15} 20 200; do \
    /sbin/ip addr add 127.0.0.${ip}/8 dev lo 2>/dev/null || true; \
  done; \
  /sbin/ip link set lo up; \
  exit 0'

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  service_enable_start kaokab-loopback.service

  # quick verify
  local missing=0
  for ip in 2 3 4 5 6 7 8 9 10 11 12 13 14 15 20 200; do
    ip -4 addr show lo | grep -q "127\.0\.0\.${ip}/8" || missing=1
  done
  [[ "$missing" -eq 0 ]] || die "Loopback aliases missing after service start"
  ok "Loopback aliases installed"
}

block06_mongodb() {
  box "▶▶ Block06" "Install MongoDB via official repo/keyring (non-interactive)\nService: mongod"
  info "Adding MongoDB repo (Jammy) using keyring method"
  mkdir -p /etc/apt/keyrings

  # As per Open5GS quickstart, MongoDB repo/keyring method (their doc shows 8.0 at time of writing). :contentReference[oaicite:1]{index=1}
  curl -fsSL https://pgp.mongodb.com/server-8.0.asc | gpg --dearmor -o /etc/apt/keyrings/mongodb-server-8.0.gpg

  cat > /etc/apt/sources.list.d/mongodb-org-8.0.list <<EOF
deb [ arch=amd64 signed-by=/etc/apt/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/8.0 multiverse
EOF

  apt-get update -y
  apt-get install -y mongodb-org
  service_enable_start mongod.service

  systemctl is-active --quiet mongod || die "MongoDB (mongod) is not running"
  ok "MongoDB installed & running"
}

block07_open5gs_install() {
  box "▶▶ Block07" "Install Open5GS (EPC + 5GC) via official Ubuntu method\nRepo: ppa:open5gs/latest"
  info "Adding Open5GS PPA (ppa:open5gs/latest) and installing"
  add-apt-repository -y ppa:open5gs/latest
  apt-get update -y
  apt-get install -y open5gs
  ok "Open5GS installed"
}

block08_write_configs() {
  box "▶▶ Block08" "Write Open5GS YAML configs (single node, SCP-based)\nBackup existing /etc/open5gs to timestamped folder"
  mkdir -p /etc/open5gs /var/log/open5gs

  if [[ -d /etc/open5gs && -n "$(ls -A /etc/open5gs 2>/dev/null || true)" ]]; then
    local backup="/etc/open5gs/backup-${TS}"
    mkdir -p "$backup"
    cp -a /etc/open5gs/* "$backup/" 2>/dev/null || true
    ok "Backup created: $backup"
  fi

  # ---- NRF ----
  cat > /etc/open5gs/nrf.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/nrf.log

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

  # ---- SCP ----
  cat > /etc/open5gs/scp.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/scp.log

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

  # ---- AUSF ----
  cat > /etc/open5gs/ausf.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/ausf.log

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

  # ---- UDM ----
  cat > /etc/open5gs/udm.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/udm.log

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

  # ---- UDR ----
  cat > /etc/open5gs/udr.yaml <<EOF
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/udr.log

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

  # ---- PCF ----
  cat > /etc/open5gs/pcf.yaml <<EOF
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/pcf.log

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

  # ---- NSSF ----
  cat > /etc/open5gs/nssf.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/nssf.log

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
EOF

  # ---- BSF ----
  cat > /etc/open5gs/bsf.yaml <<EOF
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/bsf.log

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

  # ---- AMF (working-VM style incl. network_name) ----
  cat > /etc/open5gs/amf.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/amf.log

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
      - address: ${S1AP_N2_IP}
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
    integrity_order: [ NIA2, NIA1, NIA0 ]
    ciphering_order: [ NEA0, NEA1, NEA2 ]
  network_name:
    full: ${NW_FULL}
    short: ${NW_SHORT}
  amf_name: ${AMF_NAME}
  time:
    t3512:
      value: 540
EOF

  # ---- MME (working-VM style incl. network_name) ----
  cat > /etc/open5gs/mme.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/mme.log
  level: debug

global:
  max:
    ue: 1024

mme:
  freeDiameter: /etc/freeDiameter/mme.conf
  s1ap:
    server:
      - address: ${S1AP_N2_IP}
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
    integrity_order: [ EIA2, EIA1, EIA0 ]
    ciphering_order: [ EEA0, EEA1, EEA2 ]
  network_name:
    full: ${NW_FULL}
    short: ${NW_SHORT}
  mme_name: ${MME_NAME}
EOF

  # ---- SGW-C ----
  cat > /etc/open5gs/sgwc.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/sgwc.log

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

  # ---- SGW-U ----
  cat > /etc/open5gs/sgwu.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/sgwu.log

global:
  max:
    ue: 1024

sgwu:
  pfcp:
    server:
      - address: 127.0.0.6
  gtpu:
    server:
      - address: ${GTPU_N3_IP}
EOF

  # ---- SMF (working-VM style, includes DNS list) ----
  cat > /etc/open5gs/smf.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/smf.log

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
EOF

  if [[ -n "${UE_POOL2}" && -n "${UE_GW2}" && -n "${DNN2}" ]]; then
    cat >> /etc/open5gs/smf.yaml <<EOF
    - subnet: ${UE_POOL2}
      gateway: ${UE_GW2}
      dnn: ${DNN2}
EOF
  fi

  cat >> /etc/open5gs/smf.yaml <<EOF

  dns:
    - ${DNS2}
    - ${DNS1}

  mtu: 1500
  freeDiameter: /etc/freeDiameter/smf.conf
EOF

  # ---- UPF ----
  cat > /etc/open5gs/upf.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/upf.log

global:
  max:
    ue: 1024

upf:
  pfcp:
    server:
      - address: 127.0.0.7
  gtpu:
    server:
      - address: ${UPF_GTPU_IP}
  session:
    - subnet: ${UE_POOL1}
EOF
  if [[ -n "${UE_POOL2}" ]]; then
    cat >> /etc/open5gs/upf.yaml <<EOF
    - subnet: ${UE_POOL2}
EOF
  fi

  # ---- HSS / PCRF (EPC) ----
  cat > /etc/open5gs/hss.yaml <<EOF
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/hss.log

global:
  max:
    ue: 1024

hss:
  freeDiameter: /etc/freeDiameter/hss.conf
EOF

  cat > /etc/open5gs/pcrf.yaml <<EOF
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/pcrf.log

global:
  max:
    ue: 1024

pcrf:
  freeDiameter: /etc/freeDiameter/pcrf.conf
EOF

  # SEPP optional placeholders (kept minimal)
  cat > /etc/open5gs/sepp1.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/sepp1.log
global:
  max:
    ue: 1024
sepp:
  sbi:
    server:
      - address: 127.0.0.250
        port: 7777
EOF

  cat > /etc/open5gs/sepp2.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/sepp2.log
global:
  max:
    ue: 1024
sepp:
  sbi:
    server:
      - address: 127.0.0.251
        port: 7777
EOF

  chown -R open5gs:open5gs /etc/open5gs
  chmod 640 /etc/open5gs/*.yaml
  ok "Open5GS configuration written"
}

block09_start_services() {
  box "▶▶ Block09" "Start Open5GS services in strict order (MongoDB → NRF/SCP → 5GC → EPC)"
  info "Ensuring mongod is running"
  service_enable_start mongod.service

  # Core order
  info "Starting NRF + SCP"
  systemctl enable --now open5gs-nrfd open5gs-scpd >/dev/null 2>&1 || true
  systemctl restart open5gs-nrfd open5gs-scpd

  info "Starting 5GC control plane"
  systemctl enable --now open5gs-ausfd open5gs-udmd open5gs-udrd open5gs-pcfd open5gs-nssfd open5gs-bsfd >/dev/null 2>&1 || true
  systemctl restart open5gs-ausfd open5gs-udmd open5gs-udrd open5gs-pcfd open5gs-nssfd open5gs-bsfd

  info "Starting AMF/SMF/UPF and EPC services"
  systemctl enable --now open5gs-amfd open5gs-smfd open5gs-upfd open5gs-mmed open5gs-sgwcd open5gs-sgwud open5gs-pcrfd >/dev/null 2>&1 || true
  systemctl restart open5gs-amfd open5gs-smfd open5gs-upfd open5gs-mmed open5gs-sgwcd open5gs-sgwud open5gs-pcrfd

  # Give time for sockets
  sleep 2
  ok "Open5GS start sequence completed"
}

# -------------------------
# Verification vs working-VM style + readiness
# -------------------------
expect_in_file() {
  local file="$1" pattern="$2" label="$3"
  if grep -qE "$pattern" "$file"; then
    ok "Verify: ${label}"
  else
    warn "Verify failed: ${label}"
    warn "  File: $file"
    warn "  Need: $pattern"
    return 1
  fi
}

block10_verify_configs() {
  box "▶▶ Block10" "Auto-verification (working-VM style checks)\nEnsures SCP-based SBI + network_name present"
  local fail=0

  expect_in_file /etc/open5gs/amf.yaml "network_name:" "AMF has network_name" || fail=1
  expect_in_file /etc/open5gs/amf.yaml "scp:\s*- uri: http://127\.0\.0\.200:7777" "AMF uses SCP URI" || fail=1
  expect_in_file /etc/open5gs/amf.yaml "address: ${S1AP_N2_IP}" "AMF NGAP binds to S1AP/N2 IP" || fail=1

  expect_in_file /etc/open5gs/smf.yaml "scp:\s*- uri: http://127\.0\.0\.200:7777" "SMF uses SCP URI" || fail=1
  expect_in_file /etc/open5gs/smf.yaml "dns:\s*- ${DNS2}\s*- ${DNS1}" "SMF DNS list present" || fail=1

  expect_in_file /etc/open5gs/mme.yaml "network_name:" "MME has network_name" || fail=1
  expect_in_file /etc/open5gs/nrf.yaml "address: 127\.0\.0\.10" "NRF binds 127.0.0.10" || fail=1
  expect_in_file /etc/open5gs/scp.yaml "address: 127\.0\.0\.200" "SCP binds 127.0.0.200" || fail=1

  [[ "$fail" -eq 0 ]] || warn "Some config checks failed (review warnings above)."
  ok "Config verification phase done"
}

block11_core_readiness() {
  box "▶▶ Block11" "Core readiness validation\nServices + ports + sysctl + NAT + ogstun"

  # Services
  local svcs=(mongod open5gs-nrfd open5gs-scpd open5gs-ausfd open5gs-udmd open5gs-udrd open5gs-pcfd open5gs-nssfd open5gs-bsfd open5gs-amfd open5gs-smfd open5gs-upfd open5gs-mmed open5gs-sgwcd open5gs-sgwud open5gs-pcrfd)
  local down=0
  for s in "${svcs[@]}"; do
    if systemctl is-active --quiet "$s"; then
      ok "Service active: $s"
    else
      warn "Service NOT active: $s"
      down=1
    fi
  done

  # Ports: SBI 7777 across key loopbacks
  if ss -tuln | grep -q ":7777"; then
    ok "SBI port(s) 7777 listening"
  else
    warn "No SBI port 7777 listening"
    down=1
  fi

  # PFCP (UPF)
  ss -u -l -n | grep -q "8805" && ok "PFCP 8805 listening" || warn "PFCP 8805 not seen (check UPF/SMF)"

  # Sysctl
  sysctl -n net.ipv4.ip_forward | grep -q "^1$" && ok "net.ipv4.ip_forward=1" || { warn "IP forwarding is not enabled"; down=1; }

  # NAT
  iptables -t nat -S POSTROUTING | grep -q "${UE_POOL1}.*MASQUERADE" && ok "NAT rule present for ${UE_POOL1}" || { warn "NAT missing for ${UE_POOL1}"; down=1; }
  if [[ -n "${UE_POOL2}" ]]; then
    iptables -t nat -S POSTROUTING | grep -q "${UE_POOL2}.*MASQUERADE" && ok "NAT rule present for ${UE_POOL2}" || warn "NAT missing for ${UE_POOL2}"
  fi

  # ogstun device (created when UPF is up)
  if ip link show ogstun >/dev/null 2>&1; then
    ok "ogstun exists"
  else
    warn "ogstun not found (may appear after first session)."
  fi

  if [[ "$down" -eq 0 ]]; then
    echo
    ok "CORE READY ✅"
  else
    echo
    warn "CORE NOT READY ❌  (check failed services/logs)"
    warn "Tip: journalctl -u open5gs-amfd -u open5gs-smfd -u open5gs-nrfd -u open5gs-scpd --no-pager -n 80"
  fi
}

main() {
  banner
  box "✅ KAOKAB5GC UNIFIED INSTALLER (SINGLE NODE: EPC + 5GC, SCP-BASED)" \
      "Zero-interaction: enabled (no prompts)\nLog: ${LOG_FILE}\nConfig: ${ENV_FILE} (auto-generated if missing)\nOS: Ubuntu 22.04 Jammy"

  block01_prereqs
  block02_load_config
  block03_netplan_optional
  block04_ip_forward_nat
  block05_loopback_aliases
  block06_mongodb
  block07_open5gs_install
  block08_write_configs
  block09_start_services
  block10_verify_configs
  block11_core_readiness

  echo
  echo "================================================="
  echo " ✅ KAOKAB5GC INSTALLATION COMPLETE"
  echo " Log file: ${LOG_FILE}"
  echo " Config:   ${ENV_FILE}"
  echo "================================================="
}

main "$@"
