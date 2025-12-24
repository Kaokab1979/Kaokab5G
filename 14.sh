#!/usr/bin/env bash
# 14.sh — Kaokab5G Core Configuration
# Block06: Generate Open5GS EPC + 5GC configs from /etc/kaokab/kaokab.env

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/kaokab-core-config-$(date +%F_%H%M%S).log"

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
  local ec=$?
  fail "Error on line ${BASH_LINENO[0]}: ${BASH_COMMAND}"
  fail "Log: ${LOG_FILE}"
  exit "$ec"
}
trap on_error ERR

require_root() { [[ $EUID -eq 0 ]] || { fail "Run as root: sudo ./${SCRIPT_NAME}"; exit 1; }; }

load_cfg() {
  local cfg="/etc/kaokab/kaokab.env"
  [[ -f "$cfg" ]] || { fail "Missing $cfg — run 11.sh first"; exit 1; }
  # shellcheck disable=SC1091
  source "$cfg"
  ok "Loaded config: $cfg"
}

need_cmd() { command -v "$1" >/dev/null 2>&1 || { fail "Missing command: $1"; exit 1; }; }

backup_open5gs_cfg() {
  local src="/etc/open5gs"
  [[ -d "$src" ]] || { fail "Open5GS config dir not found: $src (install Open5GS first)"; exit 1; }
  local bdir="/etc/open5gs/backup-$(date +%F_%H%M%S)"
  mkdir -p "$bdir"
  cp -a "$src"/*.yaml "$bdir"/ 2>/dev/null || true
  ok "Backed up existing configs to $bdir"
}

write_file() {
  local path="$1"
  local content="$2"
  install -m 600 /dev/null "$path"
  printf "%s\n" "$content" >"$path"
  ok "Wrote $(basename "$path")"
}

stop_open5gs() {
  info "Stopping Open5GS services (safe reconfigure)"
  systemctl stop 'open5gs-*' >>"$LOG_FILE" 2>&1 || true
  ok "Open5GS services stopped"
}

start_open5gs() {
  info "Starting Open5GS services"
  systemctl start 'open5gs-*' >>"$LOG_FILE" 2>&1 || true
  sleep 2
}

verify_services() {
  info "Verifying Open5GS services"
  local bad=0
  while read -r unit state; do
    if [[ "$state" != "active" ]]; then
      warn "Service not active: $unit ($state)"
      bad=1
    fi
  done < <(systemctl is-active open5gs-* 2>/dev/null | paste <(systemctl list-units --type=service --no-legend 'open5gs-*' | awk '{print $1}') -)

  if [[ "$bad" -eq 1 ]]; then
    fail "Some Open5GS services are not active. Check:"
    systemctl list-units --type=service --no-pager 'open5gs-*' | tee -a "$LOG_FILE"
    exit 1
  fi
  ok "All Open5GS services are active"
}

# ------------------------------------------------------------
# Block06: Generate EPC + 5GC YAML configuration
# ------------------------------------------------------------
block06_generate_configs() {
  echo -e "${BOLD}${BLUE}▶▶ Block06: Generating Open5GS Core Configuration${RESET}"
  info "Starting Block06"
  load_cfg

  need_cmd systemctl
  need_cmd ip
  need_cmd awk
  need_cmd sed

  # Sanity checks (must exist)
  [[ -n "${S1AP_IP:-}" && -n "${GTPU_IP:-}" && -n "${UPF_IP:-}" ]] || { fail "Missing IPs in kaokab.env"; exit 1; }
  [[ -n "${MCC:-}" && -n "${MNC:-}" && -n "${TAC:-}" ]] || { fail "Missing PLMN/TAC in kaokab.env"; exit 1; }
  [[ -n "${SST:-}" && -n "${SD:-}" ]] || { fail "Missing Slice SST/SD in kaokab.env"; exit 1; }
  [[ -n "${APN_POOL:-}" && -n "${APN_GW:-}" ]] || { fail "Missing APN pool/gateway in kaokab.env"; exit 1; }

  # Normalize MNC to 3 digits for some PLMN encodings (optional, safe)
  MNC3="$MNC"
  if [[ "${#MNC}" -eq 2 ]]; then MNC3="0${MNC}"; fi

  backup_open5gs_cfg
  stop_open5gs

  # Open5GS commonly uses loopback IPs for SBI/PFCP when all NFs are on the same server.
  # External-facing interfaces:
  # - AMF NGAP (N2) on S1AP_IP
  # - MME S1AP on S1AP_IP
  # - UPF GTPU (N3/S1-U) on UPF_IP
  #
  # DNN/APN:
  DNN_NAME="internet"

  # NRF / SCP / UDM / UDR / AUSF / PCF / BSF / SEPP loopback endpoints (stable)
  NRF_IP="127.0.0.10"
  AUSF_IP="127.0.0.11"
  UDM_IP="127.0.0.12"
  PCF_IP="127.0.0.13"
  NSSF_IP="127.0.0.14"
  BSF_IP="127.0.0.15"
  UDR_IP="127.0.0.20"
  SCP_IP="127.0.0.30"
  SEPP_IP="127.0.0.40"

  # SMF/UPF PFCP (N4) loopback endpoints
  SMF_PFCP_IP="127.0.0.4"
  UPF_PFCP_IP="127.0.0.7"

  # ----------------------------
  # 5GC: NRF
  # ----------------------------
  write_file "/etc/open5gs/nrf.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/nrf.log
  level: info

global:
  max:
    ue: 1024

nrf:
  sbi:
    server:
      - address: ${NRF_IP}
        port: 7777
    client:
      scp:
        - uri: http://${SCP_IP}:7777

metrics:
  server:
    - address: 127.0.0.10
      port: 9090
EOF
)"

  # ----------------------------
  # 5GC: SCP
  # ----------------------------
  write_file "/etc/open5gs/scp.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/scp.log
  level: info

scp:
  sbi:
    server:
      - address: ${SCP_IP}
        port: 7777
    client:
      nrf:
        - uri: http://${NRF_IP}:7777
EOF
)"

  # ----------------------------
  # 5GC: AMF
  # ----------------------------
  write_file "/etc/open5gs/amf.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/amf.log
  level: info

amf:
  sbi:
    server:
      - address: 127.0.0.5
        port: 7777
    client:
      scp:
        - uri: http://${SCP_IP}:7777
  ngap:
    server:
      - address: ${S1AP_IP}
  guami:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${MNC3}
      amf_id:
        region: ${GUAMI_REGION}
        set: ${GUAMI_SET}
  tai:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${MNC3}
      tac: ${TAC}
  plmn_support:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${MNC3}
      s_nssai:
        - sst: ${SST}
          sd: 0x${SD}
  security:
    integrity_order: [ NIA2, NIA1, NIA0 ]
    ciphering_order: [ NEA0, NEA1, NEA2 ]

metrics:
  server:
    - address: 127.0.0.5
      port: 9090
EOF
)"

  # ----------------------------
  # 5GC: AUSF / UDM / UDR / PCF / NSSF / BSF
  # ----------------------------
  write_file "/etc/open5gs/ausf.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/ausf.log
  level: info

ausf:
  sbi:
    server:
      - address: ${AUSF_IP}
        port: 7777
    client:
      scp:
        - uri: http://${SCP_IP}:7777
EOF
)"

  write_file "/etc/open5gs/udm.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/udm.log
  level: info

udm:
  sbi:
    server:
      - address: ${UDM_IP}
        port: 7777
    client:
      scp:
        - uri: http://${SCP_IP}:7777
EOF
)"

  write_file "/etc/open5gs/udr.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/udr.log
  level: info

udr:
  sbi:
    server:
      - address: ${UDR_IP}
        port: 7777
    client:
      scp:
        - uri: http://${SCP_IP}:7777
EOF
)"

  write_file "/etc/open5gs/pcf.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/pcf.log
  level: info

pcf:
  sbi:
    server:
      - address: ${PCF_IP}
        port: 7777
    client:
      scp:
        - uri: http://${SCP_IP}:7777
EOF
)"

  write_file "/etc/open5gs/nssf.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/nssf.log
  level: info

nssf:
  sbi:
    server:
      - address: ${NSSF_IP}
        port: 7777
    client:
      scp:
        - uri: http://${SCP_IP}:7777
EOF
)"

  write_file "/etc/open5gs/bsf.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/bsf.log
  level: info

bsf:
  sbi:
    server:
      - address: ${BSF_IP}
        port: 7777
    client:
      scp:
        - uri: http://${SCP_IP}:7777
EOF
)"

  # ----------------------------
  # 5GC: SMF + session (DNN, pool)
  # ----------------------------
  write_file "/etc/open5gs/smf.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/smf.log
  level: info

smf:
  sbi:
    server:
      - address: 127.0.0.4
        port: 7777
    client:
      scp:
        - uri: http://${SCP_IP}:7777

  pfcp:
    server:
      - address: ${SMF_PFCP_IP}
    client:
      upf:
        - address: ${UPF_PFCP_IP}

  # Session/DNN configuration
  session:
    - name: ${DNN_NAME}
      type: ipv4
      subnet: ${APN_POOL}
      gateway: ${APN_GW}
      dns:
        - ${DNS1}
        - ${DNS2}

metrics:
  server:
    - address: 127.0.0.4
      port: 9090
EOF
)"

  # ----------------------------
  # 5GC: UPF (N3/S1-U)
  # ----------------------------
  write_file "/etc/open5gs/upf.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/upf.log
  level: info

upf:
  pfcp:
    server:
      - address: ${UPF_PFCP_IP}

  gtpu:
    server:
      - address: ${UPF_IP}

  session:
    - subnet: ${APN_POOL}
      gateway: ${APN_GW}

metrics:
  server:
    - address: 127.0.0.7
      port: 9090
EOF
)"

  # ----------------------------
  # EPC: HSS / MME / SGW-C / SGW-U / PCRF
  # (kept for LTE/EPC compatibility; safe even if you run 5G only)
  # ----------------------------
  write_file "/etc/open5gs/hss.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/hss.log
  level: info

hss:
  sbi:
    server:
      - address: 127.0.0.2
        port: 7777
    client:
      scp:
        - uri: http://${SCP_IP}:7777
EOF
)"

  write_file "/etc/open5gs/mme.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/mme.log
  level: info

mme:
  freeDiameter: /etc/freeDiameter/mme.conf
  s1ap:
    server:
      - address: ${S1AP_IP}
  gummei:
    plmn_id:
      mcc: ${MCC}
      mnc: ${MNC3}
    mme_gid: 2
    mme_code: 1
  tai:
    plmn_id:
      mcc: ${MCC}
      mnc: ${MNC3}
    tac: ${TAC}
  security:
    integrity_order: [ EIA2, EIA1, EIA0 ]
    ciphering_order: [ EEA0, EEA1, EEA2 ]

metrics:
  server:
    - address: 127.0.0.2
      port: 9090
EOF
)"

  write_file "/etc/open5gs/sgwc.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/sgwc.log
  level: info

sgwc:
  pfcp:
    server:
      - address: 127.0.0.3
    client:
      sgwu:
        - address: 127.0.0.6
EOF
)"

  write_file "/etc/open5gs/sgwu.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/sgwu.log
  level: info

sgwu:
  pfcp:
    server:
      - address: 127.0.0.6
  gtpu:
    server:
      - address: ${GTPU_IP}
EOF
)"

  write_file "/etc/open5gs/pcrf.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/pcrf.log
  level: info

pcrf:
  sbi:
    server:
      - address: 127.0.0.9
        port: 7777
    client:
      scp:
        - uri: http://${SCP_IP}:7777
EOF
)"

  # ----------------------------
  # SEPP (optional for roaming; safe local)
  # ----------------------------
  write_file "/etc/open5gs/sepp1.yaml" "$(cat <<EOF
logger:
  file: /var/log/open5gs/sepp.log
  level: info

sepp:
  sbi:
    server:
      - address: ${SEPP_IP}
        port: 7777
    client:
      scp:
        - uri: http://${SCP_IP}:7777
EOF
)"

  ok "All Open5GS YAML configs generated"

  # Restart Open5GS in one go (systemd handles dependencies)
  start_open5gs
  verify_services

  echo -e "${BOLD}${GREEN}✔ Block06 completed successfully${RESET}"
  info "Log saved at: $LOG_FILE"
}

main() {
  require_root
  block06_generate_configs
}

main "$@"
