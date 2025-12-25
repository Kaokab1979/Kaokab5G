#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# KAOKAB5GC CORE CONFIGURATION (777.sh)
# EPC + 5GC | SCP-based SBI | Single-node production layout
###############################################################################

# ------------------------- UX / logging helpers ------------------------------
TS="$(date +'%Y-%m-%d_%H%M%S')"
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/kaokab5gc-config-${TS}.log"

mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

BOLD=$'\033[1m'
DIM=$'\033[2m'
RED=$'\033[31m'
GRN=$'\033[32m'
YEL=$'\033[33m'
BLU=$'\033[34m'
RST=$'\033[0m'

info(){ echo "${BLU}[INFO]${RST} $*"; }
ok(){   echo "${GRN}[OK]${RST}   $*"; }
warn(){ echo "${YEL}[WARN]${RST} $*"; }
fail(){ echo "${RED}[FAIL]${RST} $*"; exit 1; }

line(){ printf "%s\n" "╔══════════════════════════════════════════════════════════════════════════════╗"; }
block(){
  local title="$1"; local subtitle="${2:-}"
  echo
  printf "╔══════════════════════════════════════════════════════════════════════════════╗\n"
  printf "║ ▶▶ %-74s ║\n" "$title"
  printf "╠══════════════════════════════════════════════════════════════════════════════╣\n"
  if [[ -n "$subtitle" ]]; then
    while IFS= read -r l; do
      printf "║ %-76s ║\n" "$l"
    done <<< "$subtitle"
  fi
  printf "╚══════════════════════════════════════════════════════════════════════════════╝\n"
}

banner(){
  printf "\n"
  printf "╔══════════════════════════════════════════════════════════════════════════════╗\n"
  printf "║ ✅ KAOKAB5GC CORE CONFIGURATION (EPC + 5GC, SCP-BASED)                      ║\n"
  printf "╚══════════════════════════════════════════════════════════════════════════════╝\n"
  info "Zero-interaction: enabled (no prompts)"
  info "Log file: ${LOG_FILE}"
  info "Config file: /etc/kaokab/kaokab.env"
}

# ------------------------- env loading & defaults ----------------------------
ENV_FILE="/etc/kaokab/kaokab.env"

load_env(){
  [[ -f "$ENV_FILE" ]] || fail "Missing $ENV_FILE (run 666.sh first)."
  # shellcheck disable=SC1090
  source "$ENV_FILE"
}

need_var(){
  local v="$1"
  [[ -n "${!v:-}" ]] || fail "Missing required variable in $ENV_FILE: $v"
}

# ------------------------- small utilities -----------------------------------
has_cmd(){ command -v "$1" >/dev/null 2>&1; }

svc_is_active(){ systemctl is-active --quiet "$1"; }
svc_restart(){
  local s="$1"
  systemctl restart "$s"
  sleep 1
  if ! svc_is_active "$s"; then
    systemctl --no-pager -l status "$s" || true
    fail "Service failed to start: $s"
  fi
  ok "Service running: $s"
}

wait_port(){
  local host="$1" port="$2" name="$3" tries="${4:-25}"
  local i
  for i in $(seq 1 "$tries"); do
    if (echo >/dev/tcp/"$host"/"$port") >/dev/null 2>&1; then
      ok "$name listening on ${host}:${port}"
      return 0
    fi
    sleep 0.4
  done
  warn "$name not confirmed on ${host}:${port} (may still be OK if bound differently)"
  return 1
}

yaml_write(){
  local path="$1"
  install -m 0644 /dev/null "$path"
  cat > "$path"
  ok "Wrote: $path"
}

# ------------------------- main ------------------------------------------------
main(){
  banner

  block "Block01" "Safety & preflight checks\nValidate OS state, core dependencies, and kernel forwarding"
  [[ $EUID -eq 0 ]] || fail "Run as root."
  [[ -d /etc/open5gs ]] || fail "/etc/open5gs not found (Open5GS not installed?)."
  has_cmd systemctl || fail "systemctl not found."
  has_cmd ip || fail "ip tool not found."
  has_cmd iptables || fail "iptables not found."
  has_cmd mongosh || warn "mongosh not found (MongoDB tools)."

  # kernel forwarding must exist + be enabled
  if ! sysctl -n net.ipv4.ip_forward >/dev/null 2>&1; then
    fail "Kernel key net.ipv4.ip_forward missing (unexpected on Ubuntu)."
  fi
  if [[ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]]; then
    fail "net.ipv4.ip_forward is not enabled. (666.sh should set it)."
  fi
  ok "Kernel forwarding validated (net.ipv4.ip_forward=1)"

  # Mongo must be up
  if ! svc_is_active mongod; then
    fail "mongod is not running."
  fi
  ok "MongoDB running (mongod active)"

  # Open5GS packages presence (at least core ones)
  dpkg -l | grep -q '^ii\s\+open5gs' || fail "Open5GS packages not installed."
  ok "Open5GS packages present"

  info "What we did: verified prerequisites (root, /etc/open5gs, ip_forward, mongod, Open5GS installed)."

  block "Block02" "Load deployment parameters from /etc/kaokab/kaokab.env\nThis script uses kaokab.env as single source of truth"
  load_env

  need_var IFACE
  need_var S1AP_N2_IP
  need_var GTPU_N3_IP
  need_var UPF_GTPU_IP
  need_var UE_POOL_INTERNET
  need_var UE_POOL_IMS
  need_var MCC
  need_var MNC
  need_var TAC
  need_var SLICE_SST
  need_var SLICE_SD

  ok "Loaded parameters from $ENV_FILE"
  info "Interface: ${IFACE}"
  info "S1AP/N2 IP: ${S1AP_N2_IP}"
  info "GTPU/N3 IP: ${GTPU_N3_IP}"
  info "UPF GTPU IP: ${UPF_GTPU_IP}"
  info "UE pools: ${UE_POOL_INTERNET} , ${UE_POOL_IMS}"
  info "PLMN: ${MCC}/${MNC}  TAC:${TAC}  Slice:${SLICE_SST}/${SLICE_SD}"
  info "What we did: loaded and validated all required env variables."

  block "Block03" "Backup existing Open5GS configuration\nCreates timestamped backup for rollback safety"
  BK_DIR="/etc/open5gs.backup-${TS}"
  cp -a /etc/open5gs "$BK_DIR"
  ok "Backup created: $BK_DIR"
  info "What we did: backed up /etc/open5gs so rollback is always possible."

  block "Block04" "Create OGSTUN interface (if missing)\nEnsures user-plane tunnel device exists for UPF"
  if ! ip link show ogstun >/dev/null 2>&1; then
    ip tuntap add name ogstun mode tun || true
    ip addr add 10.45.0.1/16 dev ogstun 2>/dev/null || true
    ip addr add 10.46.0.1/16 dev ogstun 2>/dev/null || true
    ip link set ogstun up || true
    ok "ogstun created and brought up"
  else
    ok "ogstun already exists"
  fi
  info "What we did: ensured ogstun exists and is UP (needed for UE traffic)."

  block "Block05" "Generate EPC configuration (4G)\nWrites: mme.yaml hss.yaml sgwc.yaml sgwu.yaml pcrf.yaml"
  # Notes:
  # - EPC uses MME/HSS/SGW-C/SGW-U/PCRF.
  # - Bind addresses use your S1AP_N2_IP and GTPU_N3_IP where applicable.

  yaml_write /etc/open5gs/mme.yaml <<EOF
logger:
  file: /var/log/open5gs/mme.log

mme:
  freeDiameter: /etc/freeDiameter/mme.conf
  s1ap:
    - addr: ${S1AP_N2_IP}
  gtpc:
    - addr: ${S1AP_N2_IP}
  gummei:
    plmn_id:
      mcc: ${MCC}
      mnc: ${MNC}
    mme_gid: 2
    mme_code: 1
  tai:
    plmn_id:
      mcc: ${MCC}
      mnc: ${MNC}
    tac: ${TAC}
  security:
    integrity_order: [ EIA2, EIA1, EIA0 ]
    ciphering_order: [ EEA2, EEA1, EEA0 ]
EOF

  yaml_write /etc/open5gs/hss.yaml <<EOF
logger:
  file: /var/log/open5gs/hss.log

db_uri: mongodb://localhost/open5gs

hss:
  freeDiameter: /etc/freeDiameter/hss.conf
EOF

  yaml_write /etc/open5gs/sgwc.yaml <<EOF
logger:
  file: /var/log/open5gs/sgwc.log

sgwc:
  gtpc:
    - addr: ${S1AP_N2_IP}
EOF

  yaml_write /etc/open5gs/sgwu.yaml <<EOF
logger:
  file: /var/log/open5gs/sgwu.log

sgwu:
  gtpu:
    - addr: ${GTPU_N3_IP}
EOF

  yaml_write /etc/open5gs/pcrf.yaml <<EOF
logger:
  file: /var/log/open5gs/pcrf.log

db_uri: mongodb://localhost/open5gs

pcrf:
EOF

  ok "EPC YAML generation complete"
  info "What we did: wrote EPC configs using your kaokab.env IPs + PLMN (MME/HSS/SGW-C/SGW-U/PCRF)."

  block "Block06" "Generate 5GC configuration (SCP-based SBI)\nWrites: nrf.yaml scp.yaml amf.yaml smf.yaml ausf.yaml udm.yaml udr.yaml pcf.yaml nssf.yaml bsf.yaml sepp.yaml"
  # SBI endpoints (single node)
  NRF_ADDR="127.0.0.10"
  SCP_ADDR="127.0.0.200"
  SBI_PORT="7777"

  yaml_write /etc/open5gs/nrf.yaml <<EOF
logger:
  file: /var/log/open5gs/nrf.log

nrf:
  sbi:
    - addr: ${NRF_ADDR}
      port: ${SBI_PORT}
EOF

  yaml_write /etc/open5gs/scp.yaml <<EOF
logger:
  file: /var/log/open5gs/scp.log

scp:
  sbi:
    - addr: ${SCP_ADDR}
      port: ${SBI_PORT}

  # Route all SBI through SCP (service-based proxy)
  # NRF is still used for registration/discovery.
  nrf:
    - uri: http://${NRF_ADDR}:${SBI_PORT}
EOF

  yaml_write /etc/open5gs/amf.yaml <<EOF
logger:
  file: /var/log/open5gs/amf.log

amf:
  sbi:
    - addr: ${S1AP_N2_IP}
      port: 7777
  ngap:
    - addr: ${S1AP_N2_IP}

  guami:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${MNC}
      amf_id:
        region: 2
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
        - sst: ${SLICE_SST}
          sd: ${SLICE_SD}

  security:
    integrity_order: [ NIA2, NIA1, NIA0 ]
    ciphering_order: [ NEA2, NEA1, NEA0 ]

  # SCP-based routing
  scp:
    - uri: http://${SCP_ADDR}:${SBI_PORT}
  nrf:
    - uri: http://${NRF_ADDR}:${SBI_PORT}
EOF

  yaml_write /etc/open5gs/smf.yaml <<EOF
logger:
  file: /var/log/open5gs/smf.log

smf:
  sbi:
    - addr: ${S1AP_N2_IP}
      port: 7777

  pfcp:
    - addr: ${S1AP_N2_IP}

  gtpc:
    - addr: ${S1AP_N2_IP}

  gtpu:
    - addr: ${GTPU_N3_IP}

  subnet:
    - addr: ${UE_POOL_INTERNET}
      dnn: internet
    - addr: ${UE_POOL_IMS}
      dnn: ims

  dns:
    - 1.1.1.1
    - 1.0.0.1

  # SCP-based routing
  scp:
    - uri: http://${SCP_ADDR}:${SBI_PORT}
  nrf:
    - uri: http://${NRF_ADDR}:${SBI_PORT}
EOF

  yaml_write /etc/open5gs/udr.yaml <<EOF
logger:
  file: /var/log/open5gs/udr.log

db_uri: mongodb://localhost/open5gs

udr:
  sbi:
    - addr: ${S1AP_N2_IP}
      port: 7777

  scp:
    - uri: http://${SCP_ADDR}:${SBI_PORT}
  nrf:
    - uri: http://${NRF_ADDR}:${SBI_PORT}
EOF

  yaml_write /etc/open5gs/udm.yaml <<EOF
logger:
  file: /var/log/open5gs/udm.log

udm:
  sbi:
    - addr: ${S1AP_N2_IP}
      port: 7777

  scp:
    - uri: http://${SCP_ADDR}:${SBI_PORT}
  nrf:
    - uri: http://${NRF_ADDR}:${SBI_PORT}
EOF

  yaml_write /etc/open5gs/ausf.yaml <<EOF
logger:
  file: /var/log/open5gs/ausf.log

ausf:
  sbi:
    - addr: ${S1AP_N2_IP}
      port: 7777

  scp:
    - uri: http://${SCP_ADDR}:${SBI_PORT}
  nrf:
    - uri: http://${NRF_ADDR}:${SBI_PORT}
EOF

  yaml_write /etc/open5gs/pcf.yaml <<EOF
logger:
  file: /var/log/open5gs/pcf.log

db_uri: mongodb://localhost/open5gs

pcf:
  sbi:
    - addr: ${S1AP_N2_IP}
      port: 7777

  scp:
    - uri: http://${SCP_ADDR}:${SBI_PORT}
  nrf:
    - uri: http://${NRF_ADDR}:${SBI_PORT}
EOF

  yaml_write /etc/open5gs/nssf.yaml <<EOF
logger:
  file: /var/log/open5gs/nssf.log

nssf:
  sbi:
    - addr: ${S1AP_N2_IP}
      port: 7777

  scp:
    - uri: http://${SCP_ADDR}:${SBI_PORT}
  nrf:
    - uri: http://${NRF_ADDR}:${SBI_PORT}
EOF

  yaml_write /etc/open5gs/bsf.yaml <<EOF
logger:
  file: /var/log/open5gs/bsf.log

bsf:
  sbi:
    - addr: ${S1AP_N2_IP}
      port: 7777

  scp:
    - uri: http://${SCP_ADDR}:${SBI_PORT}
  nrf:
    - uri: http://${NRF_ADDR}:${SBI_PORT}
EOF

  yaml_write /etc/open5gs/sepp.yaml <<EOF
logger:
  file: /var/log/open5gs/sepp.log

sepp:
  sbi:
    - addr: ${S1AP_N2_IP}
      port: 7777

  scp:
    - uri: http://${SCP_ADDR}:${SBI_PORT}
  nrf:
    - uri: http://${NRF_ADDR}:${SBI_PORT}
EOF

  ok "5GC YAML generation complete (SCP-based)"
  info "What we did: wrote all 5GC configs and enforced SCP-based SBI routing (NRF+SCP+NFs)."

  block "Block07" "Generate UPF configuration\nWrites: upf.yaml (PFCP + GTP-U + UE pools via ogstun)"
  yaml_write /etc/open5gs/upf.yaml <<EOF
logger:
  file: /var/log/open5gs/upf.log

upf:
  pfcp:
    - addr: ${S1AP_N2_IP}

  gtpu:
    - addr: ${UPF_GTPU_IP}

  session:
    - subnet: ${UE_POOL_INTERNET}
      dev: ogstun
    - subnet: ${UE_POOL_IMS}
      dev: ogstun
EOF
  ok "UPF YAML generation complete"
  info "What we did: configured UPF PFCP bind + GTPU bind + ogstun UE subnets."

  block "Block08" "Configuration sanity checks\nDetect missing files, unresolved placeholders, and obvious mistakes"
  req_files=(
    /etc/open5gs/mme.yaml
    /etc/open5gs/hss.yaml
    /etc/open5gs/sgwc.yaml
    /etc/open5gs/sgwu.yaml
    /etc/open5gs/pcrf.yaml
    /etc/open5gs/nrf.yaml
    /etc/open5gs/scp.yaml
    /etc/open5gs/amf.yaml
    /etc/open5gs/smf.yaml
    /etc/open5gs/udr.yaml
    /etc/open5gs/udm.yaml
    /etc/open5gs/ausf.yaml
    /etc/open5gs/pcf.yaml
    /etc/open5gs/nssf.yaml
    /etc/open5gs/bsf.yaml
    /etc/open5gs/sepp.yaml
    /etc/open5gs/upf.yaml
  )
  for f in "${req_files[@]}"; do
    [[ -s "$f" ]] || fail "Config missing/empty: $f"
    if grep -q '\${' "$f"; then
      fail "Unresolved variable placeholder detected in $f"
    fi
  done
  ok "All required YAML files exist and contain no unresolved placeholders"
  info "What we did: validated every YAML exists, non-empty, and no leftover template variables."

  block "Block09" "Restart services in correct dependency order\nNRF → SCP → DB NFs → AMF/SMF/UPF → EPC NFs"
  # Mongo just check
  svc_is_active mongod || fail "mongod not active (unexpected)."
  ok "mongod active (no restart needed)"

  # 5GC base
  svc_restart open5gs-nrfd.service
  wait_port "$NRF_ADDR" "$SBI_PORT" "NRF" || true

  svc_restart open5gs-scpd.service
  wait_port "$SCP_ADDR" "$SBI_PORT" "SCP" || true

  # DB-centric / policy NFs
  svc_restart open5gs-udrd.service
  svc_restart open5gs-udmd.service
  svc_restart open5gs-ausfd.service
  svc_restart open5gs-nssfd.service
  svc_restart open5gs-pcfd.service
  svc_restart open5gs-bsfd.service
  svc_restart open5gs-seppd.service

  # Access/control
  svc_restart open5gs-amfd.service
  svc_restart open5gs-smfd.service

  # User plane
  svc_restart open5gs-upfd.service

  # EPC side
  svc_restart open5gs-hssd.service
  svc_restart open5gs-pcrfd.service
  svc_restart open5gs-sgwcd.service
  svc_restart open5gs-sgwud.service
  svc_restart open5gs-mmed.service

  ok "All services restarted and confirmed running"
  info "What we did: restarted NFs in a safe order and validated each service is active."

  block "Block10" "Readiness checks (local)\nValidate NF registrations, listening ports, and service health"
  # Basic systemd health
  if systemctl --failed --no-pager | grep -q .; then
    warn "Some failed units exist:"
    systemctl --failed --no-pager || true
  else
    ok "No failed systemd units"
  fi

  # SBI ports (best-effort)
  wait_port "$NRF_ADDR" "$SBI_PORT" "NRF" || true
  wait_port "$SCP_ADDR" "$SBI_PORT" "SCP" || true

  # NF registration list (best effort; curl might not exist in minimal images but you have it)
  if has_cmd curl; then
    info "Querying NRF NF instances (best-effort): http://${NRF_ADDR}:${SBI_PORT}/nnrf-nfm/v1/nf-instances"
    if curl -fsS "http://${NRF_ADDR}:${SBI_PORT}/nnrf-nfm/v1/nf-instances" >/tmp/nf-instances.json 2>/dev/null; then
      ok "NRF responded with NF instance list"
      # show a short human hint:
      jq -r '..|.nfType? // empty' /tmp/nf-instances.json 2>/dev/null | sort -u | head -n 30 | sed 's/^/[INFO] NRF has NF type: /' || true
    else
      warn "Could not fetch NF instances from NRF (may still work depending on bind/firewall)"
    fi
  else
    warn "curl not found; skipping NRF HTTP checks"
  fi

  # Final
  echo
  printf "╔══════════════════════════════════════════════════════════════════════════════╗\n"
  printf "║ ✅ KAOKAB5GC CORE CONFIG APPLIED (777.sh)                                  ║\n"
  printf "╠══════════════════════════════════════════════════════════════════════════════╣\n"
  printf "║ ✔ EPC config written (MME/HSS/SGW-C/SGW-U/PCRF)                             ║\n"
  printf "║ ✔ 5GC config written (NRF/SCP/AMF/SMF/AUSF/UDM/UDR/PCF/NSSF/BSF/SEPP)        ║\n"
  printf "║ ✔ SCP-based SBI enforced                                                    ║\n"
  printf "║ ✔ UPF configured for ogstun UE pools                                        ║\n"
  printf "║ ✔ Services restarted in correct order                                       ║\n"
  printf "║ ✔ Basic readiness checks executed                                           ║\n"
  printf "╚══════════════════════════════════════════════════════════════════════════════╝\n"

  ok "Next: connect eNB/gNB and add subscribers (or proceed to GUI script 888/GUI layer)."
  info "Log saved at: $LOG_FILE"
}

main "$@"
