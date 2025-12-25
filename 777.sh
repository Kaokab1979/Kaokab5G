#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# KAOKAB5GC CORE CONFIGURATION (777.sh)
# EPC + 5GC | SCP-based SBI | Single-node production layout
###############################################################################

TS="$(date +'%Y-%m-%d_%H%M%S')"
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/kaokab5gc-config-${TS}.log"

mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

BOLD=$'\033[1m'
RED=$'\033[31m'
GRN=$'\033[32m'
YEL=$'\033[33m'
BLU=$'\033[34m'
RST=$'\033[0m'

info(){ echo "${BLU}[INFO]${RST} $*"; }
ok(){   echo "${GRN}[OK]${RST}   $*"; }
warn(){ echo "${YEL}[WARN]${RST} $*"; }
die(){  echo "${RED}[FAIL]${RST} $*"; exit 1; }

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

ENV_FILE="/etc/kaokab/kaokab.env"

load_env(){
  [[ -f "$ENV_FILE" ]] || die "Missing $ENV_FILE (run install script first)."
  # shellcheck disable=SC1090
  source "$ENV_FILE"
}

need_var(){
  local v="$1"
  [[ -n "${!v:-}" ]] || die "Missing required variable in $ENV_FILE: $v"
}

has_cmd(){ command -v "$1" >/dev/null 2>&1; }
svc_is_active(){ systemctl is-active --quiet "$1"; }

svc_restart(){
  local s="$1"
  systemctl restart "$s" || true
  sleep 1
  if ! svc_is_active "$s"; then
    systemctl --no-pager -l status "$s" || true
    return 1
  fi
  return 0
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
  warn "$name not confirmed on ${host}:${port}"
  return 1
}

# Derive GW from pool like 10.45.0.0/16 -> 10.45.0.1
pool_to_gw(){
  local pool="$1"
  local net="${pool%%/*}"
  IFS='.' read -r a b c d <<< "$net"
  if [[ -z "${a:-}" || -z "${b:-}" || -z "${c:-}" || -z "${d:-}" ]]; then
    echo ""
    return 1
  fi
  # Make last octet 1 (works for your /16 + /24 style)
  echo "${a}.${b}.${c}.1"
}

yaml_write(){
  local path="$1"
  install -m 0644 /dev/null "$path"
  cat > "$path"
  ok "Wrote: $path"
}

main(){
  banner

  # ===========================================================================
  # Block01 - Preflight
  # ===========================================================================
  block "Block01" "Safety & preflight checks\nValidate OS state, core dependencies, and kernel forwarding"
  [[ $EUID -eq 0 ]] || die "Run as root."
  [[ -d /etc/open5gs ]] || die "/etc/open5gs not found (Open5GS not installed?)."

  has_cmd systemctl || die "systemctl not found."
  has_cmd ip || die "ip tool not found."
  has_cmd iptables || die "iptables not found."
  has_cmd sysctl || die "sysctl not found."

  if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" != "1" ]]; then
    die "net.ipv4.ip_forward is not enabled. (install script should set it)"
  fi
  ok "Kernel forwarding validated (net.ipv4.ip_forward=1)"

  if ! svc_is_active mongod; then
    die "mongod is not running."
  fi
  ok "MongoDB running (mongod active)"

  if ! dpkg -s open5gs >/dev/null 2>&1; then
    die "Open5GS metapackage not installed"
  fi
  ok "Open5GS metapackage detected"

  info "What we did: verified prerequisites (root, /etc/open5gs, ip_forward, mongod, Open5GS installed)."

  # ===========================================================================
  # Block02 - Load env + derive gateways
  # ===========================================================================
  block "Block02" "Load deployment parameters from /etc/kaokab/kaokab.env\nThis script uses kaokab.env as single source of truth"
  load_env

  need_var IFACE
  need_var N2_IP
  need_var N3_IP
  need_var UPF_GTPU_IP
  need_var UE_POOL1
  need_var UE_POOL2
  need_var MCC
  need_var MNC
  need_var TAC
  need_var SST
  need_var SD
  need_var DNS1
  need_var DNS2

  # Optional toggle
  ENABLE_SEPP="${ENABLE_SEPP:-false}"

  # Derived gateways unless already provided
  UE_GW1="${UE_GW1:-$(pool_to_gw "$UE_POOL1")}"
  UE_GW2="${UE_GW2:-$(pool_to_gw "$UE_POOL2")}"
  [[ -n "$UE_GW1" ]] || die "Could not derive UE_GW1 from UE_POOL1=$UE_POOL1"
  [[ -n "$UE_GW2" ]] || die "Could not derive UE_GW2 from UE_POOL2=$UE_POOL2"

  ok "Loaded parameters from $ENV_FILE"
  info "Interface:      ${IFACE}"
  info "N2 (S1AP/NGAP): ${N2_IP}"
  info "N3 (GTP-U):     ${N3_IP}"
  info "UPF GTP-U:      ${UPF_GTPU_IP}"
  info "UE pools:       ${UE_POOL1} (GW ${UE_GW1}) , ${UE_POOL2} (GW ${UE_GW2})"
  info "PLMN/Slice:     ${MCC}/${MNC} TAC:${TAC} Slice:${SST}/${SD}"
  info "DNS:            ${DNS1}, ${DNS2}"
  info "SEPP enabled:   ${ENABLE_SEPP}"

  # ===========================================================================
  # Block03 - Backup
  # ===========================================================================
  block "Block03" "Backup existing Open5GS configuration\nCreates timestamped backup for rollback safety"
  BK_DIR="/etc/open5gs.backup-${TS}"
  cp -a /etc/open5gs "$BK_DIR"
  ok "Backup created: $BK_DIR"

  # ===========================================================================
  # Block04 - ogstun
  # ===========================================================================
  block "Block04" "Create OGSTUN interface (if missing)\nEnsures user-plane tunnel device exists for UPF"
  if ! ip link show ogstun >/dev/null 2>&1; then
    ip tuntap add name ogstun mode tun || true
    ip link set ogstun up || true
    ok "ogstun created and brought up"
  else
    ok "ogstun already exists"
  fi

  # Ensure GWs on ogstun (idempotent)
  ip addr add "${UE_GW1}/16" dev ogstun 2>/dev/null || true
  ip addr add "${UE_GW2}/16" dev ogstun 2>/dev/null || true

  info "What we did: ensured ogstun exists and has UE gateway IPs."

  # ===========================================================================
  # Block05 - EPC YAML
  # ===========================================================================
  block "Block05" "Generate EPC configuration (4G)\nWrites: mme.yaml hss.yaml sgwc.yaml sgwu.yaml pcrf.yaml"

  yaml_write /etc/open5gs/mme.yaml <<EOF
mme:
  freeDiameter: /etc/freeDiameter/mme.conf
  s1ap:
    server:
      - address: ${N2_IP}
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
    full: Kaokab
    short: Kaokab
  mme_name: kaokab-mme0
EOF

  yaml_write /etc/open5gs/hss.yaml <<EOF
db_uri: mongodb://localhost/open5gs
hss:
  freeDiameter: /etc/freeDiameter/hss.conf
EOF

  yaml_write /etc/open5gs/sgwc.yaml <<EOF
sgwc:
  gtpc:
    server:
      - address: 127.0.0.3
  pfcp:
    server:
      - address: 127.0.0.3
  metrics:
    server:
      - address: 127.0.0.3
        port: 9090
EOF

  yaml_write /etc/open5gs/sgwu.yaml <<EOF
sgwu:
  pfcp:
    server:
      - address: 127.0.0.6
  gtpu:
    server:
      - address: ${N3_IP}
  metrics:
    server:
      - address: 127.0.0.6
        port: 9090
EOF

  yaml_write /etc/open5gs/pcrf.yaml <<EOF
pcrf:
  freeDiameter: /etc/freeDiameter/pcrf.conf
  metrics:
    server:
      - address: 127.0.0.9
        port: 9090
EOF

  ok "EPC (4G) configuration written"

  # ===========================================================================
  # Block06 - 5GC YAML (NRF/SCP + DB NFs + AMF/SMF/UPF)
  # ===========================================================================
  block "Block06" "Generate 5GC configuration (SCP mesh)\nWrites: nrf.yaml scp.yaml udr.yaml udm.yaml ausf.yaml pcf.yaml nssf.yaml bsf.yaml amf.yaml smf.yaml upf.yaml"

  # Internal loopback binds (match your working model)
  NRF_SBI_IP="127.0.0.10"
  SCP_SBI_IP="127.0.0.200"
  AUSF_SBI_IP="127.0.0.11"
  UDM_SBI_IP="127.0.0.12"
  UDR_SBI_IP="127.0.0.20"
  PCF_SBI_IP="127.0.0.13"
  NSSF_SBI_IP="127.0.0.14"
  BSF_SBI_IP="127.0.0.15"
  AMF_SBI_IP="127.0.0.5"
  SMF_SBI_IP="127.0.0.4"
  UPF_PFCP_IP="127.0.0.7"

  SBI_PORT="7777"

  NRF_ADDR="$NRF_SBI_IP"
  SCP_ADDR="$SCP_SBI_IP"

# ---------- NRF ----------


  yaml_write /etc/open5gs/nrf.yaml <<EOF
nrf:
  sbi:
    server:
      - address: ${NRF_SBI_IP}
        port: ${SBI_PORT}
EOF

  yaml_write /etc/open5gs/scp.yaml <<EOF
scp:
  sbi:
    server:
      - address: ${SCP_SBI_IP}
        port: ${SBI_PORT}
    client:
      nrf:
        - uri: http://${NRF_SBI_IP}:${SBI_PORT}
EOF

# ---------- UDR ----------

  yaml_write /etc/open5gs/udr.yaml <<EOF
db_uri: mongodb://localhost/open5gs
udr:
  sbi:
    server:
      - address: ${UDR_SBI_IP}
        port: ${SBI_PORT}
    client:
      scp:
        - uri: http://${SCP_SBI_IP}:${SBI_PORT}
EOF
# ---------- UDM ----------

  yaml_write /etc/open5gs/udm.yaml <<EOF
udm:
  sbi:
    server:
      - address: ${UDM_SBI_IP}
        port: ${SBI_PORT}
    client:
      scp:
        - uri: http://${SCP_SBI_IP}:${SBI_PORT}
EOF
# ---------- AUSF ----------

  yaml_write /etc/open5gs/ausf.yaml <<EOF
ausf:
  sbi:
    server:
      - address: ${AUSF_SBI_IP}
        port: ${SBI_PORT}
    client:
      scp:
        - uri: http://${SCP_SBI_IP}:${SBI_PORT}
EOF
# ---------- PCF ----------

  yaml_write /etc/open5gs/pcf.yaml <<EOF
pcf:
  sbi:
    server:
      - address: ${PCF_SBI_IP}
        port: ${SBI_PORT}
    client:
      scp:
        - uri: http://${SCP_SBI_IP}:${SBI_PORT}
EOF

# ---------- NSSF ----------
yaml_write /etc/open5gs/nssf.yaml <<EOF
logger:
  file:
    path: /var/log/open5gs/nssf.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024

nssf:
  sbi:
    server:
      - address: ${NSSF_SBI_IP}
        port: ${SBI_PORT}
    client:
      scp:
        - uri: http://${SCP_SBI_IP}:${SBI_PORT}
      nsi:
        - uri: http://${NRF_SBI_IP}:${SBI_PORT}
          s_nssai:
            sst: ${SST}
            sd: ${SD}
EOF

# ---------- BSF ----------

  yaml_write /etc/open5gs/bsf.yaml <<EOF
bsf:
  sbi:
    server:
      - address: ${BSF_SBI_IP}
        port: ${SBI_PORT}
    client:
      scp:
        - uri: http://${SCP_SBI_IP}:${SBI_PORT}
EOF

# ---------- AMF ----------
cat > /etc/open5gs/amf.yaml <<EOF
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
      - address: ${AMF_SBI_IP}
        port: ${SBI_PORT}
    client:
      scp:
        - uri: http://${SCP_SBI_IP}:${SBI_PORT}

  ngap:
    server:
      - address: ${N2_IP}

  metrics:
    server:
      - address: ${AMF_SBI_IP}
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
        - sst: ${SST}
          sd: ${SD}

  security:
    integrity_order: [ NIA2, NIA1, NIA0 ]
    ciphering_order: [ NEA0, NEA1, NEA2 ]

  network_name:
    full: Kaokab
    short: Kaokab

  amf_name: kaokab-amf0

  time:
    t3512:
      value: 540
EOF
# ---------- SMF----------

  yaml_write /etc/open5gs/smf.yaml <<EOF
smf:
  sbi:
    server:
      - address: ${SMF_SBI_IP}
        port: ${SBI_PORT}
    client:
      scp:
        - uri: http://${SCP_SBI_IP}:${SBI_PORT}
  pfcp:
    server:
      - address: ${SMF_SBI_IP}
    client:
      upf:
        - address: ${UPF_PFCP_IP}
  gtpc:
    server:
      - address: ${SMF_SBI_IP}
  gtpu:
    server:
      - address: ${SMF_SBI_IP}
  metrics:
    server:
      - address: ${SMF_SBI_IP}
        port: 9090
  session:
    - subnet: ${UE_POOL1}
      gateway: ${UE_GW1}
      dnn: internet
    - subnet: ${UE_POOL2}
      gateway: ${UE_GW2}
      dnn: ims
  dns:
    - ${DNS2}
    - ${DNS1}
  mtu: 1500
  freeDiameter: /etc/freeDiameter/smf.conf
EOF
# ---------- UPF ----------

  yaml_write /etc/open5gs/upf.yaml <<EOF
upf:
  pfcp:
    server:
      - address: ${UPF_PFCP_IP}
  gtpu:
    server:
      - address: ${UPF_GTPU_IP}
  session:
    - subnet: ${UE_POOL1}
      gateway: ${UE_GW1}
    - subnet: ${UE_POOL2}
      gateway: ${UE_GW2}
  metrics:
    server:
      - address: ${UPF_PFCP_IP}
        port: 9090
EOF

  ok "5GC configuration written (SCP mesh)"

  # ===========================================================================
  # Block07 - Sanity checks (SEPP optional)
  # ===========================================================================
  block "Block07" "Configuration sanity checks\nDetect missing files, unresolved placeholders, obvious mistakes"

  req_files=(
    /etc/open5gs/mme.yaml
    /etc/open5gs/hss.yaml
    /etc/open5gs/sgwc.yaml
    /etc/open5gs/sgwu.yaml
    /etc/open5gs/pcrf.yaml
    /etc/open5gs/nrf.yaml
    /etc/open5gs/scp.yaml
    /etc/open5gs/udr.yaml
    /etc/open5gs/udm.yaml
    /etc/open5gs/ausf.yaml
    /etc/open5gs/pcf.yaml
    /etc/open5gs/nssf.yaml
    /etc/open5gs/bsf.yaml
    /etc/open5gs/amf.yaml
    /etc/open5gs/smf.yaml
    /etc/open5gs/upf.yaml
  )

  if [[ "$ENABLE_SEPP" == "true" ]]; then
    req_files+=(/etc/open5gs/sepp1.yaml /etc/open5gs/sepp2.yaml)
    info "SEPP sanity: ENABLE_SEPP=true → requiring sepp1.yaml + sepp2.yaml"
  else
    info "SEPP sanity: ENABLE_SEPP=false → SEPP configs not required"
  fi

  bad=0
  for f in "${req_files[@]}"; do
    if [[ ! -s "$f" ]]; then
      warn "Missing/empty: $f"
      bad=1
      continue
    fi
    if grep -q '\${' "$f"; then
      warn "Unresolved placeholder in: $f"
      bad=1
    fi
  done

  [[ $bad -eq 0 ]] || die "Sanity FAIL: missing configs or unresolved placeholders"
  ok "Sanity OK: YAMLs exist and clean"

  # ===========================================================================
  # Final - Restart in dependency order + validation
  # ===========================================================================
  block "Final" "Restart & validate EPC + 5GC services\nNRF → SCP → DB NFs → AMF/SMF/UPF → EPC NFs"

  info "Restarting Open5GS services (dependency order)..."
  systemctl daemon-reload

  # 5GC base
  svc_restart open5gs-nrfd.service || die "NRF failed"
  wait_port "$NRF_ADDR" "$SBI_PORT" "NRF" || true

  svc_restart open5gs-scpd.service || die "SCP failed"
  wait_port "$SCP_ADDR" "$SBI_PORT" "SCP" || true

  # DB-centric / policy NFs
  svc_restart open5gs-udrd.service || die "UDR failed"
  svc_restart open5gs-udmd.service || die "UDM failed"
  svc_restart open5gs-ausfd.service || die "AUSF failed"
  svc_restart open5gs-pcfd.service  || die "PCF failed"
  svc_restart open5gs-nssfd.service || die "NSSF failed"
  svc_restart open5gs-bsfd.service  || die "BSF failed"

  # SEPP only if enabled
  if [[ "$ENABLE_SEPP" == "true" ]]; then
    svc_restart open5gs-seppd.service || die "SEPP failed"
  else
    warn "SEPP disabled → skipping open5gs-seppd restart"
  fi

  # Access/control + UPF
  svc_restart open5gs-amfd.service || die "AMF failed"
  svc_restart open5gs-smfd.service || die "SMF failed"
  svc_restart open5gs-upfd.service || die "UPF failed"

  # EPC
  svc_restart open5gs-hssd.service  || die "HSS failed"
  svc_restart open5gs-pcrfd.service || die "PCRF failed"
  svc_restart open5gs-sgwcd.service || die "SGW-C failed"
  svc_restart open5gs-sgwud.service || die "SGW-U failed"
  svc_restart open5gs-mmed.service  || die "MME failed"

  ok "All required EPC + 5GC services restarted successfully"

  info "Socket sanity (LISTEN):"
  ss -lntup | grep -E "(:${SBI_PORT}\b|:38412\b|:2152\b)" || true

  block "Block10" "Readiness checks (local)\nNRF NF list best-effort + systemd health"

  if systemctl --failed --no-pager | grep -q .; then
    warn "Some failed units exist:"
    systemctl --failed --no-pager || true
  else
    ok "No failed systemd units"
  fi

  if has_cmd curl; then
    info "Querying NRF NF instances: http://${NRF_ADDR}:${SBI_PORT}/nnrf-nfm/v1/nf-instances"
    if curl -fsS "http://${NRF_ADDR}:${SBI_PORT}/nnrf-nfm/v1/nf-instances" >/tmp/nf-instances.json 2>/dev/null; then
      ok "NRF responded with NF instance list"
      jq -r "..|.nfType? // empty" /tmp/nf-instances.json 2>/dev/null \
        | sort -u | head -n 30 \
        | sed "s/^/[INFO] NRF has NF type: /" || true
    else
      warn "Could not fetch NF instances from NRF"
    fi
  else
    warn "curl not found; skipping NRF HTTP checks"
  fi

  echo
  printf "╔══════════════════════════════════════════════════════════════════════════════╗\n"
  printf "║ ✅ KAOKAB5GC CORE CONFIG APPLIED (777.sh)                                  ║\n"
  printf "╠══════════════════════════════════════════════════════════════════════════════╣\n"
  printf "║ ✔ EPC config written + restarted                                            ║\n"
  printf "║ ✔ 5GC SCP-mesh config written + restarted                                   ║\n"
  printf "║ ✔ UE pools + gateways applied on ogstun                                      ║\n"
  printf "║ ✔ Sanity + readiness checks executed                                         ║\n"
  printf "╚══════════════════════════════════════════════════════════════════════════════╝\n"

  ok "Next: connect eNB/gNB and add subscribers (or proceed to GUI layer)."
  info "Log saved at: $LOG_FILE"
}

main "$@"
