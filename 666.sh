#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# KAOKAB5GC 666.sh
# Unified Installer (Ubuntu 22.04 Jammy)
# Single node: EPC + 5GC (SCP-based SBI)
# Zero interaction
# =========================

# ---------- UX / logging ----------
APP="kaokab5gc"
TS="$(date +%F_%H%M%S)"
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/${APP}-install-${TS}.log"
CFG_DIR="/etc/kaokab"
CFG_FILE="${CFG_DIR}/kaokab.env"

mkdir -p "$LOG_DIR" "$CFG_DIR"
touch "$LOG_FILE"
chmod 0644 "$LOG_FILE"

exec > >(tee -a "$LOG_FILE") 2>&1

cecho() { printf "%b\n" "$*"; }
ok()    { cecho "[OK] $*"; }
info()  { cecho "[INFO] $*"; }
warn()  { cecho "[WARN] $*"; }
fail()  { cecho "[FAIL] $*"; exit 1; }

box() {
  local title="$1"
  printf "\n╔══════════════════════════════════════════════════════════════════════════════╗\n"
  printf "║ %-76s ║\n" "$title"
  printf "╚══════════════════════════════════════════════════════════════════════════════╝\n"
}

block() {
  local b="$1" d="$2"
  printf "\n╔══════════════════════════════════════════════════════════════════════════════╗\n"
  printf "║ ▶▶ %-72s ║\n" "$b"
  printf "╠══════════════════════════════════════════════════════════════════════════════╣\n"
  printf "║ %-76s ║\n" "$d"
  printf "╚══════════════════════════════════════════════════════════════════════════════╝\n"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Run as root: sudo $0"
  fi
}

require_jammy() {
  if ! grep -qi "jammy" /etc/os-release; then
    fail "Ubuntu 22.04 (jammy) only. Current: $(. /etc/os-release; echo "$PRETTY_NAME")"
  fi
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

# ---------- config defaults ----------
gen_default_config() {
  cat > "$CFG_FILE" <<'EOF'
# KAOKAB5GC deployment parameters (auto-generated)
# Edit and rerun 666.sh safely (idempotent)

# Network
IFACE="ens160"
GW="192.168.178.1"
DNS1="1.1.1.1"
DNS2="1.0.0.1"

# RAN-facing / data plane
N2_IP="192.168.178.80"     # AMF NGAP / MME S1AP
N3_IP="192.168.178.81"     # (if needed for N3 external binding)
UPF_GTPU_IP="192.168.178.82"  # UPF GTP-U (N3)

# UE pools
UE_POOL_INTERNET="10.45.0.0/16"
UE_GW_INTERNET="10.45.0.1"
UE_POOL_IMS="10.46.0.0/16"
UE_GW_IMS="10.46.0.1"

# PLMN / Slice
MCC="204"
MNC="61"
TAC="1"
SST="1"
SD="010203"

# Naming
CORE_NAME="Kaokab"
AMF_NAME="kaokab-amf0"
MME_NAME="kaokab-mme0"

# SCP/NRF loopback targets (match working VM style)
SCP_ADDR="127.0.0.200"
NRF_ADDR="127.0.0.10"

# Manage netplan (optional)
MANAGE_NETPLAN="false"

# If true, script will stop if readiness checks fail
STRICT_READY="true"
EOF
  chmod 0644 "$CFG_FILE"
}

load_config() {
  # shellcheck disable=SC1090
  source "$CFG_FILE"

  : "${IFACE:?}"
  : "${N2_IP:?}"
  : "${UPF_GTPU_IP:?}"
  : "${GW:?}"
  : "${DNS1:?}"
  : "${DNS2:?}"
  : "${UE_POOL_INTERNET:?}"
  : "${UE_POOL_IMS:?}"
  : "${MCC:?}"
  : "${MNC:?}"
  : "${TAC:?}"
  : "${SST:?}"
  : "${SD:?}"
  : "${SCP_ADDR:?}"
  : "${NRF_ADDR:?}"
}

print_summary() {
  printf "\n╔══════════════════════════════════════════════════════════════════════════════╗\n"
  printf "║ CONFIG SUMMARY                                                               ║\n"
  printf "╠══════════════════════════════════════════════════════════════════════════════╣\n"
  printf "║ Interface: %-64s ║\n" "$IFACE"
  printf "║ S1AP/N2:   %-64s ║\n" "${N2_IP}/24"
  printf "║ GTPU/N3:   %-64s ║\n" "${N3_IP}/24"
  printf "║ UPF GTPU:  %-64s ║\n" "${UPF_GTPU_IP}/24"
  printf "║ GW/DNS:    %-64s ║\n" "${GW} | ${DNS1}, ${DNS2}"
  printf "║ UE pools:  %-64s ║\n" "${UE_POOL_INTERNET}(internet) , ${UE_POOL_IMS}(ims)"
  printf "║ PLMN:      %-64s ║\n" "${MCC}/${MNC}  TAC:${TAC}  Slice:${SST}/${SD}"
  printf "║ Names:     %-64s ║\n" "${CORE_NAME} AMF:${AMF_NAME} MME:${MME_NAME}"
  printf "╚══════════════════════════════════════════════════════════════════════════════╝\n"
}

# ---------- Block03: netplan (optional) ----------
maybe_manage_netplan() {
  if [[ "${MANAGE_NETPLAN,,}" != "true" ]]; then
    ok "Skipping netplan changes (MANAGE_NETPLAN=${MANAGE_NETPLAN})"
    return 0
  fi
  warn "MANAGE_NETPLAN=true was requested, but not implemented in this revision to avoid breaking connectivity."
  warn "If you want it, tell me your exact desired netplan YAML and I’ll embed it safely with backups."
  return 0
}

# ---------- Block04: sysctl + NAT ----------
apply_sysctl_and_nat() {
  info "Enabling IPv4 forwarding (only valid keys)"
  cat > /etc/sysctl.d/99-kaokab5gc.conf <<EOF
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null || true
  [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" == "1" ]] || fail "Failed to enable net.ipv4.ip_forward"
  ok "IP forwarding enabled"

  info "Installing iptables persistence"
  apt_install iptables-persistent netfilter-persistent

  info "Ensuring NAT masquerade for UE pools (match working VM: ! -o ogstun)"
  # Use iptables -C checks for idempotency
  iptables -t nat -C POSTROUTING -s "$UE_POOL_INTERNET" '!' -o ogstun -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$UE_POOL_INTERNET" '!' -o ogstun -j MASQUERADE

  iptables -t nat -C POSTROUTING -s "$UE_POOL_IMS" '!' -o ogstun -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$UE_POOL_IMS" '!' -o ogstun -j MASQUERADE

  netfilter-persistent save >/dev/null || true

  ok "NAT rules set & persisted"
  iptables -t nat -S POSTROUTING | egrep --color=never "(${UE_POOL_INTERNET%/*}|${UE_POOL_IMS%/*})" || true
}

# ---------- Block05: loopback correctness ----------
validate_loopback_model() {
  # Working VM proves:
  # - lo has 127.0.0.1/8
  # - local table includes 127.0.0.0/8
  # - ip_nonlocal_bind = 0
  # - Open5GS can still bind 127.0.0.x
  info "Validating loopback model (must match working VM expectations)"
  ip -4 addr show lo | grep -q "127.0.0.1/8" || fail "lo does not have 127.0.0.1/8"
  ip route show table local | grep -q "local 127.0.0.0/8 dev lo" || fail "Missing local route 127.0.0.0/8 dev lo"
  ok "Loopback OK: 127.0.0.1/8 + local 127/8 route present (no extra aliases required)"
}

# ---------- MongoDB 6.0 ----------
install_mongodb_60() {
  info "Installing MongoDB 6.0 (official repo)"
  apt_install ca-certificates gnupg curl

  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://pgp.mongodb.com/server-6.0.asc | gpg --dearmor -o /etc/apt/keyrings/mongodb-server-6.0.gpg

  cat > /etc/apt/sources.list.d/mongodb-org-6.0.list <<EOF
deb [ arch=amd64,arm64 signed-by=/etc/apt/keyrings/mongodb-server-6.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse
EOF

  apt-get update -y
  apt-get install -y mongodb-org

  systemctl enable --now mongod
  systemctl is-active --quiet mongod || fail "mongod not active"
  ok "MongoDB installed and running"
}

# ---------- Open5GS install ----------
install_open5gs() {
  info "Installing Open5GS from PPA (open5gs/latest)"
  apt_install software-properties-common
  add-apt-repository -y ppa:open5gs/latest
  apt-get update -y

  # packages
  aapt-get install -y open5gs freediameter


  ok "Open5GS packages installed"
}
info "WebUI not installed automatically (recommended for production)"
info "If needed, install WebUI separately using NodeJS"

# ---------- Open5GS config (SCP-based) ----------
write_open5gs_configs() {
  info "Writing Open5GS configs (SCP-based SBI, aligned to working VM patterns)"

  # Backup once
  if [[ -d /etc/open5gs && ! -e /etc/open5gs/.kaokab_backup_done ]]; then
    tar -C /etc -czf "${LOG_DIR}/open5gs-etc-backup-${TS}.tgz" open5gs || true
    touch /etc/open5gs/.kaokab_backup_done
  fi

  # Minimal configs required for your pattern; extend safely if you need more knobs.
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
      - address: ${SCP_ADDR}
        port: 7777
    client:
      nrf:
        - uri: http://${NRF_ADDR}:7777
EOF

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
      - address: ${NRF_ADDR}
        port: 7777
EOF

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
        - uri: http://${SCP_ADDR}:7777
  ngap:
    server:
      - address: ${N2_IP}
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
        - sst: ${SST}
          sd: ${SD}
  network_name:
    full: ${CORE_NAME}
    short: ${CORE_NAME}
  amf_name: ${AMF_NAME}
EOF

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
        - uri: http://${SCP_ADDR}:7777
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
    - subnet: ${UE_POOL_INTERNET}
      gateway: ${UE_GW_INTERNET}
      dnn: internet
    - subnet: ${UE_POOL_IMS}
      gateway: ${UE_GW_IMS}
      dnn: ims
  dns:
    - ${DNS2}
    - ${DNS1}
  mtu: 1500
  freeDiameter: /etc/freeDiameter/smf.conf
EOF

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
    - subnet: ${UE_POOL_INTERNET}
      gateway: ${UE_GW_INTERNET}
      dnn: internet
    - subnet: ${UE_POOL_IMS}
      gateway: ${UE_GW_IMS}
      dnn: ims
  metrics:
    server:
      - address: 127.0.0.7
        port: 9090
EOF

  ok "Open5GS core configs written"
}

enable_and_start_services() {
  info "Enabling & starting services"
  systemctl daemon-reload

  systemctl enable --now mongod || true

  # Start order: nrf -> scp -> others (pattern that matches your working layout)
  local svcs=(
    open5gs-nrfd
    open5gs-scpd
    open5gs-amfd
    open5gs-smfd
    open5gs-upfd
    open5gs-udmd
    open5gs-udrd
    open5gs-ausfd
    open5gs-pcfd
    open5gs-nssfd
    open5gs-bsfd
    open5gs-mmed
    open5gs-sgwcd
    open5gs-sgwud
    open5gs-seppd
    open5gs-pcrfd
    open5gs-hssd
    open5gs-webui
  )

  for s in "${svcs[@]}"; do
    systemctl enable "$s" >/dev/null 2>&1 || true
    systemctl restart "$s" >/dev/null 2>&1 || true
  done

  ok "Services started (restart issued)"
}

# ---------- Auto-verification vs working VM expectations ----------
verify_against_working_vm_model() {
  info "Auto-verifying against working VM model (SCP-based URIs + expected listeners)"

  # 1) Ensure configs reference SCP (not NRF direct) where applicable
  grep -qE "scp:\s*$" /etc/open5gs/amf.yaml || fail "amf.yaml missing SCP client section"
  grep -qE "uri:\s*http://${SCP_ADDR}:7777" /etc/open5gs/amf.yaml || fail "amf.yaml SCP URI mismatch"
  grep -qE "uri:\s*http://${SCP_ADDR}:7777" /etc/open5gs/smf.yaml || fail "smf.yaml SCP URI mismatch"
  grep -qE "address:\s*${SCP_ADDR}" /etc/open5gs/scp.yaml || fail "scp.yaml server address mismatch"
  grep -qE "address:\s*${NRF_ADDR}" /etc/open5gs/nrf.yaml || fail "nrf.yaml server address mismatch"

  ok "Config model matches working VM patterns (SCP-based SBI)"
}

# ---------- Final readiness ----------
core_readiness() {
  info "Core readiness validation (must match working VM checks)"

  local must_active=(mongod open5gs-nrfd open5gs-scpd open5gs-amfd open5gs-smfd open5gs-upfd)
  for s in "${must_active[@]}"; do
    systemctl is-active --quiet "$s" || fail "Service not active: $s"
  done
  ok "Key services active"

  # listeners similar to your working VM snapshot
  ss -tuln | grep -q "${SCP_ADDR}:7777" || fail "SCP not listening on ${SCP_ADDR}:7777"
  ss -tuln | grep -q "${NRF_ADDR}:7777" || fail "NRF not listening on ${NRF_ADDR}:7777"
  ss -tuln | grep -q "127.0.0.5:7777" || fail "AMF not listening on 127.0.0.5:7777"
  ss -tuln | grep -q "127.0.0.4:7777" || fail "SMF not listening on 127.0.0.4:7777"
  ss -u  -ln | grep -q "127.0.0.4:8805" || fail "SMF PFCP not listening on 127.0.0.4:8805"
  ss -u  -ln | grep -q "${UPF_GTPU_IP}:2152" || fail "UPF GTP-U not listening on ${UPF_GTPU_IP}:2152"
  ok "Key listeners present"

  # ogstun presence (created by UPF when running correctly)
  if ip -4 addr show ogstun >/dev/null 2>&1; then
    ok "ogstun present"
  else
    warn "ogstun not present yet (may appear after first session). Checking config + UPF still OK."
  fi

  # sysctl and NAT rules
  [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" == "1" ]] || fail "ip_forward not enabled"
  iptables -t nat -S POSTROUTING | grep -q "${UE_POOL_INTERNET}" || fail "NAT rule missing for ${UE_POOL_INTERNET}"
  iptables -t nat -S POSTROUTING | grep -q "${UE_POOL_IMS}" || fail "NAT rule missing for ${UE_POOL_IMS}"
  ok "Forwarding + NAT OK"

  ok "CORE READINESS: PASS"
}

main() {
  require_root
  require_jammy

  box "✅ KAOKAB5GC UNIFIED INSTALLER (SINGLE NODE: EPC + 5GC, SCP-BASED)"
  info "Zero-interaction: enabled (no prompts)"
  info "Log: ${LOG_FILE}"
  info "Config: ${CFG_FILE}"

  block "Block01" "System checks + base tooling"
  apt_install iproute2 lsb-release jq net-tools curl ca-certificates gnupg software-properties-common
  ok "Base tooling installed"

  block "Block02" "Load or auto-generate deployment parameters (non-interactive)"
  if [[ ! -f "$CFG_FILE" ]]; then
    warn "Config not found: ${CFG_FILE} → generating defaults"
    gen_default_config
  fi
  load_config
  print_summary
  ok "Parameters loaded"

  block "Block03" "Netplan management (optional)"
  maybe_manage_netplan

  block "Block04" "Enable IP forwarding & NAT for UE subnets (match working VM style)"
  apply_sysctl_and_nat

  block "Block05" "Loopback model validation (NO aliases; match working VM)"
  validate_loopback_model

  block "Block06" "Install MongoDB 6.0 (non-interactive)"
  install_mongodb_60

  block "Block07" "Install Open5GS + WebUI from PPA (no curl installer)"
  install_open5gs

  block "Block08" "Write Open5GS configs (SCP-based SBI)"
  write_open5gs_configs

  block "Block09" "Start services"
  enable_and_start_services

  block "Block10" "Auto-verification vs working VM model"
  verify_against_working_vm_model

  block "Block11" "Final core readiness validation"
  if ! core_readiness; then
    if [[ "${STRICT_READY,,}" == "true" ]]; then
      fail "Readiness failed (STRICT_READY=true). Check log: ${LOG_FILE}"
    else
      warn "Readiness failed but STRICT_READY=false; continuing. Log: ${LOG_FILE}"
    fi
  fi

  printf "\n=================================================\n"
  printf " ✅ KAOKAB5GC INSTALL COMPLETE\n"
  printf " Log: %s\n" "$LOG_FILE"
  printf "=================================================\n"
}

main "$@"
