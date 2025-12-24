#!/usr/bin/env bash
# 14.sh — Block06 v2: Correct Open5GS Core Configuration (Single Node)
set -Eeuo pipefail
IFS=$'\n\t'

LOG_DIR="/var/log/kaokab"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/block06-$(date +%F_%H%M%S).log"
touch "$LOG_FILE"; chmod 600 "$LOG_FILE"

info(){ echo -e "▶▶ $*" | tee -a "$LOG_FILE"; }
ok(){ echo -e "✔ $*" | tee -a "$LOG_FILE"; }
fail(){ echo -e "✖ $*" | tee -a "$LOG_FILE"; exit 1; }

require_root(){
  [[ $EUID -eq 0 ]] || fail "Run as root: sudo ./14.sh"
}

load_cfg(){
  [[ -f /etc/kaokab/kaokab.env ]] || fail "Missing /etc/kaokab/kaokab.env (run Block02 first)"
  # shellcheck disable=SC1091
  source /etc/kaokab/kaokab.env

  : "${S1AP_IP:?missing S1AP_IP}"
  : "${GTPU_IP:?missing GTPU_IP}"
  : "${UPF_IP:?missing UPF_IP}"
  : "${APN_POOL:?missing APN_POOL}"
  : "${APN_GW:?missing APN_GW}"
  : "${DNS1:?missing DNS1}"
  : "${DNS2:?missing DNS2}"
  : "${MCC:?missing MCC}"
  : "${MNC:?missing MNC}"
  : "${SST:?missing SST}"
  : "${SD:?missing SD}"
  : "${TAC:?missing TAC}"
  : "${GUAMI_REGION:?missing GUAMI_REGION}"
  : "${GUAMI_SET:?missing GUAMI_SET}"
}

backup_open5gs(){
  local bdir="/etc/open5gs/backup-$(date +%F_%H%M%S)"
  mkdir -p "$bdir"
  cp -a /etc/open5gs/*.yaml "$bdir"/ 2>/dev/null || true
  ok "Backup created: $bdir"
}

install_loopback_aliases(){
  info "Installing persistent loopback aliases for Open5GS (single node)"
  mkdir -p /usr/local/sbin

  cat >/usr/local/sbin/kaokab-loopback.sh <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

# Core loopbacks used by the Open5GS single-node pattern (avoid port collisions)
LO_IPS=(
  127.0.0.2   # MME
  127.0.0.3   # SGW-C
  127.0.0.4   # SMF
  127.0.0.5   # AMF
  127.0.0.6   # SGW-U
  127.0.0.7   # UPF
  127.0.0.8   # HSS (common pattern)
  127.0.0.9   # PCRF (common pattern)
  127.0.0.10  # NRF
  127.0.0.11  # AUSF
  127.0.0.12  # UDM
  127.0.0.13  # PCF
  127.0.0.14  # NSSF
  127.0.0.15  # BSF
  127.0.0.20  # UDR
  127.0.0.200 # SCP
)

# Optional SEPP lab addresses (only if you enable SEPP services later)
SEPP_IPS=(
  127.0.1.250 127.0.1.251 127.0.1.252
  127.0.2.250 127.0.2.251 127.0.2.252
)

# Set ENABLE_SEPP=1 to also add SEPP addresses
ENABLE_SEPP="${ENABLE_SEPP:-0}"

for ip in "${LO_IPS[@]}"; do
  ip addr show dev lo | grep -q "$ip" || ip addr add "$ip/8" dev lo
done

if [[ "$ENABLE_SEPP" == "1" ]]; then
  for ip in "${SEPP_IPS[@]}"; do
    ip addr show dev lo | grep -q "$ip" || ip addr add "$ip/8" dev lo
  done
fi
EOS

  chmod +x /usr/local/sbin/kaokab-loopback.sh

  cat >/etc/systemd/system/kaokab-loopback.service <<'EOS'
[Unit]
Description=Kaokab Open5GS loopback aliases
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=ENABLE_SEPP=0
ExecStart=/usr/local/sbin/kaokab-loopback.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOS

  systemctl daemon-reload
  systemctl enable --now kaokab-loopback.service
  ok "Loopback alias service installed and started (kaokab-loopback.service)"
}

write_yaml() {
  local f="$1"; shift
  cat >"/etc/open5gs/$f" <<EOF
$*
EOF
}

gen_configs(){
  info "Writing Open5GS YAML configs (Single Node)"

  # Important: keep SBI/PFCP on 127.0.0.x (matches your pattern and avoids port conflicts),
  # but bind NGAP/S1AP and GTP-U to real NIC IPs.

  # NRF
  write_yaml nrf.yaml "$(cat <<EOF
logger:
  file: /var/log/open5gs/nrf.log
  level: info
nrf:
  sbi:
    server:
      - address: 127.0.0.10
        port: 7777
metrics:
  server:
    - address: 127.0.0.10
      port: 9090
EOF
)"

  # SCP (because your AMF/SMF/UDR use scp client) :contentReference[oaicite:4]{index=4} :contentReference[oaicite:5]{index=5}
  write_yaml scp.yaml "$(cat <<EOF
logger:
  file: /var/log/open5gs/scp.log
  level: info
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
  write_yaml ausf.yaml "$(cat <<EOF
logger:
  file: /var/log/open5gs/ausf.log
  level: info
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
  write_yaml udm.yaml "$(cat <<EOF
logger:
  file: /var/log/open5gs/udm.log
  level: info
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
  write_yaml udr.yaml "$(cat <<EOF
db_uri: mongodb://localhost/open5gs
logger:
  file: /var/log/open5gs/udr.log
  level: info
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
  write_yaml pcf.yaml "$(cat <<EOF
logger:
  file: /var/log/open5gs/pcf.log
  level: info
pcf:
  sbi:
    server:
      - address: 127.0.0.13
        port: 7777
    client:
      scp:
        - uri: http://127.0.0.200:7777
EOF
)"

  # NSSF
  write_yaml nssf.yaml "$(cat <<EOF
logger:
  file: /var/log/open5gs/nssf.log
  level: info
nssf:
  sbi:
    server:
      - address: 127.0.0.14
        port: 7777
    client:
      scp:
        - uri: http://127.0.0.200:7777
EOF
)"

  # BSF
  write_yaml bsf.yaml "$(cat <<EOF
logger:
  file: /var/log/open5gs/bsf.log
  level: info
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

  # AMF — FIX: NGAP must bind to real S1AP/N2 IP (not 127.0.0.5 as you have now) :contentReference[oaicite:6]{index=6}
  # Also normalize SD format to 0x?????? for consistency.
  write_yaml amf.yaml "$(cat <<EOF
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
        - uri: http://127.0.0.200:7777

  ngap:
    server:
      - address: ${S1AP_IP}

  guami:
    - plmn_id:
        mcc: ${MCC}
        mnc: ${MNC}
      amf_id:
        region: ${GUAMI_REGION}
        set: ${GUAMI_SET}

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
          sd: 0x${SD}

metrics:
  server:
    - address: 127.0.0.5
      port: 9090
EOF
)"

  # SMF — keep PFCP on 127.0.0.4, but sessions must match APN pool
  write_yaml smf.yaml "$(cat <<EOF
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
        - uri: http://127.0.0.200:7777

  pfcp:
    server:
      - address: 127.0.0.4
    client:
      upf:
        - address: 127.0.0.7

  session:
    - subnet: ${APN_POOL}
      gateway: ${APN_GW}
      dnn: internet

  dns:
    - ${DNS1}
    - ${DNS2}

metrics:
  server:
    - address: 127.0.0.4
      port: 9090
EOF
)"

  # UPF — FIX: GTP-U must bind to real UPF_IP (not 127.0.0.7 like your current file) :contentReference[oaicite:7]{index=7}
  write_yaml upf.yaml "$(cat <<EOF
logger:
  file: /var/log/open5gs/upf.log
  level: info

upf:
  pfcp:
    server:
      - address: 127.0.0.7

  gtpu:
    server:
      - address: ${UPF_IP}

  session:
    - subnet: ${APN_POOL}
      gateway: ${APN_GW}
    - subnet: 2001:db8:cafe::/48
      gateway: 2001:db8:cafe::1

metrics:
  server:
    - address: 127.0.0.7
      port: 9090
EOF
)"

  # EPC pieces (minimal corrections so they bind to S1AP & GTPU properly)
  # MME — bind S1AP to real S1AP IP
  write_yaml mme.yaml "$(cat <<EOF
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
      mnc: ${MNC}
    mme_gid: ${GUAMI_REGION}
    mme_code: ${GUAMI_SET}
  tai:
    plmn_id:
      mcc: ${MCC}
      mnc: ${MNC}
    tac: ${TAC}

metrics:
  server:
    - address: 127.0.0.2
      port: 9090
EOF
)"

  # SGW-C (keep your PFCP model) :contentReference[oaicite:8]{index=8}
  write_yaml sgwc.yaml "$(cat <<EOF
logger:
  file: /var/log/open5gs/sgwc.log
  level: info

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

  # SGW-U — FIX: GTP-U must bind to real GTPU_IP (your current file uses 192.168.178.51) :contentReference[oaicite:9]{index=9}
  write_yaml sgwu.yaml "$(cat <<EOF
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

  ok "YAML files generated under /etc/open5gs"
}

restart_stack(){
  info "Restarting MongoDB + Open5GS in correct order"
  systemctl enable --now mongod >/dev/null 2>&1 || true
  systemctl restart mongod || fail "MongoDB failed to restart"

  # Stop all first (clean)
  systemctl stop 'open5gs-*' >/dev/null 2>&1 || true

  # Control plane base: NRF + SCP
  systemctl restart open5gs-nrfd
  sleep 1
  systemctl restart open5gs-scpd
  sleep 1

  # DB related NFs
  systemctl restart open5gs-udrd open5gs-udmd
  sleep 1
  systemctl restart open5gs-ausfd open5gs-pcfd open5gs-nssfd open5gs-bsfd
  sleep 1

  # Main CP/UP
  systemctl restart open5gs-amfd open5gs-smfd open5gs-upfd
  sleep 1

  # EPC
  systemctl restart open5gs-hssd open5gs-mmed open5gs-sgwcd open5gs-sgwud open5gs-pcrfd || true

  ok "Restart commands issued"
}

healthcheck(){
  info "Health check"
  systemctl is-active mongod | grep -q active || fail "mongod is not active"

  # Loopback aliases must exist
  ip -4 addr show lo | grep -q "127.0.0.10" || fail "Loopback alias missing (127.0.0.10)"

  # Core ports
  ss -tuln | grep -q ":7777" || fail "No SBI port 7777 listening"
  ss -tuln | grep -q ":8805" || info "Note: PFCP 8805 may not show in ss depending on protocol view"

  # Key services should be active
  systemctl is-active open5gs-nrfd open5gs-scpd open5gs-amfd open5gs-smfd open5gs-upfd | grep -q inactive && \
    fail "One or more critical services inactive"

  ok "Block06 v2 completed successfully"
  info "Next: check logs: /var/log/open5gs/amf.log and /var/log/open5gs/smf.log"
}

main(){
  require_root
  load_cfg
  backup_open5gs
  install_loopback_aliases
  gen_configs
  restart_stack
  sleep 2
  healthcheck
}

main
