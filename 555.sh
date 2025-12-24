#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

#################################################
# KAOKAB5GC — Unified Installer (Single Node)
# Ubuntu 22.04 | Open5GS 2.7.x | MongoDB 6.0
#################################################

### -----------------------------
### GLOBALS
### -----------------------------
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/kaokab5gc-install-$(date +%F_%H%M%S).log"

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

log()   { echo -e "$*" | tee -a "$LOG_FILE"; }
info()  { log "\e[1;34m[INFO]\e[0m  $*"; }
ok()    { log "\e[1;32m[OK]\e[0m    $*"; }
warn()  { log "\e[1;33m[WARN]\e[0m  $*"; }
fail()  { log "\e[1;31m[FAIL]\e[0m  $*"; exit 1; }

trap 'fail "Error at line $LINENO. See $LOG_FILE"' ERR

### -----------------------------
### BLOCK 01 — SYSTEM CHECK
### -----------------------------
info "Block01: System validation"

[[ $EUID -eq 0 ]] || fail "Run as root"

. /etc/os-release
[[ "$ID" == "ubuntu" && "$VERSION_ID" == "22.04" ]] \
  || fail "Ubuntu 22.04 required"

ok "OS OK: Ubuntu 22.04"
ok "Privileges OK: root"
ok "Log file: $LOG_FILE"

### -----------------------------
### BLOCK 02 — BASE TOOLS
### -----------------------------
info "Block02: Installing base tools"
apt update -y >>"$LOG_FILE"
apt install -y curl wget gnupg lsb-release ca-certificates \
               iptables iproute2 net-tools \
               dialog figlet >>"$LOG_FILE"
ok "Base tools installed"

clear
figlet -c "KAOKAB5GC"
figlet -c "INSTALLER"

### -----------------------------
### BLOCK 03 — IP FORWARDING & NAT
### -----------------------------
info "Block03: Enabling IP forwarding & NAT"

sysctl -w net.ipv4.ip_forward=1 >>"$LOG_FILE"
sed -i 's/^#\?net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf

iptables -t nat -C POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE \
  2>/dev/null || \
iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE

ok "IP forwarding & NAT enabled"

### -----------------------------
### BLOCK 04 — LOOPBACK ALIASES
### -----------------------------
info "Block04: Installing loopback aliases"

cat >/etc/systemd/system/kaokab-loopback.service <<'EOF'
[Unit]
Description=Kaokab Open5GS Loopback Aliases
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c '\
for i in {2..20} 200; do \
  ip addr add 127.0.0.$i/8 dev lo 2>/dev/null || true; \
done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now kaokab-loopback.service
ok "Loopback aliases installed"

### -----------------------------
### BLOCK 05 — MONGODB
### -----------------------------
info "Block05: Installing MongoDB"

curl -fsSL https://pgp.mongodb.com/server-6.0.asc \
 | gpg --dearmor -o /usr/share/keyrings/mongodb-server-6.0.gpg

echo "deb [signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg] \
https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" \
> /etc/apt/sources.list.d/mongodb-org-6.0.list

apt update -y >>"$LOG_FILE"
apt install -y mongodb-org >>"$LOG_FILE"

systemctl enable --now mongod
ok "MongoDB installed & running"

### -----------------------------
### BLOCK 06 — OPEN5GS
### -----------------------------
info "Block06: Installing Open5GS"

add-apt-repository -y ppa:open5gs/latest >>"$LOG_FILE"
apt update -y >>"$LOG_FILE"
apt install -y open5gs >>"$LOG_FILE"

ok "Open5GS installed"

### -----------------------------
### BLOCK 07 — OPEN5GS CONFIG
### -----------------------------
info "Block07: Configuring Open5GS (Single Node)"

CFG=/etc/open5gs
BACKUP="$CFG/backup-$(date +%F_%H%M%S)"
mkdir -p "$BACKUP"
cp -a "$CFG"/*.yaml "$BACKUP"/ 2>/dev/null || true
ok "Backup created: $BACKUP"

#### AMF
cat >$CFG/amf.yaml <<'EOF'
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
      - address: 192.168.178.80
  metrics:
    server:
      - address: 127.0.0.5
        port: 9090
  guami:
    - plmn_id:
        mcc: "204"
        mnc: "61"
      amf_id:
        region: 1
        set: 1
  tai:
    - plmn_id:
        mcc: "204"
        mnc: "61"
      tac: 1
  plmn_support:
    - plmn_id:
        mcc: "204"
        mnc: "61"
      s_nssai:
        - sst: 1
          sd: 010203
  network_name:
    full: Kaokab
    short: Kaokab
  amf_name: kaokab-amf0
EOF

#### NRF
cat >$CFG/nrf.yaml <<'EOF'
logger:
  file:
    path: /var/log/open5gs/nrf.log

nrf:
  serving:
    - plmn_id:
        mcc: "204"
        mnc: "61"
  sbi:
    server:
      - address: 127.0.0.10
        port: 7777
EOF

#### SMF
cat >$CFG/smf.yaml <<'EOF'
logger:
  file:
    path: /var/log/open5gs/smf.log

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
  gtpu:
    server:
      - address: 127.0.0.4
  session:
    - subnet: 10.45.0.0/16
      gateway: 10.45.0.1
      dnn: internet
  dns:
    - 1.1.1.1
    - 1.0.0.1
EOF

chown open5gs:open5gs $CFG/*.yaml
chmod 640 $CFG/*.yaml

ok "Open5GS configuration written"

### -----------------------------
### BLOCK 08 — START SERVICES
### -----------------------------
info "Block08: Starting Open5GS"

systemctl restart open5gs-nrfd
sleep 2
systemctl restart open5gs-scpd
sleep 2
systemctl restart open5gs-ausfd open5gs-udmd open5gs-udrd open5gs-pcfd open5gs-nssfd open5gs-bsfd
sleep 2
systemctl restart open5gs-smfd open5gs-upfd
sleep 2
systemctl restart open5gs-amfd

ok "Open5GS services started"

### -----------------------------
### BLOCK 09 — HEALTH CHECK
### -----------------------------
info "Block09: Health check"

ss -tuln | grep -q 7777 && ok "SBI ports listening" || fail "No SBI ports"

systemctl is-active open5gs-amfd open5gs-smfd open5gs-upfd >/dev/null \
  && ok "Core services running" \
  || fail "Core services not healthy"

### -----------------------------
### FINAL
### -----------------------------
log ""
log "================================================="
log " ✅ KAOKAB5GC INSTALLATION COMPLETE"
log "================================================="
log " WebUI & subscribers can now be added"
log " Log file: $LOG_FILE"
