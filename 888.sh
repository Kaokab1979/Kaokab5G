#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# KAOKAB5GC WEBUI & SUBSCRIBER PROVISIONING (888.sh)
# Layer: GUI + MongoDB provisioning
# Prerequisite: 777.sh completed successfully
###############################################################################

# ------------------------- logging / UX ---------------------------------------
TS="$(date +'%Y-%m-%d_%H%M%S')"
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/kaokab5gc-webui-${TS}.log"

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
fail(){ echo "${RED}[FAIL]${RST} $*"; exit 1; }

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
  printf "║ ✅ KAOKAB5GC WEBUI & SUBSCRIBER LAYER                                       ║\n"
  printf "╚══════════════════════════════════════════════════════════════════════════════╝\n"
  info "Log file: ${LOG_FILE}"
}

has_cmd(){ command -v "$1" >/dev/null 2>&1; }
svc_active(){ systemctl is-active --quiet "$1"; }

# ------------------------- main ------------------------------------------------
main(){
  banner

  # ===========================================================================
  block "Block01" "Preflight checks\nEnsure core network is running"
  # ===========================================================================
  [[ $EUID -eq 0 ]] || fail "Run as root."

  svc_active mongod        || fail "MongoDB not running"
  svc_active open5gs-amfd || fail "AMF not running"
  svc_active open5gs-smfd || fail "SMF not running"
  svc_active open5gs-upfd || fail "UPF not running"

  ok "Core EPC + 5GC is healthy"

  # ===========================================================================
  block "Block02" "Install NodeJS (LTS) for Open5GS WebUI"
  # ===========================================================================
  if ! has_cmd node; then
    info "Installing NodeJS 20 LTS"
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
  else
    ok "NodeJS already installed"
  fi

  node -v
  npm -v
  ok "NodeJS environment ready"

  # ===========================================================================
  block "Block03" "Install Open5GS WebUI"
  # ===========================================================================
  WEBUI_ROOT="/opt/open5gs"
  WEBUI_DIR="${WEBUI_ROOT}/webui"

  if [[ ! -d "$WEBUI_DIR" ]]; then
    info "Cloning Open5GS repository"
    git clone https://github.com/open5gs/open5gs.git "$WEBUI_ROOT"
  else
    ok "Open5GS repo already present"
  fi

  cd "$WEBUI_DIR"

  if [[ ! -d node_modules ]]; then
    info "Installing WebUI dependencies"
    npm install
  else
    ok "WebUI dependencies already installed"
  fi

  ok "WebUI installed"

  # ===========================================================================
  block "Block04" "Configure WebUI environment"
  # ===========================================================================
  cat > "${WEBUI_DIR}/.env" <<EOF
HOST=0.0.0.0
PORT=3000
DB_URI=mongodb://localhost/open5gs
NODE_ENV=production
EOF

  ok "WebUI environment configured"

  # ===========================================================================
  block "Block05" "Create & start WebUI systemd service"
  # ===========================================================================
  cat > /etc/systemd/system/open5gs-webui.service <<EOF
[Unit]
Description=Open5GS WebUI
After=network.target mongod.service
Requires=mongod.service

[Service]
Type=simple
WorkingDirectory=${WEBUI_DIR}
ExecStart=/usr/bin/npm run dev
Restart=always
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now open5gs-webui

  sleep 2
  svc_active open5gs-webui || fail "WebUI service failed"

  ok "WebUI service running"

  # ===========================================================================
  block "Block06" "Create default admin user (bootstrap)"
  # ===========================================================================
  if ! mongosh open5gs --quiet --eval 'db.users.findOne({username:"admin"})' | grep -q admin; then
    info "Creating default admin user"
    npm run create-admin <<EOF
admin
admin
admin123
admin123
EOF
    ok "Admin user created"
  else
    ok "Admin user already exists"
  fi

  # ===========================================================================
  block "Block07" "Optional: create test subscriber"
  # ===========================================================================
  if ! mongosh open5gs --quiet --eval 'db.subscribers.findOne({imsi:"204610000000001"})' | grep -q imsi; then
    info "Adding test subscriber"
    mongosh open5gs <<EOF
db.subscribers.insertOne({
  imsi: "204610000000001",
  key: "465B5CE8B199B49FAA5F0A2EE238A6BC",
  opc: "E8ED289DEBA952E4283B54E88E6183CA",
  amf: "8000",
  slice: [{ sst: 1, sd: "010203" }],
  dnn: ["internet", "ims"]
})
EOF
    ok "Test subscriber added"
  else
    ok "Test subscriber already exists"
  fi

  # ===========================================================================
  block "Block08" "WebUI readiness & access summary"
  # ===========================================================================
  ss -lntp | grep ':3000' >/dev/null || fail "WebUI not listening on port 3000"

  IP="$(hostname -I | awk '{print $1}')"

  echo
  printf "╔════════════════════════════════════════════════════════════════════╗n"
  printf "║ 🌐 Open5GS WebUI READY                                             ║n"
  printf "╠════════════════════════════════════════════════════════════════════╣n"
  printf "║ URL : http://%s:3000                                                ║n" "$IP"
  printf "║ USER: admin                                                         ║n"
  printf "║ PASS: admin123                                                      ║n"
  printf "╚════════════════════════════════════════════════════════════════════╝n"

  ok "WebUI layer fully operational"
  info "Log saved at: $LOG_FILE"
}

main "$@"
