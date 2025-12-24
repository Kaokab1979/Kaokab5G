#!/usr/bin/env bash
# 13.sh — Kaokab5G Core Installation
# Block05: MongoDB + Open5GS EPC/5GC installation (no config yet)

set -Eeuo pipefail
IFS=$'\n\t'

# ----------------------------
# Globals / logging
# ----------------------------
SCRIPT_NAME="$(basename "$0")"
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/kaokab-core-install-$(date +%F_%H%M%S).log"

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

require_root() {
  [[ $EUID -eq 0 ]] || { fail "Run as root: sudo ./${SCRIPT_NAME}"; exit 1; }
}

apt_install() {
  DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >>"$LOG_FILE" 2>&1
}

load_cfg() {
  local cfg="/etc/kaokab/kaokab.env"
  [[ -f "$cfg" ]] || { fail "Missing $cfg — run 11.sh first"; exit 1; }
  # shellcheck disable=SC1091
  source "$cfg"
  ok "Loaded config: $cfg"
}

# ============================================================
# Block05: MongoDB + Open5GS install
# ============================================================
block05_install_core() {
  echo -e "${BOLD}${BLUE}▶▶ Block05: Installing Core Software (MongoDB + Open5GS)${RESET}"
  info "Starting Block05"

  load_cfg

  # ----------------------------
  # Base dependencies
  # ----------------------------
  info "Installing base dependencies"
  apt_install ca-certificates curl gnupg lsb-release software-properties-common
  ok "Base dependencies installed"

  # ----------------------------
  # MongoDB 6.0
  # ----------------------------
  info "Installing MongoDB 6.0"

  if ! command -v mongod &>/dev/null; then
    curl -fsSL https://pgp.mongodb.com/server-6.0.asc \
      | gpg --dearmor -o /usr/share/keyrings/mongodb-server-6.0.gpg

    echo "deb [ arch=amd64 signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg ] \
https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" \
      > /etc/apt/sources.list.d/mongodb-org-6.0.list

    apt_install mongodb-org
  else
    ok "MongoDB already installed"
  fi

  systemctl enable mongod >>"$LOG_FILE" 2>&1
  systemctl start mongod
  systemctl is-active --quiet mongod || { fail "MongoDB failed to start"; exit 1; }
  ok "MongoDB running"

  # ----------------------------
  # Open5GS repository
  # ----------------------------
  info "Adding Open5GS repository"

  if ! grep -q open5gs /etc/apt/sources.list.d/* 2>/dev/null; then
    add-apt-repository -y ppa:open5gs/latest >>"$LOG_FILE" 2>&1
  else
    ok "Open5GS repository already present"
  fi

  # ----------------------------
  # Open5GS install
  # ----------------------------
  info "Installing Open5GS EPC + 5GC packages"

  apt_install open5gs

  # ----------------------------
  # Enable services (do not configure yet)
  # ----------------------------
  info "Enabling Open5GS services"

  systemctl daemon-reexec >>"$LOG_FILE" 2>&1

  for svc in open5gs-*; do
    systemctl enable "$svc" >>"$LOG_FILE" 2>&1 || true
  done

  ok "Open5GS services enabled"

  # ----------------------------
  # Validation
  # ----------------------------
  info "Validating core installation"

  command -v open5gs-amfd &>/dev/null || fail "Open5GS AMF binary missing"
  command -v open5gs-smfd &>/dev/null || fail "Open5GS SMF binary missing"
  command -v open5gs-upfd &>/dev/null || fail "Open5GS UPF binary missing"

  systemctl list-unit-files | grep -q open5gs || fail "Open5GS systemd units missing"

  ok "Core software installed successfully"
  echo -e "${BOLD}${GREEN}✔ Block05 completed successfully${RESET}"
  info "Log saved at: $LOG_FILE"
}

# ----------------------------
# Main
# ----------------------------
main() {
  require_root
  block05_install_core
}

main "$@"
