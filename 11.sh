#!/usr/bin/env bash
# 11.SH — Kaokab5G Core Installer (EPC + 5GC) for Ubuntu 22.04
# Block01: Foundation (safety, logging, UX, OS checks)

set -Eeuo pipefail
IFS=$'\n\t'

# ----------------------------
# Global constants / paths
# ----------------------------
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
LOG_DIR="/var/log/kaokab"
LOG_FILE="${LOG_DIR}/kaokab-install-$(date +%F_%H%M%S).log"

# ----------------------------
# Colors (professional output)
# ----------------------------
GREEN="\e[32m"
RED="\e[31m"
BLUE="\e[34m"
YELLOW="\e[33m"
BOLD="\e[1m"
RESET="\e[0m"

# ----------------------------
# Logging helpers
# ----------------------------
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

log()   { echo -e "$*" | tee -a "$LOG_FILE" >/dev/null; }
info()  { log "${BOLD}${BLUE}[INFO]${RESET} $*"; }
ok()    { log "${BOLD}${GREEN}[OK]${RESET}   $*"; }
warn()  { log "${BOLD}${YELLOW}[WARN]${RESET} $*"; }
fail()  { log "${BOLD}${RED}[FAIL]${RESET} $*"; }

# Print last command on error
on_error() {
  local exit_code=$?
  local line_no=${BASH_LINENO[0]:-unknown}
  local cmd=${BASH_COMMAND:-unknown}
  fail "Error on line ${line_no}: ${cmd}"
  fail "Installer log: ${LOG_FILE}"
  exit "$exit_code"
}
trap on_error ERR

# ----------------------------
# Privilege check
# ----------------------------
require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Please run as root: sudo ./${SCRIPT_NAME}"
    exit 1
  fi
}

# ----------------------------
# OS check (Ubuntu 22.04 only)
# ----------------------------
check_os_ubuntu_2204() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "22.04" ]]; then
      fail "Unsupported OS. Required: Ubuntu 22.04. Detected: ${PRETTY_NAME:-unknown}"
      exit 1
    fi
  else
    fail "Cannot detect OS (missing /etc/os-release)."
    exit 1
  fi
  ok "OS check passed: Ubuntu 22.04"
}

# ----------------------------
# Basic package installer
# ----------------------------
apt_install() {
  local pkgs=("$@")
  info "Installing packages: ${pkgs[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" >>"$LOG_FILE" 2>&1
  ok "Packages installed: ${pkgs[*]}"
}

# ----------------------------
# Optional UX tools (figlet/toilet/dialog)
# ----------------------------
ensure_ux_tools() {
  local need=()
  command -v dialog >/dev/null 2>&1 || need+=("dialog")
  command -v figlet >/dev/null 2>&1 || need+=("figlet")
  command -v toilet >/dev/null 2>&1 || need+=("toilet")
  if (( ${#need[@]} )); then
    apt_install "${need[@]}"
  else
    ok "UX tools already present (dialog/figlet/toilet)"
  fi
}

show_banner() {
  clear || true
  local term_width
  term_width="$(tput cols 2>/dev/null || echo 120)"
  echo -e "${BOLD}${BLUE}"
  if command -v figlet >/dev/null 2>&1; then
    figlet -c -w "$term_width" "KAOKAB5G CORE"
    figlet -c -w "$term_width" "EPC + 5GC INSTALLER"
  else
    echo "KAOKAB5G CORE — EPC + 5GC INSTALLER"
  fi
  echo -e "${RESET}"
  info "Log file: ${LOG_FILE}"
}

# ----------------------------
# Block01 entry
# ----------------------------
block01_foundation() {
  require_root
  check_os_ubuntu_2204

  # Base utilities used by later blocks
  apt_install ca-certificates curl gnupg lsb-release software-properties-common

  # Nice-to-have UX tools
  ensure_ux_tools
  show_banner

  ok "Block01 complete: foundation ready."
}

# Execute Block01 only (for now)
block01_foundation
