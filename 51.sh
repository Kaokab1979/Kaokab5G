#!/usr/bin/env bash
set -euo pipefail

# =================================================
#  KAOKAB5GC FULL UNINSTALL SCRIPT
#  Removes everything installed by 11.sh → 555.sh
# =================================================

# ---------- COLORS ----------
RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;34m"
YELLOW="\033[1;33m"
RESET="\033[0m"
BOLD="\033[1m"

# ---------- BANNER ----------
clear
echo -e "${BLUE}${BOLD}"
cat <<'EOF'
=================================================
 🧹 KAOKAB5GC FULL UNINSTALL
=================================================
 This will REMOVE:
  • Open5GS (EPC + 5GC)
  • MongoDB
  • Loopback aliases
  • NAT rules
  • Kaokab configs & logs
  • Restore Netplan (if backup exists)
=================================================
EOF
echo -e "${RESET}"

# ---------- SAFETY CHECK ----------
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}✖ Please run as root: sudo ./51.sh${RESET}"
  exit 1
fi

echo -e "${YELLOW}⚠ This operation is destructive.${RESET}"
read -rp "Type YES to continue: " CONFIRM
[[ "$CONFIRM" == "YES" ]] || { echo "Aborted."; exit 1; }

# =================================================
# STOP & DISABLE OPEN5GS
# =================================================
echo -e "\n${BLUE}▶ Stopping Open5GS services${RESET}"
systemctl list-units --type=service | awk '/open5gs-/{print $1}' | xargs -r systemctl stop || true
systemctl list-unit-files | awk '/open5gs-.*enabled/{print $1}' | xargs -r systemctl disable || true

# =================================================
# REMOVE LOOPBACK SERVICE
# =================================================
echo -e "\n${BLUE}▶ Removing loopback alias service${RESET}"
systemctl stop kaokab-loopback.service 2>/dev/null || true
systemctl disable kaokab-loopback.service 2>/dev/null || true
rm -f /etc/systemd/system/kaokab-loopback.service
systemctl daemon-reload

# =================================================
# REMOVE LOOPBACK IP ALIASES
# =================================================
echo -e "\n${BLUE}▶ Removing loopback IP aliases${RESET}"
for ip in {2..20} 200; do
  ip addr del 127.0.0.$ip/8 dev lo 2>/dev/null || true
done

# =================================================
# REMOVE NAT RULES
# =================================================
echo -e "\n${BLUE}▶ Removing NAT (MASQUERADE) rules${RESET}"
iptables -t nat -D POSTROUTING -s 10.45.0.0/16 -j MASQUERADE 2>/dev/null || true
iptables -t nat -D POSTROUTING -s 10.46.0.0/16 -j MASQUERADE 2>/dev/null || true
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

# =================================================
# REMOVE OPEN5GS PACKAGES
# =================================================
echo -e "\n${BLUE}▶ Removing Open5GS packages${RESET}"
apt purge -y 'open5gs*' || true
apt autoremove -y || true

# =================================================
# REMOVE MONGODB
# =================================================
echo -e "\n${BLUE}▶ Removing MongoDB${RESET}"
systemctl stop mongod 2>/dev/null || true
systemctl disable mongod 2>/dev/null || true

apt purge -y mongodb-org\* mongodb-database-tools mongodb-mongosh || true
rm -rf /var/lib/mongodb /var/log/mongodb
rm -f /etc/apt/sources.list.d/mongodb-org-*.list
rm -f /etc/apt/keyrings/mongodb-server-*.gpg

# =================================================
# REMOVE CONFIGS & LOGS
# =================================================
echo -e "\n${BLUE}▶ Removing Open5GS configs & logs${RESET}"
rm -rf /etc/open5gs
rm -rf /var/log/open5gs

# =================================================
# REMOVE KAOKAB CONFIG
# =================================================
echo -e "\n${BLUE}▶ Removing Kaokab configuration${RESET}"
rm -rf /etc/kaokab
rm -rf /var/log/kaokab

# =================================================
# RESTORE NETPLAN (IF BACKUP EXISTS)
# =================================================
NETPLAN_DIR="/etc/netplan"
LATEST_BACKUP=$(ls -d /etc/netplan/backup-* 2>/dev/null | sort | tail -n1 || true)

if [[ -n "$LATEST_BACKUP" ]]; then
  echo -e "\n${BLUE}▶ Restoring Netplan from ${LATEST_BACKUP}${RESET}"
  rm -f ${NETPLAN_DIR}/*.yaml
  cp -a "${LATEST_BACKUP}"/*.yaml "${NETPLAN_DIR}/"
  netplan generate
  netplan apply
else
  echo -e "${YELLOW}ℹ No Netplan backup found — skipping restore${RESET}"
fi

# =================================================
# FINAL VERIFICATION
# =================================================
echo -e "\n${BLUE}▶ Final verification${RESET}"

if dpkg -l | grep -q open5gs; then
  echo -e "${RED}✖ Open5GS packages still present${RESET}"
else
  echo -e "${GREEN}✔ Open5GS removed${RESET}"
fi

if systemctl list-units | grep -q open5gs; then
  echo -e "${RED}✖ Open5GS services still running${RESET}"
else
  echo -e "${GREEN}✔ No Open5GS services active${RESET}"
fi

if systemctl is-active --quiet mongod; then
  echo -e "${RED}✖ MongoDB still running${RESET}"
else
  echo -e "${GREEN}✔ MongoDB removed${RESET}"
fi

if [[ -d /etc/kaokab ]]; then
  echo -e "${RED}✖ /etc/kaokab still exists${RESET}"
else
  echo -e "${GREEN}✔ Kaokab config removed${RESET}"
fi

# =================================================
# DONE
# =================================================
echo -e "\n${GREEN}${BOLD}"
echo "================================================="
echo " ✅ KAOKAB5GC UNINSTALL COMPLETE"
echo " System is clean and ready for 555.sh"
echo "================================================="
echo -e "${RESET}"
