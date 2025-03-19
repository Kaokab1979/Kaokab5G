#!/bin/bash
# Text formatting
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
BOLD='\033[1m'
BLINK='\033[5m'
RESET='\033[0m'

clear
echo -e "${BOLD}${BLINK}${YELLOW}🚀 RESTARTING KAOKAB SERVICES... PLEASE WAIT... 🚀${RESET}"
sleep 2

# Restart services
echo -e "${BOLD}${BLUE}🔄 Restarting all Open5GS services...${RESET}"
sudo systemctl restart open5gs-*

# Wait for services to restart
sleep 5

# Checking service status
echo -e "${BOLD}${YELLOW}✅ Checking KAOKAB services status...${RESET}"
status_output=$(systemctl is-active open5gs-*)
active_services=$(echo "$status_output" | grep -c "active")

# Display each service status with Green success message
services=(
    "open5gs-amfd.service"
    "open5gs-ausfd.service"
    "open5gs-bsfd.service"
    "open5gs-hssd.service"
    "open5gs-mmed.service"
    "open5gs-nrfd.service"
    "open5gs-nssfd.service"
    "open5gs-pcfd.service"
    "open5gs-pcrfd.service"
    "open5gs-scpd.service"
    "open5gs-seppd.service"
    "open5gs-sgwcd.service"
    "open5gs-sgwud.service"
    "open5gs-smfd.service"
    "open5gs-udmd.service"
    "open5gs-udrd.service"
    "open5gs-upfd.service"
    "open5gs-webui.service"
)

echo -e "\n${BOLD}${BLUE}📡 Current KAOKAB Services:${RESET}"
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo -e "${GREEN}✔ $service restarted successfully!${RESET}"
    else
        echo -e "${RED}❌ $service FAILED to restart!${RESET}"
    fi
done

# Summary message
if [ "$active_services" -eq 18 ]; then
    echo -e "\n${BOLD}${GREEN}✅ ALL KAOKAB SERVICES ARE RUNNING SUCCESSFULLY! 🎉${RESET}"
else
    echo -e "\n${BOLD}${RED}⚠️ WARNING: Some services are not running! Check logs for more details.${RESET}"
fi

# Open logs for monitoring
echo -e "\n${BOLD}${YELLOW}📜 Opening MME logs...${RESET}"
sudo tail -f /var/log/open5gs/mme.log
