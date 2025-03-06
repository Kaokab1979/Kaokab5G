#!/bin/bash

# Define text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${BOLD}${BLUE}Starting KAOKAB Uninstallation Process...${RESET}"
sleep 2

# Step 1: Purge KAOKAB Packages
echo -e "${BOLD}${BLUE}Step 1: Purging KAOKAB packages...${RESET}"
sudo apt purge -y open5gs
sleep 2

# Step 2: Remove Unnecessary Packages
echo -e "${BOLD}${BLUE}Step 2: Removing unnecessary packages...${RESET}"
sudo apt autoremove -y
sleep 2

# Step 3: Remove KAOKAB Log Directory
echo -e "${BOLD}${BLUE}Step 3: Removing KAOKAB log directory...${RESET}"
sudo rm -Rf /var/log/open5gs
sleep 2

# Step 4: Uninstall KAOKAB WebUI
echo -e "${BOLD}${BLUE}Step 4: Uninstalling KAOKAB WebUI...${RESET}"
curl -fsSL https://open5gs.org/open5gs/assets/webui/uninstall | sudo -E bash -
sleep 2

# Step 5: Verify Removal
echo -e "${BOLD}${BLUE}Step 5: Verifying removal of KAOKAB packages...${RESET}"
if dpkg -l | grep -q open5gs; then
    echo -e "${RED}⚠️ Some KAOKAB packages are still installed:${RESET}"
    dpkg -l | grep open5gs
else
    echo -e "${GREEN}✅ All KAOKAB packages have been removed.${RESET}"
fi

echo -e "${BOLD}${BLUE}Checking if /var/log/open5gs directory exists...${RESET}"
if [ -d "/var/log/open5gs" ]; then
    echo -e "${RED}⚠️ /var/log/open5gs still exists. Removing it...${RESET}"
    sudo rm -Rf /var/log/open5gs
else
    echo -e "${GREEN}✅ /var/log/open5gs has been removed.${RESET}"
fi
sleep 2

# Step 6: Clean Up KAOKAB Directories
echo -e "${BOLD}${BLUE}Step 6: Removing any leftover KAOKAB files or directories...${RESET}"

# Remove KAOKAB directories from /root
echo -e "${BOLD}${BLUE}Removing KAOKAB directories from /root...${RESET}"
sudo rm -Rf /root/Open5Gs*

# Remove KAOKAB directories from all /home/* directories
for dir in /home/*; do
    if [ -d "$dir" ]; then
        echo -e "${BOLD}${BLUE}Removing KAOKAB directories from $dir...${RESET}"
        sudo rm -Rf "$dir"/Open5Gs*
    fi
done

# Remove specific KAOKAB packages if they are in 'rc' state
echo -e "${BOLD}${BLUE}Purging specific KAOKAB packages...${RESET}"
sudo apt purge -y open5gs-amf open5gs-ausf open5gs-bsf open5gs-common open5gs-hss open5gs-mme open5gs-nrf open5gs-nssf open5gs-pcf open5gs-pcrf open5gs-scp open5gs-sgwc open5gs-sgwu open5gs-smf open5gs-udm open5gs-udr open5gs-upf
sudo apt autoremove -y
sleep 2

# Final Check
echo -e "${BOLD}${BLUE}Final check to ensure no KAOKAB files or directories remain...${RESET}"
if [ -d "/var/log/open5gs" ]; then
    echo -e "${RED}⚠️ /var/log/open5gs still exists. Removing it...${RESET}"
    sudo rm -Rf /var/log/open5gs
else
    echo -e "${GREEN}✅ /var/log/open5gs has been removed.${RESET}"
fi
sleep 2

# Remove any remaining KAOKAB packages
echo -e "${BOLD}${BLUE}Removing any remaining KAOKAB packages...${RESET}"
sudo apt purge -y open5gs-sepp
sudo apt autoremove -y
sleep 2

# Step 7: Remove KAOKAB NAT Rules
echo -e "${BOLD}${BLUE}Step 7: Removing KAOKAB NAT rules from iptables...${RESET}"

# List all rules and delete any related to ogstun
sudo iptables -t nat -S | grep 'ogstun' | while read -r rule; do
    sudo iptables -t nat -D ${rule#*-A }
done

echo -e "${GREEN}✅ All KAOKAB NAT rules related to ogstun have been removed.${RESET}"
sleep 2
# Remove Kaokab5G directory
echo -e "${BOLD}${BLUE}Removing /root/Kaokab5G directory...${RESET}"
sudo rm -rf /root/Kaokab5G
echo -e "${GREEN}✅ /root/Kaokab5G has been removed.${RESET}"
sleep 2

# Step 8: Uninstall MongoDB
echo -e "${BOLD}${BLUE}Step 8: Uninstalling MongoDB...${RESET}"
sudo systemctl stop mongod
sudo apt purge -y mongodb-org*
sudo rm -r /var/log/mongodb
sudo rm -r /var/lib/mongodb
sudo rm /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt update
sleep 2

# Display Final Message in Large Font
echo -e "${BOLD}${GREEN}"
echo "=========================================="
echo "      ✅ KAOKAB UNINSTALL COMPLETE! ✅     "
echo "=========================================="
echo -e "${RESET}"
sleep 2
