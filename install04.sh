#!/bin/bash 
# CapX Core 2024 by Jeffrey Timmer | Forat Selman | Philip Prins
# Based on open-source core

# Define color codes for professional output
GREEN="\e[32m"
RED="\e[31m"
BLUE="\e[34m"
BOLD="\e[1m"
RESET="\e[0m"

# Echo message before checking the OS
echo -e "${BOLD}${BLUE}Checking the OS version...${RESET}"
issue=$(head -n 1 /etc/issue 2>/dev/null)

# OS check
if [[ "$issue" == Ubuntu\ 22.04* ]]; then
    OS=ubuntu2204
    # Large, clear success message
    echo -e "\n\033[1;32m"
    echo "=================================================="
    echo "✅  YOUR SERVER MEETS THE STANDARD SPECIFICATIONS"
    echo "                OF UBUNTU 22.04                   "
    echo "=================================================="
    echo -e "\033[0m"

    # Prompt user to continue
    echo -e "${BOLD}${BLUE}Press ENTER to proceed with the installation.${RESET}"
    read -r
else
    # Large error message if OS does not meet requirements
    echo -e "\n\033[1;31m"
    echo "=================================================="
    echo "❌ ERROR: UNSUPPORTED OPERATING SYSTEM DETECTED!"
    echo "      INSTALLATION CAN ONLY RUN ON UBUNTU 22.04   "
    echo "=================================================="
    echo -e "\033[0m"

    # Instruction to verify and exit
    echo -e "${BOLD}${RED}Please verify your OS version and try again.${RESET}"
    echo -e "${BOLD}${RED}Press Ctrl+C to exit.${RESET}"
    exit 1
fi
# Install required packages
echo -e "\n${BOLD}${BLUE}Step 1: Installing required system packages...${RESET}"
sudo apt update
sudo apt install -y vim net-tools ca-certificates curl gnupg nodejs iputils-ping git software-properties-common iptables
echo -e "${GREEN}✅ System packages installed.${RESET}"

# Enable and restart systemd-networkd
echo -e "\n${BOLD}${BLUE}Step 2: Configuring system networking...${RESET}"
sudo systemctl enable systemd-networkd
sudo systemctl restart systemd-networkd
echo -e "${GREEN}✅ System networking configured.${RESET}"

# Install MongoDB
echo -e "\n${BOLD}${BLUE}Step 3: Installing MongoDB...${RESET}"
sudo apt update
sudo apt install -y gnupg

# Import MongoDB public key
echo -e "${BOLD}${BLUE}Adding MongoDB public key...${RESET}"
curl -fsSL https://pgp.mongodb.com/server-6.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-6.0.gpg --dearmor
echo -e "${GREEN}✅ MongoDB public key added.${RESET}"

# Add MongoDB repository
echo -e "\n${BOLD}${BLUE}Adding MongoDB repository to sources list...${RESET}"
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
echo -e "${GREEN}✅ MongoDB repository added.${RESET}"

# Install MongoDB
echo -e "\n${BOLD}${BLUE}Installing MongoDB packages...${RESET}"
sudo apt update
sudo apt install -y mongodb-org
echo -e "${GREEN}✅ MongoDB installation completed.${RESET}"

# Start and enable MongoDB service
echo -e "\n${BOLD}${BLUE}Starting and enabling MongoDB service...${RESET}"
sudo systemctl start mongod
sudo systemctl enable mongod
sleep 2
echo -e "${GREEN}✅ MongoDB is now running and enabled on system startup.${RESET}"

# Verify MongoDB is running
echo -e "\n${BOLD}${BLUE}Checking MongoDB status...${RESET}"
if systemctl is-active --quiet mongod; then
    echo -e "${GREEN}✅ MongoDB is active and running.${RESET}"
else
    echo -e "${RED}❌ ERROR: MongoDB is not running! Please check the logs.${RESET}"
    exit 1
fi
#!/bin/bash

# Clone the Kaokab5G repository
echo -e "\n${BOLD}${BLUE}Step 1: Cloning Kaokab5G repository...${RESET}"
git clone https://github.com/Kaokab1979/Kaokab5G.git
echo -e "${GREEN}✅ Kaokab5G repository cloned successfully.${RESET}"
sleep 2

# Install KAOKAB
echo -e "\n${BOLD}${BLUE}Step 2: Installing KAOKAB...${RESET}"
sudo add-apt-repository -y ppa:open5gs/latest
sudo apt update
sudo apt install -y open5gs
echo -e "${GREEN}✅ KAOKAB installed successfully.${RESET}"
sleep 2

# Install Node.js and KAOKAB WebUI
echo -e "\n${BOLD}${BLUE}Step 3: Installing Node.js and KAOKAB WebUI...${RESET}"
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sleep 2

# Add Node.js repository
echo -e "${BOLD}${BLUE}Adding Node.js repository...${RESET}"
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
NODE_MAJOR=20
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list
sudo apt update
sudo apt install -y nodejs
echo -e "${GREEN}✅ Node.js installed successfully.${RESET}"
sleep 2

# Install KAOKAB WebUI
echo -e "\n${BOLD}${BLUE}Installing KAOKAB WebUI...${RESET}"
curl -fsSL https://open5gs.org/open5gs/assets/webui/install | sudo -E bash -
echo -e "${GREEN}✅ KAOKAB WebUI installed successfully.${RESET}"
sleep 2

# Apply Kaokab5G configurations
echo -e "\n${BOLD}${BLUE}Applying Kaokab5G configurations...${RESET}"
cp -fR /root/Kaokab5G/usr/lib/node_modules/open5gs/next/* /usr/lib/node_modules/open5gs/.next/
cp -fR /root/Kaokab5G/Open5GS/* /etc/open5gs/
echo -e "${GREEN}✅ Kaokab5G configurations applied successfully.${RESET}"
sleep 2

echo -e "\n${BOLD}${GREEN}🎉 Installation of KAOKAB and its components is complete!${RESET}"
# Configure IP forwarding permanently
    echo -e "${BOLD}${BLUE}Enabling IP forwarding...${RESET}"
    echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-open5gs.conf
    echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.d/99-open5gs.conf
    sudo sysctl --system

    # Display the result of IP forwarding status
    echo -e "${BOLD}${BLUE}IP forwarding status:${RESET}"
    sysctl net.ipv4.ip_forward

    # Configure NAT rules
    echo -e "${BOLD}${BLUE}Configuring NAT rules...${RESET}"
    sudo iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE
    sudo ip6tables -t nat -A POSTROUTING -s 2001:db8:cafe::/48 ! -o ogstun -j MASQUERADE

    # Save iptables rules to be persistent
    echo -e "${BOLD}${BLUE}Saving iptables rules...${RESET}"
    sudo apt-get install -y iptables-persistent
    sudo netfilter-persistent save
    sudo netfilter-persistent reload

    # Display the result of NAT rules for ogstun
    echo -e "${BOLD}${BLUE}Current NAT rules for ogstun:${RESET}"
    sudo iptables -t nat -S | grep ogstun

    echo -e "${GREEN}✅ IP forwarding and NAT rules have been set up and made persistent.${RESET}"

# Modify open5gs-webui.service to allow access from 0.0.0.0:9999
echo -e "${BOLD}${BLUE}Modifying open5gs-webui.service...${RESET}"
sudo tee /lib/systemd/system/open5gs-webui.service > /dev/null <<EOF
[Unit]
Description=Open5GS WebUI
Wants=mongodb.service mongod.service

[Service]
Type=simple
WorkingDirectory=/usr/lib/node_modules/open5gs
Environment=NODE_ENV=production
Environment=HOSTNAME=0.0.0.0
Environment=PORT=9999
ExecStart=/usr/bin/node server/index.js --address \${HOSTNAME} --port \${PORT}
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and restart the service
echo -e "${BOLD}${BLUE}Reloading systemd and restarting the Open5GS WebUI service...${RESET}"
sudo systemctl daemon-reload

# Sleep for a few seconds to allow systemd to reload and update the service
sleep 3

sudo systemctl restart open5gs-webui
sudo systemctl enable open5gs-webui
sleep 3
# Verify if the service is listening on 0.0.0.0:9999
echo -e "${BOLD}${BLUE}Checking if KAOKAB WebUI is listening on 0.0.0.0:9999...${RESET}"
if sudo ss -tuln | grep -q "0.0.0.0:9999"; then
    echo -e "${GREEN}✅ KAOKAB WebUI is successfully listening on 0.0.0.0:9999${RESET}"
else
    echo -e "${RED}❌ ERROR: KAOKAB WebUI is NOT listening on 0.0.0.0:9999. Check service status.${RESET}"
    sudo systemctl status open5gs-webui --no-pager
    exit 1
fi

    # Check the status of all Open5GS services
    echo -e "${BOLD}${BLUE}Checking KAOKAB Services Status...${RESET}"
    open5gs_status=$(sudo systemctl is-active open5gs-* )
    if echo "$open5gs_status" | grep -q "inactive\|failed"; then
        echo -e "${RED}❌ ERROR: Some KAOKAB services are not running!${RESET}"
        echo -e "${RED}Check the status below:${RESET}"
        sudo systemctl list-units --all --plain --no-pager | grep 'open5gs-'
        exit 1
    else
        echo -e "${GREEN}✅ All KAOKAB services are running successfully!${RESET}"
    fi

    # Display Open5GS service list
    echo -e "${BOLD}${BLUE}Current KAOKAB Services:${RESET}"
    sudo systemctl list-units --all --plain --no-pager | grep 'open5gs-'
#!/bin/bash

# Get server IP dynamically
SERVER_IP=$(hostname -I | awk '{print $1}')

# Connect to the KAOKAB WebUI
echo -e "\n${BOLD}${BLUE}🔗 Connect to the KAOKAB WebUI:${RESET}"
echo -e "${BOLD}${GREEN}👉 http://$SERVER_IP:9999${RESET}"
sleep 2

# Display login credentials
echo -e "\n${BOLD}${BLUE}Login Credentials:${RESET}"
echo -e "${BOLD}Username:${RESET} ${GREEN}admin${RESET}"
echo -e "${BOLD}Password:${RESET} ${GREEN}1423${RESET}"
sleep 2

# Tip to change the password
echo -e "\n${BOLD}${BLUE}Tip:${RESET} You can change the password in the Account Menu."
sleep 2

# Steps to Add a Subscriber
echo -e "\n${BOLD}${BLUE}📌 Steps to Add a Subscriber:${RESET}"
echo -e "${GREEN}1.${RESET} Go to the Subscriber Menu."
echo -e "${GREEN}2.${RESET} Click the ${BOLD}+${RESET} button to add a new subscriber."
echo -e "${GREEN}3.${RESET} Fill in the IMSI, security context (K, OPc, AMF), and APN of the subscriber."
echo -e "${GREEN}4.${RESET} Click the ${BOLD}SAVE${RESET} button."
sleep 2

# Final success message with large design and color
echo -e "\n"
echo -e "${BOLD}${GREEN}###############################${RESET}"
echo -e "${BOLD}${GREEN}# INSTALLATION COMPLETED      #${RESET}"
echo -e "${BOLD}${GREEN}# SUCCESSFULLY! 🚀           #${RESET}"
echo -e "${BOLD}${GREEN}###############################${RESET}"
sleep 2

# End of script
echo -e "\n${BOLD}${GREEN}Installation completed successfully!${RESET}"
