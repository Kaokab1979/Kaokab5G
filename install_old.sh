#!/bin/bash
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
case $issue in
    Ubuntu\ 22.04*)
        OS=ubuntu2204
        ;;
    *)
        >&2 echo -e "${RED}❌ ERROR: Unsupported OS${RESET}"
        exit 1
        ;;
esac

if [ "$OS" = "ubuntu2204" ]; then
    echo -e "${GREEN}✅ Your server meets the standard specifications of Ubuntu 22.04${RESET}"

    # Install required packages
    sudo apt install -y vim net-tools ca-certificates curl gnupg nodejs iputils-ping git software-properties-common iptables netplan
    systemctl enable systemd-networkd
    systemctl restart systemd-networkd
    systemctl enable systemd-networkd

    # Install MongoDB
    # Install MongoDB 4.4
echo -e "${BOLD}${BLUE}Installing MongoDB 4.4...${RESET}"

# Add MongoDB 4.4 repository
echo "deb [arch=amd64] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list

# Update the package list
sudo apt-get update

# Install MongoDB 4.4
sudo apt-get install -y mongodb-org

# Start the MongoDB service
sudo systemctl start mongod

# Enable MongoDB to start on boot
sudo systemctl enable mongod

# Check if MongoDB is running
echo -e "${BOLD}${BLUE}Checking if MongoDB is running...${RESET}"
if sudo systemctl is-active --quiet mongod; then
    echo -e "${GREEN}✅ MongoDB 4.4 is running successfully!${RESET}"
else
    echo -e "${RED}❌ ERROR: MongoDB 4.4 is NOT running. Please check the logs for more details.${RESET}"
    sudo journalctl -u mongod --no-pager
    exit 1
fi

# Check MongoDB status
sudo systemctl status mongod


    # Clone the Kaokab5G repository
    git clone https://github.com/Kaokab1979/Kaokab5G.git

    # Install Open5GS
    echo -e "${BOLD}${BLUE}Installing Open5GS...${RESET}"
    sudo add-apt-repository -y ppa:open5gs/latest
    sudo apt update
    sudo apt install -y open5gs

    # Install Node.js and Open5GS WebUI
    echo -e "${BOLD}${BLUE}Installing Node.js and Open5GS WebUI...${RESET}"
    sudo apt update
    sudo apt install -y ca-certificates curl gnupg
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
    NODE_MAJOR=20
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list
    sudo apt update
    sudo apt install -y nodejs
    curl -fsSL https://open5gs.org/open5gs/assets/webui/install | sudo -E bash - 
    cp -fR root/Kaokab5G/usr/lib/node_modules/open5gs/next/* /usr/lib/node_modules/open5gs/.next/
    cp -fR root/Kaokab5G/Open5GS/* /etc/open5gs/

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
    sudo systemctl daemon-reload
    sudo systemctl restart open5gs-webui
    sudo systemctl enable open5gs-webui

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
    open5gs_status=$(sudo systemctl is-active open5gs-*)
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

    # Get server IP dynamically
    SERVER_IP=$(hostname -I | awk '{print $1}')

    echo -e "\n${BOLD}${BLUE}🔗 Connect to the KAOKAB WebUI:${RESET}"
    echo -e "${GREEN}👉 http://$SERVER_IP:9999${RESET}"
    echo -e "${BOLD}${BLUE}Login Credentials:${RESET}"
    echo -e "${BOLD}Username:${RESET} admin"
    echo -e "${BOLD}Password:${RESET} 1423"
    echo -e "${BOLD}${BLUE}Tip:${RESET} You can change the password in the Account Menu."

    echo -e "\n${BOLD}${BLUE}📌 Steps to Add a Subscriber:${RESET}"
    echo -e "${GREEN}1.${RESET} Go to the Subscriber Menu."
    echo -e "${GREEN}2.${RESET} Click the ${BOLD}+${RESET} button to add a new subscriber."
    echo -e "${GREEN}3.${RESET} Fill in the IMSI, security context (K, OPc, AMF), and APN of the subscriber."
    echo -e "${GREEN}4.${RESET} Click the ${BOLD}SAVE${RESET} button."

    echo -e "\n${GREEN}✅ Setup completed successfully!${RESET} 🚀"
else
    echo -e "${RED}❌ Unsupported OS. Only Ubuntu 22.04 is supported.${RESET}"
    exit 1
fi

echo -e "${GREEN}Installation completed successfully!${RESET}"
