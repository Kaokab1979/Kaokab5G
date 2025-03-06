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
