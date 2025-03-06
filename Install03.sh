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
