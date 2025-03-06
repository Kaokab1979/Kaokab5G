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
