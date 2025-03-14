#!/bin/bash

echo "==================================="
echo -e "\e[1;33m SYSTEM INFORMATION CHECK \e[0m"
echo "==================================="

# OS Name and Version
echo -e "\e[1;34m[+] OS Information:\e[0m"
echo -e "\e[1;32m$(lsb_release -d | awk -F':' '{print $2}')\e[0m"
echo "-----------------------------------"

# Kernel Version
echo -e "\e[1;34m[+] Kernel Version:\e[0m"
echo -e "\e[1;32m$(uname -r)\e[0m"
echo "-----------------------------------"

# Total RAM
echo -e "\e[1;34m[+] Total RAM:\e[0m"
echo -e "\e[1;32m$(grep MemTotal /proc/meminfo | awk '{print $2/1024 " MB"}')\e[0m"
echo "-----------------------------------"

# Total Processors
echo -e "\e[1;34m[+] CPU Cores:\e[0m"
echo -e "\e[1;32m$(nproc)\e[0m"
echo "-----------------------------------"

# Hyperthreading Check
echo -e "\e[1;34m[+] Hyperthreading Status:\e[0m"
HT_STATUS=$(cat /sys/devices/system/cpu/cpu*/topology/thread_siblings_list | sort -u | wc -l)
if [[ "$HT_STATUS" -eq "$(nproc)" ]]; then
    echo -e "\e[1;32mDisabled\e[0m"
else
    echo -e "\e[1;31mEnabled\e[0m"
fi
echo "-----------------------------------"

# Disk Space Check
echo -e "\e[1;34m[+] Disk Space Available:\e[0m"
echo -e "\e[1;32m$(df -h / | awk 'NR==2 {print $4}')\e[0m"
echo "-----------------------------------"

# Network Connection Check
echo -e "\e[1;34m[+] Internet Connection Test:\e[0m"
if ping -c 2 google.com &> /dev/null; then
    echo -e "\e[1;32mConnected\e[0m"
else
    echo -e "\e[1;31mNot Connected\e[0m"
fi
echo "-----------------------------------"

# Display Network Interfaces
echo -e "\e[1;34m[+] Network Interfaces:\e[0m"
ip -br addr show | awk '{print "Interface: " $1 ", IP Address: " $3}'
echo "-----------------------------------"

# Display Default Gateway
echo -e "\e[1;34m[+] Default Gateway:\e[0m"
DEFAULT_GATEWAY=$(ip route show default | awk '/default/ {print $3}')
if [ -z "$DEFAULT_GATEWAY" ]; then
    echo -e "\e[1;31mNo default gateway found\e[0m"
else
    echo -e "\e[1;32m$DEFAULT_GATEWAY\e[0m"
fi
echo "==================================="
