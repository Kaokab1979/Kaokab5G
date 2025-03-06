#!/bin/bash

# Function to check if all services are active
check_services() {
  echo -e "\033[1;34mChecking running processes...\033[0m"
  ps aux | grep '[o]pen5gs'
  echo

  echo -e "\033[1;34mChecking systemd service status...\033[0m"
  services_status=$(sudo systemctl is-active open5gs-* 2>&1)
  echo "$services_status"
  echo

  echo -e "\033[1;34mListing systemd units...\033[0m"
  units_status=$(sudo systemctl list-units --all --plain --no-pager | grep 'open5gs-' 2>&1)
  echo "$units_status"
  echo

  echo -e "\033[1;34mChecking if services are enabled...\033[0m"
  unit_files_status=$(systemctl list-unit-files | grep open5gs 2>&1)
  echo "$unit_files_status"
  echo
  sleep 1
}

# Function to check IP forwarding status
check_ip_forwarding() {
  echo -e "\033[1;34mChecking IP forwarding...\033[0m"
  ipv4_forwarding=$(sysctl net.ipv4.ip_forward | awk '{print $3}')
  ipv6_forwarding=$(sysctl net.ipv6.conf.all.forwarding | awk '{print $3}')

  echo -e "\033[1;34mIPv4 Forwarding: \033[0m$ipv4_forwarding"
  echo -e "\033[1;34mIPv6 Forwarding: \033[0m$ipv6_forwarding"
  sleep 1

  if [[ "$ipv4_forwarding" -ne 1 ]]; then
    echo -e "\033[1;33mIPv4 forwarding is not enabled. Enabling now...\033[0m"
    sudo sysctl -w net.ipv4.ip_forward=1
  fi

  if [[ "$ipv6_forwarding" -ne 1 ]]; then
    echo -e "\033[1;33mIPv6 forwarding is not enabled. Enabling now...\033[0m"
    sudo sysctl -w net.ipv6.conf.all.forwarding=1
  fi
  echo
  sleep 1
}

# Function to check NAT rules
check_nat_rules() {
  echo -e "\033[1;34mChecking NAT rules for 'ogstun'...\033[0m"
  nat_rules=$(sudo iptables -t nat -S | grep ogstun 2>&1)
  echo "$nat_rules"
  echo
  sleep 1

  echo -e "\033[1;34mChecking ip6tables NAT rules for 'ogstun'...\033[0m"
  nat_rules_ipv6=$(sudo ip6tables -t nat -S | grep ogstun 2>&1)
  echo "$nat_rules_ipv6"
  echo
  sleep 1
}

# Function to display final status
display_final_status() {
  if [[ "$(sudo systemctl is-active open5gs-*)" == *"active"* ]]; then
    echo -e "\033[1;32m✅ All KAOKAB services are running.\033[0m"
  else
    echo -e "\033[1;31m❌ Some KAOKAB Services are NOT running.\033[0m"
  fi
  sleep 1
}

# Run checks
check_services
check_ip_forwarding
check_nat_rules
display_final_status

# Display Final Message in Large Font
echo -e "\033[1;32m"
echo "=========================================="
echo "      ✅ SYSTEM CHECK COMPLETED! ✅       "
echo "=========================================="
echo -e "\033[0m"
sleep 1
