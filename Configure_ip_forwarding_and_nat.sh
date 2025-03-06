#!/bin/bash

# Function to check the status of IP forwarding
check_ip_forwarding() {
    echo "Checking IP forwarding status:"
    sysctl net.ipv4.ip_forward
    sysctl net.ipv6.conf.all.forwarding
}

# Enable IP forwarding
enable_ip_forwarding() {
    echo "Enabling IP forwarding..."
    sudo sysctl -w net.ipv4.ip_forward=1
    sudo sysctl -w net.ipv6.conf.all.forwarding=1

    # Enable IP forwarding permanently
    echo "Configuring sysctl.conf to enable IP forwarding permanently..."
    sudo sed -i '/^net.ipv4.ip_forward=/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
    sudo sed -i '/^net.ipv6.conf.all.forwarding=/c\net.ipv6.conf.all.forwarding=1' /etc/sysctl.conf
    sudo sysctl -p
}

# Test the NAT rules for interface ogstun
test_nat_rules() {
    echo "Testing NAT rules for interface ogstun..."
    sudo iptables -t nat -S | grep ogstun
}

# Add NAT rule for IPv4 and IPv6
add_nat_rules() {
    echo "Adding NAT rules..."
    sudo iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE
    sudo ip6tables -t nat -A POSTROUTING -s 2001:db8:cafe::/48 ! -o ogstun -j MASQUERADE
    sudo iptables -I INPUT -i ogstun -j ACCEPT
}

# Make iptables rules persistent
make_iptables_persistent() {
    echo "Saving current iptables rules..."
    sudo iptables-save | sudo tee /etc/iptables/rules.v4
    sudo ip6tables-save | sudo tee /etc/iptables/rules.v6

    echo "Installing iptables-persistent package..."
    sudo apt-get update
    sudo apt-get install -y iptables-persistent
}

# Fixing dpkg issue if any
fix_dpkg_issue() {
    echo "Fixing dpkg issue..."
    sudo dpkg --configure -a
}

# Reboot the system to apply changes
reboot_system() {
    echo "Rebooting the system to apply changes..."
    sudo reboot
}

# Main function
main() {
    check_ip_forwarding
    enable_ip_forwarding
    test_nat_rules
    add_nat_rules
    make_iptables_persistent
    fix_dpkg_issue
    reboot_system
}

# Execute main function
main
