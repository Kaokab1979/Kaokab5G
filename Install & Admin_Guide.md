# Installation Guide for CapX Core

CapX Core: A Tailored EPC for Private LTE and 5G
The CapXCore represents a cutting-edge Evolved Packet Core (EPC) and 5G Core (5GC) solution designed to cater to the unique requirements of Private LTE and 5G networks, completely compliant with 3GPP Release 16 standards. Built on the robust foundation of the Open5GS core, the Capx Core is meticulously tailored to integrate seamlessly with Capx products, offering unparalleled performance, flexibility, and security for enterprise and industrial applications.

# Prerequisites

# Before starting, ensure you have the following:

 - A server with Ubuntu 22.04
 - Git installed on the server
 - Sufficient permissions to execute scripts
 - At least one Ethernet GbE or SFP+ interface
 
# Step 1: Download The Script

Open a terminal and navigate to the root directory by running:

cd /root

Download the script with the following command:

wget https://github.com/X3Ld0R/CapX-Nederland-5G/raw/main/Install_CapXCore.sh

This command retrieves the Install_CapXCore.sh script from the specified GitHub repository URL and saves it to the /root directory.

# Step 2: Run the Install Script

- Make the install script executable:
- 
  chmod +x Install_CapXCore.sh
  
   This command grants executable permissions (chmod +x) to the installation script (Install_CapXCore.sh).
  
- Run the install script:
  
  ./Install_CapXCore.sh
  
This Command Executes the installation script (Install_CapXCore.sh) using the Bash shell (bash). The script contains a series of commands to install and configure CapX Core components on the server.

# Step 3: Follow the steps 

- The script verifies that the operating system is Ubuntu 22.04. If the OS is not supported, the script will exit with an error message.
- The script generates a netplan configuration file with the provided IP addresses and network settings.
- The script will prompt you for several pieces of information during its execution. Be prepared to provide the following:

- Interface name (e.g., enp0s25)
- IP addresses for s1ap, gtpu, upf, and gateway
- DNS servers
- APNpool IP and gateway

# Example Configuration:

When prompted, you will enter values like these:

Interface Name: enp0s25
s1ap IP Address: 10.100.100.2/23
gtpu IP Address: 10.100.100.6/23
upf IP Address: 10.100.100.7/23
Gateway IP Address: 10.100.100.254
DNS1 IP Address: 1.0.0.1
DNS2 IP Address: 1.1.1.1
APN1 Pool IP: 10.45.0.1/16
APN1 Gateway IP: 10.45.0.1

# After the installation is complete:

- The script will display the following message:
  
echo "Install complete -- Please connect your browser to port 9999"

-  Additionally, you will be prompted to restart your server:
  
RESTART_OUTPUT="Please restart this server by running
 'reboot'"    echo $RESTART_OUTPUT

# Step 4: Post-Installation Troubleshooting and Verification

1- Display Services Status

- ps aux | grep open5gs
- sudo systemctl is-active open5gs-*
- sudo systemctl list-units --all --plain --no-pager | grep 'open5gs-'
- sudo systemctl status open5gs-*

These commands are used to check the status of various services (open5gs-*) related to CapX Core after installation. They verify whether essential components such as MME, SGW-C, SMF, etc., are running correctly. This helps in troubleshooting if any service fails to start or operate as expected.

2 - Restart Services

- sudo systemctl restart open5gs-*    # Restart specific or all services
- sudo systemctl daemon-reload        # Reload systemd configuration

 if any service is not running or needs to be restarted due to configuration changes or errors, these commands start (systemctl start) or restart (sudo systemctl restart) the specified CapX Core services. sudo systemctl daemon-reload reloads systemd configuration to ensure any changes made to service files are recognized and applied.

3- Check Network Interfaces and Status

- cd /etc/netplan
- cat 00-installer-config.yaml   # Display network configuration
- systemctl status NetworkManager

These commands inspect network configurations and status post-installation. cat 00-installer-config.yaml displays the Netplan configuration file generated during installation, which includes IP address assignments and network settings. systemctl status NetworkManager verifies the status of NetworkManager, ensuring network interfaces are managed and operational.

4- View Live Logs
  
- sudo tail -f /var/log/open5gs/*.log
- journalctl -u open5gs-mmed -f

These commands provide real-time logs (tail -f) of CapX Core services (/var/log/open5gs/*.log) and specific service logs (journalctl -u open5gs-mmed -f). Monitoring logs helps in diagnosing issues such as failed connections or errors encountered during operation, aiding in troubleshooting and maintaining system performance.
  
5- WebUI Service Status

- sudo systemctl status open5gs-webui.service
- sudo ss -tuln | grep 9999    # Check if WebUI is listening on port 9999

sudo systemctl status open5gs-webui.service, checks the status of the CapX Core WebUI service, ensuring it is active and running. sudo ss -tuln | grep 9999 verifies if the WebUI is listening on port 9999, enabling users to access the graphical interface for managing CapX Core configurations and monitoring system health.
  
6- Mongo Database and Services

- mongo --version
- sudo systemctl status mongod

mongo --version, displays the installed version of MongoDB, which is utilized by CapX Core for data storage and management. sudo systemctl status mongod checks the status of the MongoDB service, ensuring it is operational and available for CapX Core operations that rely on database functionality.
  
7- IP Forwarding and NAT Rules

- sysctl net.ipv4.ip_forward    # Check IP forwarding status
- sudo iptables -t nat -S | grep ogstun    # Check NAT rules for interfaces

sysctl net.ipv4.ip_forward, verifies the status of IP forwarding, which is crucial for routing packets between network interfaces in CapX Core. sudo iptables -t nat -S | grep ogstun inspects NAT (Network Address Translation) rules specific to CapX Core interfaces (ogstun), ensuring correct network traffic management and connectivity.
  
8- IP Routes and Firewall Rules

- ip route show    # Display IP routes
- sudo iptables -L    # Check firewall rules

ip route show, displays the configured IP routes, outlining the paths packets take through the network. sudo iptables -L lists firewall rules, which regulate incoming and outgoing traffic. Understanding and verifying these configurations are essential for maintaining network security and ensuring proper data flow within CapX Core.


# Conclusion

After completing these steps, your CapX Core installation should be ready for use. Ensure all services are running correctly and verify connectivity and functionality as per your network requirements. If any issues arise, refer to logs and system status commands for troubleshooting. For further assistance or support, you can contact support@capxnederland.nl.


