# **Installation Guide for Kaokab5G**

**Kaokab5G: A Tailored EPC for Private LTE and 5G**  
The **Kaokab5G** represents a cutting-edge **Evolved Packet Core (EPC) and 5G Core (5GC)** solution designed to cater to the unique requirements of **Private LTE and 5G networks**, completely compliant with **3GPP Release 16** standards. Built on the robust foundation of the **Open5GS core**, the **Kaokab5G** is meticulously tailored to integrate seamlessly with **Kaokab5G products**, offering unparalleled **performance, flexibility, and security** for enterprise and industrial applications.

# **Prerequisites**

## **Before starting, ensure you have the following:**

- A server with **Ubuntu 22.04**
- **Git** installed on the server
- Sufficient permissions to execute scripts
- At least one **Ethernet GbE or SFP+ interface**

# **Step 1: Download The Script**

Open a terminal and navigate to the root directory by running:

```bash
cd /root
```

Download the script with the following command:

```bash
wget https://github.com/Kaokab1979/Kaokab5G/blob/main/Kaokab_Install.sh
```

This command retrieves the **Install Kaokab_Install.sh** script from the specified GitHub repository URL and saves it to the `/root` directory.

# **Step 2: Run the Install Script**

- Make the install script executable:

```bash
chmod +x Install_Kaokab5G.sh
```

This command grants executable permissions (`chmod +x`) to the installation script (`Install_Kaokab5G.sh`).

- Run the install script:

```bash
./Install_Kaokab5G.sh
```

This Command Executes the installation script (`Install_Kaokab5G.sh`) using the **Bash shell** (`bash`). The script contains a series of commands to install and configure **Kaokab5G components** on the server.

# **Step 3: Follow the steps**

- The script verifies that the **operating system is Ubuntu 22.04**. If the OS is not supported, the script will exit with an **error message**.
- The script generates a **netplan configuration file** with the provided **IP addresses and network settings**.
- The script will prompt you for several pieces of information during its execution. Be prepared to provide the following:

  - **Interface name** (e.g., `enp0s25`)
  - **IP addresses** for **s1ap, gtpu, upf, and gateway**
  - **DNS servers**
  - **APNpool IP and gateway**

# **Example Configuration:**

When prompted, you will enter values like these:

```
Interface Name: enp0s25
s1ap IP Address: 10.100.100.2/23
gtpu IP Address: 10.100.100.6/23
upf IP Address: 10.100.100.7/23
Gateway IP Address: 10.100.100.254
DNS1 IP Address: 1.0.0.1
DNS2 IP Address: 1.1.1.1
APN1 Pool IP: 10.45.0.1/16
APN1 Gateway IP: 10.45.0.1
```

# **After the installation is complete:**

- The script will display the following message:
  
```bash
echo "Install complete -- Please connect your browser to port 9999"
```

- Additionally, you will be prompted to restart your server:
  
```bash
RESTART_OUTPUT="Please restart this server by running 'reboot'" 
echo $RESTART_OUTPUT
```

# **Step 4: Post-Installation Troubleshooting and Verification**

### **1- Display Services Status**

```bash
ps aux | grep open5gs
sudo systemctl is-active open5gs-*
sudo systemctl list-units --all --plain --no-pager | grep 'open5gs-'
sudo systemctl status open5gs-*
```

### **2 - Restart Services**

```bash
sudo systemctl restart open5gs-*    # Restart specific or all services
sudo systemctl daemon-reload        # Reload systemd configuration
```

### **3- Check Network Interfaces and Status**

```bash
cd /etc/netplan
cat 00-installer-config.yaml   # Display network configuration
systemctl status NetworkManager
```

### **4- View Live Logs**

```bash
sudo tail -f /var/log/open5gs/*.log
journalctl -u open5gs-mmed -f
```

### **5- WebUI Service Status**

```bash
sudo systemctl status open5gs-webui.service
sudo ss -tuln | grep 9999    # Check if WebUI is listening on port 9999
```

### **6- Mongo Database and Services**

```bash
mongo --version
sudo systemctl status mongod
```

### **7- IP Forwarding and NAT Rules**

```bash
sysctl net.ipv4.ip_forward    # Check IP forwarding status
sudo iptables -t nat -S | grep ogstun    # Check NAT rules for interfaces
```

### **8- IP Routes and Firewall Rules**

```bash
ip route show    # Display IP routes
sudo iptables -L    # Check firewall rules
```

# **Conclusion**

After completing these steps, your **Kaokab5G installation** should be ready for use. Ensure all services are **running correctly** and verify **connectivity and functionality** as per your network requirements.

