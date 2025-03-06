#!/bin/bash

# Step 1: Purge KAOKAB Packages
echo "Step 1: Purging KAOKAB packages..."
sudo apt purge -y open5gs

# Step 2: Remove Unnecessary Packages
echo "Step 2: Removing unnecessary packages..."
sudo apt autoremove -y

# Step 3: Remove KAOKAB Log Directory
echo "Step 3: Removing KAOKAB log directory..."
sudo rm -Rf /var/log/open5gs

# Step 4: Uninstall KAOKAB WebUI
echo "Step 4: Uninstalling KAOKAB WebUI..."
curl -fsSL https://open5gs.org/open5gs/assets/webui/uninstall | sudo -E bash -

# Step 5: Verify Removal
echo "Step 5: Verifying removal of KAOKAB packages..."
if dpkg -l | grep -q open5gs; then
    echo "Some KAOKAB packages are still installed:"
    dpkg -l | grep open5gs
else
    echo "All KAOKAB packages have been removed."
fi

echo "Checking if /var/log/open5gs directory exists..."
if [ -d "/var/log/open5gs" ]; then
    echo "/var/log/open5gs still exists. Removing it..."
    sudo rm -Rf /var/log/open5gs
else
    echo "/var/log/open5gs has been removed."
fi

# Step 6: Clean Up
echo "Step 6: Removing any leftover KAOKAB files or directories from /root and /home..."
# Remove KAOKAB directories from /root
echo "Removing KAOKAB directories from /root..."
sudo rm -Rf /root/Open5Gs*

# Remove KAOKAB directories from all /home/* directories
for dir in /home/*; do
    if [ -d "$dir" ]; then
        echo "Removing KAOKAB directories from $dir..."
        sudo rm -Rf "$dir"/Open5Gs*
    fi
done

echo "Purging specific KAOKAB packages if they are in 'rc' state..."
sudo apt purge -y open5gs-amf open5gs-ausf open5gs-bsf open5gs-common open5gs-hss open5gs-mme open5gs-nrf open5gs-nssf open5gs-pcf open5gs-pcrf open5gs-scp open5gs-sgwc open5gs-sgwu open5gs-smf open5gs-udm open5gs-udr open5gs-upf
sudo apt autoremove -y

# Final Check
echo "Final check to ensure no KAOKAB files or directories remain..."
if [ -d "/var/log/open5gs" ]; then
    echo "/var/log/open5gs still exists. Removing it..."
    sudo rm -Rf /var/log/open5gs
else
    echo "/var/log/open5gs has been removed."
fi

# Remove any remaining KAOKAB packages
echo "Removing remaining KAOKAB packages..."
sudo apt purge -y open5gs-sepp
sudo apt autoremove -y

# Uninstall MongoDB
echo "Step 7: Uninstalling MongoDB..."
sudo systemctl stop mongod
sudo apt purge -y mongodb-org*
sudo rm -r /var/log/mongodb
sudo rm -r /var/lib/mongodb
sudo rm /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt update

echo "KAOKAB has been completely uninstalled from your system."
