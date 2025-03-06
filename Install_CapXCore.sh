#!/bin/bash
# CapX Core 2024 by Jeffrey Timmer | Forat Selman | Philip Prins
# Based on opensource core

# Echo message before checking the OS
echo "Checking the OS version..."
issue=$(head -1 /etc/issue 2>/dev/null)
case $issue in
    Ubuntu\ 22.04*)
        OS=ubuntu2204
        ;;
    *)
        >&2 echo "Unsupported OS"
        exit
        ;;
esac

if [ "$OS" = "ubuntu2204" ]; then
    echo "Your server meets the standard specifications of Ubuntu 22.04"
    
    # Ask for user inputs for the IP addresses and interface name
    read -p "Enter the interface name (e.g., enp0s25): " interface
    read -p "Enter the IP address for s1ap (e.g., 10.100.100.2/23): " s1ap_ip
    read -p "Enter the IP address for gtpu (e.g., 10.100.100.6/23): " gtpu_ip
    read -p "Enter the IP address for upf (e.g., 10.100.100.7/23): " upf_ip
    read -p "Enter the gateway IP (e.g., 10.100.100.254): " gateway
    read -p "Enter DNS1 IP (e.g., 1.0.0.1): " dns1
    read -p "Enter DNS2 IP (e.g., 1.1.1.1): " dns2
    read -p "Enter APN1 pool ip (e.g., 10.45.0.1/16): " apnpool1
    read -p "Enter APN1 gateway ip (e.g., 10.45.0.1): " apngateway1
    
    # Backup the existing netplan configuration
    cp /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.bak
    echo "Backup of existing netplan configuration created at /etc/netplan/00-installer-config.yaml.bak"

    # Create new netplan configuration
    cat <<EOL > /etc/netplan/00-installer-config.yaml
network:
  version: 2
  ethernets:
    $interface:
      dhcp4: no
      addresses:
       - $s1ap_ip
       - $gtpu_ip
       - $upf_ip
      routes:
        - to: default
          via: $gateway
      nameservers:
        addresses: [$dns1, $dns2]
EOL

    echo "Netplan configuration updated successfully."

    # Apply the netplan configuration
    netplan try
    if [ $? -eq 0 ]; then
        echo "Netplan changes are valid. Applying the configuration..."
        netplan apply
    else
        echo "There was an error with the netplan configuration. Reverting changes."
        cp /etc/netplan/00-installer-config.yaml.bak /etc/netplan/00-installer-config.yaml
        netplan apply
        exit 1
    fi

    # Optional: Continue with Open5GS installation or other processes
    echo "Proceeding with further script actions..."
    # Further actions can be added here for Open5GS installation, etc.

fi
# Maak tunnel definatief
cat << EOF > /etc/systemd/network/99-open5gs.netdev
[NetDev]
Name=ogstun
Kind=tun
EOF
    apt update
    apt install -y vim net-tools ca-certificates curl gnupg nodejs iputils-ping git software-properties-common iptables netplan
    systemctl enable systemd-networkd
    systemctl restart systemd-networkd
    netplan apply
    git clone https://github.com/X3Ld0R/CapX-Nederland-5G.git
 #  cp -fR /root/CapX-Nederland-5G/00-installer-config.yaml /etc/netplan/    # File Doesn't exist !
    add-apt-repository ppa:open5gs/latest
    sudo apt update && sudo apt upgrade
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://pgp.mongodb.com/server-7.0.asc |  sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
    apt update
    echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
    deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse
    sudo apt update
    sudo apt install mongodb-org
    systemctl start mongod
    systemctl enable mongod 
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
    echo NODE_MAJOR=20
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list
    apt update
    apt install nodejs -y
    apt install open5gs
    curl -fsSL https://open5gs.org/open5gs/assets/webui/install | sudo -E bash -
    cp -fR /root/Kaokab5G/restart.sh /root/
    cp -fR root/Kaokab5G/usr/lib/node_modules/open5gs/next/* /usr/lib/node_modules/open5gs/.next/
    cp -fR root/Kaokab5G/Open5GS/* /etc/open5gs/ 
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1
    iptables -t nat -A POSTROUTING -s 10.45.0.1/16 ! -o ogstun -j MASQUERADE
    ip6tables -t nat -A POSTROUTING -s 2001:db8:cafe::/48 ! -o ogstun -j MASQUERADE
    iptables -I INPUT -i ogstun -j ACCEPT
# AMF configuratie 
    cat <<EOL > /etc/Open5gs/amf.yaml                   # Fixing directory name from /Open5GS/  to  /open5gs/
logger:
  file:
    path: /var/log/open5gs/amf.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

amf:
  sbi:
    server:
      - address: 127.0.0.5
        port: 7777
    client:
#      nrf:
#        - uri: http://127.0.0.10:7777
      scp:
        - uri: http://127.0.0.200:7777
  ngap:
    server:
      - address: $s1ap_ip
  metrics:
    server:
      - address: 127.0.0.5
        port: 9090
  guami:
    - plmn_id:
        mcc: 204
        mnc: 25
      amf_id:
        region: 2
        set: 1
  tai:
    - plmn_id:
        mcc: 204
        mnc: 25
      tac: 1
  plmn_support:
    - plmn_id:
        mcc: 204
        mnc: 25
      s_nssai:
        - sst: 1
  security:
    integrity_order : [ NIA2, NIA1, NIA0 ]
    ciphering_order : [ NEA0, NEA1, NEA2 ]
  network_name:
    full: ICTimmers
    short: ICTimmers
  amf_name: open5gs-amf0
  time:
#    t3502:
#      value: 720   # 12 minutes * 60 = 720 seconds
    t3512:
      value: 540    # 9 minutes * 60 = 540 seconds
EOL
# AUSF configuratie 
    cat <<EOL > /etc/open5gs/ausf.yaml               # Fixing directory name from /Open5GS/  to  /open5gs/
logger:
  file:
    path: /var/log/open5gs/ausf.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

ausf:
  sbi:
    server:
      - address: 127.0.0.11
        port: 7777
    client:
#      nrf:
#        - uri: http://127.0.0.10:7777
      scp:
        - uri: http://127.0.0.200:7777
EOL
# BSF configuratie 
    cat <<EOL > /etc/open5gs/bsf.yaml              # Fixing directory name from /Open5GS/  to  /open5gs/
logger:
  file:
    path: /var/log/open5gs/bsf.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

bsf:
  sbi:
    server:
      - address: 127.0.0.15
        port: 7777
    client:
#      nrf:
#        - uri: http://127.0.0.10:7777
      scp:
        - uri: http://127.0.0.200:7777
EOL
# HSS configuratie 
    cat <<EOL > /etc/open5gs/hss.yaml                    # Fixing directory name from /Open5GS/  to  /open5gs/
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/hss.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

hss:
  freeDiameter: /etc/freeDiameter/hss.conf
#  sms_over_ims: "sip:smsc.mnc001.mcc001.3gppnetwork.org:7060;transport=tcp"
#  use_mongodb_change_stream: true
EOL
# MME configuratie 
    cat <<EOL > /etc/open5gs/mme.yaml                       # Fixing directory name from /Open5GS/  to  /open5gs/ 
logger:
  file:
    path: /var/log/open5gs/mme.log
    level: debug   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

mme:
  freeDiameter: /etc/freeDiameter/mme.conf
  s1ap:
    server:
      - address: $s1ap_ip
  gtpc:
    server:
      - address: 127.0.0.2
    client:
      sgwc:
        - address: 127.0.0.3
      smf:
        - address: 127.0.0.4
  metrics:
    server:
      - address: 127.0.0.2
        port: 9090
  gummei:
    - plmn_id:
        mcc: 204
        mnc: 25
      mme_gid: 2
      mme_code: 1
  tai:
    - plmn_id:
        mcc: 204
        mnc: 25
      tac: 1
  security:
    integrity_order : [ EIA2, EIA1, EIA0 ]
    ciphering_order : [ EEA0, EEA1, EEA2 ]
  network_name:
    full: ICTimmers
    short: ICTimmers
  mme_name: open5gs-mme0
  time:
EOL
# NRF configuratie 
    cat <<EOL > /etc/open5gs/nrf.yaml                   # Fixing directory name from /Open5GS/  to  /open5gs/
logger:
  file:
    path: /var/log/open5gs/nrf.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

nrf:
  serving:  # 5G roaming requires PLMN in NRF
    - plmn_id:
        mcc: 204
        mnc: 25
    - plmn_id:
        mcc: 206
        mnc: 01
  sbi:
    server:
      - address: 127.0.0.10
        port: 7777
EOL
# NSSF configuratie 
    cat <<EOL > /etc/open5gs/nssf.yaml                   # Fixing directory name from /Open5GS/  to  /open5gs/
logger:
  file:
    path: /var/log/open5gs/nssf.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

nssf:
  sbi:
    server:
      - address: 127.0.0.14
        port: 7777
    client:
#      nrf:
#        - uri: http://127.0.0.10:7777
      scp:
        - uri: http://127.0.0.200:7777
      nsi:
        - uri: http://127.0.0.10:7777
          s_nssai:
            sst: 1
EOL
# PCF configuratie 
    cat <<EOL > /etc/open5gs/pcf.yaml                  # Fixing directory name from /Open5GS/  to  /open5gs/
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/pcf.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

pcf:
  sbi:
    server:
      - address: 127.0.0.13
        port: 7777
    client:
#      nrf:
#        - uri: http://127.0.0.10:7777
      scp:
        - uri: http://127.0.0.200:7777
  metrics:
    server:
      - address: 127.0.0.13
        port: 9090
EOL
# PCRF configuratie 
    cat <<EOL > /etc/open5gs/pcrf.yaml                   # Fixing directory name from /Open5GS/  to  /open5gs/

db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/pcrf.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64
pcrf:
  freeDiameter: /etc/freeDiameter/pcrf.conf
EOL
# SCP configuratie 
    cat <<EOL > /etc/open5gs/scp.yaml                # Fixing directory name from /Open5GS/  to  /open5gs/
logger:
  file:
    path: /var/log/open5gs/scp.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

scp:
  sbi:
    server:
      - address: 127.0.0.200
        port: 7777
    client:
      nrf:
        - uri: http://127.0.0.10:7777
EOL
# SEPP1 configuratie 
    cat <<EOL > /etc/open5gs/sepp1.yaml                 # Fixing directory name from /Open5GS/  to  /open5gs/
logger:
  file:
    path: /var/log/open5gs/sepp1.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

sepp:
  default:
    tls:
      server:
        private_key: /etc/open5gs/tls/sepp1.key
        cert: /etc/open5gs/tls/sepp1.crt
      client:
        cacert: /etc/open5gs/tls/ca.crt
  sbi:
    server:
      - address: 127.0.1.250
        port: 7777
    client:
#      nrf:
#        - uri: http://127.0.0.10:7777
      scp:
        - uri: http://127.0.0.200:7777
  n32:
    server:
      - sender: sepp1.localdomain
        scheme: https
        address: 127.0.1.251
        port: 7777
        n32f:
          scheme: https
          address: 127.0.1.252
          port: 7777
    client:
      sepp:
        - receiver: sepp2.localdomain
          uri: https://sepp2.localdomain:7777
          resolve: 127.0.2.251
          n32f:
            uri: https://sepp2.localdomain:7777
            resolve: 127.0.2.252
EOL
EOL
# SEPP2 configuratie 
    cat <<EOL > /etc/open5gs/sepp2.yaml                      # Fixing directory name from /Open5GS/  to  /open5gs/
logger:
  file:
    path: /var/log/open5gs/sepp2.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

sepp:
  default:
    tls:
      server:
        private_key: /etc/open5gs/tls/sepp2.key
        cert: /etc/open5gs/tls/sepp2.crt
      client:
        cacert: /etc/open5gs/tls/ca.crt
  sbi:
    server:
      - address: 127.0.2.250
        port: 7777
    client:
#      nrf:
#        - uri: http://127.0.0.10:7777
      scp:
        - uri: http://127.0.0.200:7777
  n32:
    server:
      - sender: sepp2.localdomain
        scheme: https
        address: 127.0.2.251
        port: 7777
        n32f:
          scheme: https
          address: 127.0.2.252
          port: 7777
    client:
      sepp:
        - receiver: sepp1.localdomain
          uri: https://sepp1.localdomain:7777
          resolve: 127.0.1.251
          n32f:
            uri: https://sepp1.localdomain:7777
            resolve: 127.0.1.252
EOL
# SGWC configuratie 
    cat <<EOL > /etc/open5gs/sgwc.yaml                       # Fixing directory name from /Open5GS/  to  /open5gs/
logger:
  file:
    path: /var/log/open5gs/sgwc.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

sgwc:
  gtpc:
    server:
      - address: 127.0.0.3
  pfcp:
    server:
      - address: 127.0.0.3
    client:
      sgwu:
        - address: 127.0.0.6
EOL
# SGWU configuratie 
    cat <<EOL > /etc/open5gs/sgwu.yaml                              # Fixing directory name from /Open5GS/  to  /open5gs/
logger:
logger:
  file:
    path: /var/log/open5gs/sgwu.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

sgwu:
  pfcp:
    server:
      - address: 127.0.0.6
    client:
#      sgwc:    # SGW-U PFCP Client try to associate SGW-C PFCP Server
#        - address: 127.0.0.3
  gtpu:
    server:
      - address: $gtpu_ip
EOL
# SMF configuratie 
    cat <<EOL > /etc/open5gs/smf.yaml                      # Fixing directory name from /Open5GS/  to  /open5gs/
logger:
  file:
    path: /var/log/open5gs/smf.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

smf:
  sbi:
    server:
      - address: 127.0.0.4
        port: 7777
    client:
#      nrf:
#        - uri: http://127.0.0.10:7777
      scp:
        - uri: http://127.0.0.200:7777
  pfcp:
    server:
      - address: 127.0.0.4
    client:
      upf:
        - address: 127.0.0.7
  gtpc:
    server:
      - address: 127.0.0.4
  gtpu:
    server:
      - address: 127.0.0.4
  metrics:
    server:
      - address: 127.0.0.4
        port: 9090
  session:
    - subnet: $apnpool1
      gateway: $apngateway1
      dnn: internet
  dns:
    - $dns1
    - $dns2
  mtu: 1500
#  p-cscf:
#    - 127.0.0.1
#    - ::1
#  ctf:
#    enabled: auto   # auto(default)|yes|no
  freeDiameter: /etc/freeDiameter/smf.conf
EOL
# UDM configuratie 
    cat <<EOL > /etc/open5gs/udm.yaml                 # Fixing directory name from /Open5GS/  to  /open5gs/
logger:
  file:
    path: /var/log/open5gs/udm.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

udm:
  hnet:
    - id: 1
      scheme: 1
      key: /etc/open5gs/hnet/curve25519-1.key
    - id: 2
      scheme: 2
      key: /etc/open5gs/hnet/secp256r1-2.key
    - id: 3
      scheme: 1
      key: /etc/open5gs/hnet/curve25519-3.key
    - id: 4
      scheme: 2
      key: /etc/open5gs/hnet/secp256r1-4.key
    - id: 5
      scheme: 1
      key: /etc/open5gs/hnet/curve25519-5.key
    - id: 6
      scheme: 2
      key: /etc/open5gs/hnet/secp256r1-6.key
  sbi:
    server:
      - address: 127.0.0.12
        port: 7777
    client:
#      nrf:
#        - uri: http://127.0.0.10:7777
      scp:
        - uri: http://127.0.0.200:7777
EOL
# UDR configuratie 
    cat <<EOL > /etc/open5gs/udr.yaml                    # Fixing directory name from /Open5GS/  to  /open5gs/
db_uri: mongodb://localhost/open5gs
logger:
  file:
    path: /var/log/open5gs/udr.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

udr:
  sbi:
    server:
      - address: 127.0.0.20
        port: 7777
    client:
#      nrf:
#        - uri: http://127.0.0.10:7777
      scp:
        - uri: http://127.0.0.200:7777
EOL
# UPF configuratie 
    cat <<EOL > /etc/open5gs/upf.yaml               # Fixing directory name from /Open5GS/  to  /open5gs/
logger:
  file:
    path: /var/log/open5gs/upf.log
#  level: info   # fatal|error|warn|info(default)|debug|trace

global:
  max:
    ue: 1024  # The number of UE can be increased depending on memory size.
#    peer: 64

upf:
  pfcp:
    server:
      - address: 127.0.0.7
    client:
#      smf:     #  UPF PFCP Client try to associate SMF PFCP Server
#        - address: 127.0.0.4
  gtpu:
    server:
      - address: $upf_ip
  session:
    - subnet: $apnpool1
      # gateway: $apngateway1
  metrics:
    server:
      - address: 127.0.0.7
        port: 9090
EOL
# WEBGUI configuratie 
    cat <<EOL > /lib/systemd/system/open5gs-webui.service
[Unit]
Description=Open5GS WebUI
Wants=mongodb.service mongod.service

[Service]
Type=simple

WorkingDirectory=/usr/lib/node_modules/open5gs
Environment=NODE_ENV=production
Environment=HOSTNAME=0.0.0.0
Environment=PORT=9999
ExecStart=/usr/bin/node server/index.js
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOL
fi
systemctl enable open5gs-mmed
systemctl enable open5gs-sgwud
systemctl enable open5gs-mmed
systemctl enable open5gs-sgwcd
systemctl enable open5gs-smfd
systemctl enable open5gs-amfd
systemctl enable open5gs-sgwud
systemctl enable open5gs-upfd
systemctl enable open5gs-hssd
systemctl enable open5gs-pcrfd
systemctl enable open5gs-nrfd
systemctl enable open5gs-scpd
systemctl enable open5gs-seppd
systemctl enable open5gs-ausfd
systemctl enable open5gs-udmd
systemctl enable open5gs-pcfd
systemctl enable open5gs-nssfd
systemctl enable open5gs-bsfd
systemctl enable open5gs-udrd
systemctl enable open5gs-webui
systemctl enable mongod

echo 
echo "Install complete -- Please connect your browser to port 9999"

RESTART_OUTPUT="Please restart this server by running 'reboot'"
echo $RESTART_OUTPUT

