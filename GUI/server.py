import os
import subprocess
from flask import Flask, render_template, jsonify

app = Flask(__name__)

# Function to check the status of Open5GS services
def get_nf_status():
    services = [
        'open5gs-amfd', 'open5gs-ausfd', 'open5gs-bsfd', 'open5gs-hssd',
        'open5gs-mmed', 'open5gs-nrfd', 'open5gs-nssfd', 'open5gs-pcfd',
        'open5gs-pcrfd', 'open5gs-scpd', 'open5gs-seppd', 'open5gs-sgwcd',
        'open5gs-sgwud', 'open5gs-smfd', 'open5gs-udmd', 'open5gs-udrd',
        'open5gs-upfd', 'open5gs-webui'
    ]
    status = {}
    for service in services:
        result = subprocess.run(['systemctl', 'is-active', service], stdout=subprocess.PIPE)
        status[service] = 'active' if result.stdout.decode('utf-8').strip() == 'active' else 'inactive'
    return status

# Function to get connected eNodeBs and gNBs from logs
def get_connected_nodes():
    # Assuming logs are in /var/log/open5gs/
    mme_log = '/var/log/open5gs/mme.log'
    amf_log = '/var/log/open5gs/amf.log'
    nodes = {
        'eNodeBs': [],
        'gNBs': []
    }

    # Read eNodeB connections from MME log
    with open(mme_log, 'r') as file:
        for line in file:
            if "gNB-N2 accepted" in line:
                ip = line.split(' ')[3]
                nodes['gNBs'].append(ip)

    # Read gNB connections from AMF log
    with open(amf_log, 'r') as file:
        for line in file:
            if "gNB-N2 accepted" in line:
                ip = line.split(' ')[3]
                nodes['gNBs'].append(ip)

    return nodes

# Function to get connected UEs (IMSI, APN, IP) from logs
def get_connected_ues():
    upf_log = '/var/log/open5gs/upf.log'
    ues = []

    with open(upf_log, 'r') as file:
        for line in file:
            if "pfcp_server" in line:  # Look for PFCP messages which might indicate UE activity
                # We will parse relevant details for IMSI, APN, and IP address.
                imsi = "IMSI Placeholder"
                apn = "APN Placeholder"
                ip = "IP Placeholder"
                ues.append({'IMSI': imsi, 'APN': apn, 'IP': ip})

    return ues

@app.route('/')
def index():
    nf_status = get_nf_status()
    connected_nodes = get_connected_nodes()
    connected_ues = get_connected_ues()

    return render_template('index.html', nf_status=nf_status, connected_nodes=connected_nodes, connected_ues=connected_ues)

@app.route('/api/nf_status')
def api_nf_status():
    nf_status = get_nf_status()
    return jsonify(nf_status)

@app.route('/api/connected_nodes')
def api_connected_nodes():
    connected_nodes = get_connected_nodes()
    return jsonify(connected_nodes)

@app.route('/api/connected_ues')
def api_connected_ues():
    connected_ues = get_connected_ues()
    return jsonify(connected_ues)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
