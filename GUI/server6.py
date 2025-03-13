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

# Function to get connected eNodeBs, gNBs, and UEs
def get_connected_nodes_and_ues():
    mme_log = '/var/log/open5gs/mme.log'
    amf_log = '/var/log/open5gs/amf.log'
    upf_log = '/var/log/open5gs/upf.log'
    nodes = {'eNodeBs': [], 'gNBs': [], 'ues': []}

    # Read eNodeB connections from MME log
    with open(mme_log, 'r') as file:
        for line in file:
            if "eNB-S1" in line:  # Look for eNodeB S1AP connections
                ip = line.split('[')[1].split(']')[0]  # Extract IP address
                nodes['eNodeBs'].append({'IP': ip, 'ID': 'eNodeB-ID', 'Status': 'active'})  # Placeholder for eNodeB ID

    # Read gNB connections from AMF log
    with open(amf_log, 'r') as file:
        for line in file:
            if "gNB-N2" in line:  # Look for gNB NGAP connections
                ip = line.split('[')[1].split(']')[0]  # Extract IP address
                nodes['gNBs'].append({'IP': ip, 'ID': 'gNB-ID', 'Status': 'active'})  # Placeholder for gNB ID

    # Read UE connections from UPF log
    with open(upf_log, 'r') as file:
        for line in file:
            if "pfcp_server" in line:  # Look for UE connection info
                # Example format: "IMSI: 001010101010010, APN: ims, IP: 10.45.0.2"
                segments = line.split(' ')
                imsi = segments[1]  # Placeholder for IMSI
                apn = segments[3]   # Placeholder for APN
                ip = segments[5]    # Placeholder for IP address

                nodes['ues'].append({'IMSI': imsi, 'APN': apn, 'IP': ip})  # Add UE info

    return nodes

@app.route('/')
def index():
    network_functions_status = get_nf_status()
    connected_nodes_and_ues = get_connected_nodes_and_ues()

    return render_template('index6.html',
                           network_functions_status=network_functions_status,
                           connected_nodes_and_ues=connected_nodes_and_ues)

@app.route('/api/status')
def api_status():
    network_functions_status = get_nf_status()
    connected_nodes_and_ues = get_connected_nodes_and_ues()

    status_data = {
        'services': network_functions_status,
        'eNodeBs': connected_nodes_and_ues['eNodeBs'],
        'gNBs': connected_nodes_and_ues['gNBs'],
        'ues': connected_nodes_and_ues['ues']
    }
    return jsonify(status_data)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)
