#!/usr/bin/env python3
import subprocess
import sys
import os

# ----------- Dependency Check and Auto-Install -----------
def install_package(pkg_name):
    try:
        __import__(pkg_name)
    except ImportError:
        print(f"📦 Installing missing package: {pkg_name}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name])

def ensure_pip():
    try:
        subprocess.run(["pip3", "--version"], check=True)
    except subprocess.CalledProcessError:
        print("⚙️ pip3 not found. Installing...")
        subprocess.run(["apt", "update"], check=True)
        subprocess.run(["apt", "install", "-y", "python3-pip"], check=True)

ensure_pip()
for pkg in ["termcolor", "pandas", "matplotlib"]:
    install_package(pkg)

# ----------- Continue script after ensuring deps -----------
from termcolor import cprint
import json
import pandas as pd
import datetime
import matplotlib.pyplot as plt
from pathlib import Path

import datetime
import matplotlib.pyplot as plt
from pathlib import Path
from termcolor import cprint
import time

LOG_DIR = Path("logs")
RESULTS_DIR = Path("results")
LOG_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

PORTS = {"UDP": 5300, "TCP": 5301}
results = []
ip_labels = {}

def run_ping(ip, count=5):
    try:
        proc = subprocess.run(
            ["ping", "-c", str(count), ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        for line in proc.stdout.splitlines():
            if "rtt min/avg/max/mdev" in line:
                parts = line.split("=")[1].strip().split("/")
                return float(parts[1])
        return None
    except Exception as e:
        print(f"⚠️ Ping error for {ip}: {e}")
        return None

def run_iperf_server_once(protocol, label):
    port = PORTS[protocol]
    cprint(f"\n📡 Waiting for {protocol} client connection on port {port}...", "cyan")
    proc = subprocess.Popen([
        "iperf3", "-s", "-p", str(port), "-1", "-J"
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    out, _ = proc.communicate()
    if not out:
        cprint("⚠️ No output received.", "red")
        return

    try:
        data = json.loads(out.decode())
        client_ip = data.get("start", {}).get("connected", [{}])[0].get("remote_host", "unknown")
        cprint(f"✅ IN PROGRESS: Client IP detected -> {client_ip}", "yellow")

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{label}_{protocol}_{client_ip}_{timestamp}.json"
        with open(LOG_DIR / filename, 'w') as f:
            json.dump(data, f, indent=2)

        latency = run_ping(client_ip)
        if latency is not None:
            cprint(f"📶 Ping average latency to {client_ip}: {latency:.2f} ms", "green")
        else:
            cprint(f"⚠️ Could not measure ping latency to {client_ip}", "red")

        ip_labels[(client_ip, timestamp)] = label.capitalize()
        results.append((client_ip, protocol, timestamp, data, latency))
        print(f"💾 Result saved: {filename}")
    except Exception as e:
        cprint(f"❌ Error parsing result: {e}", "red")

def process_results():
    if not results:
        cprint("⚠️ No results to process.", "red")
        return

    rows = []
    for client_ip, protocol, timestamp, data, latency in results:
        label = ip_labels.get((client_ip, timestamp), "Unknown")
        summary = data.get("end", {})
        duration = data.get("start", {}).get("test_start", {}).get("duration", 0)

        if protocol == "UDP":
            udp = summary.get("sum", {})
            row = {
                "Client IP": client_ip,
                "Network": label,
                "Protocol": protocol,
                "Bandwidth (Mbps)": udp.get("bits_per_second", 0) / 1e6,
                "Jitter (ms)": udp.get("jitter_ms", 0),
                "Latency (ms)": latency,
                "Packet Loss (%)": udp.get("lost_percent", 0),
                "Test Duration (s)": duration
            }
        else:
            tcp = summary.get("sum_received", {}) or summary.get("sum", {})
            row = {
                "Client IP": client_ip,
                "Network": label,
                "Protocol": protocol,
                "Bandwidth (Mbps)": tcp.get("bits_per_second", 0) / 1e6,
                "Jitter (ms)": None,
                "Latency (ms)": latency,
                "Packet Loss (%)": None,
                "Test Duration (s)": duration
            }
        rows.append(row)

    df = pd.DataFrame(rows)
    excel_path = RESULTS_DIR / "performance_report.xlsx"
    df.to_excel(excel_path, index=False)
    cprint(f"\n📊 Excel report saved: {excel_path}", "green")

    plt.figure(figsize=(10, 6))
    for net_type in df['Network'].unique():
        subset = df[df['Network'] == net_type]
        plt.bar(subset['Client IP'] + "\n" + subset['Protocol'], subset['Bandwidth (Mbps)'], label=net_type)

    plt.title("Bandwidth Comparison (Wi-Fi vs Cellular)")
    plt.ylabel("Mbps")
    plt.xticks(rotation=45)
    plt.legend()
    plt.tight_layout()
    chart_path = RESULTS_DIR / "performance_charts.png"
    plt.savefig(chart_path)
    cprint(f"📈 Chart saved: {chart_path}", "cyan")

if __name__ == "__main__":
    cprint("\n\n***   WELCOME TO PERFORMANCE TEST   ***", "magenta", attrs=["bold", "blink"])
    cprint("***        Alcadis B.V.             ***\n", "magenta", attrs=["bold", "blink"])
    input("🔶 Press ENTER to begin Wi-Fi TCP test... ")
    run_iperf_server_once("TCP", "WiFi")

    input("🔶 Press ENTER to begin Wi-Fi UDP test... ")
    run_iperf_server_once("UDP", "WiFi")

    input("🔶 Press ENTER to begin Cellular TCP test... ")
    run_iperf_server_once("TCP", "Cellular")

    input("🔶 Press ENTER to begin Cellular UDP test... ")
    run_iperf_server_once("UDP", "Cellular")

    cprint("\n🔴 To STOP and save final report, press Ctrl + C anytime...\n", "red", attrs=["bold"])
    try:
        while True:
            time.sleep(1)  # idle loop until interrupted
    except KeyboardInterrupt:
        cprint("🛑 Finalizing test and saving report...", "cyan")
        process_results()
