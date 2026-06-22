import socket
import sys
from datetime import datetime

# Define targets: You can put a specific test IP or your local gateway
TARGET_HOST = "scanme.nmap.org" 

# Real-world critical infrastructure & database ports to monitor
CRITICAL_PORTS = {
    6379: {"name": "Redis Database", "severity": "HIGH", "desc": "Unauthenticated data exposure risk."},
    27017: {"name": "MongoDB Database", "severity": "HIGH", "desc": "Potential database ransomware target."},
    1883: {"name": "MQTT IoT Broker", "severity": "CRITICAL", "desc": "Industrial IoT telemetry leakage."},
    502: {"name": "Modbus ICS/SCADA", "severity": "CRITICAL", "desc": "Critical Grid infrastructure control port exposed!"},
    9200: {"name": "Elasticsearch", "severity": "MEDIUM", "desc": "Enterprise log and data leakage risk."}
}

def generate_incident_report(port, service_info):
    """Generates a professional incident response structure."""
    print(f"\n[💥] !!! CRITICAL EXPOSURE DETECTED !!!")
    print(f"    🚨 SEVERITY LEVEL : {service_info['severity']}")
    print(f"    ⚠️ Exposed Service : {service_info['name']} (Port {port})")
    print(f"    📝 Threat Details  : {service_info['desc']}")
    print(f"    🛡️ Action Required : Restrict access via Firewall/VPC immediately.")

def monitor_infrastructure(target):
    print("=" * 65)
    print(f"🛡️ SHADOW-WATCH: CRITICAL INFRASTRUCTURE EXPOSURE MONITOR")
    print(f"📅 SCAN INITIATED AT: {datetime.now()}")
    print(f"🎯 TARGET DOMAIN/IP : {target}")
    print("=" * 65 + "\n")

    try:
        target_ip = socket.gethostbyname(target)
        print(f"[+] Target resolved to IP: {target_ip}\n")
    except socket.gaierror:
        print("[!] Error: Hostname could not be resolved. Exiting.")
        sys.exit()

    exposed_count = 0

    for port, info in CRITICAL_PORTS.items():
        # Using context manager for safe socket handling
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.5)
            # connect_ex returns 0 if the connection was successful
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                generate_incident_report(port, info)
                exposed_count += 1
            else:
                print(f"[🟢] Port {port:<5} ({info['name']:<15}) -> SECURE (Closed)")

    print("\n" + "=" * 65)
    print(f"🏁 Monitor Complete. Total Exposed Vulnerabilities Found: {exposed_count}")
    print("=" * 65)

if __name__ == "__main__":
    monitor_infrastructure(TARGET_HOST)

