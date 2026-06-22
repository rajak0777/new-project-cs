import socket
import requests
import sys
from datetime import datetime

# Safe public target allowed for testing scans
TARGET = "scanme.nmap.org" 
PORTS = [22, 80, 443]

# Simulated Vulnerability Database (Checks for outdated server banners)
VULN_DB = {
    "SSH-2.0-OpenSSH_7.4": "CVE-2018-15473: Username Enumeration vulnerability.",
    "Apache/2.4.41": "Multiple vulnerabilities: Outdated Apache version. Upgrade recommended.",
    "nginx/1.14.0": "CVE-2019-9511: HTTP/2 Denial of Service vulnerability."
}

def get_banner(sock):
    """Attempts to receive a plain text banner from the open port."""
    try:
        sock.settimeout(2.0)
        sock.sendall(b"Hello\r\n")
        return sock.recv(1024).decode('utf-8', errors='ignore').strip()
    except Exception:
        return None

def get_http_banner(target, port):
    """Sends an HTTP GET request to fetch the 'Server' header."""
    try:
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{target}"
        response = requests.get(url, timeout=3, verify=False)
        server_header = response.headers.get("Server")
        return f"HTTP Server: {server_header}" if server_header else "HTTP Open (No Server Header)"
    except requests.exceptions.RequestException:
        return "HTTP Open (Request Error)"

def scan_ports(target, ports):
    print(f"\n🚀 IITK PORT SCANNER STARTING AT: {datetime.now()}")
    print(f"🎯 Target Host: {target}\n" + "="*50)
    
    try:
        target_ip = socket.gethostbyname(target)
        print(f"[+] Target IP resolved: {target_ip}\n")
    except socket.gaierror:
        print("[!] Error: Could not resolve hostname. Exiting.")
        sys.exit()

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        result = sock.connect_ex((target_ip, port))
        
        if result == 0:
            print(f"[🟢] Port {port}: OPEN")
            banner = get_http_banner(target_ip, port) if port in [80, 443] else get_banner(sock)
            
            if banner:
                print(f"    ├─ Banner: {banner}")
                flagged = False
                for signature, vuln_details in VULN_DB.items():
                    if signature in banner:
                        print(f"    🚨 ALERT: {vuln_details}")
                        flagged = True
                if not flagged:
                    print("    └─ Status: No known critical signature matched.")
        else:
            print(f"[🔴] Port {port}: CLOSED")
        sock.close()
    print("\n✅ Scan Complete.\n" + "="*50)

if __name__ == "__main__":
    # Disable SSL Warnings for dirty environments
    requests.packages.urllib3.disable_warnings()
    scan_ports(TARGET, PORTS)
