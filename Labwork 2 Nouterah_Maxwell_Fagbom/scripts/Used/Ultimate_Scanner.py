import socket
import threading

# 🛡️ THE VULNERABILITY DATABASE
# A localized dictionary mapping specific software keywords to threat alerts
VULN_DB = {
    "vsftpd": "[!] ALERT: vsftpd detected. Check for CVE-2011-2523 if version matches 2.3.4 (Known Backdoor Exploit).",
    "OpenSSH": "[!] INFO: OpenSSH detected. Check version against recent User Enumeration bugs or configuration flaws.",
    "Telnet": "[!] WARNING: Telnet architecture detected. Data is transmitted in cleartext! Highly vulnerable to credential sniffing."
}

def check_vulnerabilities(banner):
    """Parses the text banner against the vulnerability database to flag alerts."""
    matched = False
    for keyword, alert in VULN_DB.items():
        if keyword.lower() in banner.lower():
            print(f"    └── 🛡️  VULN MATCH: {alert}")
            matched = True
    if not matched:
        print("    └── 🛡️  VULN MATCH: No instant database signature match. Requires manual audit.")

def scan_and_fingerprint(target_ip, port):
    """Core scanning logic executed by individual system threads."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        
        # Connect to the target port
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            print(f"[+] Port {port:5} : OPEN. Extracting signature...")
            
            # Read incoming service data
            raw_banner = s.recv(1024)
            clean_banner = raw_banner.decode('utf-8', errors='ignore').strip()
            
            if clean_banner:
                print(f"    └── 🧬 FINGERPRINT: {clean_banner}")
                # Cross-reference the signature with our vulnerability engine
                check_vulnerabilities(clean_banner)
            else:
                print(f"    └── 🧬 FINGERPRINT: Connected, but the service is silent.")
                
        s.close()
        
    except socket.timeout:
        print(f"[+] Port {port:5} : OPEN. Fingerprint retrieval timed out.")
    except Exception as e:
        # Prevents thread collisions from crashing the main terminal stream
        pass

if __name__ == "__main__":
    # ⚠️ REMINDER: Insert your actual SEED Ubuntu VM IP here
    TARGET_IP = "192.168.56.106" 
    
    # Because we are multi-threaded, we can check a wider list of ports instantly!
    PORTS_TO_SCAN = [21, 22, 23, 80, 443, 8000, 8080]
    
    print(f"[*] Launching Multi-Threaded Vulnerability Scanner against: {TARGET_IP}")
    print(f"[*] Thread pool initiated. Scanning {len(PORTS_TO_SCAN)} ports concurrently...\n")
    
    threads = []
    
    # ⚡ THE MULTI-THREADING ENGINE
    # Spawns a dedicated parallel worker for every single port in the list
    for port in PORTS_TO_SCAN:
        t = threading.Thread(target=scan_and_fingerprint, args=(TARGET_IP, port))
        threads.append(t)
        t.start()
        
    # Ensures the main terminal interface stays open until the final thread finishes execution
    for t in threads:
        t.join()
        
    print("\n[*] Ultimate scan operation complete. All thread channels safely closed.")