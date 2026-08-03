import socket

def scan_port(target_ip, port):
    try:
        # Create a standard TCP socket
        # AF_INET = IPv4, SOCK_STREAM = TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       
        # Set a 1-second timeout so the script doesn't hang indefinitely on closed ports
        s.settimeout(1.0)
       
        # connect_ex returns 0 if successful, or an error code if it fails
        result = s.connect_ex((target_ip, port))
       
        if result == 0:
            print(f"[+] Port {port:5} : OPEN")
        else:
            # We skip closed ports to keep the terminal clean
            pass
           
        # Always close the socket connection
        s.close()
       
    except Exception as e:
        print(f"[!] Error scanning port {port}: {e}")

if __name__ == "__main__":
    # ⚠️ REPLACE THIS with your SEED VM's actual IP address
    TARGET_IP = "192.168.56.106"
   
    # A few common ports to check on a standard SEED VM layout
    PORTS_TO_SCAN = [21, 22, 23, 80, 443, 8080]
   
    print(f"[*] Starting Red Team baseline scan on: {TARGET_IP}")
    print("[*] Scanning common ports...")
   
    for port in PORTS_TO_SCAN:
        scan_port(TARGET_IP, port)
       
    print("[*] Phase 1 scan complete.")