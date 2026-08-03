import socket

def get_service_fingerprint(target_ip, port):
    try:
        # Create the TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Give the server 2 seconds to respond with its banner
        s.settimeout(2.0)
        
        # Connect to the target port
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            print(f"[+] Port {port:5} : OPEN. Attempting to grab fingerprint...")
            
            # 💡 THE FINGERPRINT MAGIC: 
            # We read the first 1024 bytes of data the service automatically sends us
            raw_banner = s.recv(1024)
            
            # Decode the raw network bytes into clean text, ignoring weird characters
            clean_banner = raw_banner.decode('utf-8', errors='ignore').strip()
            
            if clean_banner:
                print(f"    └── 🧬 FINGERPRINT: {clean_banner}\n")
            else:
                print(f"    └── 🧬 FINGERPRINT: Connected, but service is silent.\n")
        
        s.close()
        
    except socket.timeout:
        # Some services wait for you to talk first, causing a timeout
        print(f"    └── 🧬 FINGERPRINT: Port open, but banner retrieval timed out.\n")
    except Exception as e:
        print(f"[!] Error on port {port}: {e}\n")

if __name__ == "__main__":
    # ⚠️ Keep your SEED VM's IP address here
    TARGET_IP = "192.168.56.106" 
    
    # We will target the exact open ports your baseline scan discovered
    PORTS_TO_FINGERPRINT = [21, 22, 23]
    
    print(f"[*] Starting Service Fingerprint Scan on: {TARGET_IP}\n")
    
    for port in PORTS_TO_FINGERPRINT:
        get_service_fingerprint(TARGET_IP, port)
        
    print("[*] Fingerprint scan complete.")