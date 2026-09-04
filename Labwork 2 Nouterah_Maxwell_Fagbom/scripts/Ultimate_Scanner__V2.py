#!/usr/bin/env python3
"""
Ultimate Scanner v4
Features:
- Scapy TCP SYN Half-Open Stealth Scanning
- ThreadPoolExecutor for rate limiting
- Local/Offline Banner-to-CVE Mapping
- Scapy TCP/IP Stack OS Fingerprinting
- Automated Reporting: Markdown, CSV, TXT, and Interactive Dark-Mode HTML Dashboard
"""

import os
import sys
import csv
import socket
import datetime
import logging
from concurrent.futures import ThreadPoolExecutor

# Mute Scapy logging output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import IP, TCP, sr1, send, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Local Vulnerability Database (Offline Fallback)
LOCAL_VULN_DB = {
    "apache/2.4.49": "CVE-2021-41773 (Path Traversal / RCE)",
    "vsftpd 2.3.4": "CVE-2011-2523 (Backdoor Command Execution)",
    "openssh 7.2p2": "CVE-2016-6210 (User Enumeration)",
    "openssh 4.7p1": "CVE-2008-0166 (OpenSSL Weak Key Predictability)",
    "apache/2.2.8": "CVE-2008-0455 (HTTP Response Splitting)",
    "samba 3.0.20": "CVE-2007-2447 (Username Map Script Execution)"
}

class StealthOSFingerprinter:
    """Performs OS identification via TCP/IP packet header analysis."""

    @staticmethod
    def detect_os(target_ip, port=80):
        if not SCAPY_AVAILABLE:
            return {"os": "Scapy Unavailable", "ttl": "N/A", "window": "N/A"}

        try:
            probe = IP(dst=target_ip) / TCP(dport=port, flags="S")
            reply = sr1(probe, timeout=2)

            if reply is None:
                return {"os": "Filtered / No Response", "ttl": "N/A", "window": "N/A"}

            if reply.haslayer(TCP):
                ttl = reply[IP].ttl
                window = reply[TCP].window

                if ttl <= 64:
                    os_family = "Linux / Unix / macOS"
                elif ttl <= 128:
                    os_family = "Windows System"
                elif ttl <= 255:
                    os_family = "Cisco / Network Device"
                else:
                    os_family = "Unknown Stack"

                return {"os": os_family, "ttl": ttl, "window": window}
        except Exception as e:
            return {"os": f"Error: {str(e)}", "ttl": "N/A", "window": "N/A"}

        return {"os": "Unknown", "ttl": "N/A", "window": "N/A"}

class StealthScanner:
    """TCP SYN Stealth Scanner with Banner Grabbing & Offline CVE Matching."""

    def __init__(self, target_ip, ports, max_threads=10):
        self.target_ip = target_ip
        self.ports = ports
        self.max_threads = max_threads

    def grab_banner(self, port):
        """Standard banner grabbing post-discovery."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((self.target_ip, port))
            s.sendall(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip().split("\n")[0]
            s.close()
            return banner if banner else "No banner returned"
        except Exception:
            return "No banner captured"

    def match_vulnerability(self, banner):
        """Cross-references banners with local CVE database."""
        banner_lower = banner.lower()
        matched_cves = []
        for service, cve in LOCAL_VULN_DB.items():
            if service in banner_lower:
                matched_cves.append(cve)
        return ", ".join(matched_cves) if matched_cves else "No known local CVE match"

    def syn_scan_port(self, port):
        """Performs a TCP SYN Half-Open Stealth Scan on a specific port."""
        if not SCAPY_AVAILABLE:
            return self._fallback_connect_scan(port)

        try:
            syn_pkt = IP(dst=self.target_ip) / TCP(dport=port, flags="S")
            response = sr1(syn_pkt, timeout=1.5)

            if response is not None and response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    rst_pkt = IP(dst=self.target_ip) / TCP(dport=port, flags="R")
                    send(rst_pkt)

                    banner = self.grab_banner(port)
                    vuln_info = self.match_vulnerability(banner)

                    return {
                        "port": port,
                        "status": "OPEN (SYN-ACK)",
                        "banner": banner,
                        "vulnerabilities": vuln_info
                    }
                elif response[TCP].flags == 0x14:  # RST
                    return None
        except Exception:
            pass
        return None

    def _fallback_connect_scan(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            if s.connect_ex((self.target_ip, port)) == 0:
                banner = self.grab_banner(port)
                vuln_info = self.match_vulnerability(banner)
                s.close()
                return {
                    "port": port,
                    "status": "OPEN (Connect)",
                    "banner": banner,
                    "vulnerabilities": vuln_info
                }
            s.close()
        except Exception:
            pass
        return None

    def execute_scan(self):
        print(f"[*] Initiating SYN Stealth Scan on {self.target_ip} (Threads: {self.max_threads})...")
        open_results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            scanned_ports = executor.map(self.syn_scan_port, self.ports)

        for result in scanned_ports:
            if result:
                open_results.append(result)
                print(f"  [+] Port {result['port']}: {result['status']} | Banner: {result['banner']}")

        return open_results

class AutomatedReportGenerator:
    """Generates structured CSV, Markdown, TXT, and HTML reports."""

    def __init__(self, target_ip, results, os_data, output_dir="reports"):
        self.target_ip = target_ip
        self.results = results
        self.os_data = os_data
        self.output_dir = output_dir
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def export_all(self):
        md_path = self._export_markdown()
        csv_path = self._export_csv()
        txt_path = self._export_txt()
        html_path = self._export_html()
        return md_path, csv_path, txt_path, html_path

    def _export_markdown(self):
        path = os.path.join(self.output_dir, f"report_{self.target_ip}_{self.timestamp}.md")
        with open(path, "w") as f:
            f.write(f"# Reconnaissance Report: {self.target_ip}\n\n")
            f.write(f"- **Scan Date:** {self.timestamp}\n")
            f.write(f"- **OS Prediction:** {self.os_data.get('os')} (TTL: {self.os_data.get('ttl')})\n\n")
            f.write("## Discovered Services & Vulnerabilities\n\n")
            f.write("| Port | Status | Banner | Identified Vulnerabilities |\n")
            f.write("|------|--------|--------|----------------------------|\n")
            for r in self.results:
                f.write(f"| {r['port']} | {r['status']} | {r['banner']} | {r['vulnerabilities']} |\n")
        return path

    def _export_csv(self):
        path = os.path.join(self.output_dir, f"report_{self.target_ip}_{self.timestamp}.csv")
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Target", "Port", "Status", "Banner", "Vulnerabilities", "Predicted_OS", "TTL", "Timestamp"])
            for r in self.results:
                writer.writerow([
                    self.target_ip, r['port'], r['status'], r['banner'],
                    r['vulnerabilities'], self.os_data.get('os'), self.os_data.get('ttl'), self.timestamp
                ])
        return path

    def _export_txt(self):
        path = os.path.join(self.output_dir, f"report_{self.target_ip}_{self.timestamp}.txt")
        with open(path, "w") as f:
            f.write("=" * 60 + "\n")
            f.write(f" RECONNAISSANCE SCAN REPORT - {self.target_ip}\n")
            f.write(f" Generated: {self.timestamp}\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Target OS Family: {self.os_data.get('os')}\n")
            f.write(f"Captured TTL:     {self.os_data.get('ttl')}\n\n")
            f.write("Open Port Findings:\n")
            f.write("-" * 60 + "\n")
            for r in self.results:
                f.write(f"Port {r['port']} [{r['status']}]\n")
                f.write(f"  Banner: {r['banner']}\n")
                f.write(f"  CVEs:   {r['vulnerabilities']}\n\n")
        return path

    def _export_html(self):
        path = os.path.join(self.output_dir, f"report_{self.target_ip}_{self.timestamp}.html")
        
        rows_html = ""
        for r in self.results:
            vuln_style = "color: #ff5555; font-weight: bold;" if "CVE" in r['vulnerabilities'] else "color: #a6adc8;"
            rows_html += f"""
            <tr>
                <td><span class="badge port">{r['port']}</span></td>
                <td><span class="badge open">{r['status']}</span></td>
                <td><code>{r['banner']}</code></td>
                <td style="{vuln_style}">{r['vulnerabilities']}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Recon Report - {self.target_ip}</title>
    <style>
        body {{ background-color: #1e1e2e; color: #cdd6f4; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 40px; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: #181825; padding: 30px; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }}
        h1 {{ color: #89b4fa; border-bottom: 2px solid #313244; padding-bottom: 10px; margin-top: 0; }}
        .cards {{ display: flex; gap: 20px; margin-bottom: 30px; }}
        .card {{ flex: 1; background: #313244; padding: 15px; border-radius: 8px; border-left: 4px solid #89b4fa; }}
        .card h3 {{ margin: 0 0 5px 0; font-size: 14px; color: #a6adc8; text-transform: uppercase; }}
        .card p {{ margin: 0; font-size: 18px; font-weight: bold; color: #f5e0dc; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #313244; }}
        th {{ background-color: #313244; color: #89b4fa; text-transform: uppercase; font-size: 12px; letter-spacing: 1px; }}
        tr:hover {{ background-color: #2a2b3c; }}
        code {{ background: #11111b; padding: 3px 6px; border-radius: 4px; font-family: monospace; color: #a6e3a1; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge.port {{ background: #45475a; color: #f5e0dc; }}
        .badge.open {{ background: #a6e3a1; color: #11111b; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Reconnaissance Report</h1>
        <div class="cards">
            <div class="card">
                <h3>Target Host</h3>
                <p>{self.target_ip}</p>
            </div>
            <div class="card">
                <h3>Predicted OS</h3>
                <p>{self.os_data.get('os')} (TTL: {self.os_data.get('ttl')})</p>
            </div>
            <div class="card">
                <h3>Open Ports</h3>
                <p>{len(self.results)} Detected</p>
            </div>
            <div class="card">
                <h3>Scan Timestamp</h3>
                <p>{self.timestamp}</p>
            </div>
        </div>
        <h2>Open Ports & Vulnerability Analysis</h2>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Status</th>
                    <th>Service Banner</th>
                    <th>Vulnerabilities Detected</th>
                </tr>
            </thead>
            <tbody>
                {rows_html if rows_html else '<tr><td colspan="4">No open ports detected.</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        with open(path, "w") as f:
            f.write(html_content)
        return path

if __name__ == "__main__":
    DEFAULT_TARGET = "192.168.56.106"

    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = DEFAULT_TARGET
        print(f"[*] No IP provided. Defaulting to SEED VM: {target}")

    ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 8080]

    # Step 1: Execute Stealth SYN Scan
    scanner = StealthScanner(target_ip=target, ports=ports, max_threads=10)
    results = scanner.execute_scan()

    # Step 2: Perform OS Fingerprinting
    target_port = results[0]['port'] if results else 80
    print(f"[*] Performing Scapy OS Fingerprinting against port {target_port}...")
    os_info = StealthOSFingerprinter.detect_os(target, port=target_port)
    print(f"[+] Identified OS: {os_info['os']} (TTL: {os_info['ttl']})")

    # Step 3: Generate Reports
    print("[*] Exporting scan reports...")
    reporter = AutomatedReportGenerator(target, results, os_info)
    md_out, csv_out, txt_out, html_out = reporter.export_all()

    print("\n[✔] Scan Complete. Structured reports generated successfully:")
    print(f"  - Markdown:  {md_out}")
    print(f"  - CSV:       {csv_out}")
    print(f"  - Text Log:  {txt_out}")
    print(f"  - HTML Dash: {html_out}")