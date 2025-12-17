#!/usr/bin/env python3
"""
Network Security Scanner
A comprehensive tool for network security assessment and monitoring.
Author: Your Name
License: MIT
"""

import socket
import sys
import threading
import time
from datetime import datetime
import json
import argparse

class NetworkSecurityScanner:
    def __init__(self, target, start_port=1, end_port=1024):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.open_ports = []
        self.vulnerabilities = []
        self.lock = threading.Lock()
        
    def resolve_target(self):
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(self.target)
            print(f"[+] Resolved {self.target} to {ip}")
            return ip
        except socket.gaierror:
            print(f"[-] Could not resolve hostname: {self.target}")
            return None
    
    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                with self.lock:
                    service = self.identify_service(port)
                    self.open_ports.append({
                        'port': port,
                        'service': service,
                        'status': 'open'
                    })
                    print(f"[+] Port {port} is OPEN - {service}")
                    
                    # Check for common vulnerabilities
                    vuln = self.check_vulnerability(port, service)
                    if vuln:
                        self.vulnerabilities.append(vuln)
            
            sock.close()
        except Exception as e:
            pass
    
    def identify_service(self, port):
        """Identify common services by port number"""
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Proxy',
            27017: 'MongoDB'
        }
        return common_ports.get(port, 'Unknown')
    
    def check_vulnerability(self, port, service):
        """Check for common vulnerabilities based on open ports"""
        vulnerabilities = {
            21: {
                'name': 'FTP Service Detected',
                'severity': 'MEDIUM',
                'description': 'FTP transmits credentials in plaintext. Consider using SFTP/FTPS.',
                'recommendation': 'Disable FTP or use encrypted alternatives (SFTP, FTPS)'
            },
            23: {
                'name': 'Telnet Service Detected',
                'severity': 'HIGH',
                'description': 'Telnet is unencrypted and highly insecure.',
                'recommendation': 'Disable Telnet immediately and use SSH instead'
            },
            445: {
                'name': 'SMB Service Exposed',
                'severity': 'HIGH',
                'description': 'SMB vulnerabilities are frequently exploited (e.g., EternalBlue).',
                'recommendation': 'Ensure SMB is patched, use SMBv3, and restrict access'
            },
            3389: {
                'name': 'RDP Service Exposed',
                'severity': 'MEDIUM',
                'description': 'RDP is a common target for brute force attacks.',
                'recommendation': 'Use strong passwords, enable NLA, and consider VPN access'
            }
        }
        
        if port in vulnerabilities:
            vuln = vulnerabilities[port].copy()
            vuln['port'] = port
            vuln['service'] = service
            return vuln
        return None
    
    def scan_range(self):
        """Scan a range of ports using threading"""
        print(f"\n[*] Starting scan on {self.target}")
        print(f"[*] Scanning ports {self.start_port}-{self.end_port}")
        print(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        threads = []
        for port in range(self.start_port, self.end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        print(f"\n[*] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def generate_report(self, filename='security_report.json'):
        """Generate a security report"""
        report = {
            'target': self.target,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_ports_scanned': self.end_port - self.start_port + 1,
            'open_ports': self.open_ports,
            'vulnerabilities': self.vulnerabilities,
            'risk_summary': self.calculate_risk_summary()
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        
        print(f"\n[+] Report saved to {filename}")
        return report
    
    def calculate_risk_summary(self):
        """Calculate overall risk summary"""
        severity_count = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in self.vulnerabilities:
            severity_count[vuln['severity']] += 1
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'high_severity': severity_count['HIGH'],
            'medium_severity': severity_count['MEDIUM'],
            'low_severity': severity_count['LOW']
        }
    
    def print_summary(self):
        """Print scan summary"""
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"Open Ports Found: {len(self.open_ports)}")
        print(f"Vulnerabilities Detected: {len(self.vulnerabilities)}")
        
        if self.open_ports:
            print("\nOpen Ports:")
            for port_info in self.open_ports:
                print(f"  - Port {port_info['port']}: {port_info['service']}")
        
        if self.vulnerabilities:
            print("\nVulnerabilities:")
            for vuln in self.vulnerabilities:
                print(f"\n  [{vuln['severity']}] {vuln['name']}")
                print(f"  Port: {vuln['port']} ({vuln['service']})")
                print(f"  Description: {vuln['description']}")
                print(f"  Recommendation: {vuln['recommendation']}")
        
        print("\n" + "="*60)


def main():
    parser = argparse.ArgumentParser(
        description='Network Security Scanner - Scan networks for open ports and vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_scanner.py -t scanme.nmap.org
  python network_scanner.py -t 192.168.1.1 -s 1 -e 100
  python network_scanner.py -t example.com -s 20 -e 443 -o report.json
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname')
    parser.add_argument('-s', '--start', type=int, default=1, help='Starting port (default: 1)')
    parser.add_argument('-e', '--end', type=int, default=1024, help='Ending port (default: 1024)')
    parser.add_argument('-o', '--output', default='security_report.json', help='Output report filename')
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════════╗
    ║   Network Security Scanner v1.0           ║
    ║   Educational Purpose Only                ║
    ╚═══════════════════════════════════════════╝
    """)
    
    print("[!] DISCLAIMER: Only scan networks you have permission to test!")
    print("[!] Unauthorized scanning may be illegal in your jurisdiction.\n")
    
    # Create scanner instance
    scanner = NetworkSecurityScanner(args.target, args.start, args.end)
    
    # Resolve target
    ip = scanner.resolve_target()
    if not ip:
        sys.exit(1)
    
    # Run scan
    try:
        scanner.scan_range()
        scanner.print_summary()
        scanner.generate_report(args.output)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()