# 🔒 Network Security Scanner

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**A powerful, educational network security assessment tool built with Python**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-examples) • [Documentation](#-documentation)

</div>

---

## ⚠️ Legal Disclaimer

> **IMPORTANT**: This tool is designed strictly for **educational and ethical security testing purposes**.
> 
> - ✅ Only scan networks and systems **you own**
> - ✅ Always obtain **explicit written permission** before scanning
> - ❌ Unauthorized scanning may be **illegal** and could result in criminal charges
> - ❌ The authors assume **no liability** for misuse of this tool

By using this tool, you agree to use it responsibly and legally.

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Command-Line Options](#-command-line-options)
- [Examples](#-examples)
- [Understanding the Output](#-understanding-the-output)
- [Report Format](#-report-format)
- [Detected Vulnerabilities](#-detected-vulnerabilities)
- [How It Works](#-how-it-works)
- [Contributing](#-contributing)
- [Roadmap](#-roadmap)
- [FAQ](#-faq)
- [License](#-license)

---

## ✨ Features

### Core Capabilities

- 🚀 **Fast Multi-threaded Scanning** - Scans up to 100 ports simultaneously
- 🔍 **Service Detection** - Identifies common services (HTTP, SSH, FTP, MySQL, etc.)
- 🛡️ **Vulnerability Assessment** - Detects common security misconfigurations
- 📊 **Risk Analysis** - Categorizes findings by severity (HIGH, MEDIUM, LOW)
- 📄 **JSON Reports** - Generates detailed, machine-readable security reports
- 💻 **Cross-Platform** - Works on Windows, Linux, and macOS
- 🎯 **Zero Dependencies** - Uses only Python standard library

### What Gets Detected

| Detection Type | Description |
|---------------|-------------|
| **Open Ports** | Identifies accessible network ports |
| **Services** | Recognizes 15+ common network services |
| **Insecure Protocols** | Flags Telnet, unencrypted FTP |
| **High-Risk Services** | Detects SMB, RDP exposure |
| **Security Risks** | Provides actionable recommendations |

---

## 🚀 Installation

### Prerequisites

- **Python 3.6 or higher** ([Download Python](https://www.python.org/downloads/))
- No external libraries required - uses Python standard library only

### Installation Steps

#### Option 1: Clone from GitHub

```bash
# Clone the repository
git clone https://github.com/yourusername/network-security-scanner.git

# Navigate to the directory
cd network-security-scanner

# Run the scanner
python network_scanner.py --help
```

#### Option 2: Download ZIP

1. Click the green **"Code"** button on GitHub
2. Select **"Download ZIP"**
3. Extract the ZIP file
4. Open terminal/command prompt in the extracted folder
5. Run: `python network_scanner.py --help`

#### Option 3: Manual Setup

```bash
# Create project directory
mkdir network-security-scanner
cd network-security-scanner

# Download the scanner script
# (Copy network_scanner.py from the repository)

# Run it
python network_scanner.py --help
```

### Verify Installation

```bash
# Check Python version
python --version
# Should output: Python 3.6.0 or higher

# Test the scanner
python network_scanner.py -t scanme.nmap.org -s 80 -e 80
```

---

## ⚡ Quick Start

### Basic Scan (Recommended for First-Time Users)

```bash
# Scan a safe test target with limited port range
python network_scanner.py -t scanme.nmap.org -s 20 -e 100
```

### Quick Scans

```bash
# Scan common ports only (fast)
python network_scanner.py -t scanme.nmap.org -s 1 -e 100

# Scan web ports only
python network_scanner.py -t example.com -s 80 -e 443

# Full default scan (ports 1-1024)
python network_scanner.py -t scanme.nmap.org
```

---

## 📖 Usage

### Basic Syntax

```bash
python network_scanner.py -t <target> [options]
```

### Command-Line Options

| Option | Description | Required | Default |
|--------|-------------|----------|---------|
| `-t`, `--target` | Target IP address or hostname | ✅ Yes | - |
| `-s`, `--start` | Starting port number | ❌ No | 1 |
| `-e`, `--end` | Ending port number | ❌ No | 1024 |
| `-o`, `--output` | Output report filename (JSON) | ❌ No | `security_report.json` |
| `-h`, `--help` | Show help message and exit | ❌ No | - |

### Target Formats

```bash
# Domain name
python network_scanner.py -t example.com

# IP address
python network_scanner.py -t 192.168.1.1

# Subdomain
python network_scanner.py -t api.example.com

# Test target (always use this for learning!)
python network_scanner.py -t scanme.nmap.org
```

---

## 💡 Examples

### Example 1: Basic Port Scan

```bash
python network_scanner.py -t scanme.nmap.org -s 20 -e 100
```

**Output:**
```
╔═══════════════════════════════════════════╗
║   Network Security Scanner v1.0           ║
║   Educational Purpose Only                ║
╚═══════════════════════════════════════════╝

[!] DISCLAIMER: Only scan networks you have permission to test!

[+] Resolved scanme.nmap.org to 45.33.32.156

[*] Starting scan on scanme.nmap.org
[*] Scanning ports 20-100

[+] Port 22 is OPEN - SSH
[+] Port 80 is OPEN - HTTP

============================================================
SCAN SUMMARY
============================================================
Target: scanme.nmap.org
Open Ports Found: 2
Vulnerabilities Detected: 0

Open Ports:
  - Port 22: SSH
  - Port 80: HTTP
============================================================
```

### Example 2: Localhost Scan

```bash
# Scan your own machine (safe for testing)
python network_scanner.py -t localhost -s 1 -e 1000
```

### Example 3: Specific Port Range

```bash
# Scan database ports
python network_scanner.py -t 192.168.1.100 -s 3000 -e 5000

# Scan only web services
python network_scanner.py -t example.com -s 80 -e 443
```

### Example 4: Custom Report Name

```bash
# Save report with custom filename
python network_scanner.py -t scanme.nmap.org -s 1 -e 100 -o my_scan_report.json
```

### Example 5: Full Comprehensive Scan

```bash
# Scan all default ports (takes longer)
python network_scanner.py -t scanme.nmap.org
```

---

## 📊 Understanding the Output

### Terminal Output Explained

```
[+] Port 22 is OPEN - SSH
│   │         │          │
│   │         │          └─── Service running on the port
│   │         └────────────── Port number
│   └──────────────────────── Port status
└──────────────────────────── Success indicator
```

### Status Indicators

| Symbol | Meaning |
|--------|---------|
| `[+]` | Success / Open port found |
| `[*]` | Information message |
| `[!]` | Warning / Important notice |
| `[-]` | Error / Port closed |

### Scan Summary Section

```
============================================================
SCAN SUMMARY
============================================================
Target: scanme.nmap.org           ← Target that was scanned
Open Ports Found: 2               ← Number of accessible ports
Vulnerabilities Detected: 1       ← Number of security issues found

Open Ports:                       ← List of all open ports
  - Port 22: SSH
  - Port 80: HTTP

Vulnerabilities:                  ← Security issues detected
  [HIGH] Telnet Service Detected
  Port: 23 (Telnet)
  Description: Telnet is unencrypted and highly insecure.
  Recommendation: Disable Telnet immediately and use SSH instead
============================================================
```

---

## 📄 Report Format

The scanner generates a JSON report with the following structure:

```json
{
    "target": "scanme.nmap.org",
    "scan_date": "2024-11-25 15:30:45",
    "total_ports_scanned": 100,
    "open_ports": [
        {
            "port": 22,
            "service": "SSH",
            "status": "open"
        },
        {
            "port": 80,
            "service": "HTTP",
            "status": "open"
        }
    ],
    "vulnerabilities": [
        {
            "name": "Telnet Service Detected",
            "severity": "HIGH",
            "port": 23,
            "service": "Telnet",
            "description": "Telnet is unencrypted and highly insecure.",
            "recommendation": "Disable Telnet immediately and use SSH instead"
        }
    ],
    "risk_summary": {
        "total_vulnerabilities": 1,
        "high_severity": 1,
        "medium_severity": 0,
        "low_severity": 0
    }
}
```

### Reading the JSON Report

```bash
# View the report in terminal
cat security_report.json

# Windows PowerShell
Get-Content security_report.json

# Open in default JSON viewer
start security_report.json  # Windows
open security_report.json   # macOS
xdg-open security_report.json  # Linux
```

---

## 🛡️ Detected Vulnerabilities

The scanner identifies these common security issues:

### High Severity

| Port | Service | Issue | Risk |
|------|---------|-------|------|
| **23** | Telnet | Unencrypted protocol transmits data in plaintext | Credentials can be intercepted |
| **445** | SMB | Vulnerable to attacks like EternalBlue/WannaCry | Remote code execution possible |

### Medium Severity

| Port | Service | Issue | Risk |
|------|---------|-------|------|
| **21** | FTP | Credentials transmitted in plaintext | Authentication bypass |
| **3389** | RDP | Common target for brute force attacks | Unauthorized access |

### Recommendations by Vulnerability

#### 🔴 Telnet (Port 23) - HIGH
- **Problem**: All data including passwords sent in plaintext
- **Solution**: 
  - Disable Telnet service immediately
  - Use SSH (Port 22) instead
  - Configure firewall to block port 23

#### 🔴 SMB (Port 445) - HIGH
- **Problem**: Known vulnerabilities (EternalBlue, WannaCry)
- **Solution**:
  - Update to latest SMB version (SMBv3)
  - Apply security patches
  - Restrict access with firewall rules
  - Use VPN for remote access

#### 🟡 FTP (Port 21) - MEDIUM
- **Problem**: Credentials transmitted unencrypted
- **Solution**:
  - Switch to SFTP (SSH File Transfer Protocol)
  - Use FTPS (FTP over SSL/TLS)
  - Implement strong authentication

#### 🟡 RDP (Port 3389) - MEDIUM
- **Problem**: Target for brute force attacks
- **Solution**:
  - Enable Network Level Authentication (NLA)
  - Use strong, complex passwords
  - Implement account lockout policies
  - Use VPN or jump servers for access
  - Enable two-factor authentication

---

## ⚙️ How It Works

### Architecture Overview

```
┌─────────────────────────────────────────────────┐
│           Network Security Scanner              │
├─────────────────────────────────────────────────┤
│                                                 │
│  1. Target Resolution                           │
│     └─> DNS Lookup (hostname → IP)             │
│                                                 │
│  2. Port Scanning (Multi-threaded)              │
│     └─> TCP Connection Attempts                │
│     └─> 100 Concurrent Threads                 │
│                                                 │
│  3. Service Identification                      │
│     └─> Port Number → Service Mapping          │
│                                                 │
│  4. Vulnerability Detection                     │
│     └─> Rule-based Analysis                    │
│     └─> Severity Assessment                    │
│                                                 │
│  5. Report Generation                           │
│     └─> JSON Output                            │
│     └─> Risk Summary                           │
│                                                 │
└─────────────────────────────────────────────────┘
```

### Technical Details

#### 1. **DNS Resolution**
```python
socket.gethostbyname(target)  # Converts hostname to IP
```

#### 2. **Port Scanning Method**
- Uses TCP SYN connection attempts
- Multi-threaded for speed (100 concurrent threads)
- 1-second timeout per port
- Non-invasive scanning technique

#### 3. **Service Detection**
- Port-based identification
- Supports 15+ common services
- Extensible service database

#### 4. **Vulnerability Assessment**
- Rule-based detection system
- Severity classification (HIGH/MEDIUM/LOW)
- Actionable recommendations

---

## 🤝 Contributing

Contributions make the open-source community amazing! Any contributions you make are **greatly appreciated**.

### How to Contribute

1. **Fork the Project**
2. **Create your Feature Branch**
   ```bash
   git checkout -b feature/AmazingFeature
   ```
3. **Commit your Changes**
   ```bash
   git commit -m 'Add some AmazingFeature'
   ```
4. **Push to the Branch**
   ```bash
   git push origin feature/AmazingFeature
   ```
5. **Open a Pull Request**

### Contribution Ideas

- 🐛 Report bugs and issues
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit bug fixes
- ✨ Add new vulnerability checks
- 🎨 Enhance output formatting

---

## 🗺️ Roadmap

### Version 1.1 (Planned)
- [ ] Add banner grabbing for precise service detection
- [ ] Implement OS fingerprinting
- [ ] Add stealth scanning mode
- [ ] Create HTML report generation

### Version 2.0 (Future)
- [ ] UDP port scanning support
- [ ] Integration with CVE databases
- [ ] Network mapping visualization
- [ ] Web-based dashboard
- [ ] Automated remediation suggestions
- [ ] Export to PDF reports

---

## ❓ FAQ

### Q: Is this tool safe to use?
**A:** Yes, when used on systems you own or have permission to scan. Never scan unauthorized systems.

### Q: Why is my scan slow?
**A:** Large port ranges take time. Try scanning smaller ranges like `-s 1 -e 100` for faster results.

### Q: Can I scan any website?
**A:** Only scan websites you own. Use `scanme.nmap.org` for testing - it's a public test target.

### Q: Does this work on Windows?
**A:** Yes! Works on Windows, macOS, and Linux with Python 3.6+.

### Q: How accurate is the vulnerability detection?
**A:** The tool detects common misconfigurations. For production systems, use professional tools like Nessus or OpenVAS.

### Q: Can this tool hack systems?
**A:** No. It's a passive scanning tool for assessment only. It doesn't exploit vulnerabilities.

### Q: What ports should I scan?
**A:** Common ranges:
- `1-1024`: Well-known ports
- `1-100`: Quick scan
- `80,443`: Web services only
- `20-25`: FTP and email
- `3306,5432`: Databases

---

## 📚 Educational Resources

### Learn More About Network Security

- 📖 [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - Web security testing methodology
- 📖 [Nmap Official Documentation](https://nmap.org/book/) - The network scanning bible
- 📖 [Python Socket Programming](https://docs.python.org/3/library/socket.html) - Official Python documentation
- 📖 [Port Numbers Registry](https://www.iana.org/assignments/service-names-port-numbers/) - IANA official port list
- 📖 [CVE Database](https://cve.mitre.org/) - Common Vulnerabilities and Exposures

### Practice Safely

- 🎯 [HackTheBox](https://www.hackthebox.eu/) - Legal hacking practice
- 🎯 [TryHackMe](https://tryhackme.com/) - Cybersecurity training
- 🎯 [scanme.nmap.org](http://scanme.nmap.org/) - Official test target

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

**TL;DR** - You can use, modify, and distribute this tool freely, but:
- Include the original license
- No warranty provided
- Authors not liable for misuse

---

## 👨‍💻 Author

**Your Name**
- GitHub: [@yourusername](https://github.com/yourusername)
- Twitter: [@yourtwitter](https://twitter.com/yourtwitter)
- LinkedIn: [Your Name](https://linkedin.com/in/yourprofile)
- Email: your.email@example.com

---

## 🙏 Acknowledgments

- Inspired by [Nmap](https://nmap.org/) - The industry-standard network scanner
- Thanks to the Python community for excellent documentation
- Built for educational purposes to teach network security fundamentals
- Special thanks to all contributors and the open-source security community

---

## 🔗 Project Links

- **Repository**: [https://github.com/yourusername/network-security-scanner](https://github.com/yourusername/network-security-scanner)
- **Issues**: [Report a bug](https://github.com/yourusername/network-security-scanner/issues)
- **Discussions**: [Join the conversation](https://github.com/yourusername/network-security-scanner/discussions)

---

<div align="center">

### ⭐ Star this repository if you found it helpful!

**Made with ❤️ for the cybersecurity community**

*Remember: Always scan responsibly and ethically!*

</div>