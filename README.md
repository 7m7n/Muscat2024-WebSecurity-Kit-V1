# Muscat2040 Web Security Kit

**One-Click Web Pentest Lab Setup**  
*Created by: m.alfahdi*  

Professional automated installer for building a complete web application security testing environment on Kali Linux and macOS.

## Features

 **300+ Security Tools** - Complete arsenal for web pentesting  
**Smart Installation** - Auto-detects OS, skips installed tools  
**Parallel Processing** - Fast multi-threaded installation  
**Organized Workspace** - Professional folder structure  
**Progress Tracking** - Visual progress bars and colored output  
**Comprehensive Logging** - Detailed installation logs  
**Interactive Menu** - Install everything or select categories  
**Python Libraries** - 30+ security automation modules  
**Premium Wordlists** - SecLists, PayloadsAllTheThings, FuzzDB  

## Requirements

**Linux (Kali/Ubuntu/Debian):**
- Root/sudo access
- 10GB+ free disk space

**macOS:**
- macOS 10.15+
- Homebrew (auto-installed if missing)
- 10GB+ free disk space

## 🚀 Quick Start

### Installation

```bash
# Download the installer
wget https://raw.githubusercontent.com/yourusername/muscat2040-security-kit/main/muscat2040_web_security_kit.py

# Make executable
chmod +x muscat2040_web_security_kit.py

# Run installer
sudo python3 muscat2040_web_security_kit.py  # Linux
python3 muscat2040_web_security_kit.py        # macOS
```

### One-Line Install (Linux)

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/yourusername/muscat2040-security-kit/main/muscat2040_web_security_kit.py)"
```

## Tools Included

### 🔍 Recon & Subdomain Discovery (16 tools)
- **amass** - In-depth subdomain enumeration
- **subfinder** - Fast passive subdomain discovery
- **assetfinder** - Find domains and subdomains
- **findomain** - Cross-platform subdomain enumerator
- **httpx** - Fast HTTP toolkit
- **httprobe** - Probe HTTP/HTTPS servers
- **dnsx** - Fast DNS toolkit
- **shuffledns** - Active subdomain enumeration
- **gau** - Fetch URLs from AlienVault OTX, Wayback, etc.
- **waybackurls** - Fetch URLs from Wayback Machine
- **hakrawler** - Fast web crawler
- **katana** - Next-gen crawling framework
- **gospider** - Fast web spider
- **photon** - Lightning-fast crawler
- **theHarvester** - E-mail, subdomain, and name harvester
- **nuclei** - Vulnerability scanner based on templates

### Directory & Parameter Discovery (7 tools)
- **ffuf** - Fast web fuzzer
- **gobuster** - Directory/file & DNS busting
- **dirsearch** - Web path scanner
- **wfuzz** - Web application fuzzer
- **feroxbuster** - Fast content discovery
- **arjun** - HTTP parameter discovery
- **paramspider** - Parameter mining

### Vulnerability Scanning (9 tools)
- **sqlmap** - Automatic SQL injection tool
- **dalfox** - XSS scanner and parameter analyzer
- **xsstrike** - Advanced XSS detection suite
- **nikto** - Web server scanner
- **wafw00f** - Web application firewall detection
- **jaeles** - Powerful vulnerability scanner
- **corsy** - CORS misconfiguration scanner
- **ssrfmap** - SSRF vulnerability scanner
- **testssl.sh** - SSL/TLS testing tool

###  Proxy & Manual Testing (3 tools)
- **mitmproxy** - Interactive HTTPS proxy
- **OWASP ZAP** - Web application security scanner
- **Burp Suite Community** (manual install recommended)

###  API & Modern Web Testing (4 tools)
- **kiterunner** - API & route discovery
- **graphqlmap** - GraphQL vulnerability scanner
- **jwt_tool** - JWT security testing
- **httpie** - Modern HTTP client

### Authentication & Password Testing (3 tools)
- **hydra** - Password brute-forcing
- **patator** - Multi-purpose brute-forcer
- **hashcat** - Advanced password recovery

### Utilities (8 tools)
- **whatweb** - Web technology identifier
- **curl** - Command line HTTP client
- **wget** - File downloader
- **jq** - JSON processor
- **go** - Go programming language
- **git** - Version control
- **python3** - Python interpreter
- **nmap** - Network scanner

##  Python Libraries (30+)

**HTTP & Web:**
- requests, aiohttp, httpx, urllib3
- beautifulsoup4, lxml, scrapy

**Automation & Testing:**
- selenium, playwright

**Security & Crypto:**
- scapy, pwntools, paramiko
- pyjwt, cryptography, pyOpenSSL
- pycryptodome

**Network & DNS:**
- dnspython, python-nmap, shodan
- netaddr, impacket, ldap3

**Utilities:**
- rich, colorama, tqdm
- regex, jsbeautifier, pyyaml

## Wordlists

- **SecLists** - Ultimate security wordlist collection
- **PayloadsAllTheThings** - Useful payloads and bypasses
- **FuzzDB** - Attack patterns and primitives
- **OneListForAll** - All-in-one wordlist
- **RAFT** - Comprehensive wordlist for fuzzing

##  Workspace Structure

```
~/web_pentest_lab/
├── tools/              # Downloaded security tools
├── wordlists/          # Premium wordlist collections
├── recon/              # Reconnaissance results
├── scans/              # Vulnerability scan outputs
├── reports/            # Generated reports
├── screenshots/        # Web application screenshots
├── payloads/           # Custom payloads
├── scripts/            # Automation scripts
├── nuclei-templates/   # Nuclei vulnerability templates
└── installation.log    # Installation log file
```

## Usage Examples

### Quick Subdomain Enumeration
```bash
subfinder -d target.com | httpx -silent | nuclei -t ~/web_pentest_lab/nuclei-templates/
```

### Directory Fuzzing
```bash
ffuf -u https://target.com/FUZZ -w ~/web_pentest_lab/wordlists/SecLists/Discovery/Web-Content/common.txt
```

### SQL Injection Testing
```bash
sqlmap -u "https://target.com/page?id=1" --batch --dbs
```

### Full Reconnaissance Workflow
```bash
cd ~/web_pentest_lab/recon
subfinder -d target.com -o subdomains.txt
cat subdomains.txt | httpx -silent -o live.txt
cat live.txt | nuclei -t ~/web_pentest_lab/nuclei-templates/ -o vulnerabilities.txt
```

## Interactive Menu

The installer provides an interactive menu with these options:

1. **Install Everything** - Complete automated setup
2. **Install by Category** - Select specific tool categories
3. **Install Python Libraries Only** - Security modules only
4. **Download Wordlists Only** - Wordlist collections only
5. **Update Existing Tools** - Refresh all installations
6. **Show Installation Summary** - View installation status

## Updating Tools

To update all tools to their latest versions:

```bash
# Run installer and select option 5
sudo python3 muscat2040_web_security_kit.py

# Or update specific tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
nuclei -ut  # Update Nuclei templates
```

## 🐛 Troubleshooting

### Tool Not Found After Installation
```bash
# Add Go binaries to PATH
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Permission Denied
```bash
# Linux requires sudo
sudo python3 muscat2040_web_security_kit.py

# macOS doesn't need sudo
python3 muscat2040_web_security_kit.py
```

### Failed Installations
Check the log file for details:
```bash
cat ~/web_pentest_lab/installation.log
```

### Homebrew Not Found (macOS)
The installer auto-installs Homebrew. If it fails:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This toolkit is designed for:
- Learning cybersecurity concepts
- Authorized penetration testing
- Bug bounty programs with permission
- Testing your own applications
-  Security research in controlled environments

**DO NOT use these tools on systems you don't own or have explicit permission to test.**

Unauthorized access to computer systems is illegal. Always obtain written permission before conducting security assessments.

## Log Files

All installation activities are logged to:
```
~/web_pentest_lab/installation.log
```

View logs:
```bash
tail -f ~/web_pentest_lab/installation.log
```

## Contributing

Contributions welcome! Areas for improvement:
- Additional security tools
- Tool installation optimizations
- Cross-platform compatibility
- Documentation improvements


## 🔒 Security Best Practices

1. **Keep Tools Updated** - Run updates regularly
2. **Use Virtual Machines** - Test in isolated environments
3. **Document Your Testing** - Keep detailed records
4. **Follow Responsible Disclosure** - Report vulnerabilities properly
5. **Understand the Tools** - Don't run commands blindly


## Performance

- **Installation Time**: 15-30 minutes (depending on internet speed)
- **Disk Space**: ~8-12 GB after full installation
- **Tools Installed**: 50+ core tools
- **Python Libraries**: 30+ modules
- **Wordlists**: 4 major collections

---

**Created with  by m.alfahdi**  
*Empowering the next generation of ethical hackers*

⭐ **If this helped you, give it a star!**
