#!/usr/bin/env python3
"""
Muscat2040 Web Security Kit - One-Click Web Pentest Lab Setup
Created by: m.alfahdi

Professional Web Security & Penetration Testing Environment Installer
For educational and authorized testing purposes only.
"""

import os
import sys
import platform
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple
import threading
from queue import Queue
import json

# Color codes for terminal
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    PURPLE = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

class ProgressBar:
    """Simple progress indicator"""
    def __init__(self, total):
        self.total = total
        self.current = 0
        self.lock = threading.Lock()
    
    def update(self, increment=1):
        with self.lock:
            self.current += increment
            self.display()
    
    def display(self):
        percent = (self.current / self.total) * 100
        bar_length = 50
        filled = int(bar_length * self.current / self.total)
        bar = '█' * filled + '░' * (bar_length - filled)
        print(f'\r{Colors.OKCYAN}[{bar}] {percent:.1f}%{Colors.ENDC}', end='', flush=True)
        if self.current >= self.total:
            print()

class SecurityLabInstaller:
    def __init__(self):
        self.os_type = platform.system()
        self.is_macos = self.os_type == "Darwin"
        self.is_linux = self.os_type == "Linux"
        self.home = str(Path.home())
        self.workspace = os.path.join(self.home, "web_pentest_lab")
        self.log_file = os.path.join(self.workspace, "installation.log")
        self.installed_tools = set()
        self.failed_tools = []
        
        # Tool categories
        self.tools = {
            "recon": [
                ("amass", "go install -v github.com/owasp-amass/amass/v4/...@master", "go"),
                ("subfinder", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "go"),
                ("assetfinder", "go install github.com/tomnomnom/assetfinder@latest", "go"),
                ("findomain", "wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O /usr/local/bin/findomain && chmod +x /usr/local/bin/findomain", "wget") if not self.is_macos else ("findomain", "brew install findomain", "brew"),
                ("httpx", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "go"),
                ("httprobe", "go install github.com/tomnomnom/httprobe@latest", "go"),
                ("dnsx", "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "go"),
                ("shuffledns", "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest", "go"),
                ("gau", "go install github.com/lc/gau/v2/cmd/gau@latest", "go"),
                ("waybackurls", "go install github.com/tomnomnom/waybackurls@latest", "go"),
                ("hakrawler", "go install github.com/hakluke/hakrawler@latest", "go"),
                ("katana", "go install github.com/projectdiscovery/katana/cmd/katana@latest", "go"),
                ("gospider", "go install github.com/jaeles-project/gospider@latest", "go"),
                ("photon", "pip3 install photon-python", "pip3"),
                ("theHarvester", "pip3 install theharvester", "pip3"),
                ("nuclei", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "go"),
            ],
            "directory": [
                ("ffuf", "go install github.com/ffuf/ffuf/v2@latest", "go"),
                ("gobuster", "go install github.com/OJ/gobuster/v3@latest", "go"),
                ("dirsearch", "pip3 install dirsearch", "pip3"),
                ("wfuzz", "pip3 install wfuzz", "pip3"),
                ("feroxbuster", "brew install feroxbuster" if self.is_macos else "wget https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip -O /tmp/ferox.zip && unzip /tmp/ferox.zip -d /tmp && mv /tmp/feroxbuster /usr/local/bin/ && chmod +x /usr/local/bin/feroxbuster", "brew" if self.is_macos else "wget"),
                ("arjun", "pip3 install arjun", "pip3"),
                ("paramspider", "pip3 install paramspider", "pip3"),
            ],
            "vuln_scan": [
                ("sqlmap", "pip3 install sqlmap", "pip3"),
                ("dalfox", "go install github.com/hahwul/dalfox/v2@latest", "go"),
                ("xsstrike", "git clone https://github.com/s0md3v/XSStrike.git " + self.workspace + "/tools/XSStrike", "git"),
                ("nikto", "brew install nikto" if self.is_macos else "apt install -y nikto", "brew" if self.is_macos else "apt"),
                ("wafw00f", "pip3 install wafw00f", "pip3"),
                ("jaeles", "go install github.com/jaeles-project/jaeles@latest", "go"),
                ("corsy", "pip3 install corsy", "pip3"),
                ("ssrfmap", "git clone https://github.com/swisskyrepo/SSRFmap.git " + self.workspace + "/tools/SSRFmap", "git"),
                ("testssl.sh", "git clone --depth 1 https://github.com/drwetter/testssl.sh.git " + self.workspace + "/tools/testssl.sh", "git"),
            ],
            "proxy": [
                ("mitmproxy", "pip3 install mitmproxy", "pip3"),
                ("zaproxy", "brew install --cask owasp-zap" if self.is_macos else "apt install -y zaproxy", "brew" if self.is_macos else "apt"),
            ],
            "api": [
                ("kiterunner", "git clone https://github.com/assetnote/kiterunner.git " + self.workspace + "/tools/kiterunner && cd " + self.workspace + "/tools/kiterunner && make build", "git"),
                ("graphqlmap", "git clone https://github.com/swisskyrepo/GraphQLmap.git " + self.workspace + "/tools/GraphQLmap", "git"),
                ("jwt_tool", "pip3 install pyjwt", "pip3"),
                ("httpie", "pip3 install httpie", "pip3"),
            ],
            "auth": [
                ("hydra", "brew install hydra" if self.is_macos else "apt install -y hydra", "brew" if self.is_macos else "apt"),
                ("patator", "pip3 install patator", "pip3"),
                ("hashcat", "brew install hashcat" if self.is_macos else "apt install -y hashcat", "brew" if self.is_macos else "apt"),
            ],
            "utilities": [
                ("whatweb", "brew install whatweb" if self.is_macos else "apt install -y whatweb", "brew" if self.is_macos else "apt"),
                ("curl", "brew install curl" if self.is_macos else "apt install -y curl", "brew" if self.is_macos else "apt"),
                ("wget", "brew install wget" if self.is_macos else "apt install -y wget", "brew" if self.is_macos else "apt"),
                ("jq", "brew install jq" if self.is_macos else "apt install -y jq", "brew" if self.is_macos else "apt"),
                ("go", "brew install go" if self.is_macos else "apt install -y golang-go", "brew" if self.is_macos else "apt"),
                ("git", "brew install git" if self.is_macos else "apt install -y git", "brew" if self.is_macos else "apt"),
                ("python3", "brew install python3" if self.is_macos else "apt install -y python3 python3-pip", "brew" if self.is_macos else "apt"),
                ("nmap", "brew install nmap" if self.is_macos else "apt install -y nmap", "brew" if self.is_macos else "apt"),
            ]
        }
        
        # Python libraries for security automation
        self.python_libs = [
            "requests", "aiohttp", "httpx", "urllib3", "beautifulsoup4", "lxml",
            "selenium", "playwright", "rich", "colorama", "tqdm", "scapy",
            "dnspython", "pwntools", "paramiko", "pyjwt", "cryptography",
            "flask", "fastapi", "scrapy", "regex", "jsbeautifier", "python-nmap",
            "shodan", "pytest", "asyncio-mqtt", "websockets", "pyOpenSSL",
            "pyshark", "impacket", "ldap3", "pycryptodome", "netaddr", "pyyaml"
        ]
        
        # Wordlists to download
        self.wordlists = [
            ("SecLists", "https://github.com/danielmiessler/SecLists.git"),
            ("PayloadsAllTheThings", "https://github.com/swisskyrepo/PayloadsAllTheThings.git"),
            ("FuzzDB", "https://github.com/fuzzdb-project/fuzzdb.git"),
            ("OneListForAll", "https://github.com/six2dez/OneListForAll.git"),
        ]

    def print_banner(self):
        """Display cyber-style banner"""
        banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║  {Colors.BOLD}{Colors.PURPLE}███╗   ███╗██╗   ██╗███████╗ ██████╗ █████╗ ████████╗{Colors.ENDC}{Colors.CYAN}        ║
║  {Colors.BOLD}{Colors.PURPLE}████╗ ████║██║   ██║██╔════╝██╔════╝██╔══██╗╚══██╔══╝{Colors.ENDC}{Colors.CYAN}        ║
║  {Colors.BOLD}{Colors.PURPLE}██╔████╔██║██║   ██║███████╗██║     ███████║   ██║   {Colors.ENDC}{Colors.CYAN}        ║
║  {Colors.BOLD}{Colors.PURPLE}██║╚██╔╝██║██║   ██║╚════██║██║     ██╔══██║   ██║   {Colors.ENDC}{Colors.CYAN}        ║
║  {Colors.BOLD}{Colors.PURPLE}██║ ╚═╝ ██║╚██████╔╝███████║╚██████╗██║  ██║   ██║   {Colors.ENDC}{Colors.CYAN}        ║
║  {Colors.BOLD}{Colors.PURPLE}╚═╝     ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   {Colors.ENDC}{Colors.CYAN}        ║
║                                                                   ║
║         {Colors.BOLD}{Colors.WHITE}Web Security Kit - One-Click Pentest Lab Setup{Colors.ENDC}{Colors.CYAN}          ║
║                  {Colors.WARNING}created by: m.alfahdi{Colors.ENDC}{Colors.CYAN}                          ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.OKGREEN}[+] System Detected: {Colors.BOLD}{self.os_type}{Colors.ENDC}
{Colors.OKGREEN}[+] Workspace: {Colors.BOLD}{self.workspace}{Colors.ENDC}
"""
        print(banner)

    def log(self, message, level="INFO"):
        """Log messages to file and console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # Console output with colors
        if level == "ERROR":
            print(f"{Colors.FAIL}[✗] {message}{Colors.ENDC}")
        elif level == "SUCCESS":
            print(f"{Colors.OKGREEN}[✓] {message}{Colors.ENDC}")
        elif level == "WARNING":
            print(f"{Colors.WARNING}[!] {message}{Colors.ENDC}")
        else:
            print(f"{Colors.OKBLUE}[i] {message}{Colors.ENDC}")
        
        # File logging
        try:
            with open(self.log_file, 'a') as f:
                f.write(log_entry + '\n')
        except:
            pass

    def run_command(self, command, shell=True, sudo=False):
        """Execute shell command with logging"""
        if sudo and not self.is_macos and os.geteuid() != 0:
            command = f"sudo {command}"
        
        try:
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=600
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timeout"
        except Exception as e:
            return False, "", str(e)

    def check_tool_installed(self, tool_name):
        """Check if a tool is already installed"""
        return shutil.which(tool_name) is not None

    def create_workspace(self):
        """Create organized workspace structure"""
        self.log("Creating workspace structure...")
        
        directories = [
            "tools",
            "wordlists",
            "recon",
            "scans",
            "reports",
            "screenshots",
            "payloads",
            "scripts",
            "nuclei-templates"
        ]
        
        for dir_name in directories:
            path = os.path.join(self.workspace, dir_name)
            os.makedirs(path, exist_ok=True)
        
        self.log("Workspace created successfully", "SUCCESS")

    def install_prerequisites(self):
        """Install basic requirements"""
        self.log("Installing prerequisites...")
        
        if self.is_linux:
            # Update package lists
            self.log("Updating package lists...")
            self.run_command("apt update", sudo=True)
            
            # Install essentials
            essentials = ["build-essential", "git", "wget", "curl", "python3", 
                         "python3-pip", "golang-go", "unzip", "chromium-browser"]
            
            for pkg in essentials:
                if not self.check_tool_installed(pkg.replace("-", "")):
                    self.log(f"Installing {pkg}...")
                    success, _, _ = self.run_command(f"apt install -y {pkg}", sudo=True)
                    if success:
                        self.log(f"{pkg} installed", "SUCCESS")
        
        elif self.is_macos:
            # Check for Homebrew
            if not self.check_tool_installed("brew"):
                self.log("Installing Homebrew...")
                install_cmd = '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
                self.run_command(install_cmd)
            
            # Install essentials
            essentials = ["git", "wget", "curl", "python3", "go"]
            for tool in essentials:
                if not self.check_tool_installed(tool):
                    self.log(f"Installing {tool}...")
                    self.run_command(f"brew install {tool}")
        
        # Set up Go environment
        go_path = os.path.join(self.home, "go")
        os.makedirs(go_path, exist_ok=True)
        os.environ["GOPATH"] = go_path
        os.environ["PATH"] += f":{go_path}/bin"
        
        self.log("Prerequisites installed", "SUCCESS")

    def install_tool(self, tool_name, install_cmd, installer_type):
        """Install a single tool"""
        # Skip if already installed (for binary tools)
        if self.check_tool_installed(tool_name) and installer_type not in ["git", "pip3"]:
            self.log(f"{tool_name} already installed, skipping", "WARNING")
            self.installed_tools.add(tool_name)
            return True
        
        try:
            self.log(f"Installing {tool_name}...")
            
            # Handle different installer types
            if installer_type == "apt" and self.is_linux:
                success, _, err = self.run_command(install_cmd, sudo=True)
            elif installer_type == "brew" and self.is_macos:
                success, _, err = self.run_command(install_cmd)
            elif installer_type in ["go", "pip3", "git", "wget"]:
                success, _, err = self.run_command(install_cmd)
            else:
                success = False
                err = "Unsupported installer type"
            
            if success:
                self.log(f"{tool_name} installed successfully", "SUCCESS")
                self.installed_tools.add(tool_name)
                return True
            else:
                self.log(f"Failed to install {tool_name}: {err}", "ERROR")
                self.failed_tools.append(tool_name)
                return False
                
        except Exception as e:
            self.log(f"Error installing {tool_name}: {str(e)}", "ERROR")
            self.failed_tools.append(tool_name)
            return False

    def install_category(self, category_name):
        """Install all tools in a category"""
        if category_name not in self.tools:
            self.log(f"Invalid category: {category_name}", "ERROR")
            return
        
        tools = self.tools[category_name]
        self.log(f"\n{Colors.BOLD}{Colors.HEADER}Installing {category_name.upper()} tools...{Colors.ENDC}")
        
        progress = ProgressBar(len(tools))
        for tool_name, install_cmd, installer_type in tools:
            self.install_tool(tool_name, install_cmd, installer_type)
            progress.update()

    def install_python_libraries(self):
        """Install Python security libraries"""
        self.log(f"\n{Colors.BOLD}{Colors.HEADER}Installing Python libraries...{Colors.ENDC}")
        
        progress = ProgressBar(len(self.python_libs))
        for lib in self.python_libs:
            self.log(f"Installing {lib}...")
            success, _, _ = self.run_command(f"pip3 install {lib} --break-system-packages 2>/dev/null || pip3 install {lib}")
            if success:
                self.log(f"{lib} installed", "SUCCESS")
            progress.update()

    def download_wordlists(self):
        """Download popular wordlists"""
        self.log(f"\n{Colors.BOLD}{Colors.HEADER}Downloading wordlists...{Colors.ENDC}")
        
        wordlist_dir = os.path.join(self.workspace, "wordlists")
        progress = ProgressBar(len(self.wordlists))
        
        for name, url in self.wordlists:
            target_path = os.path.join(wordlist_dir, name)
            if os.path.exists(target_path):
                self.log(f"{name} already exists, skipping", "WARNING")
            else:
                self.log(f"Downloading {name}...")
                success, _, _ = self.run_command(f"git clone --depth 1 {url} {target_path}")
                if success:
                    self.log(f"{name} downloaded", "SUCCESS")
            progress.update()

    def install_nuclei_templates(self):
        """Download Nuclei templates"""
        self.log("Downloading Nuclei templates...")
        templates_path = os.path.join(self.workspace, "nuclei-templates")
        if os.path.exists(templates_path):
            self.run_command(f"nuclei -ut -ud {templates_path}")
        else:
            self.run_command(f"nuclei -ut")
        self.log("Nuclei templates updated", "SUCCESS")

    def show_menu(self):
        """Display interactive menu"""
        menu = f"""
{Colors.BOLD}{Colors.CYAN}╔════════════════════════════════════════╗
║         INSTALLATION MENU              ║
╚════════════════════════════════════════╝{Colors.ENDC}

{Colors.OKGREEN}[1]{Colors.ENDC} Install Everything (Full Setup)
{Colors.OKGREEN}[2]{Colors.ENDC} Install by Category
{Colors.OKGREEN}[3]{Colors.ENDC} Install Python Libraries Only
{Colors.OKGREEN}[4]{Colors.ENDC} Download Wordlists Only
{Colors.OKGREEN}[5]{Colors.ENDC} Update Existing Tools
{Colors.OKGREEN}[6]{Colors.ENDC} Show Installation Summary
{Colors.OKGREEN}[0]{Colors.ENDC} Exit

{Colors.BOLD}Categories:{Colors.ENDC}
  • Recon & Subdomain Discovery
  • Directory & Parameter Discovery
  • Vulnerability Scanning
  • Proxy & Manual Testing
  • API Testing
  • Authentication Testing
  • Utilities
"""
        print(menu)

    def install_everything(self):
        """Install all tools and resources"""
        self.log(f"\n{Colors.BOLD}{Colors.PURPLE}Starting full installation...{Colors.ENDC}\n")
        
        # Prerequisites
        self.install_prerequisites()
        
        # Install all categories
        for category in self.tools.keys():
            self.install_category(category)
        
        # Python libraries
        self.install_python_libraries()
        
        # Wordlists
        self.download_wordlists()
        
        # Nuclei templates
        self.install_nuclei_templates()
        
        self.show_summary()

    def install_by_category(self):
        """Show category selection menu"""
        print(f"\n{Colors.BOLD}Select categories to install:{Colors.ENDC}")
        categories = list(self.tools.keys())
        for idx, cat in enumerate(categories, 1):
            print(f"{Colors.OKGREEN}[{idx}]{Colors.ENDC} {cat}")
        print(f"{Colors.OKGREEN}[0]{Colors.ENDC} Back to main menu")
        
        choice = input(f"\n{Colors.BOLD}Enter category number: {Colors.ENDC}")
        if choice.isdigit() and 0 < int(choice) <= len(categories):
            self.install_prerequisites()
            self.install_category(categories[int(choice) - 1])

    def show_summary(self):
        """Display installation summary"""
        total_tools = sum(len(tools) for tools in self.tools.values())
        
        summary = f"""
{Colors.BOLD}{Colors.OKGREEN}╔═══════════════════════════════════════════╗
║       INSTALLATION COMPLETED              ║
╚═══════════════════════════════════════════╝{Colors.ENDC}

{Colors.OKBLUE}📊 Summary:{Colors.ENDC}
  ✓ Tools installed: {len(self.installed_tools)}/{total_tools}
  ✓ Python libraries: {len(self.python_libs)}
  ✓ Wordlists: {len(self.wordlists)}
  ✓ Workspace: {self.workspace}

{Colors.OKGREEN}🚀 Quick Start:{Colors.ENDC}
  • Workspace location: {self.workspace}
  • Tools directory: {self.workspace}/tools
  • Wordlists: {self.workspace}/wordlists
  • Log file: {self.log_file}

{Colors.WARNING}📝 Next Steps:{Colors.ENDC}
  1. Add Go bin to PATH: export PATH=$PATH:~/go/bin
  2. Update nuclei templates: nuclei -ut
  3. Start scanning: cd {self.workspace}

{Colors.OKBLUE}🔧 Popular Tools Installed:{Colors.ENDC}
  • subfinder, amass, httpx - Subdomain enumeration
  • nuclei - Vulnerability scanning
  • ffuf, gobuster - Directory fuzzing
  • sqlmap - SQL injection testing
  • burpsuite, zaproxy - Proxy testing
"""
        
        if self.failed_tools:
            summary += f"\n{Colors.FAIL}❌ Failed installations:{Colors.ENDC}\n"
            for tool in self.failed_tools:
                summary += f"  • {tool}\n"
        
        print(summary)

    def run(self):
        """Main execution loop"""
        self.print_banner()
        
        # Check root/sudo for Linux
        if self.is_linux and os.geteuid() != 0:
            self.log("Please run with sudo on Linux", "WARNING")
            sys.exit(1)
        
        # Create workspace
        self.create_workspace()
        
        while True:
            self.show_menu()
            choice = input(f"{Colors.BOLD}Enter your choice: {Colors.ENDC}")
            
            if choice == "1":
                self.install_everything()
            elif choice == "2":
                self.install_by_category()
            elif choice == "3":
                self.install_python_libraries()
            elif choice == "4":
                self.download_wordlists()
            elif choice == "5":
                self.log("Updating tools...")
                self.install_everything()
            elif choice == "6":
                self.show_summary()
            elif choice == "0":
                print(f"\n{Colors.OKGREEN}Thanks for using Muscat2040 Web Security Kit!{Colors.ENDC}\n")
                break
            else:
                print(f"{Colors.FAIL}Invalid choice{Colors.ENDC}")

def main():
    """Entry point"""
    try:
        installer = SecurityLabInstaller()
        installer.run()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Installation cancelled by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.FAIL}Fatal error: {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
