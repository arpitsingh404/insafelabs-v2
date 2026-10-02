"""External security-tool arsenal.

Catalog of well-known offensive/defensive security tools, auto-detection of what
is installed on this host, and a STRICT shell-free runner for a subset:

  * argv arrays only — never a shell string (no command-injection surface)
  * fixed per-tool profiles — no free-form flags
  * target validated against a strict host/URL/query charset
  * bounded timeout + output size

GUI / file / interface-driven tools are catalogued for reference but NOT executed.
"""
import asyncio
import glob
import os
import re
import shutil
import subprocess
import sysconfig
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/arsenal", tags=["arsenal"])

ROOT = Path(__file__).resolve().parents[1]
WORDLIST = ROOT / "wordlists" / "rockyou_lite.txt"


def _search_dirs():
    """Directories that hold CLI entry points but are often NOT on PATH:
    the app venv, extra tool venvs (ARSENAL_EXTRA_BIN_DIRS), user-site scripts
    and the usual Windows Python install locations."""
    dirs = []

    def add(d):
        if d and os.path.isdir(d):
            dirs.append(os.path.normcase(os.path.abspath(d)))

    for d in (os.environ.get("ARSENAL_EXTRA_BIN_DIRS", "") or "").split(os.pathsep):
        add(d)

    try:
        add(sysconfig.get_path("scripts"))
    except Exception:
        pass
    try:
        import site
        for sp in [*site.getsitepackages(), site.getusersitepackages()]:
            if sp:
                add(os.path.join(os.path.dirname(sp), "Scripts"))
                add(os.path.join(sp, "Scripts"))
    except Exception:
        pass

    for base in (os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", "")):
        if not base:
            continue
        add(os.path.join(base, "Microsoft", "WinGet", "Links"))
        for pat in ("Programs/Python/Python3*/Scripts", "Python/Python3*/Scripts", "Python*/Scripts"):
            dirs += [os.path.normcase(p) for p in glob.glob(os.path.join(base, *pat.split("/"))) if os.path.isdir(p)]
    local = os.environ.get("LOCALAPPDATA", "")
    if local:
        for p in glob.glob(os.path.join(local, "Microsoft", "WinGet", "Packages", "*")):
            if os.path.isdir(p):
                add(p)
                for sub in glob.glob(os.path.join(p, "*")):
                    if os.path.isdir(sub):
                        add(sub)
    for pat in (r"C:\Program Files\Python3*\Scripts", r"C:\Program Files (x86)\Python3*\Scripts",
                r"C:\Program Files\Nmap", r"C:\Program Files (x86)\Nmap"):
        dirs += [os.path.normcase(p) for p in glob.glob(pat) if os.path.isdir(p)]
    # one level under Program Files (finds e.g. osquery, ExifTool, Wireshark, Ghidra…)
    for base in (r"C:\Program Files", r"C:\Program Files (x86)"):
        for p in glob.glob(os.path.join(base, "*")):
            if os.path.isdir(p):
                add(p)

    seen, out = set(), []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


_EXTRA_DIRS = _search_dirs()
_PATH_EXTS = [""] + [e for e in (os.environ.get("PATHEXT", "").split(os.pathsep)) if e]
_PATH_EXTS = [e.lower() for e in _PATH_EXTS] + [e.upper() for e in _PATH_EXTS if e]



def T(id, name, category, binaries, *, mode="gui", runnable=False, targetType="host",
      description="", install="", doc="", profiles=None, versionArgs=None, verify=None, timeout=None):
    t = {
        "id": id, "name": name, "category": category, "binaries": binaries,
        "versionArgs": versionArgs or ["--version"], "mode": mode, "runnable": runnable,
        "targetType": targetType, "description": description, "install": install, "doc": doc,
    }
    if verify:
        t["verify"] = verify
    if timeout:
        t["timeout"] = timeout
    if profiles:
        t["profiles"] = profiles
    return t


CATALOG = [
    # ---------------------------------------------------------------- Network
    T("nmap", "Nmap", "Network", ["nmap"], mode="cli", runnable=True, description="Network / port & service discovery — the reference port scanner.",
      install="winget install Insecure.Nmap · choco install nmap · apt install nmap", doc="https://nmap.org/",
      profiles=[{"id": "quick", "label": "Quick scan (top ports)", "args": ["-T4", "-F", "{target}"]},
                {"id": "service", "label": "Service / version detection", "args": ["-sV", "-T4", "{target}"]},
                {"id": "full", "label": "All 65535 ports", "args": ["-T4", "-p-", "{target}"]}]),
    T("masscan", "Masscan", "Network", ["masscan"], mode="cli", runnable=True, description="High-speed asynchronous port scanner.",
      install="choco install masscan · apt install masscan · build from source", doc="https://github.com/robertdavidgraham/masscan",
      profiles=[{"id": "top", "label": "Top 1000 ports @ 1000 pps", "args": ["-p1-1000", "--rate", "1000", "{target}"]}]),
    T("rustscan", "RustScan", "Network", ["rustscan"], mode="cli", runnable=True, description="Ultra-fast port scanner that pipes findings to Nmap.",
      install="cargo install rustscan · docker pull rustscan/rustscan", doc="https://github.com/RustScan/RustScan",
      profiles=[{"id": "quick", "label": "Quick (top ports)", "args": ["-a", "{target}", "--greppable"]}]),
    T("naabu", "Naabu", "Network", ["naabu"], mode="cli", runnable=True, description="Fast SYN/CONNECT port scanner (ProjectDiscovery).",
      install="go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", doc="https://github.com/projectdiscovery/naabu",
      profiles=[{"id": "top", "label": "Top ports", "args": ["-host", "{target}", "-silent"]}]),

    # ---------------------------------------------------------------- Recon
    T("amass", "Amass", "Recon", ["amass"], mode="cli", runnable=True, targetType="domain", description="Attack-surface / asset discovery and DNS enumeration.",
      install="go install github.com/owasp-amass/amass/v5/...@latest", doc="https://github.com/owasp-amass/amass",
      profiles=[{"id": "passive", "label": "Passive enum", "args": ["enum", "-passive", "-d", "{target}"]}]),
    T("subfinder", "Subfinder", "Recon", ["subfinder"], mode="cli", runnable=True, targetType="domain", description="Passive subdomain discovery from public sources.",
      install="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", doc="https://github.com/projectdiscovery/subfinder",
      profiles=[{"id": "enum", "label": "Enumerate", "args": ["-d", "{target}", "-silent"]}]),
    T("dnsx", "DNSX", "Recon", ["dnsx"], mode="cli", runnable=True, targetType="domain", description="Fast DNS resolver / toolkit (A, CNAME, MX, TXT…).",
      install="go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", doc="https://github.com/projectdiscovery/dnsx",
      profiles=[{"id": "resolve", "label": "Resolve", "args": ["-d", "{target}", "-silent"]}]),
    T("httpx", "HTTPX", "Recon", ["httpx"], mode="cli", runnable=True, targetType="url", verify="projectdiscovery|httpx version", description="Fast HTTP service probing — status, title, tech, TLS.",
      install="go install github.com/projectdiscovery/httpx/cmd/httpx@latest", doc="https://github.com/projectdiscovery/httpx",
      profiles=[{"id": "probe", "label": "Probe (title/tech/status)", "args": ["-u", "{target}", "-silent", "-title", "-tech-detect", "-status-code"]}]),
    T("katana", "Katana", "Recon", ["katana"], mode="cli", runnable=True, targetType="url", description="Next-gen crawling & spidering framework.",
      install="go install github.com/projectdiscovery/katana/cmd/katana@latest", doc="https://github.com/projectdiscovery/katana",
      profiles=[{"id": "crawl", "label": "Crawl (depth 2)", "args": ["-u", "{target}", "-silent", "-d", "2"]}]),
    T("bbot", "BBOT", "Recon", ["bbot"], mode="cli", description="Recursive internet-scale OSINT / recon framework.",
      install="pip install bbot", doc="https://github.com/blacklanternsecurity/bbot"),

    # ---------------------------------------------------------------- Enumeration
    T("gobuster", "Gobuster", "Enumeration", ["gobuster"], mode="cli", runnable=True, targetType="url", description="Directory / DNS / vhost brute-forcing (Go).",
      install="go install github.com/OJ/gobuster/v3@latest", doc="https://github.com/OJ/gobuster",
      profiles=[{"id": "dir", "label": "Directory scan (bundled wordlist)", "args": ["dir", "-u", "{target}", "-w", "{wordlist}", "-q", "--no-error"]}]),
    T("feroxbuster", "Feroxbuster", "Enumeration", ["feroxbuster"], mode="cli", runnable=True, targetType="url", description="Fast, recursive content discovery (Rust).",
      install="cargo install feroxbuster", doc="https://github.com/epi052/feroxbuster",
      profiles=[{"id": "dir", "label": "Content discovery (bundled wordlist)", "args": ["-u", "{target}", "-w", "{wordlist}", "-q", "-n"]}]),
    T("ffuf", "ffuf", "Enumeration", ["ffuf"], mode="cli", runnable=True, targetType="url", description="Fast web content discovery / fuzzing.",
      install="go install github.com/ffuf/ffuf/v2@latest", doc="https://github.com/ffuf/ffuf",
      profiles=[{"id": "dir", "label": "Content discovery (bundled wordlist)", "args": ["-u", "{target}/FUZZ", "-w", "{wordlist}", "-s", "-mc", "200,204,301,302,307,401,403"]}]),
    T("wfuzz", "Wfuzz", "Enumeration", ["wfuzz"], mode="cli", runnable=True, targetType="url", description="Web application fuzzer (paths, params, auth).",
      install="pip install wfuzz", doc="https://github.com/xmendez/wfuzz",
      profiles=[{"id": "dir", "label": "Directory fuzz (bundled wordlist)", "args": ["-z", "file,{wordlist}", "--hc", "404", "{target}/FUZZ"]}]),

    # ---------------------------------------------------------------- Web
    T("nikto", "Nikto", "Web", ["nikto"], mode="cli", runnable=True, targetType="url", description="Web-server security checks (misconfig, dangerous files).",
      install="choco install nikto · apt install nikto", doc="https://github.com/sullo/nikto",
      profiles=[{"id": "quick", "label": "Quick check (60s cap)", "args": ["-h", "{target}", "-maxtime", "60s", "-nointeractive"]}]),
    T("nuclei", "Nuclei", "Web", ["nuclei"], mode="cli", runnable=True, targetType="url", description="Template-based vulnerability scanning (community templates).",
      install="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", doc="https://github.com/projectdiscovery/nuclei",
      profiles=[{"id": "safe", "label": "Templates (low→critical)", "args": ["-u", "{target}", "-silent", "-severity", "low,medium,high,critical"]}]),
    T("zap", "OWASP ZAP", "Web", ["zap", "zap.sh", "zap.bat"], description="Web application security testing proxy + scanner (GUI/CLI).",
      install="choco install zap · https://www.zaproxy.org/download/", doc="https://www.zaproxy.org/"),
    T("burp", "Burp Suite", "Web", ["burpsuite", "BurpSuiteCommunity"], description="Web / API security testing platform (intercepting proxy, scanner).",
      install="https://portswigger.net/burp/communitydownload", doc="https://portswigger.net/burp"),
    T("caido", "Caido", "Web", ["caido"], description="Lightweight modern web security auditing toolkit (proxy).",
      install="https://caido.io/download", doc="https://caido.io/"),
    T("sqlmap", "SQLmap", "Web", ["sqlmap", "sqlmap.py"], mode="cli", runnable=True, targetType="url", description="Automatic SQL-injection detection & exploitation testing.",
      install="pip install sqlmap · apt install sqlmap", doc="https://sqlmap.org/",
      profiles=[{"id": "batch", "label": "Batch, level 1 / risk 1", "args": ["-u", "{target}", "--batch", "--level", "1", "--risk", "1"]}]),
    T("dalfox", "Dalfox", "Web", ["dalfox"], mode="cli", runnable=True, targetType="url", description="Parameter analysis & XSS scanning.",
      install="go install github.com/hahwul/dalfox/v2@latest", doc="https://github.com/hahwul/dalfox",
      profiles=[{"id": "scan", "label": "XSS scan", "args": ["url", "{target}"]}]),
    T("xsstrike", "XSStrike", "Web", ["xsstrike", "xsstrike.py"], description="Advanced XSS detection suite.",
      install="git clone https://github.com/s0md3v/XSStrike", doc="https://github.com/s0md3v/XSStrike"),
    T("arjun", "Arjun", "Web", ["arjun"], mode="cli", runnable=True, targetType="url", description="HTTP parameter discovery suite.",
      install="pip install arjun", doc="https://github.com/s0md3v/Arjun",
      profiles=[{"id": "params", "label": "Discover parameters", "args": ["-u", "{target}", "-q"]}]),
    T("kiterunner", "Kiterunner", "Web", ["kr"], description="Context-aware content discovery for APIs.",
      install="https://github.com/assetnote/kiterunner/releases", doc="https://github.com/assetnote/kiterunner"),
    T("wapiti", "Wapiti", "Web", ["wapiti"], mode="cli", runnable=True, targetType="url", description="Web application vulnerability scanner (black-box).",
      install="pip install wapiti3", doc="https://wapiti-scanner.github.io/",
      profiles=[{"id": "scan", "label": "Scan", "args": ["-u", "{target}", "-f", "json"]}]),
    T("whatweb", "WhatWeb", "Web", ["whatweb"], mode="cli", runnable=True, targetType="url", description="Web technology fingerprinting.",
      install="apt install whatweb · gem install whatweb", doc="https://github.com/urbanadventurer/WhatWeb",
      profiles=[{"id": "fingerprint", "label": "Fingerprint", "args": ["{target}"]}]),

    # ---------------------------------------------------------------- Exploit
    T("metasploit", "Metasploit Framework", "Exploit", ["msfconsole"], description="Authorized vulnerability validation & exploitation framework.",
      install="https://docs.metasploit.com/", doc="https://www.metasploit.com/"),
    T("searchsploit", "SearchSploit", "Exploit", ["searchsploit"], mode="cli", runnable=True, targetType="query", description="Offline Exploit-DB search.",
      install="apt install exploitdb · git clone https://github.com/offensive-security/exploitdb", doc="https://www.exploit-db.com/searchsploit",
      profiles=[{"id": "search", "label": "Search Exploit-DB", "args": ["--color", "{target}"]}]),
    T("impacket", "Impacket", "Exploit", ["impacket-secretsdump", "secretsdump.py"], description="Python classes for network protocols (SMB/MSRPC/Kerberos) & AD attacks.",
      install="pip install impacket", doc="https://github.com/fortra/impacket"),
    T("netexec", "NetExec (nxc)", "Exploit", ["netexec", "nxc", "crackmapexec"], description="Network service exploitation & AD enumeration (CME successor).",
      install="pip install netexec", doc="https://github.com/Pennyw0rth/NetExec"),
    T("bloodhound", "BloodHound", "Exploit", ["bloodhound"], description="AD/Entra attack-path mapping (Neo4j graph).",
      install="https://bloodhound.readthedocs.io/en/latest/installation/", doc="https://github.com/SpecterOps/BloodHound"),
    T("certipy", "Certipy", "Exploit", ["certipy"], description="AD Certificate Services (ADCS) enumeration & abuse.",
      install="pip install certipy-ad", doc="https://github.com/ly4k/Certipy"),
    T("enum4linux-ng", "Enum4linux-ng", "Exploit", ["enum4linux-ng"], description="Windows/Samba enumeration (SMB, LDAP, RPC).",
      install="pip install enum4linux-ng · git clone https://github.com/cddmp/enum4linux-ng", doc="https://github.com/cd-dmp/enum4linux-ng"),
    T("smbclient", "Smbclient", "Exploit", ["smbclient"], description="SMB/CIFS client for share enumeration & access testing.",
      install="apt install smbclient", doc="https://www.samba.org/"),
    T("responder", "Responder", "Exploit", ["responder", "Responder.py"], description="LLMNR/NBT-NS/MDNS poisoner & credential capture (authorized).",
      install="git clone https://github.com/lgandx/Responder", doc="https://github.com/lgandx/Responder"),

    # ---------------------------------------------------------------- Password
    T("john", "John the Ripper", "Password", ["john"], description="Password/hash auditing (file-driven).",
      install="apt install john · https://www.openwall.com/john/", doc="https://www.openwall.com/john/"),
    T("hashcat", "Hashcat", "Password", ["hashcat"], description="GPU-accelerated password/hash auditing (file-driven).",
      install="choco install hashcat · https://hashcat.net/hashcat/", doc="https://hashcat.net/hashcat/"),
    T("hydra", "Hydra", "Password", ["hydra"], description="Network login brute-forcer (many protocols).",
      install="apt install hydra · https://github.com/vanhauser-thc/thc-hydra", doc="https://github.com/vanhauser-thc/thc-hydra"),
    T("medusa", "Medusa", "Password", ["medusa"], description="Speedy, parallel network login brute-forcer.",
      install="apt install medusa · https://github.com/jmk-foofus/medusa", doc="https://github.com/jmk-foofus/medusa"),

    # ---------------------------------------------------------------- Wireless
    T("aircrack", "Aircrack-ng", "Wireless", ["aircrack-ng", "airodump-ng"], description="Authorized Wi-Fi security auditing (needs monitor mode + capture files).",
      install="https://www.aircrack-ng.org/downloads.html", doc="https://www.aircrack-ng.org/"),
    T("kismet", "Kismet", "Wireless", ["kismet"], description="Wireless detector / sniffer / IDS (Wi-Fi, BT, RF).",
      install="apt install kismet · https://www.kismetwireless.net/", doc="https://www.kismetwireless.net/"),
    T("bettercap", "Bettercap", "Wireless", ["bettercap"], description="Swiss-army knife for MITM, network & Wi-Fi recon (authorized).",
      install="apt install bettercap · https://www.bettercap.org/", doc="https://www.bettercap.org/"),

    # ---------------------------------------------------------------- Network Analysis
    T("wireshark", "Wireshark", "Network Analysis", ["wireshark"], description="Packet capture & protocol analysis (GUI).",
      install="winget install Wireshark.Wireshark · apt install wireshark", doc="https://www.wireshark.org/"),
    T("tshark", "TShark", "Network Analysis", ["tshark"], description="Wireshark's CLI packet analyzer.",
      install="winget install Wireshark.Wireshark · apt install tshark", doc="https://www.wireshark.org/docs/man-pages/tshark.html"),
    T("tcpdump", "tcpdump", "Network Analysis", ["tcpdump"], description="Classic CLI packet capture.",
      install="apt install tcpdump · https://www.tcpdump.org/", doc="https://www.tcpdump.org/"),
    T("zeek", "Zeek", "Network Analysis", ["zeek"], description="Network security monitor (formerly Bro) — rich protocol logs.",
      install="https://docs.zeek.org/en/master/install.html", doc="https://zeek.org/"),
    T("suricata", "Suricata", "Network Analysis", ["suricata"], description="High-performance network IDS/IPS/NSM engine.",
      install="apt install suricata · https://suricata.io/download/", doc="https://suricata.io/"),

    # ---------------------------------------------------------------- Vuln Scan
    T("nessus", "Nessus", "Vuln Scan", ["nessusd", "nessuscli"], description="Commercial vulnerability assessment scanner.",
      install="https://www.tenable.com/downloads/nessus", doc="https://www.tenable.com/products/nessus"),
    T("openvas", "Greenbone / OpenVAS", "Vuln Scan", ["gvm-cli", "openvas"], description="Open-source vulnerability scanning (Greenbone Vulnerability Management).",
      install="https://greenbone.github.io/docs/latest/", doc="https://greenbone.github.io/"),
    T("lynis", "Lynis", "Vuln Scan", ["lynis"], description="Security auditing & hardening for Linux/Unix.",
      install="apt install lynis · https://cisofy.com/lynis/", doc="https://cisofy.com/lynis/"),
    T("openscap", "OpenSCAP", "Vuln Scan", ["oscap"], description="SCAP compliance & vulnerability scanning.",
      install="apt install libopenscap8 · https://www.open-scap.org/", doc="https://www.open-scap.org/"),

    # ---------------------------------------------------------------- Reverse Engineering
    T("ghidra", "Ghidra", "Reverse Engineering", ["ghidra", "ghidraRun"], description="NSA software reverse-engineering suite.",
      install="https://github.com/NationalSecurityAgency/ghidra/releases", doc="https://ghidra-sre.org/"),
    T("radare2", "Radare2", "Reverse Engineering", ["radare2", "r2"], description="Reverse-engineering framework & disassembler.",
      install="https://github.com/radareorg/radare2", doc="https://rada.re/"),
    T("cutter", "Cutter", "Reverse Engineering", ["cutter"], description="Qt GUI for Radare2.",
      install="https://github.com/rizinorg/cutter/releases", doc="https://cutter.re/"),
    T("jadx", "JADX", "Reverse Engineering", ["jadx", "jadx-gui"], description="Dex to Java decompiler (Android).",
      install="https://github.com/skylot/jadx/releases", doc="https://github.com/skylot/jadx"),
    T("apktool", "Apktool", "Reverse Engineering", ["apktool"], description="Android APK decode / rebuild tool.",
      install="https://apktool.org/", doc="https://apktool.org/"),

    # ---------------------------------------------------------------- Mobile
    T("frida", "Frida", "Mobile", ["frida"], mode="cli", runnable=True, timeout=25, description="Dynamic instrumentation toolkit — hook functions, bypass SSL pinning / root detection (needs a device).",
      install="pip install frida-tools", doc="https://frida.re/",
      profiles=[{"id": "version", "label": "Show version", "args": ["--version"], "needsTarget": False},
                {"id": "devices", "label": "List devices (needs a device)", "args": [], "needsTarget": False,
                 "binaries": ["frida-ls-devices"]},
                {"id": "apps", "label": "List USB apps (needs a device)", "args": ["-Uai"], "needsTarget": False,
                 "binaries": ["frida-ps"]}]),
    T("mobsf", "MobSF", "Mobile", ["mobsf"], description="Mobile Security Framework — automated APK/IPA/PE analysis.",
      install="docker pull opensecurity/mobile-security-framework-mobsf", doc="https://github.com/MobSF/Mobile-Security-Framework-MobSF"),
    T("objection", "Objection", "Mobile", ["objection"], description="Runtime mobile exploration powered by Frida.",
      install="pip install objection", doc="https://github.com/sensepost/objection"),

    # ---------------------------------------------------------------- Forensics
    T("autopsy", "Autopsy", "Forensics", ["autopsy"], description="Digital forensics platform (disk image analysis).",
      install="https://www.autopsy.com/download/", doc="https://www.autopsy.com/"),
    T("volatility", "Volatility", "Forensics", ["vol", "volatility3", "vol.py"], description="Memory forensics framework.",
      install="pip install volatility3", doc="https://github.com/volatilityfoundation/volatility3"),
    T("binwalk", "Binwalk", "Forensics", ["binwalk"], description="Firmware analysis & embedded file extraction.",
      install="pip install binwalk", doc="https://github.com/ReFirmLabs/binwalk"),
    T("exiftool", "ExifTool", "Forensics", ["exiftool"], description="Read/write metadata in files (images, docs, media).",
      install="winget install OliverBetz.ExifTool · apt install libimage-exiftool-perl", doc="https://exiftool.org/"),

    # ---------------------------------------------------------------- Malware
    T("yara", "YARA", "Malware", ["yara"], description="Pattern-matching rules for malware identification.",
      install="choco install yara · apt install yara", doc="https://virustotal.github.io/yara/"),
    T("capa", "CAPA", "Malware", ["capa"], description="Detect capabilities in executables (FLARE).",
      install="pip install flare-capa", doc="https://github.com/mandiant/capa"),
    T("clamav", "ClamAV", "Malware", ["clamscan", "clamdscan"], description="Open-source antivirus / malware scanner.",
      install="choco install clamav · apt install clamav", doc="https://www.clamav.net/"),

    # ---------------------------------------------------------------- Cloud
    T("prowler", "Prowler", "Cloud", ["prowler"], description="AWS/Azure/GCP security best-practices assessment.",
      install="pip install prowler", doc="https://github.com/prowler-cloud/prowler"),
    T("scoutsuite", "ScoutSuite", "Cloud", ["scout", "scoutsuite"], description="Multi-cloud security auditing tool.",
      install="pip install scoutsuite", doc="https://github.com/nccgroup/ScoutSuite"),
    T("cloudmapper", "CloudMapper", "Cloud", ["cloudmapper"], description="AWS network visualisation & security posture.",
      install="pip install cloudmapper", doc="https://github.com/duo-labs/cloudmapper"),
    T("pacu", "Pacu", "Cloud", ["pacu"], description="AWS exploitation framework (authorized).",
      install="pip install pacu", doc="https://github.com/RhinoSecurityLabs/pacu"),

    # ---------------------------------------------------------------- Container
    T("trivy", "Trivy", "Container", ["trivy"], description="Vulnerability/misconfig/secret scanner for containers & IaC.",
      install="choco install trivy · https://github.com/aquasecurity/trivy", doc="https://trivy.dev/"),
    T("checkov", "Checkov", "Container", ["checkov"], description="IaC static analysis (Terraform, K8s, CloudFormation).",
      install="pip install checkov", doc="https://github.com/bridgecrewio/checkov"),
    T("kube-bench", "kube-bench", "Container", ["kube-bench"], description="CIS Kubernetes benchmark checks.",
      install="https://github.com/aquasecurity/kube-bench", doc="https://github.com/aquasecurity/kube-bench"),
    T("kube-hunter", "kube-hunter", "Container", ["kube-hunter"], description="Kubernetes penetration-testing tool (authorized).",
      install="pip install kube-hunter", doc="https://github.com/aquasecurity/kube-hunter"),

    # ---------------------------------------------------------------- Code & Secrets
    T("semgrep", "Semgrep", "Code & Secrets", ["semgrep"], description="Lightweight static analysis for many languages.",
      install="pip install semgrep", doc="https://semgrep.dev/"),
    T("bandit", "Bandit", "Code & Secrets", ["bandit"], description="Python static security analyser.",
      install="pip install bandit", doc="https://github.com/PyCQA/bandit"),
    T("gitleaks", "Gitleaks", "Code & Secrets", ["gitleaks"], description="Detect hardcoded secrets in git repos.",
      install="choco install gitleaks · https://github.com/gitleaks/gitleaks", doc="https://github.com/gitleaks/gitleaks"),
    T("trufflehog", "TruffleHog", "Code & Secrets", ["trufflehog"], description="Find, verify and analyse leaked credentials.",
      install="choco install trufflehog · https://github.com/trufflesecurity/trufflehog", doc="https://github.com/trufflesecurity/trufflehog"),
    T("syft", "Syft", "Code & Secrets", ["syft"], description="Generate SBOMs from images and filesystems.",
      install="choco install syft · https://github.com/anchore/syft", doc="https://github.com/anchore/syft"),
    T("grype", "Grype", "Code & Secrets", ["grype"], description="Vulnerability scanner for container images & filesystems.",
      install="https://github.com/anchore/grype", doc="https://github.com/anchore/grype"),

    # ---------------------------------------------------------------- DFIR
    T("wazuh", "Wazuh", "DFIR", ["wazuh-agentd", "wazuh-manager"], description="Open-source SIEM / XDR & host IDS.",
      install="https://documentation.wazuh.com/current/installation-guide/", doc="https://wazuh.com/"),
    T("velociraptor", "Velociraptor", "DFIR", ["velociraptor"], description="Endpoint visibility & digital forensics (VQL).",
      install="https://docs.velociraptor.app/downloads/", doc="https://docs.velociraptor.app/"),
    T("osquery", "osquery", "DFIR", ["osqueryi", "osqueryd"], description="SQL-powered OS instrumentation & endpoint visibility.",
      install="https://osquery.io/downloads/", doc="https://osquery.io/"),
    T("sigma", "Sigma", "DFIR", ["sigma"], description="Generic detection rule format + converters (SIEM rules).",
      install="pip install sigma-cli", doc="https://github.com/SigmaHQ/sigma"),

    # ---------------------------------------------------------------- Reporting
    T("dradis", "Dradis", "Reporting", ["dradis"], description="Collaboration & reporting for security assessments.",
      install="https://dradisframework.com/ce/", doc="https://dradisframework.com/"),
    T("faraday", "Faraday", "Reporting", ["faraday"], description="Vulnerability management & pentest reporting platform.",
      install="pip install faradaysec", doc="https://github.com/infobyte/faraday"),
    T("defectdojo", "DefectDojo", "Reporting", ["defectdojo"], description="Vulnerability management & orchestration (ASPM).",
      install="docker pull defectdojo/defectdojo-django", doc="https://github.com/DefectDojo/django-DefectDojo"),

    # ---------------------------------------------------------------- OSINT
    T("spiderfoot", "SpiderFoot", "OSINT", ["spiderfoot", "sf.py"], description="Automated OSINT collection & correlation.",
      install="pip install spiderfoot", doc="https://github.com/smicallef/spiderfoot"),
    T("maltego", "Maltego", "OSINT", ["maltego"], description="Link-analysis / OSINT graph platform.",
      install="https://www.maltego.com/downloads/", doc="https://www.maltego.com/"),
    T("recon-ng", "Recon-ng", "OSINT", ["recon-ng"], description="Modular web-reconnaissance framework.",
      install="pip install recon-ng", doc="https://github.com/lanmaster53/recon-ng"),
    T("theharvester", "theHarvester", "OSINT", ["theHarvester", "theharvester"], mode="cli", runnable=True, targetType="domain",
      description="Emails, subdomains, hosts & names from public sources.",
      install="pip install theHarvester", doc="https://github.com/laramies/theHarvester",
      profiles=[{"id": "all", "label": "All sources", "args": ["-d", "{target}", "-b", "all"]}]),
    T("sherlock", "Sherlock", "OSINT", ["sherlock"], description="Hunt usernames across social networks.",
      install="pip install sherlock-project", doc="https://github.com/sherlock-project/sherlock"),
    T("finalrecon", "FinalRecon", "OSINT", ["finalrecon"], description="All-in-one web reconnaissance tool.",
      install="git clone https://github.com/thewhiteh4t/FinalRecon", doc="https://github.com/thewhiteh4t/FinalRecon"),
    T("photon", "Photon", "OSINT", ["photon"], description="Fast crawler for OSINT data extraction.",
      install="git clone https://github.com/s0md3v/Photon", doc="https://github.com/s0md3v/Photon"),
    T("osmedeus", "Osmedeus", "OSINT", ["osmedeus"], description="Automated offensive reconnaissance workflow engine.",
      install="https://github.com/j3ssie/osmedeus", doc="https://github.com/j3ssie/osmedeus"),
]

_ALL_IDS = [t["id"] for t in CATALOG]
assert len(_ALL_IDS) == len(set(_ALL_IDS)), "duplicate arsenal tool id"


def _public(tool):
    return {k: v for k, v in tool.items() if k not in ("binaries", "versionArgs", "verify")}


def _candidates(binaries, dirs=None):
    """All candidate (name, path) for a tool — PATH first, then extra dirs."""
    dirs = _EXTRA_DIRS if dirs is None else dirs
    out, seen = [], set()
    for b in binaries:
        p = shutil.which(b)
        if p and p.lower() not in seen:
            seen.add(p.lower()); out.append((b, p))
    for d in dirs:
        for b in binaries:
            for ext in _PATH_EXTS:
                cand = os.path.join(d, b + ext)
                if os.path.isfile(cand) and cand.lower() not in seen:
                    seen.add(cand.lower()); out.append((b, cand))
    return out


def _version_output(path, tool):
    try:
        out = subprocess.run([path, *tool.get("versionArgs", ["--version"])],
                             capture_output=True, text=True, timeout=8)
        return re.sub(r"\x1b\[[0-9;]*m", "", (out.stdout or out.stderr or ""))
    except Exception:
        return ""


def _pick_version(clean):
    lines = [l.strip() for l in clean.splitlines() if l.strip()]
    v = next((l for l in lines if re.search(r"\d+\.\d+", l) and "projectdiscovery.io" not in l), None)
    if not v and lines:
        v = lines[0]
    return v[:140] if v else None


def _resolve(tool, dirs=None):
    """First candidate that exists AND (if `verify` set) matches its version output."""
    verify = tool.get("verify")
    for b, p in _candidates(tool.get("binaries", []), dirs):
        clean = _version_output(p, tool)
        if verify and not re.search(verify, clean, re.I):
            continue
        return b, p, _pick_version(clean)
    return None, None, None


def _detect(tool, dirs=None):
    binary, path, version = _resolve(tool, dirs)
    if not path:
        return {"installed": False, "binary": None, "path": None, "version": None}
    return {"installed": True, "binary": binary, "path": path, "version": version}


_HAS_WORDLIST = WORDLIST.exists()


@router.get("/tools")
async def tools():
    loop = asyncio.get_event_loop()
    dirs = _search_dirs()  # refresh each call so newly-installed tools appear on "re-detect"
    detected = await asyncio.gather(*[loop.run_in_executor(None, _detect, t, dirs) for t in CATALOG])
    out = []
    for tool, det in zip(CATALOG, detected):
        needs_wl = any("{wordlist}" in a for p in tool.get("profiles", []) for a in p["args"])
        runnable = bool(tool.get("runnable")) and det["installed"] and (not needs_wl or _HAS_WORDLIST)
        out.append({**_public(tool), **det, "runnable": runnable})
    categories = sorted({t["category"] for t in CATALOG})
    return {"tools": out, "categories": categories, "wordlist": str(WORDLIST) if _HAS_WORDLIST else None}


def _validate_target(t, kind):
    t = (t or "").strip()
    if not t or len(t) > 512:
        raise HTTPException(status_code=400, detail="Invalid target")
    if t.startswith("-"):
        raise HTTPException(status_code=400, detail="Target must not start with '-'")
    if re.search(r"[\s;|&$`<>(){}\[\]'\"\\]", t):
        # allow spaces only for free-text query tools
        if not (kind == "query" and not re.search(r"[;|&$`<>(){}\[\]'\"\\]", t)):
            raise HTTPException(status_code=400, detail="Target contains illegal characters")
    if kind == "url":
        if not re.match(r"^https?://", t):
            raise HTTPException(status_code=400, detail="Target must be an http(s) URL")
        if not urlsplit(t).hostname:
            raise HTTPException(status_code=400, detail="Invalid URL host")
    elif kind == "query":
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9 ._:\-/]*$", t):
            raise HTTPException(status_code=400, detail="Invalid query")
    else:
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._:\-/]*$", t):
            raise HTTPException(status_code=400, detail="Invalid host / IP")
    return t


class RunBody(BaseModel):
    id: str
    profile: str = ""
    target: str = Field(default="", max_length=512)


@router.post("/run")
async def run(body: RunBody):
    tool = next((t for t in CATALOG if t["id"] == body.id), None)
    if not tool:
        raise HTTPException(status_code=404, detail="Unknown tool")
    if not tool.get("runnable"):
        raise HTTPException(status_code=400, detail=f"{tool['name']} is a GUI / file-driven tool — run it directly on the host.")
    profiles = {p["id"]: p for p in tool.get("profiles", [])}
    if not profiles:
        raise HTTPException(status_code=400, detail="No run profiles for this tool")
    prof = profiles.get(body.profile) or next(iter(profiles.values()))

    prof_tool = {**tool, "binaries": prof.get("binaries") or tool["binaries"]}
    binary, path, _ = _resolve(prof_tool, _search_dirs())
    if not path:
        raise HTTPException(status_code=400, detail=f"{tool['name']} is not installed on this host.")

    # Some profiles need no target (e.g. "list devices / list USB apps").
    needs_target = prof.get("needsTarget", True)
    if needs_target:
        target = _validate_target(body.target, tool.get("targetType", "host"))
    else:
        target = (body.target or "").strip()

    needs_wordlist = any("{wordlist}" in a for a in prof["args"])
    if needs_wordlist and not _HAS_WORDLIST:
        raise HTTPException(status_code=400, detail="Bundled wordlist is missing")

    argv = [a.replace("{target}", target).replace("{wordlist}", str(WORDLIST)) for a in prof["args"]]

    try:
        proc = await asyncio.create_subprocess_exec(
            path, *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not start {tool['name']}: {str(e)[:120]}")

    timed_out = False
    _to = min(int(tool.get("timeout", 120) or 120), 300)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=_to)
    except asyncio.TimeoutError:
        timed_out = True
        try:
            proc.kill()
        except Exception:
            pass
        out, _ = await proc.communicate()

    text = (out or b"").decode("utf-8", errors="replace")
    truncated = len(text) > 60_000
    return {
        "tool": tool["id"], "name": tool["name"], "profile": prof["id"],
        "argv": [binary, *argv], "exit_code": proc.returncode, "timed_out": timed_out,
        "output": text[:60_000], "truncated": truncated,
    }
