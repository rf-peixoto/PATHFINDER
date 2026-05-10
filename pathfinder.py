#!/usr/bin/env python3
# ·····················································································
#
#    ___  _  _____ _  _ ___ ___ _  _ ___  ___ ___ 
#   | _ \/_\|_   _| || | __|_ _| \| |   \| __| _ \
#   |  _/ _ \ | | | __ | _| | || .` | |) | _||   /
#   |_|/_/ \_\|_| |_||_|_| |___|_|\_|___/|___|_|_\
#
#   ┃ Network Navigator & Rogue Device Detection System ┃
#   ┃ v1.0.0  ·  Navigate. Map. Identify. Secure.       ┃
#
#   Data files (same directory, or specify via CLI):
#     oui_db.json   →  MAC vendor lookup   { "AA:BB:CC": "Vendor" }
#     cve_db.json   →  CVE hint rules      [ {"match":..,"cve":..,"sev":..,"desc":..} ]
#
# ·····················································································

import os, sys, socket, subprocess, threading, time, re, json
import ipaddress, struct, argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

if sys.version_info < (3, 6):
    sys.exit("[-] Requires Python 3.6+")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  COLOUR PALETTE  ·  Amber / Teal / Steel — navigator instrument cluster
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R    = '\033[0m'
BOLD = '\033[1m'
DIM  = '\033[2m'
BLNK = '\033[5m'

AM   = '\033[38;5;220m'   # Amber         — primary UI chrome
TE   = '\033[38;5;87m'    # Teal          — secondary / IP addresses
LG   = '\033[38;5;154m'   # Lime green    — safe / confirmed
WA   = '\033[38;5;202m'   # Burnt orange  — warnings
DA   = '\033[38;5;196m'   # Hot red       — danger / hostile
SB   = '\033[38;5;111m'   # Steel blue    — OS / info
GR   = '\033[38;5;238m'   # Dim gray      — secondary text
WH   = '\033[97m'         # White         — values

SEV_COLOR = {
    "CRITICAL": DA + BOLD,
    "HIGH":     WA + BOLD,
    "MEDIUM":   AM,
    "LOW":      LG,
    "INFO":     TE,
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PORT MAP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COMMON_PORTS = {
    21:"FTP",       22:"SSH",        23:"Telnet",     25:"SMTP",
    53:"DNS",       80:"HTTP",       110:"POP3",      135:"RPC",
    139:"NetBIOS",  143:"IMAP",      161:"SNMP",      389:"LDAP",
    443:"HTTPS",    445:"SMB",       636:"LDAPS",     1883:"MQTT",
    2375:"Docker",  2376:"Docker-TLS", 3306:"MySQL",  3389:"RDP",
    5432:"PostgreSQL", 5900:"VNC",   6379:"Redis",    8080:"HTTP-Alt",
    8443:"HTTPS-Alt", 9200:"Elasticsearch", 11211:"Memcached",
    27017:"MongoDB",
}
HIGH_RISK_PORTS = {23, 135, 139, 445, 3389, 5900, 2375, 11211, 27017, 9200}

SCRIPT_DIR  = os.path.dirname(os.path.realpath(__file__))
DEFAULT_OUI = os.path.join(SCRIPT_DIR, "oui_db.json")
DEFAULT_CVE = os.path.join(SCRIPT_DIR, "cve_db.json")
DEFAULT_WL  = os.path.join(SCRIPT_DIR, "pathfinder_whitelist.json")
DEFAULT_OUT = os.path.join(SCRIPT_DIR, "pathfinder_results.json")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  DATA LOADERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def load_oui_db(path=DEFAULT_OUI):
    """Load OUI vendor DB  →  { "AA:BB:CC": "Vendor Name" }"""
    try:
        with open(path) as f:
            raw = json.load(f)
        return {k.upper().strip(): v for k, v in raw.items()}
    except FileNotFoundError:
        _status(f"{WA}OUI DB not found at {path} — vendor lookup disabled.{R}", "warn")
        return {}
    except Exception as e:
        _status(f"{DA}Failed to load OUI DB: {e}{R}", "bad")
        return {}

def load_cve_db(path=DEFAULT_CVE):
    """Load CVE hint rules  →  [ {match, cve, sev, desc} ]"""
    try:
        with open(path) as f:
            db = json.load(f)
        if not isinstance(db, list):
            raise ValueError("CVE DB must be a JSON array")
        return db
    except FileNotFoundError:
        _status(f"{WA}CVE DB not found at {path} — CVE hints disabled.{R}", "warn")
        return []
    except Exception as e:
        _status(f"{DA}Failed to load CVE DB: {e}{R}", "bad")
        return []


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  UI UTILITIES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def clr():
    os.system('cls' if os.name == 'nt' else 'clear')

def ts():
    return datetime.now().strftime("%H:%M:%S")

def banner_header(beacon_n=None):
    mode_tag = f"BEACON SCAN  #{beacon_n}" if beacon_n else "GRID SCANNER  ONLINE"
    # ASCII art pre-built to avoid f-string escape-sequence warnings
    L1 = "   ___  _  _____ _  _ ___ ___ _  _ ___  ___ ___  "
    L2 = r"  | _ \/_\|_   _| || | __|_ _| \| |   \| __| _ \ "
    L3 = r"  |  _/ _ \ | | | __ | _| | || .` | |) | _||   / "
    L4 = r"  |_|/_/ \_\|_| |_||_|_| |___|_|\_|___/|___|_|_\ "
    dots = "·" * 24
    print(f"""
{AM}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{R}
{AM}┃{R}                                                                         {AM}┃{R}
{AM}┃{R}  {AM}{BOLD}{L1}{R}                   {AM}┃{R}
{AM}┃{R}  {AM}{BOLD}{L2}{R}                  {AM}┃{R}
{AM}┃{R}  {AM}{BOLD}{L3}{R}                  {AM}┃{R}
{AM}┃{R}  {AM}{BOLD}{L4}{R}                 {AM}┃{R}
{AM}┃{R}                                                                         {AM}┃{R}
{AM}┃{R}  {GR}Navigate. Map. Identify. Secure your grid.{GR}{dots}{AM}┃{R}
{AM}┃{R}  {GR}Mode: {WH}{mode_tag:<24}{GR}·  Time: {WH}{ts()}{GR}  ·  OS: {WH}{sys.platform.upper():<6}{GR}   {AM}┃{R}
{AM}┃{R}                                                                         {AM}┃{R}
{AM}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{R}
""")

def divider(label="", width=75, color=AM):
    if label:
        side = max(1, (width - len(label) - 4) // 2)
        print(f"\n{color}{'━' * side} {WH}{BOLD}{label}{R}{color} {'━' * side}{R}")
    else:
        print(f"{color}{'╌' * width}{R}")

def _status(msg, level="info"):
    icons = {
        "info": f"{TE}▶",
        "ok":   f"{LG}✦",
        "warn": f"{WA}⚠",
        "bad":  f"{DA}✗",
        "scan": f"{AM}◉",
    }
    print(f"  {icons.get(level, icons['info'])}{R} {GR}[{ts()}]{R}  {msg}")

# public alias used from within loaders before the function is defined globally
status = _status


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  NETWORK DETECTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return None

def get_network_range(ip, prefix=24):
    return str(ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False))

def detect_gateway():
    try:
        if sys.platform == "win32":
            out = subprocess.check_output("ipconfig", text=True)
            for line in out.splitlines():
                if "Default Gateway" in line and "." in line:
                    return line.split(":")[-1].strip()
        else:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"],
                text=True, stderr=subprocess.DEVNULL)
            parts = out.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except:
        pass
    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  mDNS SNIFFER  ·  Passive signal interception on 224.0.0.251:5353
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _parse_dns_name(data, offset):
    labels, jumped, orig = [], False, offset
    max_j = 12
    while offset < len(data) and max_j > 0:
        length = data[offset]
        if length == 0:
            offset += 1; break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data): break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped: orig = offset + 2
            jumped, offset, max_j = True, ptr, max_j - 1
            continue
        offset += 1
        end = offset + length
        if end > len(data): break
        labels.append(data[offset:end].decode("ascii", errors="replace"))
        offset = end
    return ".".join(labels), (orig if jumped else offset)

def sniff_mdns(duration=5):
    """
    Passively collect mDNS (Bonjour) announcements from the local segment.
    Parses A + PTR records to map IP → hostname. Returns {ip: name}.
    """
    results = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError: pass
        sock.bind(("", 5353))
        mreq = struct.pack("4sL", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(0.4)
        deadline = time.time() + duration
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                if len(data) < 12: continue
                qdcount = struct.unpack("!H", data[4:6])[0]
                ancount = struct.unpack("!H", data[6:8])[0]
                offset  = 12
                for _ in range(qdcount):
                    if offset >= len(data): break
                    _, offset = _parse_dns_name(data, offset)
                    offset += 4
                for _ in range(ancount):
                    if offset + 10 > len(data): break
                    name, offset = _parse_dns_name(data, offset)
                    if offset + 10 > len(data): break
                    rtype, _, _, rdlen = struct.unpack("!HHIH", data[offset:offset+10])
                    offset += 10
                    rdata   = data[offset:offset+rdlen]
                    offset += rdlen
                    if rtype == 1 and len(rdata) == 4:
                        ip_str = socket.inet_ntoa(rdata)
                        label  = name[:-6] if name.endswith(".local") else name
                        if ip_str and ip_str not in results:
                            results[ip_str] = label
                    elif rtype == 12 and src_ip not in results:
                        ptr, _ = _parse_dns_name(data, offset - rdlen)
                        if ".local" in ptr:
                            results[src_ip] = ptr.replace(".local", "")
            except socket.timeout: continue
            except Exception:      continue
    except Exception: pass
    finally:
        try: sock.close()
        except: pass
    return results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  OS FINGERPRINTING  ·  TTL-based inference
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_ttl(ip, timeout=2):
    try:
        cmd = (["ping", "-n", "1", "-w", str(timeout*1000), str(ip)]
               if sys.platform == "win32"
               else ["ping", "-c", "1", "-W", str(timeout), str(ip)])
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                      timeout=timeout+1, text=True)
        m = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        return int(m.group(1)) if m else None
    except: return None

def fingerprint_os(ttl):
    if ttl is None:  return None
    if ttl <= 64:    return "Linux / macOS / Android"
    if ttl <= 128:   return "Windows"
    if ttl <= 255:   return "Cisco IOS / BSD / Solaris"
    return "Unknown"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BANNER GRABBING  ·  Service identification on open ports
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def grab_banner(ip, port, timeout=2.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((str(ip), port))
            if port in (80, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + str(ip).encode() + b"\r\n\r\n")
            elif port in (443, 8443):
                return "[HTTPS — use dedicated TLS scanner]"
            elif port == 25:
                s.sendall(b"EHLO pathfinder\r\n")
            elif port == 6379:
                s.sendall(b"PING\r\n")
            elif port == 11211:
                s.sendall(b"version\r\n")
            raw = s.recv(512)
            return raw.decode("utf-8", errors="replace").strip()[:300]
    except: return None

def check_cve_hints(banner, cve_db):
    if not banner or not cve_db: return []
    b = banner.lower()
    return [e for e in cve_db if e.get("match", "").lower() in b]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ARP / PING / PORT SCANNING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def ping_host(ip, timeout=1):
    try:
        cmd = (["ping", "-n", "1", "-w", str(timeout*1000), str(ip)]
               if sys.platform == "win32"
               else ["ping", "-c", "1", "-W", str(timeout), str(ip)])
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout+1)
        return r.returncode == 0
    except: return False

def read_arp_cache():
    cache = {}
    try:
        if sys.platform == "linux":
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    p = line.split()
                    if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                        cache[p[0]] = p[3].upper()
        else:
            out = subprocess.check_output(["arp", "-a"], text=True,
                                          stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                ip_m  = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
                mac_m = re.search(r"([\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}", line)
                if ip_m and mac_m:
                    cache[ip_m.group(1)] = mac_m.group(0).upper().replace("-", ":")
    except: pass
    return cache

def arp_scan_host(ip):
    try:
        cmd = (["arp", "-a", str(ip)] if sys.platform == "win32"
               else ["arp", "-n", str(ip)])
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        m = re.search(r"([\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}", out)
        return m.group(0).upper().replace("-", ":") if m else None
    except: return None

def resolve_hostname(ip):
    try:    return socket.gethostbyaddr(str(ip))[0]
    except: return None

def lookup_vendor(mac, oui_db):
    if not mac or len(mac) < 8 or not oui_db: return "Unknown"
    return oui_db.get(mac[:8].upper(), "Unknown")

def scan_ports(ip, ports=None, timeout=0.45):
    open_ports = []
    for port in (ports or list(COMMON_PORTS.keys())):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((str(ip), port)) == 0:
                    open_ports.append(port)
        except: pass
    return open_ports

def classify_device(vendor, hostname, ports, os_guess):
    v = (vendor   or "").lower()
    h = (hostname or "").lower()
    p = set(ports or [])
    if any(x in v for x in ["espressif","tuya","shelly","philips hue","ring"]):
        return "🔌 IoT Device"
    if any(x in v for x in ["raspberry pi","arduino"]):
        return "[SBC / IoT]"
    if any(x in v for x in ["cisco","netgear","tp-link","d-link","asus","linksys",
                              "ubiquiti","mikrotik","aruba","juniper","fortinet",
                              "avm","fritz","arris","sagemcom","zte","huawei"]):
        return "[Network Gear]"
    if any(x in v for x in ["vmware","virtualbox","qemu","hyper-v","xen"]):
        return "[Virtual Machine]"
    if "apple" in v:
        if any(x in h for x in ["iphone","ipad"]): return "📱 iPhone / iPad"
        if any(x in h for x in ["macbook","imac","mac"]): return "💻 Mac"
        return "[Apple Device]"
    if any(x in v for x in ["samsung","xiaomi","lg","sony","motorola"]):
        return "[Mobile / Consumer]"
    if "nintendo" in v: return "🎮 Nintendo"
    if any(x in v for x in ["amazon","google","roku","sonos"]):
        return "[Media / Smart Home]"
    if any(x in v for x in ["canon","epson","hp","brother","lexmark"]):
        return "[Printer]"
    if any(x in v for x in ["synology","qnap","western digital"]):
        return "[NAS Storage]"
    if any(x in v for x in ["dell","hp","lenovo","super micro"]) and 22 in p:
        return "[Server]"
    if 3389 in p or (os_guess and "windows" in os_guess.lower()):
        return "[Windows PC]"
    if 22 in p and 80 not in p and 443 not in p:
        return "[Linux / SSH Host]"
    if 80 in p or 443 in p:
        return "🌐 Web Server"
    return "[Unknown]"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECURITY ANALYSIS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def detect_arp_spoofing(devices, prev_gateway_mac=None, gateway_ip=None):
    """
    Checks for:
      1. Duplicate MAC across multiple IPs  → possible MITM / ARP poisoning
      2. Gateway MAC changed since last scan → targeted gateway spoof
    """
    alerts = []
    mac_to_ips = defaultdict(list)
    for d in devices:
        mac = d.get("mac","")
        if mac and "??" not in mac:
            mac_to_ips[mac].append(d["ip"])
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            alerts.append({
                "sev": "CRITICAL",
                "msg": f"MAC {mac} resolves to {len(ips)} IPs: {', '.join(ips)}  ← ARP poisoning?"
            })
    if gateway_ip and prev_gateway_mac:
        for d in devices:
            if d["ip"] == gateway_ip and d.get("mac") and d["mac"] != prev_gateway_mac:
                alerts.append({
                    "sev": "CRITICAL",
                    "msg": (f"Gateway {gateway_ip} hardware address changed: "
                            f"{prev_gateway_mac}  →  {d['mac']}  ← gateway spoof?")
                })
    return alerts

def check_local_promisc():
    """
    Inspects local NIC flags for IFF_PROMISC (0x100).
    Promisc = interface is capturing all segment traffic, which may
    indicate a packet sniffer running on this machine.
    """
    promisc = []
    try:
        if sys.platform == "linux":
            for iface in os.listdir("/sys/class/net"):
                try:
                    with open(f"/sys/class/net/{iface}/flags") as f:
                        if int(f.read().strip(), 16) & 0x100:
                            promisc.append(iface)
                except: continue
        elif sys.platform == "darwin":
            out = subprocess.check_output(["ifconfig"], text=True,
                                          stderr=subprocess.DEVNULL)
            cur = None
            for line in out.splitlines():
                if re.match(r"^\S", line): cur = line.split(":")[0]
                if cur and "PROMISC" in line: promisc.append(cur)
    except: pass
    return promisc


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  WHITELIST MANAGER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def load_whitelist(path=DEFAULT_WL):
    try:
        with open(path) as f:
            data = json.load(f)
        return {e["mac"]: e for e in data.get("entries",[]) if e.get("mac")}
    except: return {}

def save_whitelist(devices, path=DEFAULT_WL, existing=None):
    wl = dict(existing or {})
    for d in devices:
        mac = d.get("mac","")
        if mac and "??" not in mac and mac not in wl:
            wl[mac] = {
                "mac":      mac,
                "ip":       d.get("ip"),
                "hostname": d.get("hostname"),
                "vendor":   d.get("vendor"),
                "label":    d.get("vendor",""),
                "added":    str(datetime.now()),
            }
    with open(path,"w") as f:
        json.dump({"updated":str(datetime.now()),"entries":list(wl.values())},f,indent=2)
    return path

def wl_status(d, whitelist):
    if not whitelist: return None
    mac = d.get("mac","")
    return "OK" if (mac and "??" not in mac and mac in whitelist) else "UNCHARTED"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CORE HOST SWEEP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def sweep_host(ip, arp_cache, mdns_map, oui_db, cve_db,
               do_ports=True, do_banner=True, do_os=True):
    ip_str = str(ip)
    alive  = ping_host(ip_str) or (ip_str in arp_cache)
    if not alive: return None

    mac      = arp_cache.get(ip_str) or arp_scan_host(ip_str)
    hostname = resolve_hostname(ip_str) or mdns_map.get(ip_str)
    vendor   = lookup_vendor(mac, oui_db) if mac else "Unknown"
    ttl      = get_ttl(ip_str) if do_os else None
    os_guess = fingerprint_os(ttl)
    ports    = scan_ports(ip_str, list(COMMON_PORTS.keys())) if do_ports else []

    banners, cve_hits = {}, []
    if do_banner and ports:
        for port in ports:
            if port in (443, 8443): continue
            banner = grab_banner(ip_str, port, timeout=1.5)
            if banner:
                banners[port] = banner
                cve_hits.extend(check_cve_hints(banner, cve_db))
        if 23 in ports and 23 not in banners:
            cve_hits.append({
                "match":"telnet","cve":"INSECURE","sev":"CRITICAL",
                "desc":"Telnet port open — credentials transmitted in CLEARTEXT"
            })

    return {
        "ip":       ip_str,
        "mac":      mac or "??:??:??:??:??:??",
        "hostname": hostname or "—",
        "vendor":   vendor,
        "type":     classify_device(vendor, hostname, ports, os_guess),
        "os":       os_guess or "—",
        "ttl":      ttl,
        "ports":    ports,
        "banners":  banners,
        "cve_hits": cve_hits,
        "ts":       ts(),
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  DISPLAY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def print_node(d, index, gateway_ip, local_ip, whitelist=None, watch_tags=None):
    ip      = d["ip"]
    mac     = d["mac"]
    host    = d["hostname"]
    vendor  = d["vendor"]
    dtype   = d["type"]
    ports   = d["ports"]
    os_g    = d.get("os","—")
    banners = d.get("banners",{})
    cves    = d.get("cve_hits",[])

    is_local   = (ip == local_ip)
    is_gateway = (ip == gateway_ip)
    is_unknown = (vendor == "Unknown" and host == "—")

    tags = []
    if is_gateway:
        ip_color = AM + BOLD
        tags.append(f"{AM}[GATEWAY]{R}")
    elif is_local:
        ip_color = LG + BOLD
        tags.append(f"{LG}[HOME NODE]{R}")
    elif is_unknown:
        ip_color = DA + BOLD
        tags.append(f"{DA}{BLNK}[HOSTILE?]{R}")
    else:
        ip_color = TE + BOLD

    if watch_tags:
        if ip in watch_tags.get("new", set()):
            tags.append(f"{LG}[▶ INBOUND]{R}")
        if ip in watch_tags.get("mac_changed", {}):
            tags.append(f"{DA}{BLNK}[⚠ ID SPOOFED]{R}")

    if whitelist and not is_local and not is_gateway:
        if wl_status(d, whitelist) == "UNCHARTED":
            tags.append(f"{WA}[⚠ UNCHARTED]{R}")

    tag_str = "  ".join(tags)
    idx_str = f"{GR}{index:02d}{R}"

    print(f"\n  {AM}╭─ {idx_str}  {ip_color}{ip:<16}{R}  {tag_str}")
    print(f"  {AM}│{R}  {GR}MAC      {R} {WH}{mac}{R}   {GR}·{R}  {GR}Vendor  {R} {WA}{vendor}{R}")
    print(f"  {AM}│{R}  {GR}Hostname {R} {WH}{host}{R}")
    print(f"  {AM}│{R}  {GR}OS       {R} {SB}{os_g:<30}{R}  {GR}TTL {R}{GR}{d.get('ttl','—')}{R}")
    print(f"  {AM}│{R}  {GR}Type     {R} {dtype}")

    if ports:
        port_line = "  ".join(
            f"{DA if p in HIGH_RISK_PORTS else TE}{p}{GR}/{COMMON_PORTS.get(p,'?')}{R}"
            for p in sorted(ports))
        print(f"  {AM}│{R}  {GR}Ports    {R} {port_line}")

    for port, banner in banners.items():
        short = banner.replace("\n"," ").replace("\r","")[:80]
        print(f"  {AM}│{R}  {GR}Signal   {R} {GR}:{port}{R}  {DIM}{WH}{short}{R}")

    for hit in cves:
        sc = SEV_COLOR.get(hit.get("sev","INFO"), AM)
        print(f"  {AM}│{R}  {sc}⚡ {hit.get('cve','?'):<18}{R}  "
              f"{sc}{hit.get('sev','?'):<8}{R}  {GR}{hit.get('desc','')}{R}")

    print(f"  {AM}│{R}  {GR}Pinged   {R} {GR}{d['ts']}{R}")
    print(f"  {AM}╰{'─' * 66}{R}")


def print_threat_matrix(found, gateway_ip, local_ip, whitelist,
                        arp_alerts, promisc_ifaces, watch_tags=None):
    gone    = (watch_tags or {}).get("gone",        set())
    new_    = (watch_tags or {}).get("new",         set())
    mac_chg = (watch_tags or {}).get("mac_changed", {})

    hostiles  = [d for d in found
                 if d["vendor"] == "Unknown" and d["hostname"] == "—"
                 and d["ip"] not in (local_ip, gateway_ip)]
    exposed   = [d for d in found if any(p in HIGH_RISK_PORTS for p in d["ports"])]
    cve_devs  = [d for d in found if d.get("cve_hits")]
    uncharted = [d for d in found
                 if whitelist and wl_status(d, whitelist) == "UNCHARTED"
                 and d["ip"] not in (local_ip, gateway_ip)]

    divider("THREAT MATRIX")
    _status(f"Nodes mapped    : {AM}{BOLD}{len(found)}{R}", "info")
    _status(f"Unidentified    : {DA if hostiles  else LG}{BOLD}{len(hostiles)}{R}",
            "warn" if hostiles  else "ok")
    _status(f"Hostile ports   : {DA if exposed   else LG}{BOLD}{len(exposed)}{R}  "
            f"{GR}(Telnet/SMB/RDP/VNC/Docker…){R}",
            "warn" if exposed   else "ok")
    _status(f"Exploit vectors : {DA if cve_devs  else LG}{BOLD}{len(cve_devs)}{R}",
            "bad"  if cve_devs  else "ok")
    if whitelist:
        _status(f"Uncharted nodes : {DA if uncharted else LG}{BOLD}{len(uncharted)}{R}",
                "warn" if uncharted else "ok")
    if watch_tags:
        _status(f"Inbound nodes   : {LG if new_    else GR}{BOLD}{len(new_)}{R}",
                "warn" if new_    else "ok")
        _status(f"Lost signal     : {WA if gone    else GR}{BOLD}{len(gone)}{R}",
                "warn" if gone    else "ok")
        _status(f"ID changes      : {DA if mac_chg else GR}{BOLD}{len(mac_chg)}{R}",
                "bad"  if mac_chg else "ok")

    if arp_alerts:
        divider("SIGNAL SPOOFING ALERTS", color=DA)
        for a in arp_alerts:
            print(f"  {DA}{BOLD}⚡ [{a['sev']}]{R}  {DA}{a['msg']}{R}")

    if promisc_ifaces:
        print()
        _status(f"{WA}{BOLD}PROMISC detected on: "
                f"{', '.join(promisc_ifaces)}{R}  {GR}← local sniffer?{R}", "warn")

    if hostiles:
        divider("UNIDENTIFIED / HOSTILE NODES", color=DA)
        for d in hostiles:
            print(f"  {DA}▶  {BOLD}{d['ip']:<18}{R}  "
                  f"MAC: {WH}{d['mac']}{R}   OS: {SB}{d.get('os','—')}{R}"
                  f"   TTL: {GR}{d.get('ttl','—')}{R}")

    if exposed:
        divider("HOSTILE PORTS DETECTED", color=WA)
        for d in exposed:
            risky = [COMMON_PORTS[p] for p in d["ports"] if p in HIGH_RISK_PORTS]
            print(f"  {WA}▶  {BOLD}{d['ip']:<18}{R}  {DA}{', '.join(risky)}{R}")

    if cve_devs:
        divider("EXPLOIT VECTORS", color=DA)
        for d in cve_devs:
            for hit in d["cve_hits"]:
                sc = SEV_COLOR.get(hit.get("sev","INFO"), AM)
                print(f"  {sc}▶  {hit.get('cve','?'):<18}  "
                      f"{d['ip']:<16}  {R}{GR}{hit.get('desc','')}{R}")

    if whitelist and uncharted:
        divider("UNCHARTED NODES", color=WA)
        for d in uncharted:
            print(f"  {WA}▶  {BOLD}{d['ip']:<18}{R}  "
                  f"MAC: {WH}{d['mac']}{R}  {GR}{d['vendor']}{R}")

    if gone:
        divider("SIGNAL LOST  ·  NODES OFFLINE", color=GR)
        for ip in gone:
            print(f"  {GR}▶  {ip}{R}")

    if mac_chg:
        divider("HARDWARE ID CHANGES  ·  VERIFY IMMEDIATELY", color=DA)
        for ip, old_mac in mac_chg.items():
            cur = next((d["mac"] for d in found if d["ip"] == ip), "?")
            print(f"  {DA}▶  {BOLD}{ip:<18}{R}  {GR}{old_mac}{R}  →  {DA}{BOLD}{cur}{R}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  EXPORT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def export_results(devices, outfile=DEFAULT_OUT):
    path = os.path.abspath(outfile)
    with open(path,"w") as f:
        json.dump({"scan_time":str(datetime.now()),"nodes":devices},
                  f, indent=2, default=str)
    return path


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SCAN RUNNER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_scan(net_range, threads, do_ports, do_banner, do_os,
             mdns_map, oui_db, cve_db):
    try:
        hosts = list(ipaddress.IPv4Network(net_range, strict=False).hosts())
    except ValueError as e:
        _status(f"{DA}Invalid range: {e}{R}", "bad"); return []

    arp_cache = read_arp_cache()
    total  = len(hosts)
    found  = []
    lock   = threading.Lock()
    done   = [0]
    stop_p = threading.Event()

    def progress():
        bw = 36
        while not stop_p.is_set():
            pct    = done[0] / max(total, 1)
            filled = int(bw * pct)
            bar    = f"{LG}{'▰' * filled}{GR}{'▱' * (bw-filled)}{R}"
            print(f"\r  {AM}◉{R}  [{bar}]  {TE}{done[0]:4}/{total}{R}  "
                  f"{GR}Nodes:{R} {LG}{len(found):3}{R}   ", end="", flush=True)
            time.sleep(0.15)
        print(f"\r{' ' * 80}\r", end="", flush=True)

    pt = threading.Thread(target=progress, daemon=True)
    pt.start()

    def worker(ip):
        result = sweep_host(ip, arp_cache, mdns_map, oui_db, cve_db,
                            do_ports=do_ports, do_banner=do_banner, do_os=do_os)
        with lock:
            done[0] += 1
            if result: found.append(result)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        list(as_completed({ex.submit(worker, ip): ip for ip in hosts}))

    stop_p.set(); pt.join()
    found.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
    return found


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BEACON MODE  ·  Continuous watch with diff tracking
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def beacon_loop(args, net_range, gateway_ip, local_ip,
                whitelist, oui_db, cve_db):
    scan_n, prev_devices, prev_gw_mac = 0, {}, None

    while True:
        scan_n += 1
        clr(); banner_header(beacon_n=scan_n)

        mdns_map = {}
        if not args.no_banner:
            t = threading.Thread(
                target=lambda: mdns_map.update(sniff_mdns(duration=3)), daemon=True)
            t.start(); t.join(timeout=4)

        divider(f"BEACON SWEEP  #{scan_n}  ·  {net_range}")
        found = run_scan(net_range, args.threads,
                         not args.no_ports, not args.no_banner, not args.no_os,
                         mdns_map, oui_db, cve_db)

        cur_ips  = {d["ip"] for d in found}
        prev_ips = set(prev_devices.keys())
        mac_chg  = {
            d["ip"]: prev_devices[d["ip"]]["mac"]
            for d in found
            if d["ip"] in prev_devices
            and "??" not in (d.get("mac","") + prev_devices[d["ip"]].get("mac",""))
            and d.get("mac") != prev_devices[d["ip"]].get("mac")
        }
        watch_tags = {
            "new":         cur_ips - prev_ips,
            "gone":        prev_ips - cur_ips,
            "mac_changed": mac_chg,
        }

        arp_alerts     = detect_arp_spoofing(found, prev_gw_mac, gateway_ip)
        promisc_ifaces = check_local_promisc()

        divider(f"NODE REGISTRY  ·  {len(found)} ACTIVE")
        for i, d in enumerate(found, 1):
            print_node(d, i, gateway_ip, local_ip,
                       whitelist=whitelist, watch_tags=watch_tags)

        print_threat_matrix(found, gateway_ip, local_ip,
                            whitelist, arp_alerts, promisc_ifaces,
                            watch_tags=watch_tags)

        prev_devices = {d["ip"]: d for d in found}
        gw = next((d for d in found if d["ip"] == gateway_ip), None)
        if gw: prev_gw_mac = gw.get("mac")

        export_results(found, args.export or DEFAULT_OUT)

        divider(f"NEXT SWEEP IN {args.interval}s  ·  Ctrl+C to abort")
        try:
            for remaining in range(args.interval, 0, -1):
                mins, secs = divmod(remaining, 60)
                bfill = int(38 * (1 - remaining / args.interval))
                bar   = f"{AM}{'▰' * bfill}{GR}{'▱' * (38-bfill)}{R}"
                print(f"\r  {TE}◉{R}  [{bar}]  {AM}{mins:02d}:{secs:02d}{R} remaining   ",
                      end="", flush=True)
                time.sleep(1)
            print()
        except KeyboardInterrupt:
            print(f"\n\n  {DA}✗  BEACON TERMINATED — signal lost.{R}\n")
            sys.exit(0)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    ap = argparse.ArgumentParser(
        description="PATHFINDER — Network Navigator & Rogue Device Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Data files (auto-loaded from script directory):
  oui_db.json            MAC vendor database
  cve_db.json            CVE hint rules

Examples:
  sudo python3 pathfinder.py                        # auto-detect, full scan
  sudo python3 pathfinder.py -r 10.0.0.0/24        # custom CIDR range
  sudo python3 pathfinder.py -b -i 120             # beacon mode, 2-min interval
  sudo python3 pathfinder.py --learn               # scan and save node registry
  sudo python3 pathfinder.py --whitelist           # flag uncharted nodes
  sudo python3 pathfinder.py -q                    # quiet mode (ping only)
  sudo python3 pathfinder.py --no-banner --no-os   # fast sweep, no fingerprint
  sudo python3 pathfinder.py --oui /path/oui.json  # custom OUI file
        """)

    ap.add_argument("-r",  "--range",         help="CIDR range  (e.g. 192.168.1.0/24)")
    ap.add_argument("-t",  "--threads",       type=int, default=80,
                    help="Parallel threads (default: 80)")
    ap.add_argument("-e",  "--export",        metavar="FILE",
                    help="JSON output filename")
    ap.add_argument("-b",  "--beacon",        action="store_true",
                    help="Beacon mode — continuous scanning")
    ap.add_argument("-i",  "--interval",      type=int, default=300,
                    help="Beacon re-scan interval in seconds (default: 300)")
    ap.add_argument("-q",  "--quiet",         action="store_true",
                    help="Quiet mode: 20 threads, ping + ARP only")
    ap.add_argument("--no-ports",             action="store_true",
                    help="Skip port scanning")
    ap.add_argument("--no-banner",            action="store_true",
                    help="Skip banner grabbing and mDNS interception")
    ap.add_argument("--no-os",               action="store_true",
                    help="Skip OS fingerprinting")
    ap.add_argument("--learn",               action="store_true",
                    help="Save all discovered nodes to the node registry")
    ap.add_argument("--whitelist",           action="store_true",
                    help="Flag nodes not present in the registry")
    ap.add_argument("--whitelist-file",      default=DEFAULT_WL, metavar="FILE",
                    help="Node registry JSON path")
    ap.add_argument("--mdns-time",           type=int, default=5,
                    help="Signal interception duration in seconds (default: 5)")
    ap.add_argument("--oui",                 default=DEFAULT_OUI, metavar="FILE",
                    help="OUI vendor DB JSON path")
    ap.add_argument("--cve",                 default=DEFAULT_CVE, metavar="FILE",
                    help="CVE hints DB JSON path")
    args = ap.parse_args()

    if args.quiet:
        args.threads   = 20
        args.no_ports  = True
        args.no_banner = True

    clr(); banner_header()

    # Load external databases
    oui_db = load_oui_db(args.oui)
    cve_db = load_cve_db(args.cve)

    # Network setup
    local_ip  = get_local_ip()
    gateway   = detect_gateway()
    net_range = args.range or (get_network_range(local_ip) if local_ip else None)

    if not net_range:
        _status(f"{DA}Cannot detect network range. Use -r to specify.{R}", "bad")
        sys.exit(1)

    do_ports  = not args.no_ports
    do_banner = not args.no_banner
    do_os     = not args.no_os

    divider("NAV LINK ESTABLISHED")
    _status(f"Home node     : {TE}{BOLD}{local_ip or 'unknown'}{R}", "ok")
    _status(f"Gateway       : {AM}{gateway   or 'unknown'}{R}", "ok")
    _status(f"Grid range    : {TE}{net_range}{R}", "ok")
    _status(f"OUI DB        : {LG}{len(oui_db)} vendors{R}  ·  "
            f"CVE DB: {LG}{len(cve_db)} rules{R}", "ok")
    _status(f"Mode          : {AM}{'QUIET' if args.quiet else 'FULL SWEEP'}{R}  ·  "
            f"Threads:{TE}{args.threads}{R}  ·  "
            f"Ports:{LG if do_ports  else DA}{'ON' if do_ports  else 'OFF'}{R}  ·  "
            f"Banners:{LG if do_banner else DA}{'ON' if do_banner else 'OFF'}{R}  ·  "
            f"OS-FP:{LG if do_os     else DA}{'ON' if do_os     else 'OFF'}{R}", "ok")
    if args.beacon:
        _status(f"Beacon mode   : {LG}ACTIVE{R}  (interval: {AM}{args.interval}s{R})", "ok")
    divider()

    # Node registry (whitelist)
    whitelist = {}
    if args.whitelist or args.learn:
        whitelist = load_whitelist(args.whitelist_file)
        if whitelist:
            _status(f"Node registry : {LG}{len(whitelist)} known node(s) loaded{R}", "ok")
        else:
            _status(f"Node registry : {GR}empty — run --learn to populate{R}", "warn")

    # mDNS signal interception (single scan only)
    mdns_map = {}
    if do_banner and not args.beacon:
        _status(f"Signal intercept : listening for {args.mdns_time}s…", "scan")
        t = threading.Thread(
            target=lambda: mdns_map.update(sniff_mdns(args.mdns_time)), daemon=True)
        t.start(); t.join(timeout=args.mdns_time + 1)
        if mdns_map:
            _status(f"mDNS/Bonjour  : {LG}{len(mdns_map)} device(s) announced{R}", "ok")
        else:
            _status(f"mDNS/Bonjour  : {GR}no announcements captured{R}", "info")
    divider()

    # Beacon mode (loops forever)
    if args.beacon:
        beacon_loop(args, net_range, gateway, local_ip,
                    whitelist if (args.whitelist or args.learn) else {},
                    oui_db, cve_db)
        return

    # Single scan
    divider("DEPLOYING GRID SCAN")
    found = run_scan(net_range, args.threads, do_ports, do_banner, do_os,
                     mdns_map, oui_db, cve_db)
    print()

    for d in found:
        if d["hostname"] == "—" and d["ip"] in mdns_map:
            d["hostname"] = mdns_map[d["ip"]]

    arp_alerts     = detect_arp_spoofing(found, gateway_ip=gateway)
    promisc_ifaces = check_local_promisc()

    divider(f"NODE REGISTRY  ·  {len(found)} ACTIVE")
    for i, d in enumerate(found, 1):
        print_node(d, i, gateway, local_ip,
                   whitelist=whitelist if args.whitelist else None)

    print_threat_matrix(found, gateway, local_ip,
                        whitelist if args.whitelist else None,
                        arp_alerts, promisc_ifaces)

    if args.learn:
        path = save_whitelist(found, args.whitelist_file, existing=whitelist)
        print()
        _status(f"Registry saved → {AM}{path}{R}  ({LG}{len(found)} nodes{R})", "ok")

    outfile = args.export or DEFAULT_OUT
    path    = export_results(found, outfile)
    _status(f"Results saved  → {AM}{path}{R}", "ok")

    print()
    divider("TRACE COMPLETE")
    print(f"\n  {GR}Grid mapped at {AM}{ts()}{GR}. Coordinates secured.{R}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {DA}✗  SCAN ABORTED — signal lost.{R}\n")
        sys.exit(0)
