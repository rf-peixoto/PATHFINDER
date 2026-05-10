#!/usr/bin/env python3
# ·····················································································
#
#    ___  _  _____ _  _ ___ ___ _  _ ___  ___ ___
#   | _ \/_\|_   _| || | __|_ _| \| |   \| __| _ \
#   |  _/ _ \ | | | __ | _| | || .` | |) | _||   /
#   |_|/_/ \_\|_| |_||_|_| |___|_|\_|___/|___|_|_\
#
#   Network Navigator & Rogue Device Detection  ·  v1.1.0
#   Navigate. Map. Identify. Secure.
#
#   Data files (same directory as script, or pass via --oui / --cve):
#     oui_db.json   →  { "AA:BB:CC": "Vendor description" }
#     cve_db.json   →  [ {"match":..,"cve":..,"sev":..,"desc":..} ]
#
# ·····················································································

import os, sys, socket, subprocess, threading, time, re, json
import ipaddress, struct, argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

if sys.version_info < (3, 6):
    sys.exit("[-] Requires Python 3.6+")


# ── Privilege check  (done once, used everywhere ARP is needed) ───────────────
def _check_root():
    try:
        return os.geteuid() == 0          # Linux / macOS / Android
    except AttributeError:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

IS_ROOT = _check_root()


# ── Colours ───────────────────────────────────────────────────────────────────
R    = '\033[0m';   BOLD = '\033[1m';  DIM  = '\033[2m';  BLNK = '\033[5m'
AM   = '\033[38;5;220m'   # Amber       — primary chrome
TE   = '\033[38;5;87m'    # Teal        — IPs / secondary
LG   = '\033[38;5;154m'   # Lime green  — safe / ok
WA   = '\033[38;5;202m'   # Orange      — warning
DA   = '\033[38;5;196m'   # Red         — danger
SB   = '\033[38;5;111m'   # Steel blue  — OS info
GR   = '\033[38;5;238m'   # Dim grey    — labels
WH   = '\033[97m'         # White       — values

SEV_COLOR = {"CRITICAL": DA+BOLD, "HIGH": WA+BOLD, "MEDIUM": AM, "LOW": LG, "INFO": TE}


# ── Port map ──────────────────────────────────────────────────────────────────
PORTS = {
    21:"FTP",    22:"SSH",   23:"Telnet",  25:"SMTP",   53:"DNS",
    80:"HTTP",  110:"POP3", 135:"RPC",   139:"NetBIOS",143:"IMAP",
   161:"SNMP",  389:"LDAP", 443:"HTTPS", 445:"SMB",   636:"LDAPS",
  1883:"MQTT", 2375:"Docker",2376:"Docker-TLS",3306:"MySQL",3389:"RDP",
  5432:"PgSQL",5900:"VNC",  6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",
  9200:"Elastic",11211:"Memcached",27017:"MongoDB",
}
HIGH_RISK = {23, 135, 139, 445, 3389, 5900, 2375, 11211, 27017, 9200}
MAC_RE    = re.compile(r"(?:[\da-fA-F]{2}[:\-]){5}[\da-fA-F]{2}")
LLADDR_RE = re.compile(r"lladdr\s+((?:[\da-fA-F]{2}[:\-]){5}[\da-fA-F]{2})")

DIR         = os.path.dirname(os.path.realpath(__file__))
DEFAULT_OUI = os.path.join(DIR, "oui_db.json")
DEFAULT_CVE = os.path.join(DIR, "cve_db.json")
DEFAULT_WL  = os.path.join(DIR, "pathfinder_whitelist.json")
DEFAULT_OUT = os.path.join(DIR, "pathfinder_results.json")


# ── Data loaders ──────────────────────────────────────────────────────────────

def load_oui_db(path=DEFAULT_OUI):
    try:
        with open(path) as f:
            raw = json.load(f)
        return {k.upper().strip(): v for k, v in raw.items()}
    except FileNotFoundError:
        status(f"{WA}oui_db.json not found — vendor lookup disabled{R}", "warn")
        return {}
    except Exception as e:
        status(f"{DA}OUI DB error: {e}{R}", "bad"); return {}

def load_cve_db(path=DEFAULT_CVE):
    try:
        with open(path) as f:
            db = json.load(f)
        return db if isinstance(db, list) else []
    except FileNotFoundError:
        status(f"{WA}cve_db.json not found — CVE hints disabled{R}", "warn")
        return []
    except Exception as e:
        status(f"{DA}CVE DB error: {e}{R}", "bad"); return []


# ── UI helpers ────────────────────────────────────────────────────────────────

def clr():  os.system('cls' if os.name == 'nt' else 'clear')
def ts():   return datetime.now().strftime("%H:%M:%S")

def status(msg, level="info"):
    icons = {"info":f"{TE}▶","ok":f"{LG}✦","warn":f"{WA}⚠","bad":f"{DA}✗","scan":f"{AM}◉"}
    print(f"  {icons.get(level,icons['info'])}{R} {GR}[{ts()}]{R}  {msg}")

def divider(label="", width=75, color=AM):
    if label:
        s = max(1, (width - len(label) - 4) // 2)
        print(f"\n{color}{'━'*s} {WH}{BOLD}{label}{R}{color} {'━'*s}{R}")
    else:
        print(f"{color}{'╌'*width}{R}")

def banner_header(beacon_n=None):
    mode = f"BEACON SCAN #{beacon_n}" if beacon_n else "GRID SCANNER  ONLINE"
    priv = f"{LG}ROOT{R}" if IS_ROOT else f"{WA}UNPRIVILEGED{R}"
    L1 = "   ___  _  _____ _  _ ___ ___ _  _ ___  ___ ___  "
    L2 = r"  | _ \/_\|_   _| || | __|_ _| \| |   \| __| _ \ "
    L3 = r"  |  _/ _ \ | | | __ | _| | || .` | |) | _||   / "
    L4 = r"  |_|/_/ \_\|_| |_||_|_| |___|_|\_|___/|___|_|_\ "
    print(f"""
{AM}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{R}
{AM}┃{R}                                                                         {AM}┃{R}
{AM}┃{R}  {AM}{BOLD}{L1}{R}                   {AM}┃{R}
{AM}┃{R}  {AM}{BOLD}{L2}{R}                  {AM}┃{R}
{AM}┃{R}  {AM}{BOLD}{L3}{R}                  {AM}┃{R}
{AM}┃{R}  {AM}{BOLD}{L4}{R}                 {AM}┃{R}
{AM}┃{R}                                                                         {AM}┃{R}
{AM}┃{R}  {GR}Navigate. Map. Identify. Secure your grid.{'·'*24}{AM}┃{R}
{AM}┃{R}  {GR}Mode: {WH}{mode:<22}{GR}· {WH}{ts()}{GR} · Priv: {priv}{GR}          {AM}┃{R}
{AM}┃{R}                                                                         {AM}┃{R}
{AM}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{R}
""")


# ── Network detection ─────────────────────────────────────────────────────────

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80)); return s.getsockname()[0]
    except: return None

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
                ["ip","route","show","default"], text=True, stderr=subprocess.DEVNULL)
            p = out.split()
            if "via" in p: return p[p.index("via") + 1]
    except: pass
    return None


# ── mDNS passive listener ─────────────────────────────────────────────────────

def _dns_name(data, offset):
    labels, jumped, orig, max_j = [], False, offset, 12
    while offset < len(data) and max_j > 0:
        n = data[offset]
        if n == 0:   offset += 1; break
        if (n & 0xC0) == 0xC0:
            if offset + 1 >= len(data): break
            if not jumped: orig = offset + 2
            jumped, offset, max_j = True, ((n & 0x3F) << 8) | data[offset+1], max_j-1
            continue
        offset += 1; end = offset + n
        if end > len(data): break
        labels.append(data[offset:end].decode("ascii", errors="replace")); offset = end
    return ".".join(labels), (orig if jumped else offset)

def sniff_mdns(duration=5):
    results = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError: pass
        sock.bind(("", 5353))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                        struct.pack("4sL", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY))
        sock.settimeout(0.4)
        deadline = time.time() + duration
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                src = addr[0]
                if len(data) < 12: continue
                qd = struct.unpack("!H", data[4:6])[0]
                an = struct.unpack("!H", data[6:8])[0]
                off = 12
                for _ in range(qd):
                    if off >= len(data): break
                    _, off = _dns_name(data, off); off += 4
                for _ in range(an):
                    if off + 10 > len(data): break
                    name, off = _dns_name(data, off)
                    if off + 10 > len(data): break
                    rtype, _, _, rdlen = struct.unpack("!HHIH", data[off:off+10])
                    off += 10; rdata = data[off:off+rdlen]; off += rdlen
                    if rtype == 1 and len(rdata) == 4:
                        ip = socket.inet_ntoa(rdata)
                        if ip and ip not in results:
                            results[ip] = (name[:-6] if name.endswith(".local") else name)
                    elif rtype == 12 and src not in results:
                        ptr, _ = _dns_name(data, off - rdlen)
                        if ".local" in ptr: results[src] = ptr.replace(".local","")
            except (socket.timeout, Exception): continue
    except Exception: pass
    finally:
        try: sock.close()
        except: pass
    return results


# ── OS fingerprinting (TTL) ───────────────────────────────────────────────────

def get_ttl(ip, timeout=2):
    try:
        cmd = (["ping","-n","1","-w",str(timeout*1000),str(ip)] if sys.platform=="win32"
               else ["ping","-c","1","-W",str(timeout),str(ip)])
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout+1, text=True)
        m = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        return int(m.group(1)) if m else None
    except: return None

def fingerprint_os(ttl):
    if ttl is None: return None
    if ttl <= 64:   return "Linux / macOS / Android"
    if ttl <= 128:  return "Windows"
    if ttl <= 255:  return "Cisco IOS / BSD / Solaris"
    return "Unknown"


# ── Banner grabbing ───────────────────────────────────────────────────────────

def grab_banner(ip, port, timeout=2.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout); s.connect((str(ip), port))
            if port in (80,8080):   s.sendall(b"HEAD / HTTP/1.0\r\nHost: "+str(ip).encode()+b"\r\n\r\n")
            elif port in (443,8443): return "[HTTPS]"
            elif port == 25:         s.sendall(b"EHLO pathfinder\r\n")
            elif port == 6379:       s.sendall(b"PING\r\n")
            elif port == 11211:      s.sendall(b"version\r\n")
            return s.recv(512).decode("utf-8", errors="replace").strip()[:300]
    except: return None

def check_cve(banner, cve_db):
    if not banner or not cve_db: return []
    b = banner.lower()
    return [e for e in cve_db if e.get("match","").lower() in b]


# ── ARP / ping / ports — root-aware ──────────────────────────────────────────
#
#  Root path    →  /proc/net/arp  (Linux)  or  arp -a  (macOS/Win)
#  Non-root path →  ip neigh show  (works on Android/Termux without root,
#                   requires: pkg install iproute2)
#  Both paths normalise the result to uppercase XX:XX:XX:XX:XX:XX.

def _norm_mac(raw):
    """Uppercase and colon-separate any MAC string."""
    return raw.upper().replace("-", ":")

def read_arp_cache():
    """Bulk-load the neighbour/ARP table. Tries the appropriate method first."""
    cache = {}

    if IS_ROOT and sys.platform == "linux":
        # Fastest on rooted Linux: read kernel table directly
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    p = line.split()
                    if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                        cache[p[0]] = _norm_mac(p[3])
            if cache: return cache
        except Exception: pass

    # ip neigh show — works WITHOUT root on Linux/Android (iproute2 required)
    try:
        out = subprocess.check_output(
            ["ip","neigh","show"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            ip_m  = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            mac_m = LLADDR_RE.search(line)
            if ip_m and mac_m:
                cache[ip_m.group(1)] = _norm_mac(mac_m.group(1))
        if cache: return cache
    except Exception: pass

    # arp -a — macOS, Windows, some Linux (may need root on Android)
    try:
        out = subprocess.check_output(["arp","-a"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            ip_m  = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            mac_m = MAC_RE.search(line)
            if ip_m and mac_m:
                cache[ip_m.group(1)] = _norm_mac(mac_m.group(0))
    except Exception: pass

    return cache

def arp_scan_host(ip):
    """Single-host MAC lookup. Uses the non-root path first when not root."""
    s = str(ip)

    if IS_ROOT:
        # Root: direct arp command is faster for single-host lookup
        try:
            cmd = ["arp","-a",s] if sys.platform=="win32" else ["arp","-n",s]
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            m = MAC_RE.search(out)
            if m: return _norm_mac(m.group(0))
        except Exception: pass

    # ip neigh show <ip> — no root needed
    try:
        out = subprocess.check_output(
            ["ip","neigh","show",s], text=True, stderr=subprocess.DEVNULL)
        m = LLADDR_RE.search(out)
        if m: return _norm_mac(m.group(1))
    except Exception: pass

    # Last resort: arp -a filtered (macOS / Windows)
    try:
        out = subprocess.check_output(["arp","-a",s], text=True, stderr=subprocess.DEVNULL)
        m = MAC_RE.search(out)
        if m: return _norm_mac(m.group(0))
    except Exception: pass

    return None

def ping_host(ip, timeout=1):
    try:
        cmd = (["ping","-n","1","-w",str(timeout*1000),str(ip)] if sys.platform=="win32"
               else ["ping","-c","1","-W",str(timeout),str(ip)])
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=timeout+1).returncode == 0
    except: return False

def resolve_hostname(ip):
    try:    return socket.gethostbyaddr(str(ip))[0]
    except: return None

def lookup_vendor(mac, oui_db):
    """Look up OUI prefix (first 8 chars: XX:XX:XX) in the vendor DB."""
    if not mac or len(mac) < 8 or not oui_db: return "Unknown"
    return oui_db.get(mac[:8].upper(), "Unknown")

def scan_ports(ip, timeout=0.45):
    open_ports = []
    for port in PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((str(ip), port)) == 0: open_ports.append(port)
        except: pass
    return open_ports

def classify_device(vendor, hostname, ports, os_guess):
    """
    Device classification that works with both short vendor names and the
    enriched long-form strings from oui_db.json.
    Key rule: check for descriptive keywords present in enriched strings
    (e.g. "printer", "router", "firewall") BEFORE checking short vendor names
    so that HP laptops are not classified as printers just because "hp" is
    in the vendor field.
    """
    v = (vendor   or "").lower()
    h = (hostname or "").lower()
    p = set(ports  or [])

    # ── IoT / Embedded ────────────────────────────────────────────────────────
    if any(x in v for x in ["espressif","tuya","shelly","philips hue",
                              "iot module","smart plug","smart bulb","zigbee"]):
        return "🔌 IoT Device"
    if any(x in v for x in ["raspberry pi","arduino","libre computer"]):
        return "[SBC / IoT]"

    # ── Virtualisation ────────────────────────────────────────────────────────
    if any(x in v for x in ["vmware","virtualbox","qemu","hyper-v","xen","kvm"]):
        return "[Virtual Machine]"

    # ── Network gear — check descriptive keywords first ───────────────────────
    # The enriched DB uses words like "router", "firewall", "switch", "gateway"
    # in the description, which are more reliable than short vendor names.
    if any(x in v for x in ["router","firewall","access point","gateway","switch",
                              "modem","ont","olt","dslam","vpn appliance",
                              "wireless ap","mesh system","managed ap"]):
        return "[Network Gear]"
    if any(x in v for x in ["cisco","netgear","tp-link","d-link","ubiquiti",
                              "mikrotik","aruba","juniper","fortinet","avm (fritz",
                              "arris","sagemcom","zte","linksys","pfsense",
                              "draytek","teltonika","ruckus","cambium"]):
        return "[Network Gear]"

    # ── Printers — MUST come before the generic HP/Canon/Brother vendor check ─
    # All printer OUIs in the enriched DB have "printer", "laserjet",
    # "officejet", "mfc", "pixma" etc. in their descriptions.
    if any(x in v for x in ["printer","laserjet","officejet","pixma","imagerunner",
                              "workforce","mfc","dcp printer","inkjet","laser printer",
                              "mfp","copier","plotter","wide-format"]):
        return "[Printer]"
    # Unmistakable stand-alone printer brands (short descriptions from old DBs)
    if any(v.startswith(x) for x in ["epson","lexmark","xerox","ricoh","kyocera"]):
        return "[Printer]"
    if v.startswith("brother") and any(x in v for x in ["mfc","dcp","hl laser"]):
        return "[Printer]"
    if v.startswith("canon") and "camera" not in v:
        return "[Printer]"

    # ── IP Cameras / Surveillance ─────────────────────────────────────────────
    if any(x in v for x in ["ip camera","cctv","nvr","dvr","surveillance",
                              "hikvision","dahua","axis communications","reolink",
                              "wyze","vivotek","ezviz","imou","tiandy","uniview",
                              "geovis","provision isr","avtech","xiongmai"]):
        return "[IP Camera]"

    # ── NAS / Storage ─────────────────────────────────────────────────────────
    if any(x in v for x in ["synology","qnap","nas","diskstation","rackstation",
                              "western digital mycloud","seagate nas"]):
        return "[NAS Storage]"

    # ── Apple ─────────────────────────────────────────────────────────────────
    if "apple" in v:
        if any(x in h for x in ["iphone","ipad"]): return "📱 iPhone / iPad"
        if any(x in h for x in ["macbook","imac","mac"]): return "💻 Mac"
        return "[Apple Device]"

    # ── Mobile — specific sub-brands before generic catch-alls ───────────────
    if any(x in v for x in ["huawei honor","honor (formerly"]):
        return "[Mobile / Consumer]"
    if "huawei" in v:
        # Generic Huawei OUIs cover both phones and networking gear;
        # default to Network Gear since Huawei Honor handles the phone side.
        return "[Network Gear]"
    if any(x in v for x in ["samsung","xiaomi","motorola","oneplus","oppo","vivo",
                              "realme","htc","meizu","smartphone"]):
        return "[Mobile / Consumer]"
    if "lg electronics" in v:
        return "[Media / Smart Home]" if any(x in v for x in ["tv","oled","nanocell"]) \
               else "[Mobile / Consumer]"

    # ── Gaming ────────────────────────────────────────────────────────────────
    if any(x in v for x in ["nintendo","playstation","xbox"]):
        return "[Gaming Console]"
    if "sony" in v:
        return "[Gaming / AV]"

    # ── Media / Smart Home ────────────────────────────────────────────────────
    if any(x in v for x in ["amazon (echo","amazon echo","fire tv","chromecast",
                              "roku","sonos","google (home","google (nest",
                              "nest labs","smart speaker","shield tv","streaming"]):
        return "[Media / Smart Home]"

    # ── Servers (explicit keywords before generic brand check) ────────────────
    if any(x in v for x in ["server","poweredge","proliant","super micro",
                              "idrac","ilo","ipmi","bmc","xeon"]):
        return "[Server]"

    # ── General PC / Workstation ──────────────────────────────────────────────
    # Only classify as PC if a typical PC port is open, to avoid false positives.
    if any(x in v for x in ["dell","hp","lenovo","acer","asus","gigabyte","msi",
                              "asrock","toshiba","wistron","compal","quanta"]):
        if p & {22, 3389, 5900}: return "[PC / Workstation]"

    # ── Port-based inference (last resort) ────────────────────────────────────
    if 3389 in p or (os_guess and "windows" in os_guess.lower()):
        return "[Windows PC]"
    if 22 in p and not (p & {80, 443}):
        return "[Linux / SSH Host]"
    if p & {80, 443}:
        return "[Web Server]"

    return "[Unknown]"


# ── Security analysis ─────────────────────────────────────────────────────────

def detect_arp_spoofing(devices, prev_gw_mac=None, gateway_ip=None):
    alerts = []
    mac_to_ips = defaultdict(list)
    for d in devices:
        mac = d.get("mac","")
        if mac and "??" not in mac:
            mac_to_ips[mac].append(d["ip"])
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            alerts.append({"sev":"CRITICAL",
                "msg": f"MAC {mac} → {len(ips)} IPs: {', '.join(ips)}  ← ARP poisoning?"})
    if gateway_ip and prev_gw_mac:
        for d in devices:
            if d["ip"] == gateway_ip and d.get("mac") and d["mac"] != prev_gw_mac:
                alerts.append({"sev":"CRITICAL",
                    "msg": f"Gateway {gateway_ip} MAC changed: {prev_gw_mac} → {d['mac']}  ← spoof?"})
    return alerts

def check_local_promisc():
    promisc = []
    try:
        if sys.platform == "linux":
            for iface in os.listdir("/sys/class/net"):
                try:
                    with open(f"/sys/class/net/{iface}/flags") as f:
                        if int(f.read().strip(), 16) & 0x100: promisc.append(iface)
                except: continue
        elif sys.platform == "darwin":
            out = subprocess.check_output(["ifconfig"], text=True, stderr=subprocess.DEVNULL)
            cur = None
            for line in out.splitlines():
                if re.match(r"^\S", line): cur = line.split(":")[0]
                if cur and "PROMISC" in line: promisc.append(cur)
    except: pass
    return promisc


# ── Whitelist ─────────────────────────────────────────────────────────────────
#
#  The whitelist is keyed by MAC (uppercase XX:XX:XX:XX:XX:XX).
#  On non-root systems, devices whose MAC could not be resolved will have
#  mac = "??:??:??:??:??:??" and will never match — this is intentional:
#  we cannot confirm identity without a hardware address.

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
        # Skip placeholder MACs — we only whitelist devices we can identify.
        if mac and "??" not in mac and mac not in wl:
            wl[mac] = {"mac":mac, "ip":d.get("ip"), "hostname":d.get("hostname"),
                       "vendor":d.get("vendor"), "label":d.get("vendor",""),
                       "added":str(datetime.now())}
    with open(path,"w") as f:
        json.dump({"updated":str(datetime.now()),"entries":list(wl.values())}, f, indent=2)
    return path

def wl_status(d, whitelist):
    """
    Returns "OK" if MAC is in the whitelist, "UNCHARTED" if not, None if
    no whitelist is active.
    NOTE: devices with unresolved MACs (??:...) are always UNCHARTED because
    we cannot confirm their identity — not a bug, a safety feature.
    """
    if not whitelist: return None
    mac = d.get("mac","")
    if not mac or "??" in mac: return "UNCHARTED"
    return "OK" if mac in whitelist else "UNCHARTED"


# ── Core host sweep ───────────────────────────────────────────────────────────

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
    ports    = scan_ports(ip_str) if do_ports else []

    banners, cve_hits = {}, []
    if do_banner and ports:
        for port in ports:
            if port in (443, 8443): continue
            banner = grab_banner(ip_str, port, timeout=1.5)
            if banner:
                banners[port] = banner
                cve_hits.extend(check_cve(banner, cve_db))
        if 23 in ports and 23 not in banners:
            cve_hits.append({"cve":"INSECURE","sev":"CRITICAL",
                             "desc":"Telnet open — credentials sent in CLEARTEXT"})

    return {
        "ip": ip_str, "mac": mac or "??:??:??:??:??:??",
        "hostname": hostname or "—", "vendor": vendor,
        "type": classify_device(vendor, hostname, ports, os_guess),
        "os": os_guess or "—", "ttl": ttl,
        "ports": ports, "banners": banners, "cve_hits": cve_hits, "ts": ts(),
    }


# ── Display ───────────────────────────────────────────────────────────────────

def print_node(d, idx, gateway_ip, local_ip, whitelist=None, watch_tags=None):
    ip    = d["ip"];  mac = d["mac"];  host = d["hostname"]
    ports = d["ports"]; os_g = d.get("os","—")
    banners = d.get("banners",{}); cves = d.get("cve_hits",[])

    is_gw  = (ip == gateway_ip)
    is_me  = (ip == local_ip)
    is_unk = (d["vendor"] == "Unknown" and host == "—")

    tags = []
    if   is_gw:  ip_col = AM+BOLD; tags.append(f"{AM}[GATEWAY]{R}")
    elif is_me:  ip_col = LG+BOLD; tags.append(f"{LG}[HOME]{R}")
    elif is_unk: ip_col = DA+BOLD; tags.append(f"{DA}{BLNK}[HOSTILE?]{R}")
    else:        ip_col = TE+BOLD

    if watch_tags:
        if ip in watch_tags.get("new",set()):         tags.append(f"{LG}[NEW]{R}")
        if ip in watch_tags.get("mac_changed",{}):    tags.append(f"{DA}{BLNK}[MAC!]{R}")
    if whitelist and not is_me and not is_gw:
        ws = wl_status(d, whitelist)
        if ws == "UNCHARTED": tags.append(f"{WA}[UNCHARTED]{R}")

    print(f"\n  {AM}╭─ {GR}{idx:02d}{R}  {ip_col}{ip:<16}{R}  {'  '.join(tags)}")
    print(f"  {AM}│{R}  {GR}MAC     {R} {WH}{mac}{R}  {GR}·{R}  {GR}Vendor {R} {WA}{d['vendor']}{R}")
    print(f"  {AM}│{R}  {GR}Host    {R} {WH}{host}{R}")
    print(f"  {AM}│{R}  {GR}OS      {R} {SB}{os_g:<30}{R}  {GR}TTL {GR}{d.get('ttl','—')}{R}")
    print(f"  {AM}│{R}  {GR}Type    {R} {d['type']}")
    if ports:
        pline = "  ".join(f"{DA if p in HIGH_RISK else TE}{p}{GR}/{PORTS.get(p,'?')}{R}"
                          for p in sorted(ports))
        print(f"  {AM}│{R}  {GR}Ports   {R} {pline}")
    for port, banner in banners.items():
        print(f"  {AM}│{R}  {GR}Banner  {R} {GR}:{port}{R}  {DIM}{WH}{banner.replace(chr(10),' ')[:80]}{R}")
    for hit in cves:
        sc = SEV_COLOR.get(hit.get("sev","INFO"), AM)
        print(f"  {AM}│{R}  {sc}⚡ {hit.get('cve','?'):<18}{R}  "
              f"{sc}{hit.get('sev','?'):<8}{R}  {GR}{hit.get('desc','')}{R}")
    print(f"  {AM}│{R}  {GR}Pinged  {R} {GR}{d['ts']}{R}")
    print(f"  {AM}╰{'─'*66}{R}")


def print_threat_matrix(found, gateway_ip, local_ip, whitelist,
                         arp_alerts, promisc, watch_tags=None):
    gone    = (watch_tags or {}).get("gone",     set())
    new_    = (watch_tags or {}).get("new",      set())
    mac_chg = (watch_tags or {}).get("mac_changed",{})

    hostiles  = [d for d in found if d["vendor"]=="Unknown" and d["hostname"]=="—"
                 and d["ip"] not in (local_ip, gateway_ip)]
    exposed   = [d for d in found if any(p in HIGH_RISK for p in d["ports"])]
    cve_devs  = [d for d in found if d.get("cve_hits")]
    uncharted = [d for d in found if whitelist and wl_status(d,whitelist)=="UNCHARTED"
                 and d["ip"] not in (local_ip, gateway_ip)]

    divider("THREAT MATRIX")
    status(f"Nodes mapped    : {AM}{BOLD}{len(found)}{R}", "info")
    status(f"Unidentified    : {DA if hostiles  else LG}{BOLD}{len(hostiles)}{R}",  "warn" if hostiles  else "ok")
    status(f"Hostile ports   : {DA if exposed   else LG}{BOLD}{len(exposed)}{R}",   "warn" if exposed   else "ok")
    status(f"Exploit vectors : {DA if cve_devs  else LG}{BOLD}{len(cve_devs)}{R}",  "bad"  if cve_devs  else "ok")
    if not IS_ROOT:
        status(f"{WA}Running unprivileged — some MACs may be unresolved (ip neigh){R}", "warn")
    if whitelist:
        status(f"Uncharted nodes : {DA if uncharted else LG}{BOLD}{len(uncharted)}{R}", "warn" if uncharted else "ok")
    if watch_tags:
        status(f"New / lost      : {LG}{BOLD}{len(new_)}{R} new  ·  {WA}{BOLD}{len(gone)}{R} lost", "info")
        if mac_chg: status(f"MAC changes     : {DA}{BOLD}{len(mac_chg)}{R}", "bad")

    if arp_alerts:
        divider("SIGNAL SPOOFING ALERTS", color=DA)
        for a in arp_alerts:
            print(f"  {DA}{BOLD}⚡ [{a['sev']}]{R}  {DA}{a['msg']}{R}")
    if promisc:
        status(f"{WA}PROMISC on: {', '.join(promisc)}{R}  {GR}← local sniffer?{R}", "warn")
    if hostiles:
        divider("UNIDENTIFIED / HOSTILE NODES", color=DA)
        for d in hostiles:
            print(f"  {DA}▶  {BOLD}{d['ip']:<18}{R}  MAC: {WH}{d['mac']}{R}"
                  f"  OS: {SB}{d.get('os','—')}{R}  TTL: {GR}{d.get('ttl','—')}{R}")
    if exposed:
        divider("HOSTILE PORTS DETECTED", color=WA)
        for d in exposed:
            print(f"  {WA}▶  {BOLD}{d['ip']:<18}{R}  "
                  f"{DA}{', '.join(PORTS[p] for p in d['ports'] if p in HIGH_RISK)}{R}")
    if cve_devs:
        divider("EXPLOIT VECTORS", color=DA)
        for d in cve_devs:
            for hit in d["cve_hits"]:
                sc = SEV_COLOR.get(hit.get("sev","INFO"), AM)
                print(f"  {sc}▶  {hit.get('cve','?'):<18}  {d['ip']:<16}  {R}{GR}{hit.get('desc','')}{R}")
    if whitelist and uncharted:
        divider("UNCHARTED NODES", color=WA)
        for d in uncharted:
            mac_note = f"{WA}(MAC unresolved — run as root for full ID){R}" if "??" in d["mac"] else f"{WH}{d['mac']}{R}"
            print(f"  {WA}▶  {BOLD}{d['ip']:<18}{R}  {mac_note}")
    if gone:
        divider("SIGNAL LOST", color=GR)
        for ip in gone: print(f"  {GR}▶  {ip}{R}")
    if mac_chg:
        divider("MAC CHANGES  ⚠", color=DA)
        for ip, old in mac_chg.items():
            cur = next((d["mac"] for d in found if d["ip"]==ip), "?")
            print(f"  {DA}▶  {BOLD}{ip:<18}{R}  {GR}{old}{R}  →  {DA}{BOLD}{cur}{R}")


# ── Export ────────────────────────────────────────────────────────────────────

def export_results(devices, outfile=DEFAULT_OUT):
    path = os.path.abspath(outfile)
    with open(path,"w") as f:
        json.dump({"scan_time":str(datetime.now()),"root":IS_ROOT,"nodes":devices},
                  f, indent=2, default=str)
    return path


# ── Scan runner ───────────────────────────────────────────────────────────────

def run_scan(net_range, threads, do_ports, do_banner, do_os, mdns_map, oui_db, cve_db):
    try:
        hosts = list(ipaddress.IPv4Network(net_range, strict=False).hosts())
    except ValueError as e:
        status(f"{DA}Invalid range: {e}{R}", "bad"); return []

    arp_cache = read_arp_cache()
    total = len(hosts); found = []; lock = threading.Lock()
    done = [0]; stop_p = threading.Event()

    def progress():
        bw = 36
        while not stop_p.is_set():
            filled = int(bw * done[0] / max(total,1))
            bar = f"{LG}{'▰'*filled}{GR}{'▱'*(bw-filled)}{R}"
            print(f"\r  {AM}◉{R}  [{bar}]  {TE}{done[0]:4}/{total}{R}  {GR}Nodes:{R} {LG}{len(found):3}{R}   ",
                  end="", flush=True)
            time.sleep(0.15)
        print(f"\r{' '*80}\r", end="", flush=True)

    pt = threading.Thread(target=progress, daemon=True); pt.start()

    def worker(ip):
        r = sweep_host(ip, arp_cache, mdns_map, oui_db, cve_db,
                       do_ports=do_ports, do_banner=do_banner, do_os=do_os)
        with lock:
            done[0] += 1
            if r: found.append(r)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        list(as_completed({ex.submit(worker, ip): ip for ip in hosts}))

    stop_p.set(); pt.join()
    found.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
    return found


# ── Beacon mode ───────────────────────────────────────────────────────────────

def beacon_loop(args, net_range, gateway_ip, local_ip, whitelist, oui_db, cve_db):
    scan_n, prev, prev_gw_mac = 0, {}, None
    while True:
        scan_n += 1; clr(); banner_header(beacon_n=scan_n)
        mdns_map = {}
        if not args.no_banner:
            t = threading.Thread(target=lambda: mdns_map.update(sniff_mdns(3)), daemon=True)
            t.start(); t.join(timeout=4)
        divider(f"BEACON SWEEP #{scan_n}  ·  {net_range}")
        found = run_scan(net_range, args.threads,
                         not args.no_ports, not args.no_banner, not args.no_os,
                         mdns_map, oui_db, cve_db)
        cur = {d["ip"] for d in found}
        mac_chg = {d["ip"]: prev[d["ip"]]["mac"] for d in found
                   if d["ip"] in prev
                   and "??" not in (d.get("mac","") + prev[d["ip"]].get("mac",""))
                   and d.get("mac") != prev[d["ip"]].get("mac")}
        tags = {"new": cur-set(prev), "gone": set(prev)-cur, "mac_changed": mac_chg}

        arp_alerts = detect_arp_spoofing(found, prev_gw_mac, gateway_ip)
        promisc    = check_local_promisc()
        divider(f"NODE REGISTRY  ·  {len(found)} ACTIVE")
        for i, d in enumerate(found, 1):
            print_node(d, i, gateway_ip, local_ip, whitelist=whitelist, watch_tags=tags)
        print_threat_matrix(found, gateway_ip, local_ip, whitelist,
                            arp_alerts, promisc, watch_tags=tags)
        prev = {d["ip"]: d for d in found}
        gw = next((d for d in found if d["ip"] == gateway_ip), None)
        if gw: prev_gw_mac = gw.get("mac")
        export_results(found, args.export or DEFAULT_OUT)
        divider(f"NEXT SWEEP IN {args.interval}s  ·  Ctrl+C to abort")
        try:
            for rem in range(args.interval, 0, -1):
                m, s = divmod(rem, 60)
                bfill = int(38 * (1 - rem / args.interval))
                bar = f"{AM}{'▰'*bfill}{GR}{'▱'*(38-bfill)}{R}"
                print(f"\r  {TE}◉{R}  [{bar}]  {AM}{m:02d}:{s:02d}{R} remaining   ",
                      end="", flush=True)
                time.sleep(1)
            print()
        except KeyboardInterrupt:
            print(f"\n\n  {DA}✗  BEACON TERMINATED{R}\n"); sys.exit(0)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="PATHFINDER — Network Navigator & Rogue Device Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 pathfinder.py                     # auto-detect, full scan (no root needed)
  sudo python3 pathfinder.py                # full scan with root-level ARP access
  python3 pathfinder.py -r 10.0.0.0/24     # custom range
  python3 pathfinder.py -b -i 120          # beacon mode, 2-min interval
  python3 pathfinder.py --learn            # scan + save node registry
  python3 pathfinder.py --whitelist        # flag uncharted nodes
  python3 pathfinder.py -q                 # quiet: ping + ARP only
        """)
    ap.add_argument("-r","--range",       help="CIDR range (e.g. 192.168.1.0/24)")
    ap.add_argument("-t","--threads",     type=int, default=80, help="Threads (default: 80)")
    ap.add_argument("-e","--export",      metavar="FILE", help="JSON output path")
    ap.add_argument("-b","--beacon",      action="store_true", help="Continuous beacon mode")
    ap.add_argument("-i","--interval",    type=int, default=300, help="Beacon interval seconds")
    ap.add_argument("-q","--quiet",       action="store_true", help="Ping + ARP only, 20 threads")
    ap.add_argument("--no-ports",         action="store_true", help="Skip port scanning")
    ap.add_argument("--no-banner",        action="store_true", help="Skip banners + mDNS")
    ap.add_argument("--no-os",           action="store_true", help="Skip OS fingerprinting")
    ap.add_argument("--learn",           action="store_true", help="Save scan to node registry")
    ap.add_argument("--whitelist",       action="store_true", help="Flag uncharted nodes")
    ap.add_argument("--whitelist-file",  default=DEFAULT_WL,  help="Registry file path")
    ap.add_argument("--mdns-time",       type=int, default=5, help="mDNS listen seconds")
    ap.add_argument("--oui",             default=DEFAULT_OUI, help="OUI DB path")
    ap.add_argument("--cve",             default=DEFAULT_CVE, help="CVE DB path")
    args = ap.parse_args()

    if args.quiet:
        args.threads = 20; args.no_ports = True; args.no_banner = True

    clr(); banner_header()

    oui_db = load_oui_db(args.oui)
    cve_db = load_cve_db(args.cve)

    local_ip  = get_local_ip()
    gateway   = detect_gateway()
    net_range = args.range or (get_network_range(local_ip) if local_ip else None)
    if not net_range:
        status(f"{DA}Cannot detect network range. Use -r.{R}", "bad"); sys.exit(1)

    do_ports  = not args.no_ports
    do_banner = not args.no_banner
    do_os     = not args.no_os

    divider("NAV LINK ESTABLISHED")
    status(f"Home node   : {TE}{BOLD}{local_ip or 'unknown'}{R}", "ok")
    status(f"Gateway     : {AM}{gateway   or 'unknown'}{R}", "ok")
    status(f"Range       : {TE}{net_range}{R}", "ok")
    status(f"Privileges  : "
           + (f"{LG}ROOT — full ARP/proc access{R}" if IS_ROOT
              else f"{WA}UNPRIVILEGED — using ip neigh (install iproute2 if MACs missing){R}"),
           "ok" if IS_ROOT else "warn")
    status(f"Databases   : {LG}{len(oui_db)} vendors{R}  ·  {LG}{len(cve_db)} CVE rules{R}", "ok")
    status(f"Scan        : {AM}{'QUIET' if args.quiet else 'FULL'}{R}  "
           f"threads={TE}{args.threads}{R}  "
           f"ports={LG if do_ports  else DA}{'on' if do_ports  else 'off'}{R}  "
           f"banners={LG if do_banner else DA}{'on' if do_banner else 'off'}{R}  "
           f"os-fp={LG if do_os else DA}{'on' if do_os else 'off'}{R}", "ok")
    if args.beacon:
        status(f"Beacon mode : {LG}ACTIVE{R}  interval={AM}{args.interval}s{R}", "ok")
    divider()

    whitelist = {}
    if args.whitelist or args.learn:
        whitelist = load_whitelist(args.whitelist_file)
        status(f"Registry    : {LG}{len(whitelist)} known nodes{R}" if whitelist
               else f"{GR}Registry empty — run --learn first{R}",
               "ok" if whitelist else "warn")

    mdns_map = {}
    if do_banner and not args.beacon:
        status(f"mDNS intercept : {args.mdns_time}s…", "scan")
        t = threading.Thread(target=lambda: mdns_map.update(sniff_mdns(args.mdns_time)), daemon=True)
        t.start(); t.join(timeout=args.mdns_time + 1)
        status(f"mDNS : {LG}{len(mdns_map)} device(s){R}" if mdns_map
               else f"{GR}mDNS : no announcements{R}",
               "ok" if mdns_map else "info")
    divider()

    if args.beacon:
        beacon_loop(args, net_range, gateway, local_ip,
                    whitelist if (args.whitelist or args.learn) else {},
                    oui_db, cve_db)
        return

    divider("DEPLOYING GRID SCAN")
    found = run_scan(net_range, args.threads, do_ports, do_banner, do_os,
                     mdns_map, oui_db, cve_db)
    print()

    # Backfill mDNS hostnames missed by reverse DNS
    for d in found:
        if d["hostname"] == "—" and d["ip"] in mdns_map:
            d["hostname"] = mdns_map[d["ip"]]

    arp_alerts = detect_arp_spoofing(found, gateway_ip=gateway)
    promisc    = check_local_promisc()

    divider(f"NODE REGISTRY  ·  {len(found)} ACTIVE")
    for i, d in enumerate(found, 1):
        print_node(d, i, gateway, local_ip,
                   whitelist=whitelist if args.whitelist else None)

    print_threat_matrix(found, gateway, local_ip,
                        whitelist if args.whitelist else None,
                        arp_alerts, promisc)

    if args.learn:
        path = save_whitelist(found, args.whitelist_file, existing=whitelist)
        status(f"Registry saved → {AM}{path}{R}  ({LG}{len(found)} nodes{R})", "ok")

    path = export_results(found, args.export or DEFAULT_OUT)
    status(f"Results saved  → {AM}{path}{R}", "ok")
    print()
    divider("TRACE COMPLETE")
    print(f"\n  {GR}Grid mapped at {AM}{ts()}{GR}. Coordinates secured.{R}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {DA}✗  ABORTED{R}\n"); sys.exit(0)
