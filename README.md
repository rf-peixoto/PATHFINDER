# PATHFINDER
### Network Navigator & Rogue Device Detection System

```
   ___  _  _____ _  _ ___ ___ _  _ ___  ___ ___
  | _ \/_\|_   _| || | __|_ _| \| |   \| __| _ \
  |  _/ _ \ | | | __ | _| | || .` | |) | _||   /
  |_|/_/ \_\|_| |_||_|_| |___|_|\_|___/|___|_|_\

  Navigate. Map. Identify. Secure your grid.
```

PATHFINDER is a Python-based network scanner designed to inventory every device on your local network, identify unknown or rogue nodes, fingerprint operating systems, grab service banners, and flag CVE-matched vulnerabilities — all from a single terminal command with a cyberpunk-styled interface.

---

## Features

- **Ping sweep + ARP resolution** — discovers all live hosts; resolves MAC addresses via `/proc/net/arp` (root), `ip neigh show` (no-root / Android), or `arp -a` (macOS/Windows)
- **Privilege-aware ARP** — detects whether running as root at startup and selects the best MAC resolution method automatically; shows `ROOT` or `UNPRIVILEGED` in the header on every scan
- **MAC randomisation detection** — identifies locally-administered (privacy) MACs from Android 10+, iOS 14+, and Windows 10+ and labels them `⚄ Randomised MAC` rather than silently showing "Unknown"
- **OUI vendor lookup** — resolves the first 3 bytes of each MAC against a local JSON database; the full IEEE registry (~38,852 entries) can be built with `update_oui_db.py`
- **OS fingerprinting** — infers operating system from ICMP TTL values (Linux/macOS/Android ≤ 64, Windows ≤ 128, Cisco/BSD ≤ 255)
- **Banner grabbing** — connects to open ports and reads service greetings with correct `\r\n` handling so banners never corrupt the terminal display
- **CVE hint engine** — matches banners against a local JSON rules file; 339 rules covering FTP, SSH, web servers, databases, network gear, VPN gateways, industrial protocols, NAS, cameras, and more
- **mDNS / Bonjour interception** — passively listens on 224.0.0.251:5353 to capture device hostnames that reverse DNS misses
- **Port scanning** — checks 28 common ports including all high-risk services
- **ARP spoof detection** — flags duplicate MACs across multiple IPs and alerts when the gateway hardware address changes between scans
- **Promiscuous mode check** — inspects local NIC flags for `IFF_PROMISC`, which may indicate a sniffer running on the scanning machine
- **Device whitelist** — learn your network once, then flag anything uncharted in future scans; devices with unresolvable MACs are always UNCHARTED by design
- **MAC change tracking** — beacon mode detects when a known IP starts responding with a different MAC
- **Beacon mode** — continuous re-scanning at a configurable interval with per-cycle diff (new nodes, lost nodes, changed MACs)
- **JSON export** — saves full scan results after every run, including the privilege level that produced the scan
- **External data files** — OUI database and CVE rules are loaded from JSON files; update either without touching the script

---

## Requirements

- Python 3.6 or newer
- For no-root MAC resolution on Android / Linux: `ip` from `iproute2`

```bash
# Termux
pkg install iproute2 iputils

# Debian / Ubuntu
sudo apt install iproute2 iputils-ping
```

---

## File Layout

Place these files in the same directory:

```
pathfinder.py               ← main scanner
oui_db.json                 ← MAC vendor database (~38,852 IEEE entries)
cve_db.json                 ← CVE hint rules (339 entries)
```

Created automatically on first run:

```
pathfinder_results.json     ← scan output (overwritten each run)
pathfinder_whitelist.json   ← node registry (created with --learn)
```

---

## Quick Start

```bash
# Step 1 — learn your network and save the registry
sudo python3 pathfinder.py --learn

# Step 2 — regular scans that flag anything new or unknown
sudo python3 pathfinder.py --whitelist
```

---

## Data Files

### `oui_db.json`

A JSON object mapping 3-byte OUI prefixes (uppercase XX:XX:XX) to vendor description strings. The enriched version includes device family, OS/firmware context, and security notes.

```json
{
  "B8:27:EB": "Raspberry Pi Foundation | RPi 3B/3B+/Zero W | Linux Raspberry Pi OS ...",
  "00:0C:29": "VMware | Virtual machine NIC (Workstation / ESXi) | Any guest OS ...",
  "50:C7:BF": "TP-Link | Archer / Deco / TL-series router or AP | TP-Link firmware ..."
}
```

### `cve_db.json`

A JSON array of CVE hint rules. Each rule is matched case-insensitively as a substring of a service banner.

```json
[
  {
    "match": "apache/2.4.49",
    "cve":   "CVE-2021-41773",
    "sev":   "CRITICAL",
    "desc":  "Apache 2.4.49 path traversal + RCE via mod_cgi — unauthenticated, weaponised immediately"
  }
]
```

Valid severity values: `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO`

**CVE database coverage (339 rules):**

| Category | Rules | Examples |
|---|---|---|
| FTP servers | 17 | vsftpd 2.3.4 backdoor, ProFTPD mod_copy, wu-ftpd |
| SSH | 48 | OpenSSH 2.x → 9.3p2, Dropbear, libssh auth bypass (CVE-2018-10933) |
| Telnet / legacy | 6 | Always CRITICAL; telnetd CVE-2011-4862 RCE |
| Apache httpd | 27 | Every patched CVE from 1.3 through 2.4.55 |
| nginx | 12 | 0.x EOL through 1.20.x mp4 module UAF |
| IIS | 5 | IIS 5.x → 10.x including CVE-2022-21907 |
| Embedded web servers | 7 | GoAhead, Boa, mini_httpd (router/IoT targets) |
| PHP | 14 | EOL from PHP 4.x through 8.0.x |
| Application servers | 15 | Tomcat Ghostcat, JBoss deserialization, WebLogic RCE |
| Log4j / Spring / CGI | 5 | Log4Shell, Spring4Shell, Shellshock |
| SMTP / mail servers | 21 | Exim 4.87–4.96 (21Nails), Exchange ProxyLogon/Shell, Zimbra |
| IMAP / POP3 | 5 | Dovecot CVE-2019-11500, Cyrus, UW-IMAP |
| Databases | 26 | MySQL/MariaDB EOL, Redis Lua RCE, MongoDB, InfluxDB auth bypass, MinIO credential leak, etcd |
| Windows / SMB | 11 | EternalBlue MS17-010, BlueKeep CVE-2019-0708, SMBGhost, SambaCry |
| VNC | 8 | RFB 3.3 auth bypass, TigerVNC, UltraVNC, TightVNC |
| Network gear | 28 | Cisco IOS/ASA/IOS-XE 0-day, Juniper Junos RCE, Fortinet auth bypass, MikroTik Winbox, TP-Link Mirai, Zyxel, DrayTek, SonicWall, Barracuda |
| VPN gateways | 11 | Pulse/Ivanti, Citrix ADC CVE-2023-3519, F5 BIG-IP, Palo Alto GlobalProtect 0-day |
| DevOps / CI/CD | 24 | Jenkins CVE-2024-23897, GitLab, Confluence, Grafana, GoAnywhere, MOVEit, SolarWinds, Zabbix, PaperCut, Veeam |
| VMware | 4 | vCenter RCE, ESXi ESXiArgs ransomware vector |
| CMS / e-commerce | 9 | Drupal Drupalgeddon 2/3, Joomla, Magento pre-auth RCE |
| Remote management | 5 | iDRAC, HP iLO 4 auth bypass, IPMI cipher-0, Intel AMT |
| NAS storage | 7 | Synology DSM 6/7, QNAP Deadbolt target, WD My Cloud |
| IP cameras | 4 | Hikvision CVE-2021-36260, Dahua CVE-2021-33044 |
| Printers | 5 | HP JetDirect, HP LaserJet, Lexmark, Xerox |
| Industrial / OT | 9 | Modbus, Siemens S7/SIMATIC, CODESYS, PROFINET |
| Misc protocols | 12 | SNMP v1/v2c, MQTT, NFS, TFTP, X11, xRDP |
| SSL / TLS | 3 | Heartbleed, POODLE, DROWN |

---

## Usage

### Basic scan — auto-detects your network

```bash
python3 pathfinder.py
```

### Full scan with root-level ARP access

```bash
sudo python3 pathfinder.py
```

### Scan a specific range

```bash
python3 pathfinder.py -r 10.0.0.0/24
```

### Build your node registry

```bash
sudo python3 pathfinder.py --learn
```

Scans and saves every discovered device to `pathfinder_whitelist.json`. Devices whose MACs cannot be resolved are not saved — identity cannot be confirmed without a hardware address.

### Flag unknown devices

```bash
sudo python3 pathfinder.py --whitelist
```

Any device not in the registry is tagged `[⚠ UNCHARTED]`. Devices with randomised MACs will always appear as UNCHARTED by design.

### Beacon mode — continuous monitoring

```bash
sudo python3 pathfinder.py --beacon --interval 120
```

Re-scans every 120 seconds. Each cycle diffs against the previous: new nodes get `[▶ NEW]`, disappeared nodes appear under **SIGNAL LOST**, MAC changes trigger `[⚠ MAC!]` and appear in **MAC CHANGES** in the threat matrix.

### Quiet mode — fast ping and ARP only

```bash
python3 pathfinder.py -q
```

20 threads, skips port scanning and banner grabbing. Fast headcount with minimal noise.

### Skip individual modules

```bash
python3 pathfinder.py --no-ports
python3 pathfinder.py --no-banner
python3 pathfinder.py --no-os
python3 pathfinder.py --no-banner --no-os
```

### Android / Termux (no root)

```bash
pkg install iproute2 iputils python
python pathfinder.py -r 192.168.1.0/24 --no-os
```

---

## All Options

| Flag | Default | Description |
|---|---|---|
| `-r`, `--range` | auto-detect | CIDR range to scan |
| `-t`, `--threads` | `80` | Parallel threads |
| `-e`, `--export` | `pathfinder_results.json` | JSON output path |
| `-b`, `--beacon` | off | Continuous beacon mode |
| `-i`, `--interval` | `300` | Beacon re-scan interval (seconds) |
| `-q`, `--quiet` | off | 20 threads, ping + ARP only |
| `--no-ports` | off | Skip port scanning |
| `--no-banner` | off | Skip banner grabbing and mDNS |
| `--no-os` | off | Skip TTL OS fingerprinting |
| `--learn` | off | Save discovered nodes to registry |
| `--whitelist` | off | Flag nodes not in the registry |
| `--whitelist-file` | `pathfinder_whitelist.json` | Registry file path |
| `--mdns-time` | `5` | mDNS listen duration (seconds) |
| `--oui` | `oui_db.json` | OUI vendor DB path |
| `--cve` | `cve_db.json` | CVE hints DB path |

---

## Understanding the Output

### Privilege indicator

```
Priv: ROOT           ← /proc/net/arp + arp -n available
Priv: UNPRIVILEGED   ← ip neigh show used instead
```

### Node card

```
  ╭─ 03  192.168.1.105       [⚠ UNCHARTED]
  │  MAC      B8:27:EB:xx:xx:xx  ·  Vendor  Raspberry Pi Foundation | RPi 4B ...
  │  Host     raspberrypi.local
  │  OS       Linux / macOS / Android          TTL 64
  │  Type     [SBC / IoT]
  │  Ports    22/SSH  80/HTTP
  │  Banner   :22  SSH-2.0-OpenSSH_8.9p1 Debian
  │  ⚡ CVE-2021-41617   HIGH      OpenSSH privilege escalation via supplemental groups
  │  Pinged   13:57:44
  ╰──────────────────────────────────────────────────────────────────
```

### Node tags

| Tag | Meaning |
|---|---|
| `[GATEWAY]` | Detected default route (by IP or hostname) |
| `[HOME]` | The machine running the scan |
| `[HOSTILE?]` | Unknown vendor AND no hostname resolved |
| `[▶ NEW]` | Appeared since the last beacon cycle |
| `[⚠ MAC!]` | MAC address changed since last beacon cycle |
| `[⚠ UNCHARTED]` | Not in the node registry (`--whitelist` active) |

### MAC vendor field

| Display | Meaning |
|---|---|
| Vendor name / description | OUI matched in the database |
| `OUI not in database — run update_oui_db.py` | Real OUI not yet in local DB |
| `⚄ Randomised MAC (privacy/Android/iOS)` | Locally-administered MAC — cannot be resolved by any OUI database |
| `Unknown` | MAC could not be resolved |

### Threat matrix sections

| Section | Trigger |
|---|---|
| UNIDENTIFIED / HOSTILE NODES | Unknown vendor + no hostname |
| HOSTILE PORTS DETECTED | High-risk port open (Telnet, SMB, RDP, VNC, Docker, Memcached, MongoDB, Elasticsearch) |
| EXPLOIT VECTORS | CVE rule matched in a banner |
| SIGNAL SPOOFING ALERTS | Duplicate MACs or gateway MAC change |
| UNCHARTED NODES | Not in registry (with `--whitelist`) |
| SIGNAL LOST | Devices that disappeared since last beacon cycle |
| MAC CHANGES | Hardware address change per IP (beacon mode) |

### Severity levels

| Level | Colour | Meaning |
|---|---|---|
| `CRITICAL` | Red | Unauthenticated RCE, auth bypass, or actively exploited |
| `HIGH` | Orange | Authenticated RCE, critical disclosure, or EOL with known exploits |
| `MEDIUM` | Amber | DoS, info disclosure, or EOL without active public exploitation |
| `LOW` | Green | Minor issue or hardening recommendation |
| `INFO` | Teal | Exposure worth reviewing; no direct CVE |

---

## MAC Resolution — Root vs No-Root

PATHFINDER runs `os.geteuid() == 0` once at startup. ARP functions use the result throughout:

| Step | Method | When |
|---|---|---|
| 1 | `/proc/net/arp` — direct kernel table read | Root + Linux only |
| 2 | `ip neigh show` — iproute2 neighbour table | **No root needed** (Android, Termux, Linux) |
| 3 | `arp -a` — system ARP command | macOS, Windows, fallback |

All three methods normalise the result to uppercase `XX:XX:XX:XX:XX:XX` before storage and comparison.

**Why some MACs always show `OUI not in database`:**
Run `update_oui_db.py` to pull the complete IEEE registry. The shipped `oui_db.json` may not cover every manufacturer — newer or smaller OUI allocations are missing until the database is refreshed.

**Why some MACs always show `Randomised MAC`:**
Bit 1 of the first octet is set (values like `x2`, `x6`, `xA`, `xE`). This is the IEEE locally-administered bit — the device generated this MAC randomly for Wi-Fi privacy. No database can resolve it. These nodes can never be whitelisted by MAC.

---

## Recommended Workflow

**First time setup:**
```bash
sudo python3 pathfinder.py --learn  # scan and save known-good baseline
```

**Daily / scheduled check:**
```bash
sudo python3 pathfinder.py --whitelist
```

**Ongoing monitoring:**
```bash
sudo python3 pathfinder.py --beacon --whitelist --interval 300
```

**Quick headcount:**
```bash
python3 pathfinder.py -q
```

---

## Ports Scanned (28 total)

| Port | Service | High-risk |
|---|---|---|
| 21 | FTP | |
| 22 | SSH | |
| 23 | Telnet | ⚠ |
| 25 | SMTP | |
| 53 | DNS | |
| 80 | HTTP | |
| 110 | POP3 | |
| 135 | RPC | ⚠ |
| 139 | NetBIOS | ⚠ |
| 143 | IMAP | |
| 161 | SNMP | |
| 389 | LDAP | |
| 443 | HTTPS | |
| 445 | SMB | ⚠ |
| 636 | LDAPS | |
| 1883 | MQTT | |
| 2375 | Docker | ⚠ |
| 2376 | Docker-TLS | |
| 3306 | MySQL | |
| 3389 | RDP | ⚠ |
| 5432 | PostgreSQL | |
| 5900 | VNC | ⚠ |
| 6379 | Redis | |
| 8080 | HTTP-Alt | |
| 8443 | HTTPS-Alt | |
| 9200 | Elasticsearch | ⚠ |
| 11211 | Memcached | ⚠ |
| 27017 | MongoDB | ⚠ |

---

## Notes

- **Authorization** — only scan networks you own or have explicit written permission to test.
- **mDNS** — binding to port 5353 may require root on some systems; PATHFINDER skips it gracefully if it fails.
- **Promiscuous mode detection** — only inspects the local machine. Remote promisc detection requires raw packet injection and is outside the scope of this tool.
- **ARP spoof detection** — a gateway MAC change between scans is a strong indicator but not conclusive. Legitimate causes include router replacement or firmware upgrade.
- **Banner grabbing** — some services close before sending a banner or require a specific protocol handshake. PATHFINDER sends basic probes; `nmap -sV` provides deeper identification where needed.
- **CVE matching** — rules are banner substring matches, not a substitute for a proper vulnerability scanner. Treat matches as leads to investigate, not confirmed exploits.
- **OUI database** — even with the full IEEE MA-L registry, some MACs will not resolve. MA-M and MA-S allocations are separate IEEE registries not included in the standard download. Randomised MACs will never resolve regardless of database size.

---

## License

For personal and authorised professional use. Comply with your jurisdiction's laws regarding network scanning before deploying on any network you do not own.
