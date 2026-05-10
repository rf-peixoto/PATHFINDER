# PATHFINDER
### Network Navigator & Rogue Device Detection System

```
   ___  _  _____ _  _ ___ ___ _  _ ___  ___ ___
  | _ \/_\|_   _| || | __|_ _| \| |   \| __| _ \
  |  _/ _ \ | | | __ | _| | || .` | |) | _||   /
  |_|/_/ \_\|_| |_||_|_| |___|_|\_|___/|___|_|_\

  Navigate. Map. Identify. Secure your grid.
```

PATHFINDER is a Python-based network scanning tool designed to help you inventory every device on your local network, identify unknown or rogue nodes, fingerprint operating systems, grab service banners, and receive CVE-based vulnerability hints — all from a single terminal command with a cyberpunk-styled interface.

---

## Features

- **Ping sweep + ARP resolution** — discovers all live hosts on the segment, with MAC address identification from both the ARP cache and direct ARP queries
- **OS fingerprinting** — infers the operating system from ICMP TTL values (Linux/macOS → 64, Windows → 128, Cisco/BSD → 255)
- **Banner grabbing** — connects to open ports and reads service greetings to identify software and versions
- **CVE hint engine** — matches banners against a local CVE rules file and flags known-vulnerable software with severity levels
- **mDNS / Bonjour interception** — passively listens on the multicast group to capture device names that DNS misses entirely
- **MAC vendor lookup** — resolves the OUI prefix against a local vendor database to identify manufacturers
- **Port scanning** — checks 24 common ports including high-risk ones (Telnet, SMB, RDP, VNC, Docker, Redis, MongoDB, and more)
- **ARP spoof detection** — flags duplicate MACs across multiple IPs and alerts when the gateway's hardware address changes between scans
- **Promiscuous mode check** — inspects local NIC flags for `IFF_PROMISC`, which may indicate a packet sniffer running on your machine
- **Device whitelist** — learn your network once, then flag anything that appears uncharted in future scans
- **MAC change tracking** — detects when a known IP starts responding with a different MAC address
- **Beacon mode** — continuous re-scanning at a configurable interval with per-cycle diff output (new nodes, lost nodes, changed MACs)
- **JSON export** — saves full scan results automatically after every run
- **External data files** — OUI vendor database and CVE hint rules are loaded from JSON files, keeping the script lean and easy to update

---

## Requirements

- Python 3.6 or newer
- Linux, macOS, or Windows
- `sudo` / administrator privileges recommended (required for ARP cache reads and mDNS multicast on some systems)
- No third-party Python packages — standard library only

---

## File Layout

Place all four files in the same directory:

```
pathfinder.py           ← main script
oui_db.json             ← MAC vendor database
cve_db.json             ← CVE hint rules
```

The following files are created automatically on first run:

```
pathfinder_results.json     ← scan output (overwritten each run)
pathfinder_whitelist.json   ← node registry (created with --learn)
```

---

## Data Files

PATHFINDER reads vendor and CVE data from local JSON files rather than hardcoding them, so you can update either database without touching the script.

### `oui_db.json`

A JSON object mapping 3-byte OUI prefixes (uppercase, colon-separated) to vendor name strings.

```json
{
  "B8:27:EB": "Raspberry Pi",
  "DC:A6:32": "Raspberry Pi",
  "00:0C:29": "VMware",
  "50:C7:BF": "TP-Link",
  "AC:BC:32": "Apple"
}
```

### `cve_db.json`

A JSON array of hint rules. Each rule specifies a case-insensitive substring to match against a service banner, the associated CVE identifier, a severity level, and a description.

```json
[
  {
    "match": "vsftpd 2.3.4",
    "cve":   "CVE-2011-2523",
    "sev":   "CRITICAL",
    "desc":  "vsftpd 2.3.4 backdoor — shell spawns on port 6200"
  },
  {
    "match": "apache/2.4.49",
    "cve":   "CVE-2021-41773",
    "sev":   "CRITICAL",
    "desc":  "Apache 2.4.49 path traversal & unauthenticated RCE"
  }
]
```

Valid severity values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

---

## Usage

### Basic scan — auto-detects your network

```bash
sudo python3 pathfinder.py
```

### Scan a specific range

```bash
sudo python3 pathfinder.py -r 10.0.0.0/24
```

### Build your node registry (first-time setup)

```bash
sudo python3 pathfinder.py --learn
```

Scans the network and saves every discovered device to `pathfinder_whitelist.json`. Run this once on a known-good network state.

### Flag unknown devices against the registry

```bash
sudo python3 pathfinder.py --whitelist
```

Any device not in the registry is tagged **UNCHARTED** in the output and listed in the threat matrix.

### Beacon mode — continuous monitoring

```bash
sudo python3 pathfinder.py --beacon --interval 120
```

Re-scans every 120 seconds. Each cycle shows a diff: new nodes are tagged **INBOUND**, disappeared nodes are listed under **SIGNAL LOST**, and MAC changes trigger an **ID SPOOFED** alert.

### Quiet mode — fast ping and ARP only

```bash
sudo python3 pathfinder.py -q
```

Reduces thread count to 20, skips port scanning and banner grabbing. Useful for a quick headcount with minimal noise.

### Skip individual modules

```bash
sudo python3 pathfinder.py --no-ports        # ping sweep only
sudo python3 pathfinder.py --no-banner       # ports but no banners or mDNS
sudo python3 pathfinder.py --no-os           # skip TTL fingerprinting
sudo python3 pathfinder.py --no-banner --no-os  # fastest full port sweep
```

### Custom data file paths

```bash
sudo python3 pathfinder.py --oui /path/to/oui_db.json
sudo python3 pathfinder.py --cve /path/to/cve_db.json
```

### Export to a specific file

```bash
sudo python3 pathfinder.py -e /tmp/my_scan.json
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
| `--no-os` | off | Skip OS fingerprinting |
| `--learn` | off | Save discovered nodes to registry |
| `--whitelist` | off | Flag nodes not in registry |
| `--whitelist-file` | `pathfinder_whitelist.json` | Registry file path |
| `--mdns-time` | `5` | mDNS interception duration (seconds) |
| `--oui` | `oui_db.json` | OUI vendor DB path |
| `--cve` | `cve_db.json` | CVE hints DB path |

---

## Understanding the Output

### Node cards

Each discovered device is shown as a card:

```
  ╭─ 04  192.168.1.105       [⚠ UNCHARTED]
  │  MAC      DC:A6:32:xx:xx:xx   ·  Vendor  Raspberry Pi
  │  Hostname raspberrypi.local
  │  OS       Linux / macOS / Android          TTL 64
  │  Type     🤖 SBC / IoT
  │  Ports    22/SSH  80/HTTP
  │  Signal   :22  SSH-2.0-OpenSSH_8.9p1 Debian
  │  Pinged   14:32:07
  ╰──────────────────────────────────────────────────────────────────
```

### Threat matrix

After the node list, PATHFINDER prints a consolidated threat matrix covering:

- **Unidentified nodes** — unknown vendor and no hostname (tagged `HOSTILE?`)
- **Hostile ports** — high-risk services open: Telnet, SMB, RDP, VNC, Docker, Memcached, MongoDB, Elasticsearch
- **Exploit vectors** — CVE matches from banner grabbing, with severity and description
- **Signal spoofing alerts** — duplicate MACs or gateway MAC changes (ARP poisoning indicators)
- **Uncharted nodes** — devices not in your whitelist
- **Inbound / lost** — beacon mode new and disappeared nodes
- **ID changes** — MAC address changes per IP (beacon mode)

### Severity levels

| Level | Colour | Meaning |
|---|---|---|
| `CRITICAL` | Red | Exploit available, likely unpatched, immediate action required |
| `HIGH` | Orange | Serious risk, remediate soon |
| `MEDIUM` | Amber | Notable finding, review when possible |
| `LOW` | Green | Informational, low immediate risk |
| `INFO` | Teal | General note, no direct CVE |

---

## Recommended Workflow

**First run on a new network:**

```bash
sudo python3 pathfinder.py --learn
```

**Daily / scheduled check:**

```bash
sudo python3 pathfinder.py --whitelist
```

**Set-and-forget monitoring:**

```bash
sudo python3 pathfinder.py --beacon --whitelist --interval 300
```

**Quick check before/after a change:**

```bash
sudo python3 pathfinder.py -q
```

---

## Ports Scanned

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

- **Authorization** — only scan networks you own or have explicit written permission to test. Unauthorized network scanning may be illegal in your jurisdiction.
- **mDNS** — binding to port 5353 may require root on some systems. If it fails, PATHFINDER falls back gracefully and skips mDNS without affecting other features.
- **Promiscuous mode detection** — the local interface check only inspects the machine running PATHFINDER. Remote promiscuous detection requires raw packet injection, which is outside the scope of this tool.
- **ARP spoof detection** — a gateway MAC change between scans is a strong indicator but not conclusive proof of an attack. Changes can also occur after a legitimate router replacement or firmware update.
- **Banner grabbing** — some services close the connection before sending a banner, or require specific protocol handshakes. PATHFINDER sends basic probes; a dedicated scanner like `nmap -sV` provides deeper identification.
- **CVE matching** — hints are based on banner string matching and are not a substitute for a proper vulnerability scanner. Treat matches as leads to investigate, not confirmed vulnerabilities.

---

## License

For personal and authorized professional use. See your jurisdiction's laws regarding network scanning before deploying on any network you do not own.
