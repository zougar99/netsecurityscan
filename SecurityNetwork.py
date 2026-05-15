1# -*- coding: utf-8 -*-
# Security Network - Application wa7da (one app)
# Chkon m3ak f WiFi | Who is trying to kick you | Bzaaf tools
# Run: py -3 SecurityNetwork.py

import sys
import subprocess
import re
import socket
import platform
import time
import shutil
import concurrent.futures
import urllib.request
import urllib.parse
import ssl
import hashlib
import base64
import random
import string
import os
import json
from collections import defaultdict

if sys.version_info[0] < 3:
    print("Security Network needs Python 3. Run: py -3 SecurityNetwork.py")
    sys.exit(1)

# --- Rich (optional) ---
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, IntPrompt
    RICH = True
except ImportError:
    RICH = False

if RICH:
    console = Console()
else:
    console = None

# ========== APP IDENTITY (i7tarafiya mn jami3 nawa7i) ==========
APP_NAME = "Security Network"
APP_VERSION = "2.0"
APP_TAGLINE = "i7tarafiya mn jami3 nawa7i"
APP_FULL = "%s v%s - %s" % (APP_NAME, APP_VERSION, APP_TAGLINE)
TOTAL_TOOLS = 62

def show_banner():
    """Show app identity from all sides - recognizable everywhere."""
    sep = "=" * 50
    if RICH:
        console.print(Panel(
            "[bold cyan]%s[/bold cyan]\n[bold]v%s[/bold]\n[dim]%s[/dim]" % (APP_NAME, APP_VERSION, APP_TAGLINE),
            title="[bold white] Application [/bold white]",
            border_style="cyan",
            padding=(0, 2),
        ))
    else:
        _print(sep)
        _print("  %s  |  v%s" % (APP_NAME, APP_VERSION))
        _print("  %s" % APP_TAGLINE)
        _print(sep)

def set_window_title():
    """Set console/title so app is recognizable from taskbar."""
    try:
        if platform.system().lower() == "windows":
            os.system("title %s v%s" % (APP_NAME, APP_VERSION))
    except Exception:
        pass

def show_dashboard():
    """7stat - Dashboard like PC applications, i7rafiya mn jami3 nawa7i."""
    my_ip = get_my_ip()
    gw = get_gateway_windows()
    hostname = get_hostname()
    try:
        pub_ip = my_public_ip()
        if not pub_ip or "error" in str(pub_ip).lower() or "errno" in str(pub_ip).lower():
            pub_ip = "—"
    except Exception:
        pub_ip = "—"
    devices = get_connected_devices()
    conns = get_connections_windows()
    if RICH:
        from rich.table import Table as RichTable
        from rich.panel import Panel as RichPanel
        table = RichTable(show_header=False, title="  Dashboard | 7stat  ", border_style="green")
        table.add_column("Stat", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Application", "%s v%s" % (APP_NAME, APP_VERSION))
        table.add_row("Tagline", APP_TAGLINE)
        table.add_row("Total tools", str(TOTAL_TOOLS))
        table.add_row("—", "—")
        table.add_row("My IP (local)", my_ip)
        table.add_row("Public IP", pub_ip if pub_ip and len(str(pub_ip)) < 20 else (str(pub_ip)[:30] + "…" if pub_ip else "—"))
        table.add_row("Gateway", gw or "—")
        table.add_row("Hostname", hostname)
        table.add_row("OS", "%s %s" % (platform.system(), platform.release()))
        table.add_row("—", "—")
        table.add_row("Devices in ARP", str(len(devices)))
        table.add_row("Active connections", str(len(conns)))
        console.print(RichPanel(table, title="[bold] Application PC | i7rafiya [/bold]", border_style="blue", padding=(0, 1)))
    else:
        sep = "-" * 40
        _print(sep)
        _print("  DASHBOARD | 7stat")
        _print(sep)
        _print("  Application : %s v%s" % (APP_NAME, APP_VERSION))
        _print("  %s" % APP_TAGLINE)
        _print("  Total tools : %s" % TOTAL_TOOLS)
        _print(sep)
        _print("  My IP       : %s" % my_ip)
        _print("  Public IP   : %s" % (pub_ip[:25] + "…" if pub_ip and len(str(pub_ip)) > 25 else (pub_ip or "—")))
        _print("  Gateway     : %s" % (gw or "—"))
        _print("  Hostname    : %s" % hostname)
        _print("  OS          : %s %s" % (platform.system(), platform.release()))
        _print(sep)
        _print("  Devices (ARP): %s" % len(devices))
        _print("  Connections : %s" % len(conns))
        _print(sep)

# ========== SCANNER (WiFi devices) ==========
def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_arp_table_windows():
    try:
        out = subprocess.check_output(["arp", "-a"], shell=False, text=True, encoding="utf-8", errors="replace")
        return out
    except Exception as e:
        return str(e)

def parse_arp_table(arp_text):
    devices = []
    for line in arp_text.splitlines():
        match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F\-]{17})", line)
        if match:
            ip, mac = match.groups()
            if not ip.startswith("224.") and not ip.startswith("239."):
                devices.append((ip.strip(), mac.strip()))
    return devices

def get_connected_devices():
    return parse_arp_table(get_arp_table_windows())

def ping_host(ip, timeout=1):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        subprocess.run(["ping", param, "1", "-w", str(timeout * 1000), ip], capture_output=True, timeout=timeout + 2)
    except Exception:
        pass

def scan_subnet_arp(my_ip=None):
    if my_ip is None:
        my_ip = get_my_ip()
    parts = my_ip.split(".")
    if len(parts) != 4:
        return []
    base = ".".join(parts[:3])
    for i in range(1, 255):
        ping_host("%s.%d" % (base, i))
    return get_connected_devices()

def get_mac_vendor(mac):
    mac_upper = mac.replace("-", ":").upper()[:8]
    vendors = {
        "00:50:56": "VMware", "00:0C:29": "VMware", "00:1A:2B": "Cisco", "08:00:27": "VirtualBox",
        "52:54:00": "QEMU", "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
        "F4:5C:89": "Apple", "00:1E:C2": "Apple", "28:CF:E9": "Apple", "AC:DE:48": "Apple", "D0:03:4B": "Apple",
        "00:17:88": "Philips Hue", "94:B9:7E": "TP-Link", "50:C7:BF": "TP-Link", "C0:25:E9": "TP-Link", "F8:1A:67": "TP-Link",
        "E4:D3:32": "Xiaomi", "64:CC:2E": "Xiaomi", "34:80:B3": "Intel", "8C:EC:4B": "Intel", "30:65:EC": "Intel",
    }
    for prefix, name in vendors.items():
        if mac_upper.startswith(prefix.replace(":", "")) or mac.replace("-", ":").upper().startswith(prefix):
            return name
    return "Unknown"

# ========== ARP MONITOR (detect kick / spoofing) ==========
def monitor_arp_changes(duration_seconds=60, check_interval=2, on_change_callback=None):
    history = defaultdict(list)
    alerts = []
    my_ip = get_my_ip()
    start = time.time()
    while (time.time() - start) < duration_seconds:
        devices = get_connected_devices()
        now = time.time()
        for ip, mac in devices:
            if ip == my_ip:
                continue
            if ip not in history:
                history[ip].append((now, mac))
            else:
                last_mac = history[ip][-1][1]
                if last_mac.upper() != mac.upper():
                    msg = "[!] ARP CHANGE: %s was %s now %s - POSSIBLE SPOOFING / KICK ATTEMPT" % (ip, last_mac, mac)
                    alerts.append(msg)
                    history[ip].append((now, mac))
                    if on_change_callback:
                        on_change_callback(msg)
        time.sleep(check_interval)
    return alerts

# ========== PORT SCAN ==========
def scan_port(ip, port, timeout=0.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return (port, r == 0)
    except Exception:
        return (port, False)

def scan_ports(ip, ports=None, timeout=0.5, max_workers=50):
    if ports is None:
        ports = list(range(1, 1025))
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_port, ip, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            port, is_open = f.result()
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt",
}

# ========== DNS ==========
def dns_lookup(hostname):
    try:
        return list(set(socket.gethostbyname_ex(hostname)[2]))
    except socket.gaierror:
        try:
            return [socket.gethostbyname(hostname)]
        except Exception:
            return []
    except Exception as e:
        return [str(e)]

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception as e:
        return str(e)

# ========== PING ==========
def ping_one(ip, timeout=1):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        r = subprocess.run(["ping", param, "1", "-w", str(timeout * 1000), ip], capture_output=True, text=True, timeout=timeout + 2)
        return r.returncode == 0
    except Exception:
        return False

def ping_sweep(base_ip, start=1, end=255):
    parts = base_ip.split(".")
    if len(parts) != 4:
        return []
    base = ".".join(parts[:3])
    alive = []
    for i in range(start, min(end + 1, 256)):
        ip = "%s.%d" % (base, i)
        if ping_one(ip):
            alive.append(ip)
    return alive

def ping_latency(ip, count=4):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        out = subprocess.run(["ping", param, str(count), ip], capture_output=True, text=True, timeout=count * 3).stdout
        ms = re.findall(r"(?:temps?|time)=?\s*(\d+)\s*ms?", out, re.I)
        return [int(m) for m in ms]
    except Exception:
        return []

# ========== NETWORK INFO ==========
def get_hostname():
    return socket.gethostname()

def get_gateway_windows():
    try:
        out = subprocess.check_output(["ipconfig"], shell=False, text=True, encoding="utf-8", errors="replace")
        m = re.search(r"Default Gateway[^\d]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", out, re.I)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    return None

def get_dns_servers_windows():
    try:
        out = subprocess.check_output(["ipconfig", "/all"], shell=False, text=True, encoding="utf-8", errors="replace")
        servers = re.findall(r"DNS Servers[^\d]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", out, re.I)
        servers += re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*\(Preferred\)", out, re.I)
        return list(dict.fromkeys(servers))
    except Exception:
        return []

# ========== TRACEROUTE ==========
def traceroute(host, max_hops=30):
    cmd = ["tracert", "-h", str(max_hops), host] if platform.system().lower() == "windows" else ["traceroute", "-m", str(max_hops), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return out.stdout.splitlines() if out.stdout else []
    except Exception as e:
        return [str(e)]

# ========== WHOIS ==========
def whois_lookup(domain_or_ip):
    if shutil.which("whois"):
        try:
            r = subprocess.run(["whois", domain_or_ip], capture_output=True, text=True, timeout=15)
            return r.stdout or r.stderr or "No output"
        except Exception as e:
            return str(e)
    return "whois not installed (optional)."

# ========== HTTP HEADERS ==========
def get_headers(url, timeout=10):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "SecurityNetwork/1.0")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return dict(r.headers)
    except Exception as e:
        return {"Error": str(e)}

def check_security_headers(url):
    headers = get_headers(url)
    if "Error" in headers:
        return [headers["Error"]]
    important = ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "X-XSS-Protection"]
    results = []
    for h in important:
        for k, v in headers.items():
            if k.lower() == h.lower():
                results.append("[OK] %s: %s" % (k, v))
                break
        else:
            results.append("[--] Missing: %s" % h)
    return results

# ========== SUBNET ==========
def subnet_info(cidr):
    try:
        import ipaddress
        net = ipaddress.ip_network(cidr, strict=False)
        return {
            "network": str(net.network_address),
            "netmask": str(net.netmask),
            "broadcast": str(net.broadcast_address),
            "hosts_count": net.num_addresses - 2,
            "first_host": str(list(net.hosts())[0]) if net.num_addresses > 2 else "N/A",
            "last_host": str(list(net.hosts())[-1]) if net.num_addresses > 2 else "N/A",
        }
    except Exception as e:
        return {"error": str(e)}

# ========== CONNECTIONS (netstat) ==========
def get_connections_windows():
    try:
        out = subprocess.check_output(["netstat", "-an"], shell=False, text=True, encoding="utf-8", errors="replace")
        lines = []
        for line in out.splitlines():
            if "ESTABLISHED" in line or "LISTENING" in line:
                parts = line.split()
                if len(parts) >= 4:
                    lines.append((parts[0], parts[1], parts[2], parts[3] if len(parts) > 3 else ""))
        return lines
    except Exception as e:
        return [(str(e), "", "", "")]

# ========== MAC VENDOR API ==========
def mac_vendor_api(mac):
    mac_clean = mac.replace(":", "").replace("-", "").upper()[:6]
    try:
        url = "https://api.macvendors.com/%s" % mac_clean
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        return "Unknown"

# ========== EXTRA TOOLS (bzaaf dyal l7wyj) ==========
def wake_on_lan(mac):
    """Send Wake-on-LAN magic packet."""
    mac_clean = mac.replace(":", "").replace("-", "").upper()
    if len(mac_clean) != 12:
        return "Invalid MAC"
    data = bytes.fromhex("FF" * 6 + mac_clean * 16)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(data, ("255.255.255.255", 9))
        sock.close()
        return "Magic packet sent to %s" % mac
    except Exception as e:
        return str(e)

def http_status(url):
    """Check if site is up and return status code."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return "UP - Status: %s" % r.status
    except urllib.error.HTTPError as e:
        return "HTTP %s" % e.code
    except Exception as e:
        return "DOWN - %s" % e

def ssl_cert_info(host, port=443):
    """SSL certificate expiry."""
    try:
        hostname = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                from datetime import datetime
                not_after = cert["notAfter"]
                return "Valid until: %s" % not_after
    except Exception as e:
        return str(e)

def ip_geolocation(ip):
    """IP geolocation (free API)."""
    try:
        url = "http://ip-api.com/json/%s?fields=country,regionName,city,isp,org,lat,lon" % ip
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read().decode())
            return " | ".join("%s: %s" % (k, v) for k, v in d.items() if v)
    except Exception as e:
        return str(e)

def flush_dns():
    """Flush DNS cache (Windows: ipconfig /flushdns)."""
    try:
        if platform.system().lower() == "windows":
            out = subprocess.check_output(["ipconfig", "/flushdns"], shell=False, text=True, encoding="utf-8", errors="replace")
            return "DNS cache flushed.\n" + out[:500]
        return "Run manually: ipconfig /flushdns (Windows)"
    except Exception as e:
        return str(e)

def network_interfaces():
    """List network interfaces (ipconfig)."""
    try:
        out = subprocess.check_output(["ipconfig", "/all"], shell=False, text=True, encoding="utf-8", errors="replace")
        return out[:3000]
    except Exception as e:
        return str(e)

def url_encode(s):
    return urllib.parse.quote(s, safe="")

def url_decode(s):
    return urllib.parse.unquote(s)

def hash_string(s, algo="sha256"):
    h = hashlib.new(algo)
    h.update(s.encode("utf-8", errors="replace"))
    return h.hexdigest()

def random_password(length=16, with_special=True):
    chars = string.ascii_letters + string.digits
    if with_special:
        chars += "!@#$%&*"
    return "".join(random.SystemRandom().choice(chars) for _ in range(length))

def wifi_networks_list():
    """List WiFi networks (netsh wlan show networks)."""
    try:
        out = subprocess.check_output(["netsh", "wlan", "show", "networks"], shell=False, text=True, encoding="utf-8", errors="replace")
        return out
    except Exception as e:
        return str(e)

# ========== WiFi Analyzer (b7al WiFi Scanner app) ==========
def wifi_analyzer_networks():
    """Access point discovery: SSID, BSSID, Signal %, Channel, Security (netsh mode=bssid)."""
    if platform.system().lower() != "windows":
        return []
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            shell=False, text=True, encoding="utf-8", errors="replace"
        )
    except Exception:
        return []
    networks = []
    current = None
    for line in out.splitlines():
        line_strip = line.strip()
        if line_strip.startswith("SSID ") and ":" in line_strip:
            if current and current.get("ssid") is not None:
                networks.append(dict(current))
            ssid = line_strip.split(":", 1)[-1].strip()
            current = {"ssid": ssid, "bssid": "", "signal": 0, "channel": 0, "auth": "", "encryption": ""}
        elif current is None:
            continue
        elif line_strip.startswith("BSSID ") and ":" in line_strip:
            if current.get("bssid"):
                networks.append(dict(current))
            current["bssid"] = line_strip.split(":", 1)[-1].strip()
            current["signal"] = 0
            current["channel"] = 0
        elif "Signal" in line_strip and ":" in line_strip:
            try:
                val = line_strip.split(":", 1)[-1].strip().replace("%", "").strip()
                current["signal"] = int(val)
            except ValueError:
                pass
        elif line_strip.startswith("Channel") and ":" in line_strip:
            try:
                current["channel"] = int(line_strip.split(":", 1)[-1].strip())
            except ValueError:
                pass
        elif "Authentication" in line_strip and ":" in line_strip:
            current["auth"] = line_strip.split(":", 1)[-1].strip()
        elif "Encryption" in line_strip and ":" in line_strip:
            current["encryption"] = line_strip.split(":", 1)[-1].strip()
    if current and current.get("ssid") is not None:
        networks.append(current)
    return networks

def signal_bars(pct, width=10):
    """Signal strength as bars: |||||||--- 80%"""
    if pct is None or pct < 0:
        pct = 0
    if pct > 100:
        pct = 100
    filled = int(round(width * pct / 100))
    return "|" * filled + "-" * (width - filled) + " %s%%" % pct

def speed_test(download_url=None, size_mb=1):
    """Speed test: download file, return Mbps."""
    if download_url is None:
        download_url = "https://speed.hetzner.de/1MB.bin"
    try:
        req = urllib.request.Request(download_url, headers={"User-Agent": "SecurityNetwork"})
        start = time.time()
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
        elapsed = time.time() - start
        if elapsed <= 0:
            return 0, 0, "Too fast to measure"
        size_mb_actual = len(data) / (1024 * 1024)
        mbps = (len(data) * 8 / 1_000_000) / elapsed
        return round(mbps, 2), round(elapsed, 2), "%.2f MB in %.2f s" % (size_mb_actual, elapsed)
    except Exception as e:
        return 0, 0, str(e)

def wifi_channel_analysis(networks=None):
    """Channel finding: which channels used, suggest best (least crowded)."""
    if networks is None:
        networks = wifi_analyzer_networks()
    channels = {}
    for n in networks:
        ch = n.get("channel") or 0
        if ch > 0:
            channels[ch] = channels.get(ch, 0) + 1
    if not channels:
        return "No channel data (run WiFi Analyzer first or netsh wlan show networks mode=bssid)"
    used = sorted(channels.items(), key=lambda x: -x[1])
    best = min(channels.keys(), key=lambda c: channels[c])
    lines = ["Channels in use: %s" % dict(channels), "Most crowded: %s" % [c for c, _ in used[:3]], "Suggested (least crowded): Channel %s" % best]
    return "\n".join(lines)

def signal_pct_to_dbm(pct):
    """Approximate: 100%% = -50 dBm, 0%% = -100 dBm."""
    if pct is None or pct < 0:
        pct = 0
    if pct > 100:
        pct = 100
    return -50 - (100 - pct) * 0.5  # -50 to -100 dBm

def channel_to_band(ch):
    """Channel to band: 1-14 = 2.4 GHz, 15-165 = 5 GHz, else 6 GHz."""
    if not ch or ch <= 0:
        return "—"
    if ch <= 14:
        return "2.4 GHz"
    if ch <= 165:
        return "5 GHz"
    return "6 GHz"

def get_wifi_adapter_name():
    """Adapter name like 'Intel WiFi 6E' (netsh wlan show interfaces)."""
    if platform.system().lower() != "windows":
        return "WiFi"
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            shell=False, text=True, encoding="utf-8", errors="replace"
        )
        for line in out.splitlines():
            if "Description" in line and ":" in line:
                return line.split(":", 1)[-1].strip() or "WiFi"
    except Exception:
        pass
    return "WiFi"

def wifi_scanner_full_view():
    """Full view like WIFI Scanner app: top bar, sidebar stats, table, spectrum."""
    networks = wifi_analyzer_networks()
    adapter = get_wifi_adapter_name()
    if not networks:
        _print("No networks found. (Windows: netsh wlan show networks mode=bssid)")
        return
    # Stats (sidebar-like)
    bands = set()
    ssids = set()
    vendors = set()
    securities = set()
    signal_levels = set()
    for n in networks:
        ch = n.get("channel") or 0
        bands.add(channel_to_band(ch))
        ssids.add((n.get("ssid") or "").strip())
        bssid = n.get("bssid") or ""
        if bssid:
            v = get_mac_vendor(bssid)
            if v != "Unknown":
                vendors.add(v)
        sec = (n.get("auth") or "").strip()
        if sec:
            securities.add(sec)
        sig = n.get("signal") or 0
        if sig > 0:
            signal_levels.add("-%d" % int(signal_pct_to_dbm(sig)))
    # Channel usage for spectrum
    ch_usage = {}
    for n in networks:
        ch = n.get("channel") or 0
        if ch > 0:
            ch_usage[ch] = ch_usage.get(ch, 0) + 1
    max_count = max(ch_usage.values()) if ch_usage else 1
    if RICH:
        from rich.panel import Panel as RichPanel
        from rich.layout import Layout
        from rich.text import Text
        # Top bar
        top = Text()
        top.append("WIFI Scanner", style="bold cyan")
        top.append("  |  ", style="dim")
        top.append("Showing data from %s" % adapter, style="white")
        top.append("  |  ", style="dim")
        top.append("Scanner", style="green")
        console.print(RichPanel(top, border_style="blue", padding=(0, 1)))
        # Sidebar stats
        stats_text = "[bold]Band:[/bold] %d  [bold]SSID:[/bold] %d  [bold]BSSID:[/bold] %d  [bold]Vendor:[/bold] %d  [bold]Security:[/bold] %d  [bold]Signal:[/bold] %d" % (
            len(bands), len(ssids), len(networks), len(vendors), len(securities), len(signal_levels))
        console.print(RichPanel(stats_text, title="[bold] Filters [/bold]", border_style="green", padding=(0, 1)))
        # Main table: SSID, BSSID, Vendor, Channel, Band, Signal (dBm), Security
        table = Table(title="Showing %d of %d" % (min(50, len(networks)), len(networks)), show_lines=False)
        table.add_column("SSID", style="cyan")
        table.add_column("BSSID", style="dim")
        table.add_column("Vendor", style="yellow")
        table.add_column("Channel", style="white")
        table.add_column("Band", style="green")
        table.add_column("Signal", style="red")
        table.add_column("Security", style="white")
        for n in networks[:50]:
            ssid = (n.get("ssid") or "")[:22]
            bssid = (n.get("bssid") or "")[:17]
            vendor = (get_mac_vendor(n.get("bssid") or "") or "—")[:18]
            ch = n.get("channel") or 0
            band = channel_to_band(ch)
            sig_pct = n.get("signal") or 0
            dbm = int(signal_pct_to_dbm(sig_pct))
            sec = (n.get("auth") or "—")[:16]
            table.add_row(ssid, bssid, vendor, str(ch) if ch else "—", band, "%d dBm" % dbm, sec)
        console.print(table)
        # Spectrum (ASCII bar chart)
        if ch_usage:
            spec_lines = ["[bold]Spectrum - Channel usage[/bold]"]
            for ch in sorted(ch_usage.keys()):
                cnt = ch_usage[ch]
                bar_len = max(1, int(20 * cnt / max_count))
                bar = "[" + "#" * bar_len + "]" + " Ch %s (%d)" % (ch, cnt)
                spec_lines.append(bar)
            console.print(RichPanel("\n".join(spec_lines), title="[bold] Spectrum [/bold]", border_style="blue", padding=(0, 1)))
        _print("- %s | i7rafiya" % APP_NAME)
    else:
        sep = "=" * 70
        _print(sep)
        _print("WIFI Scanner  |  Showing data from %s  |  Scanner" % adapter)
        _print(sep)
        _print("Band: %d  SSID: %d  BSSID: %d  Vendor: %d  Security: %d  Signal: %d" % (len(bands), len(ssids), len(networks), len(vendors), len(securities), len(signal_levels)))
        _print("-" * 70)
        _print("%-22s %-18s %-12s %-6s %-8s %-8s %s" % ("SSID", "BSSID", "Vendor", "Ch", "Band", "Signal", "Security"))
        _print("-" * 70)
        for n in networks[:50]:
            _print("%-22s %-18s %-12s %-6s %-8s %-8s %s" % (
                (n.get("ssid") or "")[:22],
                (n.get("bssid") or "")[:17],
                (get_mac_vendor(n.get("bssid") or "") or "—")[:12],
                n.get("channel") or "—",
                channel_to_band(n.get("channel")),
                "%d dBm" % int(signal_pct_to_dbm(n.get("signal") or 0)),
                (n.get("auth") or "—")[:16],
            ))
        _print("-" * 70)
        _print("Showing %d of %d" % (min(50, len(networks)), len(networks)))
        if ch_usage:
            _print("\nSpectrum - Channel usage:")
            for ch in sorted(ch_usage.keys()):
                cnt = ch_usage[ch]
                bar_len = max(1, int(20 * cnt / max_count))
                _print("  Ch %3s [%s] %d" % (ch, "#" * bar_len, cnt))
        _print(sep)
        _print("- %s | i7rafiya" % APP_NAME)

def ip_to_decimal(ip):
    """Convert IP to decimal."""
    try:
        parts = [int(x) for x in ip.split(".")]
        return sum(parts[i] << (24 - 8 * i) for i in range(4))
    except Exception:
        return "Invalid IP"

def decimal_to_ip(n):
    """Convert decimal to IP."""
    try:
        n = int(n)
        return "%d.%d.%d.%d" % ((n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255)
    except Exception:
        return "Invalid number"

def base64_encode(s):
    return base64.b64encode(s.encode("utf-8", errors="replace")).decode("ascii")

def base64_decode(s):
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except Exception as e:
        return str(e)

def get_all_http_headers(url):
    """Fetch all HTTP headers."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return "\n".join("%s: %s" % (k, v) for k, v in r.headers.items())
    except Exception as e:
        return str(e)

def ping_stats(host, count=10):
    """Ping statistics: min, max, avg, jitter."""
    times = ping_latency(host, count=count)
    if not times:
        return "Host unreachable"
    mn, mx = min(times), max(times)
    avg = sum(times) / len(times)
    jitter = (sum(abs(times[i] - times[i - 1]) for i in range(1, len(times))) / (len(times) - 1)) if len(times) > 1 else 0
    return "Min: %d ms | Max: %d ms | Avg: %.1f ms | Jitter: %.1f ms" % (mn, mx, avg, jitter)

def system_info():
    """OS and basic system info."""
    info = [
        "OS: %s" % platform.system(),
        "Release: %s" % platform.release(),
        "Machine: %s" % platform.machine(),
        "Hostname: %s" % get_hostname(),
        "Python: %s" % platform.python_version(),
    ]
    return "\n".join(info)

def hosts_file_content():
    """Read hosts file."""
    path = r"C:\Windows\System32\drivers\etc\hosts" if platform.system().lower() == "windows" else "/etc/hosts"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        return str(e)

def port_to_process_windows(port):
    """Which process uses this port (netstat -ano)."""
    try:
        out = subprocess.check_output(["netstat", "-ano"], shell=False, text=True, encoding="utf-8", errors="replace")
        pid = None
        for line in out.splitlines():
            if ":%s " % port in line or ":%s\t" % port in line:
                parts = line.split()
                if len(parts) >= 5 and parts[-1].isdigit():
                    pid = parts[-1]
                    break
        if not pid:
            return "No process found on port %s" % port
        # tasklist /FI "PID eq X"
        out2 = subprocess.check_output(["tasklist", "/FI", "PID eq %s" % pid, "/FO", "CSV"], shell=False, text=True, encoding="utf-8", errors="replace")
        return "Port %s -> PID %s\n%s" % (port, pid, out2[:500])
    except Exception as e:
        return str(e)

def hex_to_bin(hex_s):
    try:
        n = int(hex_s.replace("0x", ""), 16)
        return bin(n)
    except Exception:
        return "Invalid hex"

def bin_to_hex(bin_s):
    try:
        n = int(bin_s.replace("0b", ""), 2)
        return hex(n)
    except Exception:
        return "Invalid binary"

def my_public_ip():
    """Get public IP."""
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read().decode().strip()
    except Exception as e:
        return str(e)

def renew_dhcp():
    """Renew DHCP (ipconfig /renew)."""
    try:
        if platform.system().lower() == "windows":
            out = subprocess.check_output(["ipconfig", "/renew"], shell=False, text=True, encoding="utf-8", errors="replace")
            return out[:800]
        return "Run: ipconfig /renew (Windows)"
    except Exception as e:
        return str(e)

def local_listening_ports():
    """Ports in LISTENING state on this machine."""
    try:
        out = subprocess.check_output(["netstat", "-an"], shell=False, text=True, encoding="utf-8", errors="replace")
        lines = []
        for line in out.splitlines():
            if "LISTENING" in line:
                parts = line.split()
                if len(parts) >= 2:
                    lines.append(parts[1])
        return "\n".join(sorted(set(lines))[:50])
    except Exception as e:
        return str(e)

# ========== MORE TOOLS (bzaaaaaaf) ==========
def file_checksum(path, algo="sha256"):
    """MD5 or SHA256 of file."""
    try:
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return str(e)

def password_strength(pwd):
    """Simple password strength: length, upper, lower, digit, special."""
    if not pwd:
        return "Empty"
    score = 0
    if len(pwd) >= 8:
        score += 1
    if len(pwd) >= 12:
        score += 1
    if any(c.isupper() for c in pwd):
        score += 1
    if any(c.islower() for c in pwd):
        score += 1
    if any(c.isdigit() for c in pwd):
        score += 1
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd):
        score += 1
    labels = ["Very weak", "Weak", "Fair", "Good", "Strong", "Very strong", "Excellent"]
    return labels[min(score, 6)]

def uuid_generate():
    import uuid
    return str(uuid.uuid4())

def timestamp_to_date(ts):
    """Unix timestamp to readable date."""
    try:
        from datetime import datetime
        return datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "Invalid"

def date_to_timestamp(s):
    """Parse date string to unix timestamp (basic)."""
    try:
        from datetime import datetime
        dt = datetime.now()
        return int(dt.timestamp())
    except Exception:
        return "Invalid"

def json_validate(s):
    """Validate JSON string."""
    try:
        json.loads(s)
        return "Valid JSON"
    except json.JSONDecodeError as e:
        return "Invalid: %s" % e

def url_expand(url):
    """Expand short URL (follow redirect, return final URL)."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "SecurityNetwork"})
        req.add_header("Accept", "*/*")
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.geturl()
    except Exception as e:
        return str(e)

def wifi_saved_profiles():
    """List saved WiFi profiles (netsh wlan show profiles)."""
    if platform.system().lower() != "windows":
        return "Windows only"
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "profiles"],
            shell=False, text=True, encoding="utf-8", errors="replace"
        )
        return out[:2000]
    except Exception as e:
        return str(e)

def connection_state_summary():
    """Netstat: count by state (ESTABLISHED, LISTENING, etc.)."""
    try:
        out = subprocess.check_output(["netstat", "-an"], shell=False, text=True, encoding="utf-8", errors="replace")
        counts = {}
        for line in out.splitlines():
            for state in ["ESTABLISHED", "LISTENING", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT"]:
                if state in line:
                    counts[state] = counts.get(state, 0) + 1
                    break
        return "\n".join("%s: %d" % (k, v) for k, v in sorted(counts.items(), key=lambda x: -x[1]))
    except Exception as e:
        return str(e)

def bytes_to_units(n):
    """Convert bytes to KB, MB, GB."""
    try:
        n = int(n)
        if n < 1024:
            return "%d B" % n
        if n < 1024 * 1024:
            return "%.2f KB" % (n / 1024)
        if n < 1024 * 1024 * 1024:
            return "%.2f MB" % (n / (1024 * 1024))
        return "%.2f GB" % (n / (1024 * 1024 * 1024))
    except Exception:
        return "Invalid"

def hex_encode(s):
    return s.encode("utf-8", errors="replace").hex()

def hex_decode(s):
    try:
        return bytes.fromhex(s.replace(" ", "")).decode("utf-8", errors="replace")
    except Exception as e:
        return str(e)

def random_ip():
    """Random private IP (10.x, 172.16-31.x, 192.168.x)."""
    import random as r
    kind = r.choice([1, 2, 3])
    if kind == 1:
        return "10.%d.%d.%d" % (r.randint(0, 255), r.randint(0, 255), r.randint(0, 255))
    if kind == 2:
        return "172.%d.%d.%d" % (r.randint(16, 31), r.randint(0, 255), r.randint(0, 255))
    return "192.168.%d.%d" % (r.randint(0, 255), r.randint(1, 254))

def user_agent_string():
    """Common User-Agent string."""
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def port_range_scan(ip, start, end, timeout=0.5):
    """Scan port range (start-end)."""
    open_ports = scan_ports(ip, ports=list(range(start, end + 1)), timeout=timeout)
    return open_ports

def netstat_summary():
    """Summary: ESTABLISHED count, LISTENING count."""
    try:
        out = subprocess.check_output(["netstat", "-an"], shell=False, text=True, encoding="utf-8", errors="replace")
        established = sum(1 for line in out.splitlines() if "ESTABLISHED" in line)
        listening = sum(1 for line in out.splitlines() if "LISTENING" in line)
        return "ESTABLISHED: %d  |  LISTENING: %d" % (established, listening)
    except Exception as e:
        return str(e)

# ========== ADAWAT SECURITY NETWORK (tools lighadi n7tajhom) ==========
def route_table():
    """Route table (route print on Windows)."""
    if platform.system().lower() != "windows":
        return "Windows: route print"
    try:
        out = subprocess.check_output(["route", "print"], shell=False, text=True, encoding="utf-8", errors="replace")
        return out[:4000]
    except Exception as e:
        return str(e)

def arp_table_full():
    """Full ARP table (arp -a)."""
    return get_arp_table_windows()

def firewall_status():
    """Windows firewall status (netsh advfirewall)."""
    if platform.system().lower() != "windows":
        return "Windows only"
    try:
        out = subprocess.check_output(
            ["netsh", "advfirewall", "show", "currentprofile"],
            shell=False, text=True, encoding="utf-8", errors="replace"
        )
        return out[:1500]
    except Exception as e:
        return str(e)

def ping_packet_loss(host, count=10):
    """Ping with packet loss %%."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        out = subprocess.run(
            ["ping", param, str(count), host],
            capture_output=True, text=True, timeout=count * 2 + 5
        ).stdout or ""
        # Windows: "Packets: Sent = 10, Received = 9, Lost = 1 (10%% loss)"
        m = re.search(r"Lost\s*=\s*(\d+)\s*\((\d+)\s*%", out, re.I)
        if m:
            return "Packet loss: %s%% (%s lost)" % (m.group(2), m.group(1))
        m = re.search(r"(\d+)%\s*loss", out, re.I)
        if m:
            return "Packet loss: %s%%" % m.group(1)
        return out[-500:] if len(out) > 500 else out
    except Exception as e:
        return str(e)

def tcp_connect_test(host, port, timeout=3):
    """Test TCP connection to host:port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, int(port)))
        s.close()
        return "OK - %s:%s reachable" % (host, port)
    except Exception as e:
        return "FAIL - %s" % e

def cidr_to_range(cidr):
    """CIDR to first and last IP."""
    try:
        import ipaddress
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        if not hosts:
            return "No hosts (e.g. /32)"
        return "First: %s  |  Last: %s  |  Count: %d" % (hosts[0], hosts[-1], len(hosts))
    except Exception as e:
        return str(e)

def http_method_test(url, method="GET"):
    """Test HTTP method (GET, POST, HEAD)."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        req = urllib.request.Request(url, method=method.upper(), headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return "%s - Status: %s" % (method.upper(), r.status)
    except urllib.error.HTTPError as e:
        return "%s - Status: %s" % (method.upper(), e.code)
    except Exception as e:
        return "%s - %s" % (method.upper(), e)

def export_wifi_scan_to_file(path=None):
    """Export WiFi scan (networks) to text file."""
    networks = wifi_analyzer_networks()
    if path is None:
        path = "wifi_scan_export.txt"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("Security Network - WiFi Scan Export\n")
            f.write("SSID | BSSID | Channel | Signal | Security\n")
            f.write("-" * 60 + "\n")
            for n in networks:
                f.write("%s | %s | %s | %s | %s\n" % (
                    n.get("ssid", ""), n.get("bssid", ""), n.get("channel", ""),
                    n.get("signal", ""), n.get("auth", "")
                ))
        return "Exported %d networks to %s" % (len(networks), path)
    except Exception as e:
        return str(e)

def export_devices_to_file(path=None):
    """Export devices (IP, MAC) to text file."""
    devices = get_connected_devices()
    if path is None:
        path = "devices_export.txt"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("Security Network - Devices Export\n")
            f.write("IP | MAC | Vendor\n")
            f.write("-" * 50 + "\n")
            for ip, mac in devices:
                f.write("%s | %s | %s\n" % (ip, mac, get_mac_vendor(mac)))
        return "Exported %d devices to %s" % (len(devices), path)
    except Exception as e:
        return str(e)

def dns_servers_in_use():
    """DNS servers currently in use (ipconfig)."""
    dns = get_dns_servers_windows()
    if not dns:
        return "No DNS servers found (ipconfig /all)"
    return "DNS in use: " + ", ".join(dns)

# ========== UI helpers ==========
def _print(*a, **k):
    if RICH:
        console.print(*a, **k)
    else:
        print(*a, **k)

def _prompt(msg, default=None):
    if RICH:
        return Prompt.ask(msg, default=default)
    return input(msg + (" [%s] " % default if default else " ")).strip() or default

def _int_prompt(msg, default=60):
    if RICH:
        return IntPrompt.ask(msg, default=default)
    s = input(msg + " [%s] " % default).strip() or str(default)
    try:
        return int(s)
    except ValueError:
        return default

def menu():
    return """
[%s]  v%s  |  %s
--- Dashboard ---
H.  Dashboard (7stat) - Stats like PC application
--- WiFi Analyzer (signal, channel, speed) ---
W.  WiFi Analyzer - AP discovery, signal strength, channel
S.  Speed test - Download speed (Mbps)
C.  Channel finder - Best channel (least crowded)
--- WiFi & Network ---
""" % (APP_NAME, APP_VERSION, APP_TAGLINE) + """
1.  Chkon m3ak f WiFi - Scan connected devices
2.  ARP Guard - Detect who is trying to kick you
3.  Port Scanner
4.  Ping Sweep
5.  DNS Lookup / Reverse DNS
6.  My Network Info
7.  Traceroute
8.  My Public IP
9.  WiFi networks list (netsh)
10. Flush DNS cache
11. Renew DHCP
--- Scan & Security ---
12. HTTP Status - Is site up?
13. HTTP Security Headers
14. All HTTP Headers
15. SSL Certificate expiry
16. Whois
17. Active Connections (netstat)
18. Local listening ports
19. Who uses this port? (process)
--- Calculators & Convert ---
20. Subnet Calculator (CIDR)
21. IP to Decimal / Decimal to IP
22. Hex to Binary / Binary to Hex
23. URL Encode / Decode
24. Base64 Encode / Decode
--- Hash & Password ---
25. Hash (MD5, SHA256)
26. Random password generator
--- Tools ---
27. MAC Vendor Lookup
28. Ping One Host
29. Ping statistics (jitter)
30. IP Geolocation
31. Wake-on-LAN (magic packet)
32. Subnet full scan + devices
33. System info
34. Hosts file viewer
--- More Tools (bzaaaaaaf) ---
35. File checksum (MD5/SHA256)
36. Password strength checker
37. UUID generator
38. Timestamp to date
39. URL expand (unshorten)
40. WiFi saved profiles list
41. Connection state summary (netstat)
42. Bytes to units converter
43. Hex encode / decode
44. Random IP generator
45. User-Agent string
46. Port range scanner
47. Netstat summary (EST/LISTEN)
48. JSON validator
--- Adawat Security Network (tools n7tajhom) ---
49. Route table
50. ARP table (full)
51. Firewall status (Windows)
52. Ping with packet loss %%
53. TCP connection test (host:port)
54. CIDR to IP range
55. HTTP method test (GET/POST/HEAD)
56. Export WiFi scan to file
57. Export devices to file
58. DNS servers in use
59. Network interfaces (ipconfig)
0.  Exit
---
%s  |  Application PC i7rafiya | 7stat
""" % APP_NAME

# ========== RUNNERS ==========
def run_wifi_scan():
    _print("Scanning devices on your WiFi...")
    my_ip = get_my_ip()
    _print("Your IP: %s" % my_ip)
    _print("Pinging subnet to discover devices...")
    devices = scan_subnet_arp(my_ip)
    if not devices:
        devices = get_connected_devices()
    if RICH:
        table = Table(title="Devices on your network")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="yellow")
        table.add_column("Vendor", style="green")
        for ip, mac in devices:
            table.add_row(ip, mac, get_mac_vendor(mac))
        _print(table)
    else:
        _print("IP\t\tMAC\t\tVendor")
        for ip, mac in devices:
            _print("%s\t%s\t%s" % (ip, mac, get_mac_vendor(mac)))
    _print("Total: %d devices" % len(devices))

def run_arp_guard():
    _print("ARP Guard - Detects spoofing/kick attempt")
    sec = _int_prompt("Monitor for how many seconds?", 60)
    _print("Monitoring for %d seconds..." % sec)
    alerts = []
    def on_alert(msg):
        alerts.append(msg)
        _print(msg)
    monitor_arp_changes(duration_seconds=sec, on_change_callback=on_alert)
    _print("No ARP changes detected." if not alerts else "%d alert(s)." % len(alerts))

def run_port_scan():
    ip = _prompt("IP or hostname to scan")
    if ip and not ip.replace(".", "").replace(":", "").replace("-", "").isdigit():
        ips = dns_lookup(ip)
        if ips:
            ip = ips[0]
    _print("Scanning common ports on %s..." % ip)
    open_ports = scan_ports(ip, ports=list(COMMON_PORTS.keys()))
    if RICH:
        table = Table(title="Open ports on %s" % ip)
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="green")
        for p in open_ports:
            table.add_row(str(p), COMMON_PORTS.get(p, "?"))
        _print(table)
    else:
        for p in open_ports:
            _print("%s\t%s" % (p, COMMON_PORTS.get(p, "?")))

def run_ping_sweep():
    my_ip = get_my_ip()
    base = ".".join(my_ip.split(".")[:3]) + ".0"
    base = _prompt("Subnet base (e.g. 192.168.1)", base)
    if base and not base.endswith(".0") and len(base.split(".")) == 3:
        base = base + ".0"
    _print("Ping sweep %s.1-255 ..." % base.replace(".0", ""))
    alive = ping_sweep(base)
    for ip in sorted(alive, key=lambda x: [int(i) for i in x.split(".")]):
        _print("  %s" % ip)
    _print("Total alive: %d" % len(alive))

def run_dns():
    host = _prompt("Hostname to resolve")
    if host:
        _print("%s -> %s" % (host, dns_lookup(host)))

def run_reverse_dns():
    ip = _prompt("IP for reverse DNS")
    if ip:
        _print("%s -> %s" % (ip, reverse_dns(ip)))

def run_network_info():
    ip = get_my_ip()
    hostname = get_hostname()
    gw = get_gateway_windows()
    dns = get_dns_servers_windows()
    _print("Hostname: %s\nYour IP: %s\nGateway: %s\nDNS: %s" % (hostname, ip, gw or "N/A", ", ".join(dns) if dns else "N/A"))

def run_traceroute():
    host = _prompt("Host to trace")
    if host:
        _print("Traceroute to %s..." % host)
        for line in traceroute(host):
            _print(line)

def run_whois():
    target = _prompt("Domain or IP for whois")
    if target:
        _print(whois_lookup(target))

def run_http_headers():
    url = _prompt("URL (e.g. https://example.com)")
    if url:
        _print("Security headers:")
        for line in check_security_headers(url):
            _print(line)

def run_subnet():
    cidr = _prompt("CIDR (e.g. 192.168.1.0/24)")
    if cidr:
        info = subnet_info(cidr)
        if "error" in info:
            _print(info["error"])
        else:
            for k, v in info.items():
                _print("  %s: %s" % (k, v))

def run_connections():
    _print("Active connections (ESTABLISHED / LISTENING)")
    conns = get_connections_windows()
    if RICH:
        table = Table()
        table.add_column("Proto")
        table.add_column("Local")
        table.add_column("Foreign")
        table.add_column("State")
        for row in conns[:80]:
            table.add_row(*[str(x) for x in row])
        _print(table)
    else:
        for row in conns[:80]:
            _print("\t".join(str(x) for x in row))
    if len(conns) > 80:
        _print("... and %d more" % (len(conns) - 80))

def run_mac_lookup():
    mac = _prompt("MAC address (e.g. AA:BB:CC:DD:EE:FF)")
    if mac:
        _print("%s -> %s" % (mac, mac_vendor_api(mac)))

def run_ping_one():
    host = _prompt("Host to ping")
    if host:
        times = ping_latency(host)
        if times:
            _print("RTT (ms): %s" % times)
            _print("Avg: %.1f ms" % (sum(times) / len(times)))
        else:
            _print("Host unreachable")

def run_dns_or_reverse():
    c = _prompt("1=DNS (hostname->IP) 2=Reverse DNS (IP->name)", "1")
    if c == "2":
        ip = _prompt("IP")
        if ip:
            _print("%s -> %s" % (ip, reverse_dns(ip)))
    else:
        host = _prompt("Hostname")
        if host:
            _print("%s -> %s" % (host, dns_lookup(host)))

def run_public_ip():
    _print("Public IP: %s" % my_public_ip())

def run_wifi_list():
    _print(wifi_networks_list())

def run_wifi_analyzer():
    """WiFi Scanner view: top bar, filters/stats, table (SSID, BSSID, Vendor, Channel, Band, Signal dBm, Security), spectrum."""
    wifi_scanner_full_view()

def run_speed_test():
    """Speed test - download speed in Mbps."""
    _print("Speed test - Measuring download speed...")
    mbps, sec, msg = speed_test()
    _print("Result: %s" % msg)
    _print("Download speed: %s Mbps" % mbps)
    if RICH:
        _print(Panel("[bold green]%s Mbps[/bold green]" % mbps, title="Speed", border_style="green"))

def run_wifi_channels():
    """Channel finder - best channel (least crowded)."""
    _print("Channel finder - Analyzing WiFi channels...")
    networks = wifi_analyzer_networks()
    _print(wifi_channel_analysis(networks))

def run_flush_dns():
    _print(flush_dns())

def run_renew_dhcp():
    _print(renew_dhcp())

def run_http_status():
    url = _prompt("URL or domain")
    if url:
        _print(http_status(url))

def run_all_headers():
    url = _prompt("URL")
    if url:
        _print(get_all_http_headers(url))

def run_ssl_cert():
    host = _prompt("Host (e.g. google.com)")
    if host:
        _print(ssl_cert_info(host))

def run_listening_ports():
    _print("Ports in LISTENING state:")
    _print(local_listening_ports())

def run_port_to_process():
    port = _prompt("Port number")
    if port and port.isdigit():
        _print(port_to_process_windows(port))

def run_ip_decimal():
    c = _prompt("1=IP to Decimal 2=Decimal to IP", "1")
    if c == "2":
        n = _prompt("Decimal number")
        if n:
            _print(decimal_to_ip(n))
    else:
        ip = _prompt("IP address")
        if ip:
            _print(ip_to_decimal(ip))

def run_hex_bin():
    c = _prompt("1=Hex to Binary 2=Binary to Hex", "1")
    if c == "2":
        s = _prompt("Binary (e.g. 0b1010)")
        if s:
            _print(bin_to_hex(s))
    else:
        s = _prompt("Hex (e.g. 0xFF)")
        if s:
            _print(hex_to_bin(s))

def run_url_encode_decode():
    c = _prompt("1=Encode 2=Decode", "1")
    s = _prompt("String")
    if s:
        _print(url_decode(s) if c == "2" else url_encode(s))

def run_base64():
    c = _prompt("1=Encode 2=Decode", "1")
    s = _prompt("String")
    if s:
        _print(base64_decode(s) if c == "2" else base64_encode(s))

def run_hash_tool():
    s = _prompt("String to hash")
    if s:
        algo = _prompt("Algorithm (md5, sha1, sha256)", "sha256")
        _print(hash_string(s, algo.lower()))

def run_random_pass():
    length = _int_prompt("Length", 16)
    p = random_password(length)
    _print("Password: %s" % p)

def run_ping_stats():
    host = _prompt("Host to ping")
    if host:
        _print(ping_stats(host))

def run_ip_geo():
    ip = _prompt("IP address", get_my_ip())
    if ip:
        _print(ip_geolocation(ip))

def run_wol():
    mac = _prompt("MAC address (e.g. AA:BB:CC:DD:EE:FF)")
    if mac:
        _print(wake_on_lan(mac))

def run_system_info():
    _print(system_info())

def run_hosts_file():
    _print(hosts_file_content())

def run_file_checksum():
    path = _prompt("File path")
    if path and os.path.isfile(path):
        algo = _prompt("Algorithm (md5, sha256)", "sha256")
        _print(file_checksum(path, algo.lower()))
    elif path:
        _print("File not found.")

def run_password_strength():
    pwd = _prompt("Password to check")
    if pwd:
        _print("Strength: %s" % password_strength(pwd))

def run_uuid():
    _print(uuid_generate())

def run_timestamp_to_date():
    ts = _prompt("Unix timestamp")
    if ts and ts.isdigit():
        _print(timestamp_to_date(ts))

def run_url_expand():
    url = _prompt("Short URL")
    if url:
        _print(url_expand(url))

def run_wifi_profiles():
    _print(wifi_saved_profiles())

def run_connection_state_summary():
    _print(connection_state_summary())

def run_bytes_to_units():
    n = _prompt("Bytes (number)")
    if n and n.isdigit():
        _print(bytes_to_units(n))

def run_hex_encode_decode():
    c = _prompt("1=Encode to hex 2=Decode from hex", "1")
    s = _prompt("String")
    if s:
        _print(hex_decode(s) if c == "2" else hex_encode(s))

def run_random_ip():
    _print("Random private IP: %s" % random_ip())

def run_user_agent():
    _print(user_agent_string())

def run_port_range_scan():
    ip = _prompt("IP or hostname")
    if not ip:
        return
    start = _int_prompt("Start port", 1)
    end = _int_prompt("End port", 100)
    if start > end:
        start, end = end, start
    _print("Scanning %s ports %d-%d..." % (ip, start, end))
    open_ports = port_range_scan(ip, start, end)
    _print("Open: %s" % (open_ports if open_ports else "None"))

def run_netstat_summary():
    _print(netstat_summary())

def run_json_validate():
    s = _prompt("JSON string (or paste)")
    if s:
        _print(json_validate(s))

def run_route_table():
    _print(route_table())

def run_arp_table_full():
    _print(arp_table_full())

def run_firewall_status():
    _print(firewall_status())

def run_ping_packet_loss():
    host = _prompt("Host to ping")
    if host:
        count = _int_prompt("Number of pings", 10)
        _print(ping_packet_loss(host, count))

def run_tcp_connect_test():
    host = _prompt("Host or IP")
    if host:
        port = _prompt("Port")
        if port and port.isdigit():
            _print(tcp_connect_test(host, port))

def run_cidr_to_range():
    cidr = _prompt("CIDR (e.g. 192.168.1.0/24)")
    if cidr:
        _print(cidr_to_range(cidr))

def run_http_method_test():
    url = _prompt("URL")
    if url:
        method = _prompt("Method (GET, POST, HEAD)", "GET")
        _print(http_method_test(url, method))

def run_export_wifi_scan():
    path = _prompt("Filename to save", "wifi_scan_export.txt")
    if path:
        _print(export_wifi_scan_to_file(path))

def run_export_devices():
    path = _prompt("Filename to save", "devices_export.txt")
    if path:
        _print(export_devices_to_file(path))

def run_dns_in_use():
    _print(dns_servers_in_use())

def run_network_interfaces():
    _print(network_interfaces())

def main():
    set_window_title()
    show_banner()
    show_dashboard()
    if sys.platform != "win32":
        _print("Best experience on Windows. Some features may differ.")
    while True:
        _print(menu())
        choice = _prompt("Choice", "H")
        if choice:
            choice = choice.strip().upper()
        try:
            if choice == "0":
                _print("Bye!")
                break
            elif choice == "1":
                run_wifi_scan()
            elif choice == "2":
                run_arp_guard()
            elif choice == "3":
                run_port_scan()
            elif choice == "4":
                run_ping_sweep()
            elif choice == "5":
                run_dns_or_reverse()
            elif choice == "6":
                run_network_info()
            elif choice == "7":
                run_traceroute()
            elif choice == "8":
                run_public_ip()
            elif choice == "9":
                run_wifi_list()
            elif choice == "10":
                run_flush_dns()
            elif choice == "11":
                run_renew_dhcp()
            elif choice == "12":
                run_http_status()
            elif choice == "13":
                run_http_headers()
            elif choice == "14":
                run_all_headers()
            elif choice == "15":
                run_ssl_cert()
            elif choice == "16":
                run_whois()
            elif choice == "17":
                run_connections()
            elif choice == "18":
                run_listening_ports()
            elif choice == "19":
                run_port_to_process()
            elif choice == "20":
                run_subnet()
            elif choice == "21":
                run_ip_decimal()
            elif choice == "22":
                run_hex_bin()
            elif choice == "23":
                run_url_encode_decode()
            elif choice == "24":
                run_base64()
            elif choice == "25":
                run_hash_tool()
            elif choice == "26":
                run_random_pass()
            elif choice == "27":
                run_mac_lookup()
            elif choice == "28":
                run_ping_one()
            elif choice == "29":
                run_ping_stats()
            elif choice == "30":
                run_ip_geo()
            elif choice == "31":
                run_wol()
            elif choice == "32":
                run_wifi_scan()
            elif choice == "33":
                run_system_info()
            elif choice == "34":
                run_hosts_file()
            elif choice == "35":
                run_file_checksum()
            elif choice == "36":
                run_password_strength()
            elif choice == "37":
                run_uuid()
            elif choice == "38":
                run_timestamp_to_date()
            elif choice == "39":
                run_url_expand()
            elif choice == "40":
                run_wifi_profiles()
            elif choice == "41":
                run_connection_state_summary()
            elif choice == "42":
                run_bytes_to_units()
            elif choice == "43":
                run_hex_encode_decode()
            elif choice == "44":
                run_random_ip()
            elif choice == "45":
                run_user_agent()
            elif choice == "46":
                run_port_range_scan()
            elif choice == "47":
                run_netstat_summary()
            elif choice == "48":
                run_json_validate()
            elif choice == "49":
                run_route_table()
            elif choice == "50":
                run_arp_table_full()
            elif choice == "51":
                run_firewall_status()
            elif choice == "52":
                run_ping_packet_loss()
            elif choice == "53":
                run_tcp_connect_test()
            elif choice == "54":
                run_cidr_to_range()
            elif choice == "55":
                run_http_method_test()
            elif choice == "56":
                run_export_wifi_scan()
            elif choice == "57":
                run_export_devices()
            elif choice == "58":
                run_dns_in_use()
            elif choice == "59":
                run_network_interfaces()
            elif choice == "H":
                show_dashboard()
            elif choice == "W":
                run_wifi_analyzer()
            elif choice == "S":
                run_speed_test()
            elif choice == "C":
                run_wifi_channels()
            else:
                _print("Invalid choice.")
        except KeyboardInterrupt:
            _print("\nCancelled.")
        except Exception as e:
            _print("Error: %s" % e)
        _prompt("\nPress Enter to continue")

if __name__ == "__main__":
    main()
