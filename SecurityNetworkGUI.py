# -*- coding: utf-8 -*-
# Security Network - GUI Application (WiFi & Network Security)
# Standalone: all tools embedded, no dependency on SecurityNetwork.py
# Run: py -3 SecurityNetworkGUI.py

import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import platform
import subprocess
import re
import socket
import time
import random
import string
import uuid
import shutil
import concurrent.futures
import urllib.request
import urllib.parse
import ssl
import hashlib
import base64
import json
from datetime import datetime
from collections import defaultdict

if sys.version_info[0] < 3:
    print("Python 3 required. Run: py -3 SecurityNetworkGUI.py")
    sys.exit(1)

# ========== Embedded Security Network logic (standalone) ==========
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

def get_wifi_adapter_name():
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

def wifi_analyzer_networks():
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

def signal_pct_to_dbm(pct):
    if pct is None or pct < 0:
        pct = 0
    if pct > 100:
        pct = 100
    return -50 - (100 - pct) * 0.5

def channel_to_band(ch):
    if not ch or ch <= 0:
        return "-"
    if ch <= 14:
        return "2.4 GHz"
    if ch <= 165:
        return "5 GHz"
    return "6 GHz"

def speed_test(download_url=None, size_mb=1):
    if download_url is None:
        download_url = "https://speed.hetzner.de/1MB.bin"
    try:
        import urllib.request
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

def get_dns_servers_windows():
    try:
        out = subprocess.check_output(["ipconfig", "/all"], shell=False, text=True, encoding="utf-8", errors="replace")
        servers = re.findall(r"DNS Servers[^\d]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", out, re.I)
        servers += re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*\(Preferred\)", out, re.I)
        return list(dict.fromkeys(servers))
    except Exception:
        return []

def network_interfaces():
    try:
        out = subprocess.check_output(["ipconfig", "/all"], shell=False, text=True, encoding="utf-8", errors="replace")
        return out[:3000]
    except Exception as e:
        return str(e)

def random_password(length=16, with_special=True):
    chars = string.ascii_letters + string.digits
    if with_special:
        chars += "!@#$%&*"
    return "".join(random.SystemRandom().choice(chars) for _ in range(length))

def password_strength(pwd):
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
    return str(uuid.uuid4())

def wifi_saved_profiles():
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

def random_ip():
    kind = random.choice([1, 2, 3])
    if kind == 1:
        return "10.%d.%d.%d" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
    if kind == 2:
        return "172.%d.%d.%d" % (random.randint(16, 31), random.randint(0, 255), random.randint(0, 255))
    return "192.168.%d.%d" % (random.randint(0, 255), random.randint(1, 254))

def user_agent_string():
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def netstat_summary():
    try:
        out = subprocess.check_output(["netstat", "-an"], shell=False, text=True, encoding="utf-8", errors="replace")
        established = sum(1 for line in out.splitlines() if "ESTABLISHED" in line)
        listening = sum(1 for line in out.splitlines() if "LISTENING" in line)
        return "ESTABLISHED: %d  |  LISTENING: %d" % (established, listening)
    except Exception as e:
        return str(e)

def route_table():
    if platform.system().lower() != "windows":
        return "Windows: route print"
    try:
        out = subprocess.check_output(["route", "print"], shell=False, text=True, encoding="utf-8", errors="replace")
        return out[:4000]
    except Exception as e:
        return str(e)

def arp_table_full():
    return get_arp_table_windows()

def firewall_status():
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

def tcp_connect_test(host, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, int(port)))
        s.close()
        return "OK - %s:%s reachable" % (host, port)
    except Exception as e:
        return "FAIL - %s" % e

# ========== Netcat-style (TCP connect / listen) ==========
def netcat_connect(host, port, send_data=None, timeout=5):
    """Connect to host:port, optionally send data, return received data (like netcat)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, int(port)))
        out = []
        if send_data:
            s.sendall(send_data.encode("utf-8", errors="replace") if isinstance(send_data, str) else send_data)
        try:
            while True:
                buf = s.recv(4096)
                if not buf:
                    break
                out.append(buf.decode("utf-8", errors="replace"))
        except socket.timeout:
            pass
        s.close()
        return "Connected to %s:%s\n\nReceived:\n%s" % (host, port, "".join(out)) if out else "Connected to %s:%s (no data received)" % (host, port)
    except Exception as e:
        return "FAIL - %s" % e

def netcat_listen(port, timeout=30):
    """Listen on port, accept one connection, return received data (like netcat -l)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        s.bind(("0.0.0.0", int(port)))
        s.listen(1)
        conn, addr = s.accept()
        conn.settimeout(5)
        out = []
        try:
            while True:
                buf = conn.recv(4096)
                if not buf:
                    break
                out.append(buf.decode("utf-8", errors="replace"))
        except socket.timeout:
            pass
        conn.close()
        s.close()
        return "Connection from %s:%s\n\nReceived:\n%s" % (addr[0], addr[1], "".join(out)) if out else "Connection from %s:%s (no data)" % (addr[0], addr[1])
    except socket.timeout:
        return "Listen on port %s: timeout (no connection)" % port
    except Exception as e:
        return "FAIL - %s" % e

def cidr_to_range(cidr):
    try:
        import ipaddress
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        if not hosts:
            return "No hosts (e.g. /32)"
        return "First: %s  |  Last: %s  |  Count: %d" % (hosts[0], hosts[-1], len(hosts))
    except Exception as e:
        return str(e)

def export_wifi_scan_to_file(path=None):
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
    dns = get_dns_servers_windows()
    if not dns:
        return "No DNS servers found (ipconfig /all)"
    return "DNS in use: " + ", ".join(dns)

def get_drive_info():
    """Get Windows drive letters and info."""
    if platform.system().lower() != "windows":
        return "Windows only"
    try:
        drives = []
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = "%s:\\" % letter
            if os.path.exists(drive):
                drives.append(drive)
        return "Drives: " + ", ".join(drives) if drives else "No drives found"
    except Exception as e:
        return str(e)

def get_drive_letters_short():
    r"""Drive letters only for header display (e.g. C:\, D:\)."""
    if platform.system().lower() != "windows":
        return ""
    try:
        drives = [letter + ":\\" for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(letter + ":\\")]
        return ", ".join(drives) if drives else ""
    except Exception:
        return ""

def get_hostname():
    return socket.gethostname()

def get_gateway_windows():
    try:
        out = subprocess.check_output(["ipconfig"], shell=False, text=True, encoding="utf-8", errors="replace")
        m = re.search(r"Default Gateway[^\d]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", out, re.I)
        return m.group(1) if m else None
    except Exception:
        return None

def my_public_ip():
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read().decode().strip()
    except Exception as e:
        return "Error: %s" % str(e)

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

def traceroute(host, max_hops=30):
    cmd = ["tracert", "-h", str(max_hops), host] if platform.system().lower() == "windows" else ["traceroute", "-m", str(max_hops), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return out.stdout.splitlines() if out.stdout else []
    except Exception as e:
        return [str(e)]

def whois_lookup(domain_or_ip):
    if shutil.which("whois"):
        try:
            r = subprocess.run(["whois", domain_or_ip], capture_output=True, text=True, timeout=15)
            return r.stdout or r.stderr or "No output"
        except Exception as e:
            return str(e)
    return "whois not installed (optional)."

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

def http_status(url):
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
    try:
        hostname = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert["notAfter"]
                return "Valid until: %s" % not_after
    except Exception as e:
        return str(e)

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

def wake_on_lan(mac):
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

def ip_geolocation(ip):
    try:
        url = "http://ip-api.com/json/%s?fields=country,regionName,city,isp,org,lat,lon" % ip
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read().decode())
            return " | ".join("%s: %s" % (k, v) for k, v in d.items() if v)
    except Exception as e:
        return str(e)

def flush_dns():
    try:
        if platform.system().lower() == "windows":
            out = subprocess.check_output(["ipconfig", "/flushdns"], shell=False, text=True, encoding="utf-8", errors="replace")
            return "DNS cache flushed.\n" + out[:500]
        return "Run manually: ipconfig /flushdns (Windows)"
    except Exception as e:
        return str(e)

def renew_dhcp():
    try:
        if platform.system().lower() == "windows":
            out = subprocess.check_output(["ipconfig", "/renew"], shell=False, text=True, encoding="utf-8", errors="replace")
            return "DHCP renewed.\n" + out[:500]
        return "Run manually: ipconfig /renew (Windows)"
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

def file_checksum(path, algo="sha256"):
    try:
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return str(e)

def base64_encode(s):
    return base64.b64encode(s.encode("utf-8", errors="replace")).decode()

def base64_decode(s):
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except Exception as e:
        return str(e)

def hex_encode(s):
    return s.encode("utf-8", errors="replace").hex()

def hex_decode(s):
    try:
        return bytes.fromhex(s.replace(" ", "")).decode("utf-8", errors="replace")
    except Exception as e:
        return str(e)

def timestamp_to_date(ts):
    try:
        return datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "Invalid"

def url_expand(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "SecurityNetwork"})
        req.add_header("Accept", "*/*")
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.geturl()
    except Exception as e:
        return str(e)

def json_validate(s):
    try:
        json.loads(s)
        return "Valid JSON"
    except json.JSONDecodeError as e:
        return "Invalid: %s" % e

def ip_to_decimal(ip):
    try:
        parts = ip.split(".")
        return str(int(parts[0]) * 256**3 + int(parts[1]) * 256**2 + int(parts[2]) * 256 + int(parts[3]))
    except Exception as e:
        return str(e)

def decimal_to_ip(dec):
    try:
        n = int(dec)
        return "%d.%d.%d.%d" % ((n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255)
    except Exception as e:
        return str(e)

def hex_to_binary(hex_str):
    try:
        return bin(int(hex_str.replace(" ", ""), 16))[2:]
    except Exception as e:
        return str(e)

def binary_to_hex(bin_str):
    try:
        return hex(int(bin_str.replace(" ", ""), 2))[2:].upper()
    except Exception as e:
        return str(e)

def get_listening_ports():
    try:
        out = subprocess.check_output(["netstat", "-an"], shell=False, text=True, encoding="utf-8", errors="replace")
        ports = set()
        for line in out.splitlines():
            if "LISTENING" in line:
                parts = line.split()
                if len(parts) >= 2:
                    addr = parts[1]
                    if ":" in addr:
                        port = addr.split(":")[-1]
                        if port.isdigit():
                            ports.add(int(port))
        return sorted(ports)
    except Exception as e:
        return [str(e)]

def get_port_process(port):
    try:
        if platform.system().lower() == "windows":
            out = subprocess.check_output(["netstat", "-ano"], shell=False, text=True, encoding="utf-8", errors="replace")
            for line in out.splitlines():
                if ":%s" % port in line and "LISTENING" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        pid = parts[-1]
                        return "Port %s used by PID: %s" % (port, pid)
        return "Windows only (netstat -ano)"
    except Exception as e:
        return str(e)

def get_hosts_file():
    try:
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if platform.system().lower() == "windows" else "/etc/hosts"
        with open(hosts_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()[:5000]
    except Exception as e:
        return str(e)

def get_system_info():
    try:
        info = []
        info.append("OS: %s %s" % (platform.system(), platform.release()))
        info.append("Architecture: %s" % platform.machine())
        info.append("Processor: %s" % platform.processor())
        info.append("Hostname: %s" % get_hostname())
        info.append("Python: %s" % platform.python_version())
        return "\n".join(info)
    except Exception as e:
        return str(e)

def wifi_networks_list():
    try:
        out = subprocess.check_output(["netsh", "wlan", "show", "networks"], shell=False, text=True, encoding="utf-8", errors="replace")
        return out
    except Exception as e:
        return str(e)

# ========== Security tools (WiFi & Network) ==========
def wifi_security_scan():
    """Report WiFi security: open/weak/strong networks."""
    networks = wifi_analyzer_networks()
    if not networks:
        return "No WiFi networks found. Run Scanner first."
    lines = ["=== WiFi Security Scan ===\n"]
    open_n = [n for n in networks if "Open" in (n.get("auth") or "")]
    wep_n = [n for n in networks if "WEP" in (n.get("auth") or "")]
    wpa2_n = [n for n in networks if "WPA2" in (n.get("auth") or "") or "WPA3" in (n.get("auth") or "")]
    weak_n = [n for n in networks if n not in open_n and n not in wep_n and n not in wpa2_n]
    lines.append("Open (no password): %d - RISK\n" % len(open_n))
    for n in open_n[:5]:
        lines.append("  - %s (%s)\n" % (n.get("ssid", ""), n.get("bssid", "")))
    lines.append("WEP (weak): %d - RISK\n" % len(wep_n))
    for n in wep_n[:5]:
        lines.append("  - %s (%s)\n" % (n.get("ssid", ""), n.get("bssid", "")))
    lines.append("WPA2/WPA3 (strong): %d - OK\n" % len(wpa2_n))
    if weak_n:
        lines.append("Other/weak: %d - check\n" % len(weak_n))
    return "".join(lines)

def arp_guard_scan(duration_sec=10):
    """Detect ARP changes (possible spoofing / kick attempt)."""
    my_ip = get_my_ip()
    history = {}
    alerts = []
    start = time.time()
    while (time.time() - start) < duration_sec:
        devices = get_connected_devices()
        for ip, mac in devices:
            if ip == my_ip:
                continue
            if ip not in history:
                history[ip] = mac
            elif history[ip].upper() != mac.upper():
                alerts.append("ALERT: %s changed MAC %s -> %s (possible ARP spoofing)" % (ip, history[ip], mac))
                history[ip] = mac
        time.sleep(2)
    if not alerts:
        return "ARP Guard: No changes detected in %d sec. OK." % duration_sec
    return "ARP Guard - Alerts:\n" + "\n".join(alerts)

def dns_leak_check():
    """Check DNS servers (basic leak check: are you using expected DNS?)."""
    dns = get_dns_servers_windows()
    my_ip = get_my_ip()
    lines = ["=== DNS Check ===\n"]
    lines.append("Your DNS: %s\n" % (", ".join(dns) if dns else "None found"))
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=5) as r:
            pub = r.read().decode().strip()
        lines.append("Public IP: %s\n" % pub)
    except Exception as e:
        lines.append("Public IP: Error %s\n" % e)
    if dns:
        if "8.8.8.8" in dns or "1.1.1.1" in dns:
            lines.append("Using public DNS (Google/Cloudflare).\n")
        else:
            lines.append("Using ISP/other DNS. No leak test run (use 8.8.8.8 or 1.1.1.1 for privacy).\n")
    return "".join(lines)

def listening_ports_security():
    """List listening ports with security note."""
    ports = get_listening_ports()
    risky = {21: "FTP", 23: "Telnet", 135: "RPC", 445: "SMB", 3389: "RDP", 5900: "VNC"}
    lines = ["=== Listening Ports (Security) ===\n"]
    for p in ports[:50]:
        note = risky.get(p, "")
        if note:
            lines.append("Port %d - %s - REVIEW (often targeted)\n" % (p, note))
        else:
            lines.append("Port %d\n" % p)
    if len(ports) > 50:
        lines.append("... and %d more\n" % (len(ports) - 50))
    return "".join(lines)

def security_audit_quick():
    """Quick security audit: firewall, DNS, WiFi, ports."""
    lines = ["=== Quick Security Audit ===\n"]
    fw = firewall_status()
    lines.append("Firewall: %s\n" % ("ON" if "ON" in fw.upper() or "ENABLED" in fw.upper() else "Check - " + fw[:80]))
    dns = get_dns_servers_windows()
    lines.append("DNS: %s\n" % (", ".join(dns) if dns else "None"))
    networks = wifi_analyzer_networks()
    open_n = len([n for n in networks if "Open" in (n.get("auth") or "")])
    lines.append("WiFi: %d networks, %d open (risk)\n" % (len(networks), open_n))
    ports = get_listening_ports()
    lines.append("Listening ports: %d\n" % len(ports))
    lines.append("Done.\n")
    return "".join(lines)

# ========== End embedded logic ==========

APP_NAME = "Security Network"
APP_VERSION = "2.0"
APP_TAGLINE = "WiFi & Network Security"
TITLE = "%s v%s - %s" % (APP_NAME, APP_VERSION, APP_TAGLINE)


def get_adapter():
    return get_wifi_adapter_name()


def get_networks():
    return wifi_analyzer_networks()


def get_devices():
    scan_subnet_arp(get_my_ip())
    return get_connected_devices()


def signal_to_dbm(pct):
    return int(signal_pct_to_dbm(pct or 0))


def get_vendor(mac):
    return get_mac_vendor(mac)


def run_speed_test(callback):
    def _run():
        try:
            mbps, sec, msg = speed_test()
            callback(mbps, sec, msg)
        except Exception as e:
            callback(0, 0, str(e))
    threading.Thread(target=_run, daemon=True).start()


class ScannerTab(ttk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self.setup_ui()

    def setup_ui(self):
        # Top: data source + Refresh
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(top, text="Showing data from:", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.adapter_var = tk.StringVar(value=get_adapter())
        ttk.Label(top, textvariable=self.adapter_var, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="Refresh", command=self.refresh).pack(side=tk.RIGHT)

        # Main: left sidebar (stats) + table
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left sidebar - Filters / Stats
        left = ttk.LabelFrame(paned, text="Filters", padding=5)
        paned.add(left, weight=0)
        self.stat_vars = {}
        for key in ["Band", "SSID", "BSSID", "Vendor", "Security", "Signal"]:
            f = ttk.Frame(left)
            f.pack(fill=tk.X, pady=2)
            ttk.Label(f, text="%s:" % key, width=10, anchor=tk.W).pack(side=tk.LEFT)
            v = tk.StringVar(value="0")
            self.stat_vars[key] = v
            ttk.Label(f, textvariable=v, width=6).pack(side=tk.RIGHT)

        # Table
        right = ttk.Frame(paned)
        paned.add(right, weight=1)
        cols = ("SSID", "BSSID", "Vendor", "Channel", "Band", "Signal", "Security")
        self.tree = ttk.Treeview(right, columns=cols, show="headings", height=12, selectmode="browse")
        vsb = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(right, orient=tk.HORIZONTAL, command=self.tree.xview)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=100, minwidth=60)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        # Bottom: Spectrum
        bottom = ttk.LabelFrame(self, text="Spectrum - Channel usage", padding=5)
        bottom.pack(fill=tk.X, padx=5, pady=5)
        self.spectrum_text = tk.Text(bottom, height=4, wrap=tk.WORD, font=("Consolas", 9))
        self.spectrum_text.pack(fill=tk.X)
        self.refresh()

    def refresh(self):
        for v in self.stat_vars.values():
            v.set("...")
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.spectrum_text.delete("1.0", tk.END)
        self.spectrum_text.insert(tk.END, "Scanning...")
        self.after(100, self._do_refresh)

    def _do_refresh(self):
        def work():
            networks = get_networks()
            self.after(0, lambda: self._fill_scanner(networks))
        threading.Thread(target=work, daemon=True).start()

    def _fill_scanner(self, networks):
        bands = set()
        ssids = set()
        vendors = set()
        securities = set()
        signals = set()
        ch_usage = {}
        for n in networks:
            ch = n.get("channel") or 0
            bands.add(channel_to_band(ch))
            ssids.add((n.get("ssid") or "").strip())
            bssid = n.get("bssid") or ""
            if bssid:
                v = get_vendor(bssid)
                if v != "Unknown":
                    vendors.add(v)
            sec = (n.get("auth") or "").strip()
            if sec:
                securities.add(sec)
            sig = n.get("signal") or 0
            if sig > 0:
                signals.add("%d" % signal_to_dbm(sig))
            if ch > 0:
                ch_usage[ch] = ch_usage.get(ch, 0) + 1
        self.stat_vars["Band"].set(str(len(bands)))
        self.stat_vars["SSID"].set(str(len(ssids)))
        self.stat_vars["BSSID"].set(str(len(networks)))
        self.stat_vars["Vendor"].set(str(len(vendors)))
        self.stat_vars["Security"].set(str(len(securities)))
        self.stat_vars["Signal"].set(str(len(signals)))
        self.adapter_var.set(get_adapter())
        for n in networks:
            ssid = (n.get("ssid") or "")[:24]
            bssid = (n.get("bssid") or "")[:17]
            vendor = (get_vendor(n.get("bssid") or "") or "-")[:14]
            ch = n.get("channel") or 0
            band = channel_to_band(ch)
            dbm = signal_to_dbm(n.get("signal"))
            sec = (n.get("auth") or "-")[:14]
            self.tree.insert("", tk.END, values=(ssid, bssid, vendor, ch or "-", band, "%d dBm" % dbm, sec))
        self.spectrum_text.delete("1.0", tk.END)
        if ch_usage:
            max_c = max(ch_usage.values())
            for ch in sorted(ch_usage.keys()):
                cnt = ch_usage[ch]
                bar_len = max(1, int(20 * cnt / max_c))
                self.spectrum_text.insert(tk.END, "Ch %s [%s] %d\n" % (ch, "#" * bar_len, cnt))
        else:
            self.spectrum_text.insert(tk.END, "No channel data.")


class PerformanceTab(ttk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="Speed Test", font=("Segoe UI", 12, "bold")).pack(pady=10)
        ttk.Label(self, text="Measure download speed (Mbps).").pack(pady=5)
        ttk.Button(self, text="Run Speed Test", command=self.run_test).pack(pady=10)
        self.result_var = tk.StringVar(value="Click 'Run Speed Test' to start.")
        ttk.Label(self, textvariable=self.result_var, font=("Segoe UI", 10)).pack(pady=5)
        self.mbps_var = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.mbps_var, font=("Segoe UI", 14, "bold")).pack(pady=5)

    def run_test(self):
        self.result_var.set("Testing...")
        self.mbps_var.set("")
        def done(mbps, sec, msg):
            def update():
                self.result_var.set(msg)
                self.mbps_var.set("%s Mbps" % mbps if mbps else "Failed")
            self.after(0, update)
        run_speed_test(done)


def get_device_name(ip, timeout=1):
    """Get hostname for IP (reverse DNS)."""
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old)
        return (name or "-")[:30]
    except Exception:
        return "-"


class WhosOnNetworkTab(ttk.Frame):
    """Chkon m3ak f WiFi — who is connected on router/WiFi; see names, block from router."""
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="Chkon m3ak f WiFi / Router", font=("Segoe UI", 14, "bold")).pack(pady=5)
        ttk.Label(self, text="Who is connected with you on the router or WiFi. See names. Block from router if you want.", font=("Segoe UI", 9)).pack(pady=2)
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(top, text="Devices (IP, Name, MAC, Vendor).", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        ttk.Button(top, text="Refresh", command=self.refresh).pack(side=tk.LEFT, padx=10)
        ttk.Button(top, text="Copy list", command=self._copy_devices_list).pack(side=tk.LEFT, padx=2)
        ttk.Button(top, text="Block selected (from router)", command=self._block_from_router).pack(side=tk.LEFT, padx=2)
        cols = ("IP", "Name", "MAC", "Vendor")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14, selectmode="browse")
        vsb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=100, minwidth=60)
        self.tree.column("Name", width=140)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.count_var = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.count_var).pack(pady=5)
        self.refresh()

    def refresh(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.count_var.set("Scanning...")
        def work():
            devices = get_devices()
            self.after(0, lambda: self._fill(devices))
        threading.Thread(target=work, daemon=True).start()

    def _fill(self, devices):
        for ip, mac in devices:
            name = get_device_name(ip)
            vendor = (get_vendor(mac) or "-")[:20]
            self.tree.insert("", tk.END, values=(ip, name, mac, vendor))
        self.count_var.set("%d devices found." % len(devices))

    def _block_from_router(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Block from router", "Select a device in the list first, then click 'Block selected (from router)'.")
            return
        item = self.tree.item(sel[0])
        vals = item["values"]
        if len(vals) < 4:
            return
        ip, name, mac, vendor = vals[0], vals[1], vals[2], vals[3]
        gw = get_gateway_windows()
        router_url = ("http://%s" % gw) if gw else "http://192.168.1.1"
        msg = (
            "Block this device from your WiFi/router:\n\n"
            "Device: %s\nName: %s\nMAC: %s\n\n"
            "Steps:\n1. Open your router (login in browser).\n"
            "2. Find 'MAC Filtering' or 'Access Control' or 'Blocked Devices'.\n"
            "3. Add this MAC to the block list: %s\n\n"
            "Then this device will no longer use your WiFi/router.\n\n"
            "Open router in browser now?"
        ) % (ip, name, mac, mac)
        if messagebox.askyesno("Block from router", msg):
            try:
                import webbrowser
                webbrowser.open(router_url)
            except Exception as e:
                messagebox.showerror("Error", "Could not open browser: %s" % e)

    def _copy_devices_list(self):
        """Copy device list (IP, Name, MAC, Vendor) to clipboard."""
        lines = ["IP\tName\tMAC\tVendor"]
        for item in self.tree.get_children():
            vals = self.tree.item(item)["values"]
            if len(vals) >= 4:
                lines.append("%s\t%s\t%s\t%s" % (vals[0], vals[1], vals[2], vals[3]))
        if len(lines) <= 1:
            messagebox.showinfo("Copy list", "No devices to copy. Click Refresh first.")
            return
        try:
            text = "\n".join(lines)
            self.winfo_toplevel().clipboard_clear()
            self.winfo_toplevel().clipboard_append(text)
            messagebox.showinfo("Copy list", "Device list copied to clipboard (%d devices)." % (len(lines) - 1))
        except Exception as e:
            messagebox.showerror("Copy list", str(e))


class AITab(ttk.Frame):
    """AI Assistant - Security Analysis, Recommendations, Chat."""
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="AI Assistant", font=("Segoe UI", 14, "bold")).pack(pady=5)
        ttk.Label(self, text="Network Security Analysis & Recommendations", font=("Segoe UI", 9)).pack(pady=2)
        
        # Notebook for AI features
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Tab 1: Security Analysis
        analysis_frame = ttk.Frame(nb)
        nb.add(analysis_frame, text="Security Analysis")
        ttk.Label(analysis_frame, text="AI Network Security Analysis", font=("Segoe UI", 11, "bold")).pack(pady=5)
        ttk.Button(analysis_frame, text="Analyze Network", command=self._analyze_network).pack(pady=5)
        self.analysis_text = tk.Text(analysis_frame, height=15, wrap=tk.WORD, font=("Consolas", 9))
        self.analysis_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 2: AI Chat
        chat_frame = ttk.Frame(nb)
        nb.add(chat_frame, text="AI Chat")
        ttk.Label(chat_frame, text="Ask AI about network security", font=("Segoe UI", 11, "bold")).pack(pady=5)
        chat_input_frame = ttk.Frame(chat_frame)
        chat_input_frame.pack(fill=tk.X, padx=5, pady=5)
        self.chat_input = tk.Text(chat_input_frame, height=3, wrap=tk.WORD, font=("Segoe UI", 9))
        self.chat_input.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2)
        ttk.Button(chat_input_frame, text="Ask", command=self._ask_ai).pack(side=tk.RIGHT, padx=2)
        self.chat_text = tk.Text(chat_frame, height=12, wrap=tk.WORD, font=("Consolas", 9))
        self.chat_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.chat_text.insert("1.0", "AI Assistant: Ask me anything about network security!\n\n")
        self.chat_text.config(state=tk.DISABLED)
        
        # Tab 3: Anomaly Detection
        anomaly_frame = ttk.Frame(nb)
        nb.add(anomaly_frame, text="Anomaly Detection")
        ttk.Label(anomaly_frame, text="AI Anomaly Detection", font=("Segoe UI", 11, "bold")).pack(pady=5)
        ttk.Button(anomaly_frame, text="Detect Anomalies", command=self._detect_anomalies).pack(pady=5)
        self.anomaly_text = tk.Text(anomaly_frame, height=15, wrap=tk.WORD, font=("Consolas", 9))
        self.anomaly_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 4: Recommendations
        rec_frame = ttk.Frame(nb)
        nb.add(rec_frame, text="Recommendations")
        ttk.Label(rec_frame, text="AI Security Recommendations", font=("Segoe UI", 11, "bold")).pack(pady=5)
        ttk.Button(rec_frame, text="Get Recommendations", command=self._get_recommendations).pack(pady=5)
        self.rec_text = tk.Text(rec_frame, height=15, wrap=tk.WORD, font=("Consolas", 9))
        self.rec_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _analyze_network(self):
        self.analysis_text.delete("1.0", tk.END)
        self.analysis_text.insert(tk.END, "Analyzing network...\n\n")
        self.update()
        
        def analyze():
            try:
                networks = wifi_analyzer_networks()
                devices = get_connected_devices()
                my_ip = get_my_ip()
                dns = get_dns_servers_windows()
                fw_status = firewall_status()
                
                report = []
                report.append("=== AI NETWORK SECURITY ANALYSIS ===\n")
                report.append("Analysis Date: %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
                report.append("-" * 50 + "\n\n")
                
                # WiFi Analysis
                report.append("📡 WIFI NETWORKS ANALYSIS:\n")
                report.append("Total networks found: %d\n" % len(networks))
                if networks:
                    open_networks = [n for n in networks if "Open" in (n.get("auth") or "")]
                    weak_security = [n for n in networks if "WEP" in (n.get("auth") or "") or "WPA" in (n.get("auth") or "") and "WPA2" not in (n.get("auth") or "")]
                    strong_security = [n for n in networks if "WPA2" in (n.get("auth") or "") or "WPA3" in (n.get("auth") or "")]
                    
                    report.append("  • Open networks (no password): %d ⚠️\n" % len(open_networks))
                    report.append("  • Weak security (WEP/WPA): %d ⚠️\n" % len(weak_security))
                    report.append("  • Strong security (WPA2/WPA3): %d ✅\n" % len(strong_security))
                    
                    # Channel congestion
                    channels = {}
                    for n in networks:
                        ch = n.get("channel") or 0
                        if ch > 0:
                            channels[ch] = channels.get(ch, 0) + 1
                    if channels:
                        crowded = [ch for ch, cnt in channels.items() if cnt >= 3]
                        report.append("  • Crowded channels (3+ networks): %d ⚠️\n" % len(crowded))
                        if crowded:
                            report.append("    Channels: %s\n" % ", ".join(map(str, crowded)))
                
                # Device Analysis
                report.append("\n🖥️  CONNECTED DEVICES ANALYSIS:\n")
                report.append("Total devices: %d\n" % len(devices))
                if devices:
                    vendors = {}
                    for ip, mac in devices:
                        v = get_mac_vendor(mac)
                        vendors[v] = vendors.get(v, 0) + 1
                    
                    unknown_devices = [d for d in devices if get_mac_vendor(d[1]) == "Unknown"]
                    report.append("  • Unknown vendors: %d ⚠️\n" % len(unknown_devices))
                    report.append("  • Known vendors: %d ✅\n" % (len(devices) - len(unknown_devices)))
                    
                    if len(devices) > 10:
                        report.append("  • Many devices detected - verify all are authorized ⚠️\n")
                
                # DNS Analysis
                report.append("\n🌐 DNS ANALYSIS:\n")
                if dns:
                    report.append("DNS servers: %s\n" % ", ".join(dns))
                    if "8.8.8.8" in dns or "1.1.1.1" in dns:
                        report.append("  • Using public DNS (Google/Cloudflare) ✅\n")
                    else:
                        report.append("  • Using ISP DNS - consider switching to 8.8.8.8 or 1.1.1.1\n")
                else:
                    report.append("  • No DNS servers detected ⚠️\n")
                
                # Firewall Analysis
                report.append("\n🔥 FIREWALL ANALYSIS:\n")
                if "ON" in fw_status.upper() or "ENABLED" in fw_status.upper():
                    report.append("  • Firewall is ON ✅\n")
                else:
                    report.append("  • Firewall status unclear or OFF ⚠️\n")
                
                # Security Score
                score = 100
                if open_networks:
                    score -= 20
                if weak_security:
                    score -= 15
                if len(unknown_devices) > 2:
                    score -= 10
                if len(devices) > 15:
                    score -= 5
                if not dns or ("8.8.8.8" not in dns and "1.1.1.1" not in dns):
                    score -= 5
                
                report.append("\n" + "=" * 50 + "\n")
                report.append("🔒 SECURITY SCORE: %d/100\n" % max(0, score))
                if score >= 80:
                    report.append("Status: ✅ Good security posture\n")
                elif score >= 60:
                    report.append("Status: ⚠️  Moderate - improvements recommended\n")
                else:
                    report.append("Status: ❌ Weak - immediate action needed\n")
                
                self.analysis_text.delete("1.0", tk.END)
                self.analysis_text.insert("1.0", "".join(report))
            except Exception as e:
                self.analysis_text.delete("1.0", tk.END)
                self.analysis_text.insert("1.0", "Error: %s" % str(e))
        
        threading.Thread(target=analyze, daemon=True).start()

    def _ask_ai(self):
        question = self.chat_input.get("1.0", tk.END).strip()
        if not question:
            return
        
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.insert(tk.END, "\nYou: %s\n" % question)
        self.chat_text.insert(tk.END, "AI: ")
        self.chat_input.delete("1.0", tk.END)
        self.update()
        
        def respond():
            try:
                answer = self._ai_chat_response(question)
                self.chat_text.insert(tk.END, "%s\n" % answer)
            except Exception as e:
                self.chat_text.insert(tk.END, "Error: %s\n" % str(e))
            self.chat_text.config(state=tk.DISABLED)
            self.chat_text.see(tk.END)
        
        threading.Thread(target=respond, daemon=True).start()

    def _ai_chat_response(self, question):
        q_lower = question.lower()
        
        # Network security questions
        if any(w in q_lower for w in ["wifi", "wireless", "network"]):
            if "secure" in q_lower or "security" in q_lower:
                return "For WiFi security: Use WPA2 or WPA3 encryption, strong passwords (12+ chars), disable WPS, hide SSID if possible, and use MAC filtering for extra protection."
            if "speed" in q_lower or "slow" in q_lower:
                return "To improve WiFi speed: Use 5 GHz band, choose less crowded channels (1, 6, 11 for 2.4 GHz), position router centrally, update firmware, and limit connected devices."
            if "channel" in q_lower:
                return "WiFi channels: 2.4 GHz uses channels 1-14 (best: 1, 6, 11 non-overlapping). 5 GHz uses channels 36-165. Choose channels with least interference."
        
        # Device questions
        if any(w in q_lower for w in ["device", "connected", "who"]):
            return "To see connected devices: Use ARP table (arp -a), scan subnet, check router admin page. Unknown devices may be intruders - verify MAC addresses."
        
        # DNS questions
        if "dns" in q_lower:
            return "DNS servers: Use 8.8.8.8 (Google) or 1.1.1.1 (Cloudflare) for faster, more private DNS. Change in network adapter settings."
        
        # Firewall questions
        if "firewall" in q_lower:
            return "Firewall protects your network by blocking unauthorized access. Keep it enabled. Windows Firewall is usually sufficient for home use."
        
        # Port questions
        if "port" in q_lower:
            return "Open ports can be security risks. Only open necessary ports. Use port scanner to check what's open. Close unused ports."
        
        # General security
        if any(w in q_lower for w in ["secure", "protect", "safe"]):
            return "Network security tips: 1) Strong WiFi password (WPA2/WPA3), 2) Enable firewall, 3) Use VPN for public WiFi, 4) Update router firmware, 5) Disable remote admin, 6) Monitor connected devices."
        
        # Default response
        return "I can help with WiFi security, network analysis, device detection, DNS, firewall, ports, and general network security. Ask me a specific question!"

    def _detect_anomalies(self):
        self.anomaly_text.delete("1.0", tk.END)
        self.anomaly_text.insert(tk.END, "Detecting anomalies...\n\n")
        self.update()
        
        def detect():
            try:
                networks = wifi_analyzer_networks()
                devices = get_connected_devices()
                my_ip = get_my_ip()
                
                anomalies = []
                anomalies.append("=== AI ANOMALY DETECTION ===\n")
                anomalies.append("Scan Date: %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
                anomalies.append("-" * 50 + "\n\n")
                
                # Check for open networks
                open_nets = [n for n in networks if "Open" in (n.get("auth") or "")]
                if open_nets:
                    anomalies.append("⚠️  ANOMALY: Open WiFi networks detected\n")
                    anomalies.append("   Found %d open networks (no password)\n" % len(open_nets))
                    anomalies.append("   Risk: Anyone can connect\n\n")
                
                # Check for weak security
                weak_nets = [n for n in networks if "WEP" in (n.get("auth") or "")]
                if weak_nets:
                    anomalies.append("⚠️  ANOMALY: Weak encryption (WEP) detected\n")
                    anomalies.append("   WEP is easily cracked - upgrade to WPA2/WPA3\n\n")
                
                # Check for many devices
                if len(devices) > 15:
                    anomalies.append("⚠️  ANOMALY: High number of connected devices\n")
                    anomalies.append("   Found %d devices - verify all are authorized\n" % len(devices))
                    anomalies.append("   Possible: Unauthorized access or IoT devices\n\n")
                
                # Check for unknown vendors
                unknown_devices = [(ip, mac) for ip, mac in devices if get_mac_vendor(mac) == "Unknown"]
                if len(unknown_devices) > 2:
                    anomalies.append("⚠️  ANOMALY: Multiple unknown device vendors\n")
                    anomalies.append("   Found %d devices with unknown MAC vendors\n" % len(unknown_devices))
                    for ip, mac in unknown_devices[:5]:
                        anomalies.append("   - %s (%s)\n" % (ip, mac))
                    anomalies.append("   Action: Verify these devices\n\n")
                
                # Check for channel congestion
                channels = {}
                for n in networks:
                    ch = n.get("channel") or 0
                    if ch > 0:
                        channels[ch] = channels.get(ch, 0) + 1
                crowded = [(ch, cnt) for ch, cnt in channels.items() if cnt >= 5]
                if crowded:
                    anomalies.append("⚠️  ANOMALY: Channel congestion detected\n")
                    anomalies.append("   Channels with 5+ networks:\n")
                    for ch, cnt in crowded:
                        anomalies.append("   - Channel %d: %d networks\n" % (ch, cnt))
                    anomalies.append("   Impact: Slower WiFi speeds\n\n")
                
                # Check for suspicious MAC patterns
                mac_patterns = {}
                for ip, mac in devices:
                    prefix = mac.replace("-", ":").upper()[:8]
                    mac_patterns[prefix] = mac_patterns.get(prefix, 0) + 1
                suspicious = [(p, c) for p, c in mac_patterns.items() if c > 3]
                if suspicious:
                    anomalies.append("⚠️  ANOMALY: Multiple devices with same MAC prefix\n")
                    anomalies.append("   Possible: MAC spoofing or virtual machines\n")
                    for p, c in suspicious:
                        anomalies.append("   - Prefix %s: %d devices\n" % (p, c))
                    anomalies.append("\n")
                
                if len(anomalies) == 3:  # Only header and date
                    anomalies.append("✅ No anomalies detected!\n")
                    anomalies.append("Your network appears normal.\n")
                else:
                    anomalies.insert(2, "⚠️  ANOMALIES FOUND - Review below:\n\n")
                
                self.anomaly_text.delete("1.0", tk.END)
                self.anomaly_text.insert("1.0", "".join(anomalies))
            except Exception as e:
                self.anomaly_text.delete("1.0", tk.END)
                self.anomaly_text.insert("1.0", "Error: %s" % str(e))
        
        threading.Thread(target=detect, daemon=True).start()

    def _get_recommendations(self):
        self.rec_text.delete("1.0", tk.END)
        self.rec_text.insert(tk.END, "Generating recommendations...\n\n")
        self.update()
        
        def recommend():
            try:
                networks = wifi_analyzer_networks()
                devices = get_connected_devices()
                dns = get_dns_servers_windows()
                fw_status = firewall_status()
                
                recs = []
                recs.append("=== AI SECURITY RECOMMENDATIONS ===\n")
                recs.append("Generated: %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
                recs.append("-" * 50 + "\n\n")
                
                # WiFi Recommendations
                recs.append("📡 WIFI RECOMMENDATIONS:\n")
                open_nets = [n for n in networks if "Open" in (n.get("auth") or "")]
                if open_nets:
                    recs.append("1. ⚠️  CRITICAL: Secure open networks with WPA2/WPA3\n")
                    recs.append("   Open networks are vulnerable to attacks\n\n")
                
                weak_nets = [n for n in networks if "WEP" in (n.get("auth") or "")]
                if weak_nets:
                    recs.append("2. ⚠️  Upgrade from WEP to WPA2/WPA3 encryption\n")
                    recs.append("   WEP is outdated and insecure\n\n")
                
                channels = {}
                for n in networks:
                    ch = n.get("channel") or 0
                    if ch > 0:
                        channels[ch] = channels.get(ch, 0) + 1
                if channels:
                    best_ch = min(channels.keys(), key=lambda c: channels[c])
                    recs.append("3. 📶 Use channel %d (least crowded)\n" % best_ch)
                    recs.append("   Current: %s\n\n" % ", ".join("%s (%d)" % (ch, cnt) for ch, cnt in sorted(channels.items())[:5]))
                
                # Device Recommendations
                recs.append("🖥️  DEVICE MANAGEMENT:\n")
                if len(devices) > 10:
                    recs.append("4. Review connected devices regularly\n")
                    recs.append("   You have %d devices - verify all are authorized\n\n" % len(devices))
                
                unknown_devices = [d for d in devices if get_mac_vendor(d[1]) == "Unknown"]
                if unknown_devices:
                    recs.append("5. Investigate unknown devices\n")
                    recs.append("   %d devices have unknown MAC vendors\n" % len(unknown_devices))
                    recs.append("   Check router admin page for device names\n\n")
                
                # DNS Recommendations
                recs.append("🌐 DNS RECOMMENDATIONS:\n")
                if not dns or ("8.8.8.8" not in dns and "1.1.1.1" not in dns):
                    recs.append("6. Switch to public DNS servers\n")
                    recs.append("   Recommended: 8.8.8.8 (Google) or 1.1.1.1 (Cloudflare)\n")
                    recs.append("   Faster and more private than ISP DNS\n\n")
                
                # Firewall Recommendations
                recs.append("🔥 FIREWALL:\n")
                if "OFF" in fw_status.upper() or "DISABLED" in fw_status.upper():
                    recs.append("7. ⚠️  CRITICAL: Enable Windows Firewall\n")
                    recs.append("   Firewall is your first line of defense\n\n")
                else:
                    recs.append("7. ✅ Firewall is enabled - good!\n\n")
                
                # General Recommendations
                recs.append("🔒 GENERAL SECURITY:\n")
                recs.append("8. Use strong WiFi password (12+ characters, mixed case, numbers, symbols)\n")
                recs.append("9. Update router firmware regularly\n")
                recs.append("10. Disable WPS (WiFi Protected Setup) - it's vulnerable\n")
                recs.append("11. Enable MAC address filtering for extra security\n")
                recs.append("12. Use VPN on public WiFi networks\n")
                recs.append("13. Monitor network activity regularly\n")
                recs.append("14. Change default router admin password\n")
                recs.append("15. Disable remote router administration\n\n")
                
                recs.append("=" * 50 + "\n")
                recs.append("💡 TIP: Implement recommendations in priority order (critical first)\n")
                
                self.rec_text.delete("1.0", tk.END)
                self.rec_text.insert("1.0", "".join(recs))
            except Exception as e:
                self.rec_text.delete("1.0", tk.END)
                self.rec_text.insert("1.0", "Error: %s" % str(e))
        
        threading.Thread(target=recommend, daemon=True).start()


class SecurityTab(ttk.Frame):
    """Security tools - WiFi & Network security (framework-based)."""
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="Security Tools", font=("Segoe UI", 14, "bold")).pack(pady=5)
        ttk.Label(self, text="Network Security | Encryption | Monitoring & Detection", font=("Segoe UI", 9)).pack(pady=2)
        
        # 1. Network Security (الأساس) - Firewall, IDS-like, Segmentation
        f_net = ttk.LabelFrame(self, text="1. Network Security (حماية الشبكة) — Firewall, IDS/IPS-like", padding=8)
        f_net.pack(fill=tk.X, padx=10, pady=4)
        row1 = ttk.Frame(f_net)
        row1.pack(fill=tk.X, pady=2)
        ttk.Button(row1, text="Firewall Status", command=lambda: self._result(firewall_status())).pack(side=tk.LEFT, padx=3)
        ttk.Button(row1, text="ARP Guard (IDS-like)", command=self._arp_guard).pack(side=tk.LEFT, padx=3)
        ttk.Button(row1, text="Listening Ports", command=lambda: self._result(listening_ports_security())).pack(side=tk.LEFT, padx=3)
        ttk.Button(row1, text="Quick Security Audit", command=lambda: self._result(security_audit_quick())).pack(side=tk.LEFT, padx=3)
        
        # 2. Encryption & Secure Communication (TLS/SSL, HTTPS)
        f_enc = ttk.LabelFrame(self, text="2. Encryption & Secure Protocols — TLS/SSL, HTTPS", padding=8)
        f_enc.pack(fill=tk.X, padx=10, pady=4)
        row2 = ttk.Frame(f_enc)
        row2.pack(fill=tk.X, pady=2)
        ttk.Button(row2, text="SSL/TLS Certificate", command=self._ssl_cert).pack(side=tk.LEFT, padx=3)
        ttk.Button(row2, text="HTTP Security Headers", command=self._security_headers).pack(side=tk.LEFT, padx=3)
        ttk.Button(row2, text="HTTP Status (site up?)", command=self._http_status).pack(side=tk.LEFT, padx=3)
        
        # 3. WiFi Security + Monitoring & Detection
        f_wifi = ttk.LabelFrame(self, text="3. WiFi Security & Monitoring — Open/WEP/WPA2, Detection", padding=8)
        f_wifi.pack(fill=tk.X, padx=10, pady=4)
        row3 = ttk.Frame(f_wifi)
        row3.pack(fill=tk.X, pady=2)
        ttk.Button(row3, text="WiFi Security Scan", command=self._wifi_security).pack(side=tk.LEFT, padx=3)
        ttk.Button(row3, text="DNS Check (leak)", command=lambda: self._result(dns_leak_check())).pack(side=tk.LEFT, padx=3)
        
        # 4. Security Framework reference
        f_ref = ttk.LabelFrame(self, text="Security Framework Reference", padding=8)
        f_ref.pack(fill=tk.X, padx=10, pady=4)
        ttk.Button(f_ref, text="Show Security Pillars (1-10)", command=self._show_framework).pack(side=tk.LEFT, padx=3)
        
        # Result
        result_frame = ttk.Frame(self)
        result_frame.pack(fill=tk.X, padx=10, pady=(5, 0))
        ttk.Label(result_frame, text="Result:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(result_frame, text="Copy result", command=self._copy_result).pack(side=tk.LEFT, padx=2)
        self.result_text = tk.Text(self, height=16, wrap=tk.WORD, font=("Consolas", 9))
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _copy_result(self):
        try:
            text = self.result_text.get("1.0", tk.END)
            if text.strip():
                self.winfo_toplevel().clipboard_clear()
                self.winfo_toplevel().clipboard_append(text)
                messagebox.showinfo("Copy", "Result copied to clipboard.")
            else:
                messagebox.showinfo("Copy", "Nothing to copy.")
        except Exception as e:
            messagebox.showerror("Copy", str(e))

    def _result(self, s):
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, str(s) if s else "N/A")

    def _wifi_security(self):
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, "Scanning WiFi security...\n\n")
        self.update()
        def run():
            result = wifi_security_scan()
            self.after(0, lambda: self._result(result))
        threading.Thread(target=run, daemon=True).start()

    def _arp_guard(self):
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, "ARP Guard running 10 sec...\n\n")
        self.update()
        def run():
            result = arp_guard_scan(10)
            self.after(0, lambda: self._result(result))
        threading.Thread(target=run, daemon=True).start()

    def _ssl_cert(self):
        from tkinter import simpledialog
        host = simpledialog.askstring("SSL/TLS Certificate", "Hostname (e.g. google.com)", parent=self)
        if host:
            self._result("Checking...")
            def check():
                result = ssl_cert_info(host)
                self.after(0, lambda: self._result(result))
            threading.Thread(target=check, daemon=True).start()

    def _security_headers(self):
        from tkinter import simpledialog
        url = simpledialog.askstring("Security Headers", "URL", parent=self)
        if url:
            self._result("Checking...")
            def check():
                results = check_security_headers(url)
                self.after(0, lambda: self._result("\n".join(results)))
            threading.Thread(target=check, daemon=True).start()

    def _http_status(self):
        from tkinter import simpledialog
        url = simpledialog.askstring("HTTP Status", "URL", parent=self)
        if url:
            self._result("Checking...")
            def check():
                result = http_status(url)
                self.after(0, lambda: self._result(result))
            threading.Thread(target=check, daemon=True).start()

    def _show_framework(self):
        text = """=== Security Framework (1-10) ===

1. Network Security (الأساس)
   Firewall | IDS/IPS | Network Segmentation (VLAN, Zero Trust)

2. Encryption & Secure Communication
   AES, RSA, TLS/SSL, HTTPS, SSH, IPsec, VPN

3. Authentication & Access Control
   MFA | RBAC | NAC | Least Privilege

4. Endpoint Security
   EDR | Antivirus | Patch Management | Device Control

5. Application Security
   WAF | API Security | Rate Limiting | Anti-DDoS | XSS/CSRF/SQLi

6. Monitoring & Detection
   SIEM | Logs | Real-time Alerts | UEBA | Threat Intel

7. Cloud & Container Security
   Cloud Firewall | IAM | CASB | Kubernetes | Docker

8. Data Security
   DLP | Encryption | Tokenization | Backup | HSM/KMS

9. Architecture
   Dashboard | Microservices | Policy Engine | AI Engine

10. Advanced
    AI/ML Detection | Zero Trust | SOAR | Compliance (ISO 27001, GDPR)
"""
        self._result(text)


class ToolsTab(ttk.Frame):
    """More tools (bzaaaaaaf) - quick access from GUI."""
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self.setup_ui()

    def setup_ui(self):
        # Scrollable frame for all tools
        canvas = tk.Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        scrollable_frame.bind("<MouseWheel>", lambda e: _on_mousewheel(e))
        
        ttk.Label(scrollable_frame, text="All Tools (bzaaaaaaf)", font=("Segoe UI", 14, "bold")).pack(pady=10)
        
        # Quick Tools
        f1 = ttk.LabelFrame(scrollable_frame, text="Quick Tools", padding=10)
        f1.pack(fill=tk.X, padx=10, pady=5)
        row1 = ttk.Frame(f1)
        row1.pack(fill=tk.X, pady=2)
        ttk.Button(row1, text="UUID", command=lambda: self._result(uuid_generate())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="Random password", command=self._random_pass).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="Random IP", command=lambda: self._result(random_ip())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="User-Agent", command=lambda: self._result(user_agent_string())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="Public IP", command=lambda: self._result(my_public_ip())).pack(side=tk.LEFT, padx=2)
        row1b = ttk.Frame(f1)
        row1b.pack(fill=tk.X, pady=2)
        ttk.Button(row1b, text="System Info", command=lambda: self._result(get_system_info())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1b, text="Hostname", command=lambda: self._result(get_hostname())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1b, text="Gateway", command=lambda: self._result(get_gateway_windows() or "Not found")).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1b, text="Drive Info", command=lambda: self._result(get_drive_info())).pack(side=tk.LEFT, padx=2)
        
        # Network Tools
        f2 = ttk.LabelFrame(scrollable_frame, text="Network Tools", padding=10)
        f2.pack(fill=tk.X, padx=10, pady=5)
        row2 = ttk.Frame(f2)
        row2.pack(fill=tk.X, pady=2)
        ttk.Button(row2, text="Port Scanner", command=self._port_scan).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2, text="Ping Sweep", command=self._ping_sweep).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2, text="DNS Lookup", command=self._dns_lookup).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2, text="Reverse DNS", command=self._reverse_dns).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2, text="Traceroute", command=self._traceroute).pack(side=tk.LEFT, padx=2)
        row2b = ttk.Frame(f2)
        row2b.pack(fill=tk.X, pady=2)
        ttk.Button(row2b, text="Whois", command=self._whois).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2b, text="IP Geolocation", command=self._ip_geo).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2b, text="Wake-on-LAN", command=self._wol).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2b, text="Flush DNS", command=lambda: self._result(flush_dns())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2b, text="Renew DHCP", command=lambda: self._result(renew_dhcp())).pack(side=tk.LEFT, padx=2)
        
        # Netcat-style (TCP connect / listen)
        f_nc = ttk.LabelFrame(scrollable_frame, text="Netcat-style (TCP connect / listen)", padding=10)
        f_nc.pack(fill=tk.X, padx=10, pady=5)
        row_nc = ttk.Frame(f_nc)
        row_nc.pack(fill=tk.X, pady=2)
        ttk.Button(row_nc, text="Connect (client)", command=self._netcat_connect).pack(side=tk.LEFT, padx=2)
        ttk.Button(row_nc, text="Listen (server)", command=self._netcat_listen).pack(side=tk.LEFT, padx=2)
        ttk.Button(row_nc, text="TCP Test (quick)", command=self._tcp_test).pack(side=tk.LEFT, padx=2)
        
        # HTTP & Security
        f3 = ttk.LabelFrame(scrollable_frame, text="HTTP & Security", padding=10)
        f3.pack(fill=tk.X, padx=10, pady=5)
        row3 = ttk.Frame(f3)
        row3.pack(fill=tk.X, pady=2)
        ttk.Button(row3, text="HTTP Status", command=self._http_status).pack(side=tk.LEFT, padx=2)
        ttk.Button(row3, text="HTTP Headers", command=self._http_headers).pack(side=tk.LEFT, padx=2)
        ttk.Button(row3, text="Security Headers", command=self._security_headers).pack(side=tk.LEFT, padx=2)
        ttk.Button(row3, text="SSL Certificate", command=self._ssl_cert).pack(side=tk.LEFT, padx=2)
        ttk.Button(row3, text="URL Expand", command=self._url_expand).pack(side=tk.LEFT, padx=2)
        
        # Network Info
        f4 = ttk.LabelFrame(scrollable_frame, text="Network Info & Tables", padding=10)
        f4.pack(fill=tk.X, padx=10, pady=5)
        row4 = ttk.Frame(f4)
        row4.pack(fill=tk.X, pady=2)
        ttk.Button(row4, text="Route table", command=lambda: self._result(route_table())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row4, text="ARP table", command=lambda: self._result(arp_table_full())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row4, text="Active Connections", command=lambda: self._result("\n".join(str(c) for c in get_connections_windows()[:50]))).pack(side=tk.LEFT, padx=2)
        ttk.Button(row4, text="Listening Ports", command=lambda: self._result(", ".join(map(str, get_listening_ports()[:30])))).pack(side=tk.LEFT, padx=2)
        ttk.Button(row4, text="Port to Process", command=self._port_process).pack(side=tk.LEFT, padx=2)
        row4b = ttk.Frame(f4)
        row4b.pack(fill=tk.X, pady=2)
        ttk.Button(row4b, text="Firewall status", command=lambda: self._result(firewall_status())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row4b, text="DNS in use", command=lambda: self._result(dns_servers_in_use())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row4b, text="Network interfaces", command=lambda: self._result(network_interfaces())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row4b, text="WiFi saved profiles", command=lambda: self._result(wifi_saved_profiles())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row4b, text="WiFi networks list", command=lambda: self._result(wifi_networks_list())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row4b, text="Netstat summary", command=lambda: self._result(netstat_summary())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row4b, text="Connection state", command=lambda: self._result(connection_state_summary())).pack(side=tk.LEFT, padx=2)
        
        # Calculators & Converters
        f5 = ttk.LabelFrame(scrollable_frame, text="Calculators & Converters", padding=10)
        f5.pack(fill=tk.X, padx=10, pady=5)
        row5 = ttk.Frame(f5)
        row5.pack(fill=tk.X, pady=2)
        ttk.Button(row5, text="Subnet Calculator", command=self._subnet_calc).pack(side=tk.LEFT, padx=2)
        ttk.Button(row5, text="CIDR to Range", command=self._cidr_range).pack(side=tk.LEFT, padx=2)
        ttk.Button(row5, text="IP to Decimal", command=self._ip_to_dec).pack(side=tk.LEFT, padx=2)
        ttk.Button(row5, text="Decimal to IP", command=self._dec_to_ip).pack(side=tk.LEFT, padx=2)
        ttk.Button(row5, text="Hex to Binary", command=self._hex_to_bin).pack(side=tk.LEFT, padx=2)
        ttk.Button(row5, text="Binary to Hex", command=self._bin_to_hex).pack(side=tk.LEFT, padx=2)
        row5b = ttk.Frame(f5)
        row5b.pack(fill=tk.X, pady=2)
        ttk.Button(row5b, text="URL Encode", command=self._url_encode).pack(side=tk.LEFT, padx=2)
        ttk.Button(row5b, text="URL Decode", command=self._url_decode).pack(side=tk.LEFT, padx=2)
        ttk.Button(row5b, text="Base64 Encode", command=self._base64_encode).pack(side=tk.LEFT, padx=2)
        ttk.Button(row5b, text="Base64 Decode", command=self._base64_decode).pack(side=tk.LEFT, padx=2)
        ttk.Button(row5b, text="Hex Encode", command=self._hex_encode).pack(side=tk.LEFT, padx=2)
        ttk.Button(row5b, text="Hex Decode", command=self._hex_decode).pack(side=tk.LEFT, padx=2)
        
        # Hash & Password
        f6 = ttk.LabelFrame(scrollable_frame, text="Hash & Password", padding=10)
        f6.pack(fill=tk.X, padx=10, pady=5)
        row6 = ttk.Frame(f6)
        row6.pack(fill=tk.X, pady=2)
        ttk.Label(row6, text="Hash (MD5/SHA256):").pack(side=tk.LEFT)
        self.hash_input = tk.StringVar()
        ttk.Entry(row6, textvariable=self.hash_input, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(row6, text="MD5", command=lambda: self._result(hash_string(self.hash_input.get(), "md5"))).pack(side=tk.LEFT, padx=2)
        ttk.Button(row6, text="SHA256", command=lambda: self._result(hash_string(self.hash_input.get(), "sha256"))).pack(side=tk.LEFT, padx=2)
        ttk.Button(row6, text="File Checksum", command=self._file_checksum).pack(side=tk.LEFT, padx=2)
        row6b = ttk.Frame(f6)
        row6b.pack(fill=tk.X, pady=2)
        ttk.Label(row6b, text="Password strength:").pack(side=tk.LEFT)
        self.pwd_var = tk.StringVar()
        ttk.Entry(row6b, textvariable=self.pwd_var, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(row6b, text="Check", command=self._pwd_strength).pack(side=tk.LEFT, padx=2)
        ttk.Label(row6b, text="Bytes to units:").pack(side=tk.LEFT, padx=(15, 0))
        self.bytes_var = tk.StringVar()
        ttk.Entry(row6b, textvariable=self.bytes_var, width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(row6b, text="Convert", command=self._bytes_convert).pack(side=tk.LEFT, padx=2)
        
        # Other Tools
        f7 = ttk.LabelFrame(scrollable_frame, text="Other Tools", padding=10)
        f7.pack(fill=tk.X, padx=10, pady=5)
        row7 = ttk.Frame(f7)
        row7.pack(fill=tk.X, pady=2)
        ttk.Button(row7, text="Timestamp to Date", command=self._timestamp_date).pack(side=tk.LEFT, padx=2)
        ttk.Button(row7, text="JSON Validator", command=self._json_validate).pack(side=tk.LEFT, padx=2)
        ttk.Button(row7, text="Hosts File", command=lambda: self._result(get_hosts_file())).pack(side=tk.LEFT, padx=2)
        ttk.Button(row7, text="Export WiFi scan", command=self._export_wifi).pack(side=tk.LEFT, padx=2)
        ttk.Button(row7, text="Export devices", command=self._export_devices).pack(side=tk.LEFT, padx=2)
        ttk.Button(row7, text="TCP test", command=self._tcp_test).pack(side=tk.LEFT, padx=2)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        result_frame = ttk.Frame(self)
        result_frame.pack(fill=tk.X, padx=10, pady=(5, 0))
        ttk.Label(result_frame, text="Result:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(result_frame, text="Copy result", command=self._copy_result).pack(side=tk.LEFT, padx=2)
        self.result_text = tk.Text(self, height=8, wrap=tk.WORD, font=("Consolas", 9))
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _copy_result(self):
        try:
            text = self.result_text.get("1.0", tk.END)
            if text.strip():
                self.winfo_toplevel().clipboard_clear()
                self.winfo_toplevel().clipboard_append(text)
                messagebox.showinfo("Copy", "Result copied to clipboard.")
            else:
                messagebox.showinfo("Copy", "Nothing to copy.")
        except Exception as e:
            messagebox.showerror("Copy", str(e))

    def _result(self, s):
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, str(s) if s else "N/A")

    def _random_pass(self):
        p = random_password(16)
        self._result("Random password: %s" % p)

    def _pwd_strength(self):
        pwd = self.pwd_var.get()
        self._result("Strength: %s" % password_strength(pwd))

    def _bytes_convert(self):
        n = self.bytes_var.get().strip()
        self._result(bytes_to_units(n) if n.isdigit() else "Enter a number (bytes).")

    def _export_wifi(self):
        self._result(export_wifi_scan_to_file())

    def _export_devices(self):
        self._result(export_devices_to_file())

    def _cidr_range(self):
        from tkinter import simpledialog
        cidr = simpledialog.askstring("CIDR", "e.g. 192.168.1.0/24", parent=self)
        if cidr:
            self._result(cidr_to_range(cidr))

    def _tcp_test(self):
        from tkinter import simpledialog
        host = simpledialog.askstring("TCP test", "Host or IP", parent=self)
        if not host:
            return
        port = simpledialog.askstring("TCP test", "Port", parent=self)
        if port and port.isdigit():
            self._result(tcp_connect_test(host, port))

    def _netcat_connect(self):
        from tkinter import simpledialog
        host = simpledialog.askstring("Netcat Connect", "Host or IP", parent=self)
        if not host:
            return
        port = simpledialog.askstring("Netcat Connect", "Port", parent=self)
        if not port or not port.isdigit():
            return
        send_data = simpledialog.askstring("Netcat Connect", "Data to send (optional, leave empty to only receive)", parent=self)
        self._result("Connecting...")
        def run():
            result = netcat_connect(host, port, send_data.strip() or None)
            self.after(0, lambda: self._result(result))
        threading.Thread(target=run, daemon=True).start()

    def _netcat_listen(self):
        from tkinter import simpledialog
        port = simpledialog.askstring("Netcat Listen", "Port to listen on", parent=self)
        if not port or not port.isdigit():
            return
        self._result("Listening on port %s (waiting for connection, 30 sec timeout)..." % port)
        self.update()
        def run():
            result = netcat_listen(port, timeout=30)
            self.after(0, lambda: self._result(result))
        threading.Thread(target=run, daemon=True).start()
    
    def _port_scan(self):
        from tkinter import simpledialog
        host = simpledialog.askstring("Port Scanner", "Host or IP", parent=self)
        if host:
            self._result("Scanning ports...")
            def scan():
                ports = scan_ports(host, ports=list(range(1, 1025))[:100])  # First 100 ports
                result = "Open ports on %s:\n" % host
                for p in ports:
                    service = COMMON_PORTS.get(p, "")
                    result += "Port %d %s\n" % (p, ("- " + service) if service else "")
                self.after(0, lambda: self._result(result if ports else "No open ports found"))
            threading.Thread(target=scan, daemon=True).start()
    
    def _ping_sweep(self):
        from tkinter import simpledialog
        base = simpledialog.askstring("Ping Sweep", "Base IP (e.g. 192.168.1)", parent=self)
        if base:
            self._result("Scanning...")
            def sweep():
                alive = ping_sweep(base)
                self.after(0, lambda: self._result("Alive hosts:\n" + "\n".join(alive) if alive else "No hosts found"))
            threading.Thread(target=sweep, daemon=True).start()
    
    def _dns_lookup(self):
        from tkinter import simpledialog
        host = simpledialog.askstring("DNS Lookup", "Hostname", parent=self)
        if host:
            ips = dns_lookup(host)
            self._result("IPs for %s:\n%s" % (host, "\n".join(ips) if ips else "Not found"))
    
    def _reverse_dns(self):
        from tkinter import simpledialog
        ip = simpledialog.askstring("Reverse DNS", "IP address", parent=self)
        if ip:
            self._result("Hostname: %s" % reverse_dns(ip))
    
    def _traceroute(self):
        from tkinter import simpledialog
        host = simpledialog.askstring("Traceroute", "Host or IP", parent=self)
        if host:
            self._result("Tracing...")
            def trace():
                hops = traceroute(host)
                self.after(0, lambda: self._result("\n".join(hops[:50])))
            threading.Thread(target=trace, daemon=True).start()
    
    def _whois(self):
        from tkinter import simpledialog
        domain = simpledialog.askstring("Whois", "Domain or IP", parent=self)
        if domain:
            self._result("Querying...")
            def query():
                result = whois_lookup(domain)
                self.after(0, lambda: self._result(result[:5000]))
            threading.Thread(target=query, daemon=True).start()
    
    def _ip_geo(self):
        from tkinter import simpledialog
        ip = simpledialog.askstring("IP Geolocation", "IP address", parent=self)
        if ip:
            self._result("Looking up...")
            def lookup():
                result = ip_geolocation(ip)
                self.after(0, lambda: self._result(result))
            threading.Thread(target=lookup, daemon=True).start()
    
    def _wol(self):
        from tkinter import simpledialog
        mac = simpledialog.askstring("Wake-on-LAN", "MAC address (e.g. 00:11:22:33:44:55)", parent=self)
        if mac:
            self._result(wake_on_lan(mac))
    
    def _http_status(self):
        from tkinter import simpledialog
        url = simpledialog.askstring("HTTP Status", "URL", parent=self)
        if url:
            self._result("Checking...")
            def check():
                result = http_status(url)
                self.after(0, lambda: self._result(result))
            threading.Thread(target=check, daemon=True).start()
    
    def _http_headers(self):
        from tkinter import simpledialog
        url = simpledialog.askstring("HTTP Headers", "URL", parent=self)
        if url:
            self._result("Fetching...")
            def fetch():
                headers = get_headers(url)
                result = "\n".join("%s: %s" % (k, v) for k, v in headers.items())
                self.after(0, lambda: self._result(result))
            threading.Thread(target=fetch, daemon=True).start()
    
    def _security_headers(self):
        from tkinter import simpledialog
        url = simpledialog.askstring("Security Headers", "URL", parent=self)
        if url:
            self._result("Checking...")
            def check():
                results = check_security_headers(url)
                self.after(0, lambda: self._result("\n".join(results)))
            threading.Thread(target=check, daemon=True).start()
    
    def _ssl_cert(self):
        from tkinter import simpledialog
        host = simpledialog.askstring("SSL Certificate", "Hostname", parent=self)
        if host:
            self._result("Checking...")
            def check():
                result = ssl_cert_info(host)
                self.after(0, lambda: self._result(result))
            threading.Thread(target=check, daemon=True).start()
    
    def _url_expand(self):
        from tkinter import simpledialog
        url = simpledialog.askstring("URL Expand", "Short URL", parent=self)
        if url:
            self._result("Expanding...")
            def expand():
                result = url_expand(url)
                self.after(0, lambda: self._result(result))
            threading.Thread(target=expand, daemon=True).start()
    
    def _subnet_calc(self):
        from tkinter import simpledialog
        cidr = simpledialog.askstring("Subnet Calculator", "CIDR (e.g. 192.168.1.0/24)", parent=self)
        if cidr:
            info = subnet_info(cidr)
            if "error" in info:
                self._result(info["error"])
            else:
                result = "Network: %s\nNetmask: %s\nBroadcast: %s\nHosts: %d\nFirst: %s\nLast: %s" % (
                    info["network"], info["netmask"], info["broadcast"], info["hosts_count"],
                    info["first_host"], info["last_host"]
                )
                self._result(result)
    
    def _ip_to_dec(self):
        from tkinter import simpledialog
        ip = simpledialog.askstring("IP to Decimal", "IP address", parent=self)
        if ip:
            self._result("Decimal: %s" % ip_to_decimal(ip))
    
    def _dec_to_ip(self):
        from tkinter import simpledialog
        dec = simpledialog.askstring("Decimal to IP", "Decimal number", parent=self)
        if dec:
            self._result("IP: %s" % decimal_to_ip(dec))
    
    def _hex_to_bin(self):
        from tkinter import simpledialog
        hex_str = simpledialog.askstring("Hex to Binary", "Hex string", parent=self)
        if hex_str:
            self._result("Binary: %s" % hex_to_binary(hex_str))
    
    def _bin_to_hex(self):
        from tkinter import simpledialog
        bin_str = simpledialog.askstring("Binary to Hex", "Binary string", parent=self)
        if bin_str:
            self._result("Hex: %s" % binary_to_hex(bin_str))
    
    def _url_encode(self):
        from tkinter import simpledialog
        text = simpledialog.askstring("URL Encode", "Text to encode", parent=self)
        if text:
            self._result("Encoded: %s" % url_encode(text))
    
    def _url_decode(self):
        from tkinter import simpledialog
        text = simpledialog.askstring("URL Decode", "Text to decode", parent=self)
        if text:
            self._result("Decoded: %s" % url_decode(text))
    
    def _base64_encode(self):
        from tkinter import simpledialog
        text = simpledialog.askstring("Base64 Encode", "Text to encode", parent=self)
        if text:
            self._result("Encoded: %s" % base64_encode(text))
    
    def _base64_decode(self):
        from tkinter import simpledialog
        text = simpledialog.askstring("Base64 Decode", "Text to decode", parent=self)
        if text:
            self._result("Decoded: %s" % base64_decode(text))
    
    def _hex_encode(self):
        from tkinter import simpledialog
        text = simpledialog.askstring("Hex Encode", "Text to encode", parent=self)
        if text:
            self._result("Encoded: %s" % hex_encode(text))
    
    def _hex_decode(self):
        from tkinter import simpledialog
        text = simpledialog.askstring("Hex Decode", "Hex string", parent=self)
        if text:
            self._result("Decoded: %s" % hex_decode(text))
    
    def _file_checksum(self):
        path = filedialog.askopenfilename(title="Select file for checksum")
        if path:
            self._result("Calculating...")
            def calc():
                md5 = file_checksum(path, "md5")
                sha256 = file_checksum(path, "sha256")
                self.after(0, lambda: self._result("File: %s\nMD5: %s\nSHA256: %s" % (os.path.basename(path), md5, sha256)))
            threading.Thread(target=calc, daemon=True).start()
    
    def _timestamp_date(self):
        from tkinter import simpledialog
        ts = simpledialog.askstring("Timestamp to Date", "Unix timestamp", parent=self)
        if ts:
            self._result("Date: %s" % timestamp_to_date(ts))
    
    def _json_validate(self):
        from tkinter import simpledialog
        json_str = simpledialog.askstring("JSON Validator", "JSON string", parent=self)
        if json_str:
            self._result(json_validate(json_str))
    
    def _port_process(self):
        from tkinter import simpledialog
        port = simpledialog.askstring("Port to Process", "Port number", parent=self)
        if port and port.isdigit():
            self._result(get_port_process(port))


class MainApp(tk.Tk):
    """Security Network - WiFi & Network Security."""
    def __init__(self):
        super().__init__()
        self.title(TITLE)
        self.minsize(920, 620)
        self.geometry("1024x680")
        # Linux/X11: taskbar class (skip on Windows - wm_class not available)
        if platform.system() != "Windows":
            try:
                self.wm_class("SecurityNetwork", APP_NAME)
            except (AttributeError, tk.TclError):
                pass
        if platform.system() == "Windows":
            try:
                self.attributes("-toolwindow", False)
            except tk.TclError:
                pass
        # Icon (optional: put icon.ico in same folder)
        self._set_icon()
        self._style()
        self._menu()
        self._ui()
        self._status_var = None

    def _set_icon(self):
        try:
            base = os.path.dirname(os.path.abspath(__file__))
            ico = os.path.join(base, "icon.ico")
            if os.path.isfile(ico):
                self.iconbitmap(ico)
        except Exception:
            pass

    def _style(self):
        style = ttk.Style()
        # Windows native look
        if platform.system() == "Windows":
            for t in ("vista", "xpnative", "winnative", "clam"):
                if t in style.theme_names():
                    style.theme_use(t)
                    break
        elif "clam" in style.theme_names():
            style.theme_use("clam")

    def _menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.quit)
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Scanner", command=lambda: self._select_tab(0))
        view_menu.add_command(label="Performance", command=lambda: self._select_tab(1))
        view_menu.add_command(label="Chkon m3ak f WiFi (Who's On My Network)", command=lambda: self._select_tab(2))
        view_menu.add_command(label="AI Assistant", command=lambda: self._select_tab(3))
        view_menu.add_command(label="Security", command=lambda: self._select_tab(4))
        view_menu.add_command(label="Tools", command=lambda: self._select_tab(5))
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About %s" % APP_NAME, command=self._about)

    def _select_tab(self, index):
        if hasattr(self, "_notebook"):
            self._notebook.select(index)

    def _about(self):
        messagebox.showinfo(
            "About %s" % APP_NAME,
            "%s  v%s\n\n%s\n\n"
            "Scanner | Performance | Who's On My Network | AI Assistant | Security | Tools\n\n"
            "Windows application for WiFi and network security." % (APP_NAME, APP_VERSION, APP_TAGLINE)
        )

    def _ui(self):
        # Header
        header = ttk.Frame(self, padding=(10, 8))
        header.pack(fill=tk.X)
        ttk.Label(header, text=APP_NAME, font=("Segoe UI", 16, "bold")).pack(side=tk.LEFT)
        ttk.Label(header, text="  —  ", font=("Segoe UI", 10)).pack(side=tk.LEFT)
        ttk.Label(header, text=APP_TAGLINE, font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
        # Network status + Drive (IP, Gateway, Drives)
        status_frame = ttk.Frame(header)
        status_frame.pack(side=tk.RIGHT, padx=10)
        try:
            my_ip = get_my_ip()
            gateway = get_gateway_windows()
            drives = get_drive_letters_short()
            status_frame._ip_label = ttk.Label(status_frame, text="IP: %s" % my_ip, font=("Segoe UI", 9), foreground="blue")
            status_frame._ip_label.pack(side=tk.LEFT, padx=5)
            if gateway:
                status_frame._gw_label = ttk.Label(status_frame, text="Gateway: %s" % gateway, font=("Segoe UI", 9), foreground="green")
                status_frame._gw_label.pack(side=tk.LEFT, padx=5)
            if drives:
                status_frame._dr_label = ttk.Label(status_frame, text="Drives: %s" % drives, font=("Segoe UI", 9), foreground="gray")
                status_frame._dr_label.pack(side=tk.LEFT, padx=5)
        except Exception:
            pass
        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 5))

        # Tabs
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=5)
        self._notebook = nb
        nb.add(ScannerTab(nb), text="  Scanner  ")
        nb.add(PerformanceTab(nb), text="  Performance  ")
        nb.add(WhosOnNetworkTab(nb), text="  Chkon m3ak f WiFi  ")
        nb.add(AITab(nb), text="  AI Assistant  ")
        nb.add(SecurityTab(nb), text="  Security  ")
        nb.add(ToolsTab(nb), text="  Tools  ")

        # Footer
        footer = ttk.Frame(self, padding=(8, 6))
        footer.pack(fill=tk.X)
        ttk.Label(footer, text="%s  —  %s" % (APP_NAME, APP_TAGLINE), font=("Segoe UI", 10, "bold")).pack(anchor=tk.CENTER)

        # Status bar
        status_frame = ttk.Frame(self, padding=(8, 4))
        status_frame.pack(fill=tk.X)
        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X)
        self._status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, text="%s  |  " % APP_TAGLINE, font=("Segoe UI", 8)).pack(side=tk.LEFT)
        ttk.Label(status_frame, textvariable=self._status_var, font=("Segoe UI", 8)).pack(side=tk.LEFT)
        ttk.Label(status_frame, text="%s v%s" % (APP_NAME, APP_VERSION), font=("Segoe UI", 8)).pack(side=tk.RIGHT)


def main():
    app = MainApp()
    app.mainloop()


if __name__ == "__main__":
    main()
