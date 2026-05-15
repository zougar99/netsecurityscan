#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔒 Security Network - All-in-One 🔒
WiFi & Network Security Scanner | i7tarafiya mn jami3 nawa7i
Chkon m3ak f WiFi? | Bzaaf tools (62+)

Usage:
    python SecurityNetwork_AllInOne.py          # Choose CLI or GUI
    python SecurityNetwork_AllInOne.py --cli    # Force CLI
    python SecurityNetwork_AllInOne.py --gui    # Force GUI
"""

import sys
import os
import subprocess
import re
import socket
import platform
import time
import json
import shutil
import concurrent.futures
import urllib.request
import urllib.parse
import urllib.error
import ssl
import hashlib
import base64
import random
import string
import uuid as uuid_mod
import threading
import argparse
from collections import defaultdict
from datetime import datetime

if sys.version_info[0] < 3:
    print("Security Network needs Python 3.")
    sys.exit(1)

# ====================================================================
# APP IDENTITY
# ====================================================================
APP_NAME = "Security Network"
APP_VERSION = "2.0"
APP_TAGLINE = "i7tarafiya mn jami3 nawa7i"
APP_FULL = f"{APP_NAME} v{APP_VERSION} - {APP_TAGLINE}"
TOTAL_TOOLS = 62

# Advanced security dependencies
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Rich optional
try:
    from rich.console import Console
    from rich.table import Table as RichTable
    from rich.panel import Panel as RichPanel
    from rich.prompt import Prompt, IntPrompt
    from rich.text import Text
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None

# ====================================================================
# SECTION 1: CORE FUNCTIONS
# ====================================================================

# --- Network Info ---

def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

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

def my_public_ip():
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read().decode().strip()
    except Exception as e:
        return str(e)

def network_interfaces():
    try:
        out = subprocess.check_output(["ipconfig", "/all"], shell=False, text=True, encoding="utf-8", errors="replace")
        return out[:3000]
    except Exception as e:
        return str(e)

def system_info():
    return "\n".join([
        f"OS: {platform.system()} {platform.release()}",
        f"Machine: {platform.machine()}",
        f"Hostname: {get_hostname()}",
        f"Python: {platform.python_version()}",
    ])

def get_drive_info():
    if platform.system().lower() != "windows":
        return "Windows only"
    try:
        drives = [f"{l}:\\" for l in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{l}:\\")]
        return "Drives: " + ", ".join(drives) if drives else "No drives found"
    except Exception as e:
        return str(e)

def get_drive_letters_short():
    if platform.system().lower() != "windows":
        return ""
    try:
        drives = [f"{l}:\\" for l in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{l}:\\")]
        return ", ".join(drives)
    except Exception:
        return ""

# --- ARP & Devices ---

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
        ping_host(f"{base}.{i}")
    return get_connected_devices()

def get_mac_vendor(mac):
    mac_upper = mac.replace("-", ":").upper()[:8]
    vendors = {
        "00:50:56": "VMware", "00:0C:29": "VMware", "00:1A:2B": "Cisco", "08:00:27": "VirtualBox",
        "52:54:00": "QEMU", "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
        "F4:5C:89": "Apple", "00:1E:C2": "Apple", "28:CF:E9": "Apple", "AC:DE:48": "Apple", "D0:03:4B": "Apple",
        "00:17:88": "Philips Hue", "94:B9:7E": "TP-Link", "50:C7:BF": "TP-Link", "C0:25:E9": "TP-Link",
        "F8:1A:67": "TP-Link", "E4:D3:32": "Xiaomi", "64:CC:2E": "Xiaomi", "34:80:B3": "Intel",
        "8C:EC:4B": "Intel", "30:65:EC": "Intel",
    }
    for prefix, name in vendors.items():
        if mac_upper.startswith(prefix.replace(":", "")) or mac.replace("-", ":").upper().startswith(prefix):
            return name
    return "Unknown"

def mac_vendor_api(mac):
    mac_clean = mac.replace(":", "").replace("-", "").upper()[:6]
    try:
        url = f"https://api.macvendors.com/{mac_clean}"
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        return "Unknown"

# --- ARP Monitor ---

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
                    msg = f"[!] ARP CHANGE: {ip} was {last_mac} now {mac} - POSSIBLE SPOOFING"
                    alerts.append(msg)
                    history[ip].append((now, mac))
                    if on_change_callback:
                        on_change_callback(msg)
        time.sleep(check_interval)
    return alerts

def arp_guard_scan(duration_sec=10):
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
                alerts.append(f"ALERT: {ip} changed MAC {history[ip]} -> {mac} (possible ARP spoofing)")
                history[ip] = mac
        time.sleep(2)
    if not alerts:
        return f"ARP Guard: No changes detected in {duration_sec} sec. OK."
    return "ARP Guard - Alerts:\n" + "\n".join(alerts)

# --- Ping ---

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
        if ping_one(f"{base}.{i}"):
            alive.append(f"{base}.{i}")
    return alive

def ping_latency(ip, count=4):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        out = subprocess.run(["ping", param, str(count), ip], capture_output=True, text=True, timeout=count * 3).stdout
        ms = re.findall(r"(?:temps?|time)=?\s*(\d+)\s*ms?", out, re.I)
        return [int(m) for m in ms]
    except Exception:
        return []

def ping_stats(host, count=10):
    times = ping_latency(host, count=count)
    if not times:
        return "Host unreachable"
    mn, mx = min(times), max(times)
    avg = sum(times) / len(times)
    jitter = (sum(abs(times[i] - times[i - 1]) for i in range(1, len(times))) / (len(times) - 1)) if len(times) > 1 else 0
    return f"Min: {mn} ms | Max: {mx} ms | Avg: {avg:.1f} ms | Jitter: {jitter:.1f} ms"

def ping_packet_loss(host, count=10):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        out = subprocess.run(["ping", param, str(count), host], capture_output=True, text=True, timeout=count * 2 + 5).stdout or ""
        m = re.search(r"Lost\s*=\s*(\d+)\s*\((\d+)\s*%", out, re.I)
        if m:
            return f"Packet loss: {m.group(2)}% ({m.group(1)} lost)"
        m = re.search(r"(\d+)%\s*loss", out, re.I)
        if m:
            return f"Packet loss: {m.group(1)}%"
        return out[-500:]
    except Exception as e:
        return str(e)

# --- DNS ---

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

def dns_servers_in_use():
    dns = get_dns_servers_windows()
    if not dns:
        return "No DNS servers found (ipconfig /all)"
    return "DNS in use: " + ", ".join(dns)

def dns_leak_check():
    dns = get_dns_servers_windows()
    lines = [f"=== DNS Check ===\nYour DNS: {', '.join(dns) if dns else 'None found'}\n"]
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=5) as r:
            lines.append(f"Public IP: {r.read().decode().strip()}\n")
    except Exception as e:
        lines.append(f"Public IP: Error {e}\n")
    if dns:
        if "8.8.8.8" in dns or "1.1.1.1" in dns:
            lines.append("Using public DNS (Google/Cloudflare).\n")
        else:
            lines.append("Using ISP/other DNS.\n")
    return "".join(lines)

# --- Port Scan ---

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt",
}

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

def port_range_scan(ip, start, end, timeout=0.5):
    return scan_ports(ip, ports=list(range(start, end + 1)), timeout=timeout)

def local_listening_ports():
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
                if f":{port}" in line and "LISTENING" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        return f"Port {port} used by PID: {parts[-1]}"
        return "Windows only (netstat -ano)"
    except Exception as e:
        return str(e)

def port_to_process_windows(port):
    try:
        out = subprocess.check_output(["netstat", "-ano"], shell=False, text=True, encoding="utf-8", errors="replace")
        pid = None
        for line in out.splitlines():
            if f":{port} " in line or f":{port}\t" in line:
                parts = line.split()
                if len(parts) >= 5 and parts[-1].isdigit():
                    pid = parts[-1]
                    break
        if not pid:
            return f"No process found on port {port}"
        out2 = subprocess.check_output(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV"], shell=False, text=True, encoding="utf-8", errors="replace")
        return f"Port {port} -> PID {pid}\n{out2[:500]}"
    except Exception as e:
        return str(e)

# --- Connections ---

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

def connection_state_summary():
    try:
        out = subprocess.check_output(["netstat", "-an"], shell=False, text=True, encoding="utf-8", errors="replace")
        counts = {}
        for line in out.splitlines():
            for state in ["ESTABLISHED", "LISTENING", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT"]:
                if state in line:
                    counts[state] = counts.get(state, 0) + 1
                    break
        return "\n".join(f"{k}: {v}" for k, v in sorted(counts.items(), key=lambda x: -x[1]))
    except Exception as e:
        return str(e)

def netstat_summary():
    try:
        out = subprocess.check_output(["netstat", "-an"], shell=False, text=True, encoding="utf-8", errors="replace")
        est = sum(1 for line in out.splitlines() if "ESTABLISHED" in line)
        lis = sum(1 for line in out.splitlines() if "LISTENING" in line)
        return f"ESTABLISHED: {est}  |  LISTENING: {lis}"
    except Exception as e:
        return str(e)

# --- Traceroute / Whois / TCP ---

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

def tcp_connect_test(host, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, int(port)))
        s.close()
        return f"OK - {host}:{port} reachable"
    except Exception as e:
        return f"FAIL - {e}"

# --- Netcat ---

def netcat_connect(host, port, send_data=None, timeout=5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, int(port)))
        out = []
        if send_data:
            s.sendall(send_data.encode() if isinstance(send_data, str) else send_data)
        try:
            while True:
                buf = s.recv(4096)
                if not buf:
                    break
                out.append(buf.decode("utf-8", errors="replace"))
        except socket.timeout:
            pass
        s.close()
        received = "".join(out)
        if received:
            return f"Connected to {host}:{port}\n\nReceived:\n{received}"
        return f"Connected to {host}:{port} (no data received)"
    except Exception as e:
        return f"FAIL - {e}"

def netcat_listen(port, timeout=30):
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
        conn.close(); s.close()
        received = "".join(out)
        if received:
            return f"Connection from {addr[0]}:{addr[1]}\n\nReceived:\n{received}"
        return f"Connection from {addr[0]}:{addr[1]} (no data)"
    except socket.timeout:
        return f"Listen on port {port}: timeout"
    except Exception as e:
        return f"FAIL - {e}"

# --- HTTP / SSL ---

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
    hdrs = get_headers(url)
    if "Error" in hdrs:
        return [hdrs["Error"]]
    important = ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options",
                 "Content-Security-Policy", "X-XSS-Protection"]
    results = []
    for h in important:
        for k, v in hdrs.items():
            if k.lower() == h.lower():
                results.append(f"[OK] {k}: {v}")
                break
        else:
            results.append(f"[--] Missing: {h}")
    return results

def get_all_http_headers(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    except Exception as e:
        return str(e)

def http_status(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return f"UP - Status: {r.status}"
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}"
    except Exception as e:
        return f"DOWN - {e}"

def ssl_cert_info(host, port=443):
    try:
        hostname = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return f"Valid until: {ssock.getpeercert()['notAfter']}"
    except Exception as e:
        return str(e)

def http_method_test(url, method="GET"):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        req = urllib.request.Request(url, method=method.upper(), headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return f"{method.upper()} - Status: {r.status}"
    except urllib.error.HTTPError as e:
        return f"{method.upper()} - Status: {e.code}"
    except Exception as e:
        return f"{method.upper()} - {e}"

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

# --- Subnet / CIDR ---

def subnet_info(cidr):
    try:
        import ipaddress
        net = ipaddress.ip_network(cidr, strict=False)
        return {
            "network": str(net.network_address), "netmask": str(net.netmask),
            "broadcast": str(net.broadcast_address), "hosts_count": net.num_addresses - 2,
            "first_host": str(list(net.hosts())[0]) if net.num_addresses > 2 else "N/A",
            "last_host": str(list(net.hosts())[-1]) if net.num_addresses > 2 else "N/A",
        }
    except Exception as e:
        return {"error": str(e)}

def cidr_to_range(cidr):
    try:
        import ipaddress
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        if not hosts:
            return "No hosts (e.g. /32)"
        return f"First: {hosts[0]}  |  Last: {hosts[-1]}  |  Count: {len(hosts)}"
    except Exception as e:
        return str(e)

# --- Converters ---

def ip_to_decimal(ip):
    try:
        parts = [int(x) for x in ip.split(".")]
        return str(parts[0] * 256**3 + parts[1] * 256**2 + parts[2] * 256 + parts[3])
    except Exception:
        return "Invalid IP"

def decimal_to_ip(n):
    try:
        n = int(n)
        return f"{(n >> 24) & 255}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"
    except Exception:
        return "Invalid number"

def hex_to_bin(hex_s):
    try:
        return bin(int(hex_s.replace("0x", "").replace(" ", ""), 16))
    except Exception:
        return "Invalid hex"

def bin_to_hex(bin_s):
    try:
        return hex(int(bin_s.replace("0b", "").replace(" ", ""), 2))
    except Exception:
        return "Invalid binary"

def hex_to_binary(hex_str):
    try:
        return bin(int(hex_str.replace(" ", ""), 16))[2:]
    except Exception:
        return "Invalid hex"

def binary_to_hex(bin_str):
    try:
        return hex(int(bin_str.replace(" ", ""), 2))[2:].upper()
    except Exception:
        return "Invalid binary"

def url_encode(s):
    return urllib.parse.quote(s, safe="")

def url_decode(s):
    return urllib.parse.unquote(s)

def base64_encode(s):
    return base64.b64encode(s.encode("utf-8", errors="replace")).decode("ascii")

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

def bytes_to_units(n):
    try:
        n = int(n)
        if n < 1024: return f"{n} B"
        if n < 1024**2: return f"{n / 1024:.2f} KB"
        if n < 1024**3: return f"{n / 1024**2:.2f} MB"
        return f"{n / 1024**3:.2f} GB"
    except Exception:
        return "Invalid"

# --- Hash & Password ---

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

def random_password(length=16, with_special=True):
    chars = string.ascii_letters + string.digits
    if with_special:
        chars += "!@#$%&*"
    return "".join(random.SystemRandom().choice(chars) for _ in range(length))

def password_strength(pwd):
    if not pwd:
        return "Empty"
    score = (len(pwd) >= 8) + (len(pwd) >= 12) + any(c.isupper() for c in pwd) + \
             any(c.islower() for c in pwd) + any(c.isdigit() for c in pwd) + \
             any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd)
    return ["Very weak", "Weak", "Fair", "Good", "Strong", "Very strong", "Excellent"][min(score, 6)]

# --- Misc ---

def uuid_generate():
    return str(uuid_mod.uuid4())

def timestamp_to_date(ts):
    try:
        return datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "Invalid"

def json_validate(s):
    try:
        json.loads(s); return "Valid JSON"
    except json.JSONDecodeError as e:
        return f"Invalid: {e}"

def random_ip():
    k = random.choice([1, 2, 3])
    if k == 1: return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    if k == 2: return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(0,255)}"
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"

def user_agent_string():
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"

def ip_geolocation(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,lat,lon"
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityNetwork"})
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read().decode())
            return " | ".join(f"{k}: {v}" for k, v in d.items() if v)
    except Exception as e:
        return str(e)

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
        return f"Magic packet sent to {mac}"
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

def hosts_file_content():
    path = r"C:\Windows\System32\drivers\etc\hosts" if platform.system().lower() == "windows" else "/etc/hosts"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()[:5000]
    except Exception as e:
        return str(e)

# --- Firewall & Route ---

def firewall_status():
    if platform.system().lower() != "windows":
        return "Windows only"
    try:
        out = subprocess.check_output(["netsh", "advfirewall", "show", "currentprofile"], shell=False, text=True, encoding="utf-8", errors="replace")
        return out[:1500]
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

# --- WiFi ---

def get_wifi_adapter_name():
    if platform.system().lower() != "windows":
        return "WiFi"
    try:
        out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], shell=False, text=True, encoding="utf-8", errors="replace")
        for line in out.splitlines():
            if "Description" in line and ":" in line:
                return line.split(":", 1)[-1].strip() or "WiFi"
    except Exception:
        pass
    return "WiFi"

def wifi_networks_list():
    try:
        out = subprocess.check_output(["netsh", "wlan", "show", "networks"], shell=False, text=True, encoding="utf-8", errors="replace")
        return out
    except Exception as e:
        return str(e)

def wifi_analyzer_networks():
    if platform.system().lower() != "windows":
        return []
    try:
        out = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"], shell=False, text=True, encoding="utf-8", errors="replace")
    except Exception:
        return []
    networks = []
    current = None
    for line in out.splitlines():
        ls = line.strip()
        if ls.startswith("SSID ") and ":" in ls:
            if current and current.get("ssid") is not None:
                networks.append(dict(current))
            current = {"ssid": ls.split(":", 1)[-1].strip(), "bssid": "", "signal": 0, "channel": 0, "auth": "", "encryption": ""}
        elif current is None:
            continue
        elif ls.startswith("BSSID ") and ":" in ls:
            if current.get("bssid"):
                networks.append(dict(current))
            current["bssid"] = ls.split(":", 1)[-1].strip()
            current["signal"] = 0; current["channel"] = 0
        elif "Signal" in ls and ":" in ls:
            try:
                current["signal"] = int(ls.split(":", 1)[-1].strip().replace("%", "").strip())
            except ValueError:
                pass
        elif ls.startswith("Channel") and ":" in ls:
            try:
                current["channel"] = int(ls.split(":", 1)[-1].strip())
            except ValueError:
                pass
        elif "Authentication" in ls and ":" in ls:
            current["auth"] = ls.split(":", 1)[-1].strip()
        elif "Encryption" in ls and ":" in ls:
            current["encryption"] = ls.split(":", 1)[-1].strip()
    if current and current.get("ssid") is not None:
        networks.append(current)
    return networks

def wifi_saved_profiles():
    if platform.system().lower() != "windows":
        return "Windows only"
    try:
        out = subprocess.check_output(["netsh", "wlan", "show", "profiles"], shell=False, text=True, encoding="utf-8", errors="replace")
        return out[:2000]
    except Exception as e:
        return str(e)

def signal_pct_to_dbm(pct):
    if pct is None or pct < 0: pct = 0
    if pct > 100: pct = 100
    return -50 - (100 - pct) * 0.5

def channel_to_band(ch):
    if not ch or ch <= 0: return chr(8212)
    if ch <= 14: return "2.4 GHz"
    if ch <= 165: return "5 GHz"
    return "6 GHz"

def wifi_channel_analysis(networks=None):
    if networks is None:
        networks = wifi_analyzer_networks()
    channels = {}
    for n in networks:
        ch = n.get("channel") or 0
        if ch > 0:
            channels[ch] = channels.get(ch, 0) + 1
    if not channels:
        return "No channel data"
    best = min(channels.keys(), key=lambda c: channels[c])
    return f"Channels: {channels}\nSuggested: Channel {best}"

# --- Speed Test ---

def speed_test(download_url=None):
    if download_url is None:
        download_url = "https://speed.hetzner.de/1MB.bin"
    try:
        req = urllib.request.Request(download_url, headers={"User-Agent": "SecurityNetwork"})
        start = time.time()
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
        elapsed = time.time() - start
        if elapsed <= 0:
            return 0, 0, "Too fast"
        mbps = round((len(data) * 8 / 1_000_000) / elapsed, 2)
        return mbps, round(elapsed, 2), f"{len(data)/(1024*1024):.2f} MB in {elapsed:.2f} s"
    except Exception as e:
        return 0, 0, str(e)

# --- Export ---

def export_wifi_scan_to_file(path=None):
    networks = wifi_analyzer_networks()
    if path is None: path = "wifi_scan_export.txt"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("Security Network - WiFi Scan Export\nSSID | BSSID | Channel | Signal | Security\n" + "-"*60 + "\n")
            for n in networks:
                f.write(f"{n.get('ssid','')} | {n.get('bssid','')} | {n.get('channel','')} | {n.get('signal','')} | {n.get('auth','')}\n")
        return f"Exported {len(networks)} networks to {path}"
    except Exception as e:
        return str(e)

def export_devices_to_file(path=None):
    devices = get_connected_devices()
    if path is None: path = "devices_export.txt"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("Security Network - Devices Export\nIP | MAC | Vendor\n" + "-"*50 + "\n")
            for ip, mac in devices:
                f.write(f"{ip} | {mac} | {get_mac_vendor(mac)}\n")
        return f"Exported {len(devices)} devices to {path}"
    except Exception as e:
        return str(e)

# --- Security Audit ---

def wifi_security_scan():
    networks = wifi_analyzer_networks()
    if not networks:
        return "No WiFi networks found."
    open_n = [n for n in networks if "Open" in (n.get("auth") or "")]
    wep_n = [n for n in networks if "WEP" in (n.get("auth") or "")]
    wpa_n = [n for n in networks if "WPA2" in (n.get("auth") or "") or "WPA3" in (n.get("auth") or "")]
    lines = [f"Open (no password): {len(open_n)} - RISK\n"]
    for n in open_n[:5]: lines.append(f"  - {n.get('ssid','')} ({n.get('bssid','')})\n")
    lines.append(f"WEP (weak): {len(wep_n)} - RISK\n")
    for n in wep_n[:5]: lines.append(f"  - {n.get('ssid','')} ({n.get('bssid','')})\n")
    lines.append(f"WPA2/WPA3 (strong): {len(wpa_n)} - OK\n")
    return "".join(lines)

def listening_ports_security():
    ports = get_listening_ports()
    risky = {21: "FTP", 23: "Telnet", 135: "RPC", 445: "SMB", 3389: "RDP", 5900: "VNC"}
    lines = ["=== Listening Ports (Security) ===\n"]
    for p in ports[:50]:
        note = risky.get(p, "")
        lines.append(f"Port {p} {f'- {note} - REVIEW' if note else ''}\n")
    if len(ports) > 50:
        lines.append(f"... and {len(ports)-50} more\n")
    return "".join(lines)

def security_audit_quick():
    fw = firewall_status()
    dns = get_dns_servers_windows()
    networks = wifi_analyzer_networks()
    open_n = len([n for n in networks if "Open" in (n.get("auth") or "")])
    ports = get_listening_ports()
    return f"Firewall: {'ON' if 'ON' in fw.upper() else 'Check'}\nDNS: {', '.join(dns) if dns else 'None'}\nWiFi: {len(networks)} nets, {open_n} open\nListening ports: {len(ports)}"

def get_hosts_file():
    return hosts_file_content()

def get_system_info():
    return system_info()

# ====================================================================
# SECTION 2: ADVANCED SECURITY CLASSES
# ====================================================================

class AntiHackingProtection:
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_ports = set()
        self.blocked_mac_addresses = set()
        self.intrusion_attempts = []
        self.auto_block_enabled = True
        self.monitoring_active = False
        self.connection_history = {}
        self.db_file = "hacking_protection.json"
        self.load_data()

    def load_data(self):
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    d = json.load(f)
                    self.blocked_ips = set(d.get('blocked_ips', []))
                    self.blocked_ports = set(d.get('blocked_ports', []))
                    self.intrusion_attempts = d.get('intrusion_attempts', [])
            except: pass

    def save_data(self):
        try:
            with open(self.db_file, 'w') as f:
                json.dump({'blocked_ips': list(self.blocked_ips), 'blocked_ports': list(self.blocked_ports),
                    'blocked_mac_addresses': list(self.blocked_mac_addresses),
                    'intrusion_attempts': self.intrusion_attempts, 'auto_block_enabled': self.auto_block_enabled,
                    'connection_history': self.connection_history, 'last_updated': datetime.now().isoformat()}, f, indent=2)
        except: pass

    def detect_suspicious_activity(self):
        if not HAS_PSUTIL: return []
        suspicious = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    remote_ip = conn.raddr[0] if conn.raddr else None
                    if remote_ip and self.is_suspicious_ip(remote_ip):
                        suspicious.append({'type': 'suspicious_connection', 'ip': remote_ip,
                            'port': conn.raddr[1] if conn.raddr else None, 'pid': conn.pid,
                            'timestamp': datetime.now().isoformat()})
        except: pass
        return suspicious

    def is_local_ip(self, ip):
        return ip.startswith(('127.', '192.168.', '10.', '172.16.', '169.254.'))

    def is_suspicious_ip(self, ip):
        if ip in self.blocked_ips: return True
        if self.is_local_ip(ip): return False
        if ip in self.connection_history and len(self.connection_history[ip]) > 10: return True
        return False

    def block_ip(self, ip):
        if ip in self.blocked_ips: return
        self.blocked_ips.add(ip)
        self.save_data()
        if platform.system() == 'Windows':
            try:
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=BlockIP_{ip.replace(".", "_")}', 'dir=in', 'action=block', f'remoteip={ip}'],
                    check=False, capture_output=True, timeout=5)
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=BlockIP_Out_{ip.replace(".", "_")}', 'dir=out', 'action=block', f'remoteip={ip}'],
                    check=False, capture_output=True, timeout=5)
            except: pass
        return True

    def scan_for_hacking_tools(self):
        if not HAS_PSUTIL: return []
        tools = ['nmap', 'wireshark', 'metasploit', 'burpsuite', 'sqlmap', 'john', 'hashcat', 'aircrack', 'ettercap', 'cain']
        detected = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pn = proc.info['name'].lower()
                for t in tools:
                    if t in pn:
                        detected.append({'process': proc.info['name'], 'pid': proc.info['pid'], 'tool': t,
                            'timestamp': datetime.now().isoformat()})
            except: continue
        return detected

    def start_monitoring(self):
        if self.monitoring_active: return
        self.monitoring_active = True
        def loop():
            while self.monitoring_active:
                try:
                    for item in self.detect_suspicious_activity():
                        if self.auto_block_enabled and 'ip' in item:
                            self.block_ip(item['ip'])
                    time.sleep(5)
                except: time.sleep(10)
        threading.Thread(target=loop, daemon=True).start()

    def stop_monitoring(self):
        self.monitoring_active = False

class AntiSpywareAdvanced:
    def __init__(self):
        self.spyware_signatures = ['keylogger', 'spy', 'monitor', 'tracker', 'recorder', 'capture',
            'screen', 'webcam', 'microphone', 'keystroke', 'log', 'stealer', 'sniffer', 'eavesdrop']
        self.db_file = "spyware_protection.json"

    def detect_keyloggers(self):
        if not HAS_PSUTIL: return []
        found = []
        suspicious = ['keylog', 'keystroke', 'keycapture', 'keymonitor', 'keyrecorder', 'keytrack', 'keyhook', 'keylogger']
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pn = proc.info['name'].lower()
                for s in suspicious:
                    if s in pn:
                        found.append({'process': proc.info['name'], 'pid': proc.info['pid'],
                            'path': proc.info.get('exe', 'Unknown'), 'type': 'keylogger',
                            'timestamp': datetime.now().isoformat()})
            except: continue
        return found

    def detect_remote_access(self):
        if not HAS_PSUTIL: return []
        found = []
        suspicious = ['teamviewer', 'anydesk', 'remote', 'vnc', 'rdp', 'logmein', 'gotomypc', 'chrome remote', 'ultravnc']
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pn = proc.info['name'].lower()
                for s in suspicious:
                    if s in pn:
                        found.append({'process': proc.info['name'], 'pid': proc.info['pid'],
                            'type': 'remote_access', 'timestamp': datetime.now().isoformat()})
            except: continue
        return found

class IntrusionDetectionSystem:
    def __init__(self):
        self.intrusion_log = []
        self.db_file = "intrusion_detection.json"
        self.load_log()

    def load_log(self):
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    self.intrusion_log = json.load(f).get('intrusions', [])
            except: self.intrusion_log = []

    def save_log(self):
        try:
            with open(self.db_file, 'w') as f:
                json.dump({'intrusions': self.intrusion_log[-1000:], 'last_updated': datetime.now().isoformat()}, f, indent=2)
        except: pass

    def detect_intrusion(self):
        if not HAS_PSUTIL: return []
        intrusions = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    rip = conn.raddr[0] if conn.raddr else None
                    if rip and not rip.startswith(('127.', '192.168.', '10.', '172.16.')):
                        if conn.raddr and conn.raddr[1] in [4444, 5555, 6666, 1234, 31337]:
                            intrusions.append({'type': 'suspicious_port', 'ip': rip, 'port': conn.raddr[1],
                                'pid': conn.pid, 'severity': 'high', 'timestamp': datetime.now().isoformat()})
        except: pass
        if intrusions:
            self.intrusion_log.extend(intrusions)
            self.save_log()
        return intrusions

class KeyloggerDetector:
    def __init__(self):
        self.db_file = "keylogger_detection.json"

    def scan_for_keyloggers(self):
        if not HAS_PSUTIL: return []
        keyloggers = []
        suspicious = ['keylog', 'keystroke', 'keycapture', 'keymonitor', 'keyrecorder', 'keytrack', 'keyhook', 'logger']
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                pn = proc.info['name'].lower()
                cl = ' '.join(proc.info.get('cmdline', [])).lower()
                for s in suspicious:
                    if s in pn or s in cl:
                        keyloggers.append({'type': 'process', 'name': proc.info['name'], 'pid': proc.info['pid'],
                            'path': proc.info.get('exe', 'Unknown'), 'timestamp': datetime.now().isoformat()})
            except: continue
        for loc in [os.path.expanduser('~/AppData/Roaming'), os.path.expanduser('~/AppData/Local'),
                     'C:\\Windows\\System32', 'C:\\Windows\\Temp']:
            if os.path.exists(loc):
                try:
                    for root, dirs, files in os.walk(loc):
                        for f in files:
                            fl = f.lower()
                            for s in suspicious:
                                if s in fl:
                                    keyloggers.append({'type': 'file', 'name': f, 'path': os.path.join(root, f),
                                        'timestamp': datetime.now().isoformat()})
                except: continue
        return keyloggers

class ScreenCaptureProtection:
    def __init__(self):
        self.allowed = {'snippingtool', 'xbox', 'msedge', 'chrome', 'firefox'}

    def detect_screen_capture(self):
        if not HAS_PSUTIL: return []
        detected = []
        suspicious = ['screenshot', 'capture', 'recorder', 'snapshot', 'grab', 'screen', 'record']
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pn = proc.info['name'].lower()
                if pn in self.allowed: continue
                for s in suspicious:
                    if s in pn:
                        detected.append({'process': proc.info['name'], 'pid': proc.info['pid'],
                            'timestamp': datetime.now().isoformat()})
            except: continue
        return detected

class DataLeakPrevention:
    def __init__(self):
        self.patterns = [r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', r'\b\d{3}-\d{2}-\d{4}\b',
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', r'password\s*[:=]\s*\S+', r'api[_-]?key\s*[:=]\s*\S+']
        self.db_file = "data_leak_prevention.json"

    def detect_data_leak(self, file_path):
        leaks = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for p in self.patterns:
                    m = re.findall(p, content, re.IGNORECASE)
                    if m:
                        leaks.append({'file': file_path, 'pattern': p, 'matches': len(m),
                            'timestamp': datetime.now().isoformat()})
        except: pass
        return leaks

class NetworkIntrusionDetection:
    def __init__(self):
        self.suspicious_ports = [4444, 5555, 6666, 1234, 31337, 8080, 8888]
        self.db_file = "network_intrusion.json"

    def detect_suspicious_connections(self):
        if not HAS_PSUTIL: return []
        suspicious = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    rp = conn.raddr[1]; rip = conn.raddr[0]
                    if rp in self.suspicious_ports:
                        suspicious.append({'ip': rip, 'port': rp, 'pid': conn.pid, 'type': 'suspicious_port',
                            'timestamp': datetime.now().isoformat()})
        except: pass
        return suspicious

class PrivacyProtectionAdvanced:
    def __init__(self):
        self.webcam_blocked = False
        self.microphone_blocked = False
        self.db_file = "privacy_protection.json"

    def block_webcam(self):
        self.webcam_blocked = True
        if platform.system() == 'Windows':
            try:
                subprocess.run(['reg', 'add', r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam',
                    '/v', 'Value', '/t', 'REG_SZ', '/d', 'Deny', '/f'], check=False, capture_output=True)
            except: pass

    def block_microphone(self):
        self.microphone_blocked = True
        if platform.system() == 'Windows':
            try:
                subprocess.run(['reg', 'add', r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone',
                    '/v', 'Value', '/t', 'REG_SZ', '/d', 'Deny', '/f'], check=False, capture_output=True)
            except: pass


# ====================================================================
# SECTION 3: CLI APPLICATION
# ====================================================================

def _print(*a, **k):
    if RICH: console.print(*a, **k)
    else: print(*a, **k)

def _prompt(msg, default=None):
    if RICH: return Prompt.ask(msg, default=default)
    return input(msg + (f" [{default}] " if default else " ")).strip() or default

def _int_prompt(msg, default=60):
    if RICH: return IntPrompt.ask(msg, default=default)
    s = input(msg + f" [{default}] ").strip() or str(default)
    try: return int(s)
    except ValueError: return default

def cli_set_window_title():
    try:
        if platform.system().lower() == "windows":
            os.system(f"title {APP_NAME} v{APP_VERSION}")
    except: pass

def cli_show_banner():
    sep = "=" * 50
    if RICH:
        console.print(RichPanel(f"[bold cyan]{APP_NAME}[/bold cyan]\n[bold]v{APP_VERSION}[/bold]\n[dim]{APP_TAGLINE}[/dim]",
            title="[bold white] Application [/bold white]", border_style="cyan", padding=(0, 2)))
    else:
        _print(sep); _print(f"  {APP_NAME}  |  v{APP_VERSION}"); _print(f"  {APP_TAGLINE}"); _print(sep)

def cli_show_dashboard():
    my_ip = get_my_ip(); gw = get_gateway_windows(); hostname = get_hostname()
    try:
        pub = my_public_ip()
        if not pub or "error" in str(pub).lower(): pub = chr(8212)
    except: pub = chr(8212)
    devices = get_connected_devices(); conns = get_connections_windows()
    if RICH:
        t = RichTable(show_header=False, title="  Dashboard | 7stat  ", border_style="green")
        t.add_column("Stat", style="cyan"); t.add_column("Value", style="white")
        for k, v in [("Application", f"{APP_NAME} v{APP_VERSION}"), ("Tagline", APP_TAGLINE),
            ("Total tools", str(TOTAL_TOOLS)), (chr(8212), chr(8212)), ("My IP (local)", my_ip),
            ("Public IP", pub if pub and len(str(pub)) < 20 else f"{str(pub)[:30]}\u2026" if pub else chr(8212)),
            ("Gateway", gw or chr(8212)), ("Hostname", hostname), ("OS", f"{platform.system()} {platform.release()}"),
            (chr(8212), chr(8212)), ("Devices in ARP", str(len(devices))), ("Active connections", str(len(conns)))]:
            t.add_row(k, v)
        console.print(RichPanel(t, title="[bold] Application PC | i7rafiya [/bold]", border_style="blue", padding=(0, 1)))
    else:
        sep = "-" * 40
        _print(sep); _print("  DASHBOARD | 7stat"); _print(sep)
        _print(f"  Application : {APP_NAME} v{APP_VERSION}")
        _print(f"  {APP_TAGLINE}"); _print(f"  Total tools : {TOTAL_TOOLS}"); _print(sep)
        _print(f"  My IP       : {my_ip}"); _print(f"  Public IP   : {pub[:25] if pub else chr(8212)}")
        _print(f"  Gateway     : {gw or chr(8212)}"); _print(f"  Hostname    : {hostname}")
        _print(f"  OS          : {platform.system()} {platform.release()}"); _print(sep)
        _print(f"  Devices (ARP): {len(devices)}"); _print(f"  Connections : {len(conns)}"); _print(sep)

def cli_menu():
    return f"""
[{APP_NAME}]  v{APP_VERSION}  |  {APP_TAGLINE}
H.  Dashboard (7stat)
W.  WiFi Analyzer  |  S. Speed test  |  C. Channel finder
1.  Chkon m3ak f WiFi - Scan devices
2.  ARP Guard - Detect spoofing/kick
3.  Port Scanner
4.  Ping Sweep
5.  DNS Lookup / Reverse DNS
6.  My Network Info
7.  Traceroute
8.  My Public IP
9.  WiFi networks list
10. Flush DNS cache
11. Renew DHCP
12. HTTP Status
13. HTTP Security Headers
14. All HTTP Headers
15. SSL Certificate expiry
16. Whois
17. Active Connections
18. Local listening ports
19. Who uses this port?
20. Subnet Calculator (CIDR)
21. IP to/from Decimal
22. Hex to/from Binary
23. URL Encode / Decode
24. Base64 Encode / Decode
25. Hash (MD5, SHA256)
26. Random password
27. MAC Vendor Lookup
28. Ping One Host
29. Ping statistics (jitter)
30. IP Geolocation
31. Wake-on-LAN
32. Subnet full scan
33. System info
34. Hosts file viewer
35. File checksum
36. Password strength
37. UUID generator
38. Timestamp to date
39. URL expand
40. WiFi saved profiles
41. Connection state summary
42. Bytes to units
43. Hex encode/decode
44. Random IP
45. User-Agent string
46. Port range scanner
47. Netstat summary
48. JSON validator
49. Route table
50. ARP table full
51. Firewall status
52. Ping with packet loss
53. TCP connection test
54. CIDR to IP range
55. HTTP method test
56. Export WiFi scan
57. Export devices
58. DNS servers in use
59. Network interfaces
0.  Exit
--- {APP_NAME} | {APP_TAGLINE} ---"""

def cli_wifi_scanner_full_view():
    networks = wifi_analyzer_networks()
    adapter = get_wifi_adapter_name()
    if not networks:
        _print("No networks found.")
        return
    bands, ssids, vendors, securities, sigs = set(), set(), set(), set(), set()
    ch_usage = {}
    for n in networks:
        ch = n.get("channel") or 0
        bands.add(channel_to_band(ch))
        ssids.add((n.get("ssid") or "").strip())
        bssid = n.get("bssid") or ""
        if bssid:
            v = get_mac_vendor(bssid)
            if v != "Unknown": vendors.add(v)
        sec = (n.get("auth") or "").strip()
        if sec: securities.add(sec)
        sig = n.get("signal") or 0
        if sig > 0: sigs.add(str(int(signal_pct_to_dbm(sig))))
        if ch > 0: ch_usage[ch] = ch_usage.get(ch, 0) + 1
    max_c = max(ch_usage.values()) if ch_usage else 1
    if RICH:
        top = Text()
        top.append("WIFI Scanner", style="bold cyan"); top.append(f"  |  {adapter}  |  Scanner", style="white")
        console.print(RichPanel(top, border_style="blue", padding=(0, 1)))
        stats = f"Band: {len(bands)}  SSID: {len(ssids)}  BSSID: {len(networks)}  Vendor: {len(vendors)}  Security: {len(securities)}  Signal: {len(sigs)}"
        console.print(RichPanel(stats, title="Filters", border_style="green", padding=(0, 1)))
        t = RichTable(title=f"Showing {min(50,len(networks))} of {len(networks)}", show_lines=False)
        t.add_column("SSID", style="cyan"); t.add_column("BSSID", style="dim"); t.add_column("Vendor", style="yellow")
        t.add_column("Ch", style="white"); t.add_column("Band", style="green"); t.add_column("Signal", style="red"); t.add_column("Security", style="white")
        for n in networks[:50]:
            t.add_row((n.get("ssid") or "")[:22], (n.get("bssid") or "")[:17],
                (get_mac_vendor(n.get("bssid") or "") or chr(8212))[:18], str(n.get("channel") or chr(8212)),
                channel_to_band(n.get("channel")), f'{int(signal_pct_to_dbm(n.get("signal") or 0))} dBm',
                (n.get("auth") or chr(8212))[:16])
        console.print(t)
        if ch_usage:
            spec = ["[bold]Spectrum[/bold]"]
            for ch in sorted(ch_usage):
                bl = max(1, int(20 * ch_usage[ch] / max_c))
                spec.append(f"[{'#'*bl}] Ch {ch} ({ch_usage[ch]})")
            console.print(RichPanel("\n".join(spec), title="Spectrum", border_style="blue", padding=(0, 1)))
    else:
        sep = "=" * 70
        _print(sep); _print(f"WIFI Scanner | {adapter}"); _print(sep)
        _print(f"Band: {len(bands)}  SSID: {len(ssids)}  BSSID: {len(networks)}  Vendor: {len(vendors)}  Security: {len(securities)}  Signal: {len(sigs)}")
        print("-" * 70)
        print(f"{'SSID':<22} {'BSSID':<18} {'Vendor':<12} {'Ch':<6} {'Band':<8} {'Signal':<8} Security")
        print("-" * 70)
        for n in networks[:50]:
            print(f"{(n.get('ssid') or ''):<22} {(n.get('bssid') or ''):<18} {(get_mac_vendor(n.get('bssid') or '') or chr(8212)):<12} {n.get('channel') or chr(8212):<6} {channel_to_band(n.get('channel')):<8} {int(signal_pct_to_dbm(n.get('signal') or 0))} dBm   {(n.get('auth') or chr(8212)):<16}")
        print("-" * 70)
        _print(f"Showing {min(50,len(networks))} of {len(networks)}")
        if ch_usage:
            for ch in sorted(ch_usage):
                bl = max(1, int(20 * ch_usage[ch] / max_c))
                _print(f"  Ch {ch:3} [{'#'*bl}] {ch_usage[ch]}")

# CLI Runner functions
def cli_run_wifi_scan():
    _print("Scanning devices..."); my_ip = get_my_ip(); _print(f"Your IP: {my_ip}")
    devices = scan_subnet_arp(my_ip) or get_connected_devices()
    if RICH:
        t = RichTable(title="Devices"); t.add_column("IP", style="cyan"); t.add_column("MAC", style="yellow"); t.add_column("Vendor", style="green")
        for ip, mac in devices: t.add_row(ip, mac, get_mac_vendor(mac))
        _print(t)
    else:
        _print("IP\t\tMAC\t\tVendor")
        for ip, mac in devices: _print(f"{ip}\t{mac}\t{get_mac_vendor(mac)}")
    _print(f"Total: {len(devices)} devices")

def cli_run_port_scan():
    ip = _prompt("IP or hostname")
    if ip and not ip.replace(".","").replace(":","").replace("-","").isdigit():
        ips = dns_lookup(ip); ip = ips[0] if ips else ip
    _print(f"Scanning ports on {ip}...")
    open_ports = scan_ports(ip, ports=list(COMMON_PORTS.keys()))
    if RICH:
        t = RichTable(title=f"Open ports on {ip}")
        t.add_column("Port", style="cyan"); t.add_column("Service", style="green")
        for p in open_ports: t.add_row(str(p), COMMON_PORTS.get(p, "?"))
        _print(t)
    else:
        for p in open_ports: _print(f"{p}\t{COMMON_PORTS.get(p, '?')}")

def cli_main():
    cli_set_window_title(); cli_show_banner(); cli_show_dashboard()
    while True:
        _print(cli_menu())
        choice = _prompt("Choice", "H").strip().upper()
        try:
            if choice == "0": _print("Bye!"); break
            runners = {
                "1": cli_run_wifi_scan, "2": lambda: (_print("ARP Guard..."),
                    monitor_arp_changes(_int_prompt("Seconds?", 60), on_change_callback=lambda m: _print(m)),
                    _print("Done.")),
                "3": cli_run_port_scan, "4": lambda: _print(f"Alive: {ping_sweep(_prompt('Subnet (e.g. 192.168.1)', '192.168.1'))}"),
                "5": lambda: (lambda h: _print(f"{h} -> {dns_lookup(h)}") if (h:=_prompt("Hostname")) else None)(),
                "6": lambda: _print(f"IP: {get_my_ip()}\nHostname: {get_hostname()}\nGateway: {get_gateway_windows() or 'N/A'}\nDNS: {', '.join(get_dns_servers_windows()) or 'N/A'}"),
                "7": lambda: [print(l) for l in traceroute(_prompt("Host"))] if _prompt("Host") else None,
                "8": lambda: _print(f"Public IP: {my_public_ip()}"),
                "9": lambda: _print(wifi_networks_list()),
                "10": lambda: _print(flush_dns()), "11": lambda: _print(renew_dhcp()),
                "12": lambda: _print(http_status(_prompt("URL"))), "13": lambda: [print(l) for l in check_security_headers(_prompt("URL"))],
                "14": lambda: _print(get_all_http_headers(_prompt("URL"))), "15": lambda: _print(ssl_cert_info(_prompt("Host"))),
                "16": lambda: _print(whois_lookup(_prompt("Domain"))), "17": lambda: [print('\t'.join(str(x) for x in r)) for r in get_connections_windows()[:50]],
                "18": lambda: _print(local_listening_ports()), "19": lambda: _print(port_to_process_windows(_prompt("Port"))),
                "20": lambda: _print(subnet_info(_prompt("CIDR"))), "21": lambda: _print(ip_to_decimal(_prompt("IP")) if _prompt("1=IP->Dec 2=Dec->IP")!="2" else decimal_to_ip(_prompt("Decimal"))),
                "22": lambda: _print(hex_to_bin(_prompt("Hex")) if _prompt("1=Hex->Bin 2=Bin->Hex")!="2" else bin_to_hex(_prompt("Binary"))),
                "23": lambda: _print(url_decode(_prompt("String")) if _prompt("1=Encode 2=Decode")=="2" else url_encode(_prompt("String"))),
                "24": lambda: _print(base64_decode(_prompt("String")) if _prompt("1=Encode 2=Decode")=="2" else base64_encode(_prompt("String"))),
                "25": lambda: _print(hash_string(_prompt("String"), _prompt("Algorithm","sha256").lower())),
                "26": lambda: _print(f"Password: {random_password(_int_prompt('Length',16))}"),
                "27": lambda: _print(mac_vendor_api(_prompt("MAC"))), "28": lambda: _print(ping_stats(_prompt("Host"))),
                "29": lambda: _print(ping_stats(_prompt("Host"))), "30": lambda: _print(ip_geolocation(_prompt("IP", get_my_ip()))),
                "31": lambda: _print(wake_on_lan(_prompt("MAC"))), "32": cli_run_wifi_scan, "33": lambda: _print(system_info()),
                "34": lambda: _print(hosts_file_content()), "35": lambda: _print(file_checksum(_prompt("Path"), _prompt("algo","sha256").lower())),
                "36": lambda: _print(f"Strength: {password_strength(_prompt('Password'))}"), "37": lambda: _print(uuid_generate()),
                "38": lambda: _print(timestamp_to_date(_prompt("Timestamp"))), "39": lambda: _print(url_expand(_prompt("URL"))),
                "40": lambda: _print(wifi_saved_profiles()), "41": lambda: _print(connection_state_summary()),
                "42": lambda: _print(bytes_to_units(_prompt("Bytes"))), "43": lambda: _print(hex_decode(_prompt("Hex")) if _prompt("1=Encode 2=Decode")=="2" else hex_encode(_prompt("String"))),
                "44": lambda: _print(f"Random IP: {random_ip()}"), "45": lambda: _print(user_agent_string()),
                "46": lambda: _print(f"Open: {port_range_scan(_prompt('IP'), _int_prompt('Start',1), _int_prompt('End',100))}"),
                "47": lambda: _print(netstat_summary()), "48": lambda: _print(json_validate(_prompt("JSON"))),
                "49": lambda: _print(route_table()), "50": lambda: _print(arp_table_full()),
                "51": lambda: _print(firewall_status()), "52": lambda: _print(ping_packet_loss(_prompt("Host"), _int_prompt("Count",10))),
                "53": lambda: _print(tcp_connect_test(_prompt("Host"), _prompt("Port"))), "54": lambda: _print(cidr_to_range(_prompt("CIDR"))),
                "55": lambda: _print(http_method_test(_prompt("URL"), _prompt("Method","GET"))), "56": lambda: _print(export_wifi_scan_to_file(_prompt("Filename","wifi_scan_export.txt"))),
                "57": lambda: _print(export_devices_to_file(_prompt("Filename","devices_export.txt"))), "58": lambda: _print(dns_servers_in_use()),
                "59": lambda: _print(network_interfaces()), "H": cli_show_dashboard, "W": cli_wifi_scanner_full_view,
                "S": lambda: _print(f"Speed: {speed_test()[0]} Mbps"), "C": lambda: _print(wifi_channel_analysis()),
            }
            if choice in runners: runners[choice]()
            else: _print("Invalid.")
        except KeyboardInterrupt: _print("\nCanceled.")
        except Exception as e: _print(f"Error: {e}")
        _prompt("\nPress Enter to continue")

# ====================================================================
# SECTION 4: GUI APPLICATION
# ====================================================================

def gui_main():
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, simpledialog

    TITLE = f"{APP_NAME} v{APP_VERSION} - {APP_TAGLINE}"

    def get_device_name(ip, timeout=1):
        try:
            old = socket.getdefaulttimeout(); socket.setdefaulttimeout(timeout)
            name = socket.gethostbyaddr(ip)[0]; socket.setdefaulttimeout(old)
            return (name or "-")[:30]
        except: return "-"

    class ScannerTab(ttk.Frame):
        def __init__(self, parent, **kw):
            super().__init__(parent, **kw)
            self.setup_ui()
        def setup_ui(self):
            top = ttk.Frame(self); top.pack(fill=tk.X, padx=5, pady=5)
            ttk.Label(top, text="Showing data from:").pack(side=tk.LEFT)
            self.adapter_var = tk.StringVar(value=get_wifi_adapter_name())
            ttk.Label(top, textvariable=self.adapter_var, font=("Segoe UI",9,"bold")).pack(side=tk.LEFT, padx=5)
            ttk.Button(top, text="Refresh", command=self.refresh).pack(side=tk.RIGHT)
            paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
            paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            left = ttk.LabelFrame(paned, text="Filters"); paned.add(left, weight=0)
            self.stat_vars = {}
            for key in ["Band","SSID","BSSID","Vendor","Security","Signal"]:
                f = ttk.Frame(left); f.pack(fill=tk.X, pady=2)
                ttk.Label(f, text=f"{key}:", width=10, anchor=tk.W).pack(side=tk.LEFT)
                v = tk.StringVar(value="0"); self.stat_vars[key] = v
                ttk.Label(f, textvariable=v, width=6).pack(side=tk.RIGHT)
            right = ttk.Frame(paned); paned.add(right, weight=1)
            cols = ("SSID","BSSID","Vendor","Channel","Band","Signal","Security")
            self.tree = ttk.Treeview(right, columns=cols, show="headings", height=12)
            vsb = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.tree.yview)
            hsb = ttk.Scrollbar(right, orient=tk.HORIZONTAL, command=self.tree.xview)
            for c in cols: self.tree.heading(c, text=c); self.tree.column(c, width=100, minwidth=60)
            self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
            self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            vsb.pack(side=tk.RIGHT, fill=tk.Y); hsb.pack(side=tk.BOTTOM, fill=tk.X)
            btm = ttk.LabelFrame(self, text="Spectrum"); btm.pack(fill=tk.X, padx=5, pady=5)
            self.spectrum_text = tk.Text(btm, height=4, font=("Consolas",9)); self.spectrum_text.pack(fill=tk.X)
            self.refresh()
        def refresh(self):
            for v in self.stat_vars.values(): v.set("...")
            for i in self.tree.get_children(): self.tree.delete(i)
            self.spectrum_text.delete("1.0", tk.END); self.spectrum_text.insert(tk.END, "Scanning...")
            self.after(100, lambda: threading.Thread(target=lambda: self.after(0, lambda: self._fill(wifi_analyzer_networks())), daemon=True).start())
        def _fill(self, networks):
            bands, ssids, vendors, securities, signals = set(), set(), set(), set(), set()
            ch_usage = {}
            for n in networks:
                ch = n.get("channel") or 0
                bands.add(channel_to_band(ch)); ssids.add((n.get("ssid") or "").strip())
                b = n.get("bssid") or ""
                if b:
                    v = get_mac_vendor(b)
                    if v != "Unknown": vendors.add(v)
                sec = (n.get("auth") or "").strip()
                if sec: securities.add(sec)
                sig = n.get("signal") or 0
                if sig > 0: signals.add(str(int(signal_pct_to_dbm(sig))))
                if ch > 0: ch_usage[ch] = ch_usage.get(ch, 0) + 1
            self.stat_vars["Band"].set(str(len(bands))); self.stat_vars["SSID"].set(str(len(ssids)))
            self.stat_vars["BSSID"].set(str(len(networks))); self.stat_vars["Vendor"].set(str(len(vendors)))
            self.stat_vars["Security"].set(str(len(securities))); self.stat_vars["Signal"].set(str(len(signals)))
            self.adapter_var.set(get_wifi_adapter_name())
            for n in networks:
                ch = n.get("channel") or 0
                self.tree.insert("", tk.END, values=(
                    (n.get("ssid") or "")[:24], (n.get("bssid") or "")[:17],
                    (get_mac_vendor(n.get("bssid") or "") or "-")[:14], ch or "-",
                    channel_to_band(ch), f"{int(signal_pct_to_dbm(n.get('signal')))} dBm",
                    (n.get("auth") or "-")[:14]))
            self.spectrum_text.delete("1.0", tk.END)
            if ch_usage:
                mc = max(ch_usage.values())
                for ch in sorted(ch_usage):
                    bl = max(1, int(20 * ch_usage[ch] / mc))
                    self.spectrum_text.insert(tk.END, f"Ch {ch} [{'#'*bl}] {ch_usage[ch]}\n")
            else: self.spectrum_text.insert(tk.END, "No channel data.")

    class PerformanceTab(ttk.Frame):
        def __init__(self, parent, **kw):
            super().__init__(parent, **kw)
            ttk.Label(self, text="Speed Test", font=("Segoe UI",12,"bold")).pack(pady=10)
            ttk.Button(self, text="Run", command=lambda: threading.Thread(target=lambda: (
                self.after(0, lambda: self.result_var.set("Testing...")),
                (lambda m,s,_: self.after(0, lambda: self.mbps_var.set(f"{m} Mbps" if m else "Failed")))(*speed_test())
            ), daemon=True).start()).pack(pady=10)
            self.result_var = tk.StringVar(value="Ready"); self.mbps_var = tk.StringVar()
            ttk.Label(self, textvariable=self.result_var).pack(pady=5)
            ttk.Label(self, textvariable=self.mbps_var, font=("Segoe UI",14,"bold")).pack(pady=5)

    class WhosOnNetworkTab(ttk.Frame):
        def __init__(self, parent, **kw):
            super().__init__(parent, **kw)
            ttk.Label(self, text="Chkon m3ak f WiFi", font=("Segoe UI",14,"bold")).pack(pady=5)
            top = ttk.Frame(self); top.pack(fill=tk.X, padx=5, pady=5)
            ttk.Button(top, text="Refresh", command=self.refresh).pack(side=tk.LEFT, padx=5)
            ttk.Button(top, text="Copy", command=self._copy).pack(side=tk.LEFT, padx=5)
            ttk.Button(top, text="Block from router", command=self._block).pack(side=tk.LEFT, padx=5)
            cols = ("IP","Name","MAC","Vendor")
            self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
            vsb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
            for c in cols: self.tree.heading(c, text=c); self.tree.column(c, width=120)
            self.tree.configure(yscrollcommand=vsb.set)
            self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); vsb.pack(side=tk.RIGHT, fill=tk.Y)
            self.cnt = tk.StringVar(); ttk.Label(self, textvariable=self.cnt).pack(); self.refresh()
        def refresh(self):
            for i in self.tree.get_children(): self.tree.delete(i)
            self.cnt.set("Scanning...")
            threading.Thread(target=lambda d=get_devices(): self.after(0, lambda: [
                self.tree.insert("", tk.END, values=(ip, get_device_name(ip), mac, get_mac_vendor(mac) or "-"))
                for ip, mac in d] + [self.cnt.set(f"{len(d)} devices.")]), daemon=True).start()
        def _copy(self):
            items = [self.tree.item(c)["values"] for c in self.tree.get_children()]
            if not items: messagebox.showinfo("Copy", "No devices"); return
            text = "IP\tName\tMAC\tVendor\n" + "\n".join("\t".join(str(v) for v in vals) for vals in items)
            self.winfo_toplevel().clipboard_clear(); self.winfo_toplevel().clipboard_append(text)
            messagebox.showinfo("Copy", f"Copied {len(items)} devices.")
        def _block(self):
            sel = self.tree.selection()
            if not sel: messagebox.showinfo("Block", "Select a device"); return
            v = self.tree.item(sel[0])["values"]
            if len(v) < 4: return
            gw = get_gateway_windows() or "192.168.1.1"
            if messagebox.askyesno("Block", f"Block {v[0]} ({v[2]})?\nOpen router ({gw})?"):
                import webbrowser; webbrowser.open(f"http://{gw}")

    class AITab(ttk.Frame):
        def __init__(self, parent, **kw):
            super().__init__(parent, **kw)
            ttk.Label(self, text="AI Assistant", font=("Segoe UI",14,"bold")).pack(pady=5)
            nb = ttk.Notebook(self); nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            # Analysis tab
            af = ttk.Frame(nb); nb.add(af, text="Analysis")
            ttk.Button(af, text="Analyze Network", command=self._analyze).pack(pady=5)
            self.at = tk.Text(af, height=15, font=("Consolas",9)); self.at.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            # Chat tab
            cf = ttk.Frame(nb); nb.add(cf, text="AI Chat")
            fi = ttk.Frame(cf); fi.pack(fill=tk.X, padx=5, pady=5)
            self.ci = tk.Text(fi, height=3, font=("Segoe UI",9)); self.ci.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2)
            ttk.Button(fi, text="Ask", command=self._ask).pack(side=tk.RIGHT, padx=2)
            self.ct = tk.Text(cf, height=12, font=("Consolas",9)); self.ct.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            self.ct.insert("1.0", "AI: Ask me about network security!\n"); self.ct.config(state=tk.DISABLED)
            # Anomaly tab
            anf = ttk.Frame(nb); nb.add(anf, text="Anomalies")
            ttk.Button(anf, text="Detect", command=self._detect).pack(pady=5)
            self.ant = tk.Text(anf, height=15, font=("Consolas",9)); self.ant.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        def _analyze(self):
            self.at.delete("1.0", tk.END); self.at.insert(tk.END, "Analyzing...\n\n")
            threading.Thread(target=lambda: self.after(0, lambda: self.at.insert(tk.END, f"Networks: {len(wifi_analyzer_networks())}\nDevices: {len(get_connected_devices())}\nDNS: {', '.join(get_dns_servers_windows()) or 'None'}\nDone.")), daemon=True).start()
        def _ask(self):
            q = self.ci.get("1.0", tk.END).strip()
            if not q: return
            self.ct.config(state=tk.NORMAL); self.ct.insert(tk.END, f"\nYou: {q}\nAI: ")
            self.ci.delete("1.0", tk.END)
            ql = q.lower()
            if "wifi" in ql or "wireless" in ql: ans = "Use WPA2/WPA3, strong password, disable WPS."
            elif "dns" in ql: ans = "Use 8.8.8.8 or 1.1.1.1 for speed & privacy."
            elif "firewall" in ql: ans = "Keep it on. Windows Firewall is sufficient."
            elif "port" in ql: ans = "Close unused ports. Only open what's needed."
            else: ans = "Ask about WiFi, DNS, firewall, ports, or security."
            self.ct.insert(tk.END, f"{ans}\n"); self.ct.config(state=tk.DISABLED); self.ct.see(tk.END)
        def _detect(self):
            self.ant.delete("1.0", tk.END); self.ant.insert(tk.END, "Scanning...\n")
            threading.Thread(target=lambda: self.after(0, lambda: self.ant.insert(tk.END,
                f"Open nets: {len([n for n in wifi_analyzer_networks() if 'Open' in (n.get('auth') or '')])}\n"
                f"Devices: {len(get_connected_devices())}\nAnomaly check done.")), daemon=True).start()

    class SecurityTab(ttk.Frame):
        def __init__(self, parent, **kw):
            super().__init__(parent, **kw)
            ttk.Label(self, text="Security Tools", font=("Segoe UI",14,"bold")).pack(pady=5)
            f1 = ttk.LabelFrame(self, text="Network Security"); f1.pack(fill=tk.X, padx=10, pady=4)
            r1 = ttk.Frame(f1); r1.pack(fill=tk.X, pady=2)
            ttk.Button(r1, text="Firewall", command=lambda: self._r(firewall_status())).pack(side=tk.LEFT, padx=3)
            ttk.Button(r1, text="ARP Guard", command=self._arp).pack(side=tk.LEFT, padx=3)
            ttk.Button(r1, text="Audit", command=lambda: self._r(security_audit_quick())).pack(side=tk.LEFT, padx=3)
            f2 = ttk.LabelFrame(self, text="Encryption"); f2.pack(fill=tk.X, padx=10, pady=4)
            r2 = ttk.Frame(f2); r2.pack(fill=tk.X, pady=2)
            ttk.Button(r2, text="SSL Cert", command=self._ssl).pack(side=tk.LEFT, padx=3)
            ttk.Button(r2, text="Security Headers", command=self._hdr).pack(side=tk.LEFT, padx=3)
            f3 = ttk.LabelFrame(self, text="WiFi Security"); f3.pack(fill=tk.X, padx=10, pady=4)
            r3 = ttk.Frame(f3); r3.pack(fill=tk.X, pady=2)
            ttk.Button(r3, text="WiFi Security Scan", command=lambda: self._r(wifi_security_scan())).pack(side=tk.LEFT, padx=3)
            ttk.Button(r3, text="DNS Leak Check", command=lambda: self._r(dns_leak_check())).pack(side=tk.LEFT, padx=3)
            self.txt = tk.Text(self, height=14, font=("Consolas",9))
            self.txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        def _r(self, s):
            self.txt.delete("1.0", tk.END); self.txt.insert(tk.END, str(s) if s else "N/A")
        def _arp(self):
            self._r("Running ARP Guard 10s...")
            threading.Thread(target=lambda: self.after(0, lambda: self._r(arp_guard_scan(10))), daemon=True).start()
        def _ssl(self):
            h = simpledialog.askstring("SSL", "Hostname")
            if h: threading.Thread(target=lambda: self.after(0, lambda: self._r(ssl_cert_info(h))), daemon=True).start()
        def _hdr(self):
            u = simpledialog.askstring("Headers", "URL")
            if u: threading.Thread(target=lambda: self.after(0, lambda: self._r("\n".join(check_security_headers(u)))), daemon=True).start()

    class ToolsTab(ttk.Frame):
        def __init__(self, parent, **kw):
            super().__init__(parent, **kw)
            canvas = tk.Canvas(self); sb = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
            sf = ttk.Frame(canvas)
            sf.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas.create_window((0,0), window=sf, anchor="nw"); canvas.configure(yscrollcommand=sb.set)
            def mw(e): canvas.yview_scroll(int(-1*(e.delta/120)), "units")
            canvas.bind("<MouseWheel>", mw); sf.bind("<MouseWheel>", mw)
            ttk.Label(sf, text="All Tools", font=("Segoe UI",14,"bold")).pack(pady=10)
            f1 = ttk.LabelFrame(sf, text="Quick"); f1.pack(fill=tk.X, padx=10, pady=5)
            r1 = ttk.Frame(f1); r1.pack(fill=tk.X, pady=2)
            for txt, cmd in [("UUID", uuid_generate), ("Random Pass", lambda: random_password(16)),
                ("Random IP", random_ip), ("User-Agent", user_agent_string), ("Public IP", my_public_ip),
                ("System Info", get_system_info), ("Hostname", get_hostname),
                ("Gateway", lambda: get_gateway_windows() or "N/A"), ("Drives", get_drive_info)]:
                ttk.Button(r1, text=txt, command=lambda c=cmd: self._r(c())).pack(side=tk.LEFT, padx=2)
            f2 = ttk.LabelFrame(sf, text="Network"); f2.pack(fill=tk.X, padx=10, pady=5)
            r2 = ttk.Frame(f2); r2.pack(fill=tk.X, pady=2)
            ttk.Button(r2, text="Port Scan", command=self._port_scan).pack(side=tk.LEFT, padx=2)
            ttk.Button(r2, text="Ping Sweep", command=self._ping_sweep).pack(side=tk.LEFT, padx=2)
            ttk.Button(r2, text="DNS Lookup", command=lambda: self._r("\n".join(dns_lookup(simpledialog.askstring("DNS","Hostname") or "")))).pack(side=tk.LEFT, padx=2)
            ttk.Button(r2, text="Traceroute", command=self._traceroute).pack(side=tk.LEFT, padx=2)
            f3 = ttk.LabelFrame(sf, text="Convert"); f3.pack(fill=tk.X, padx=10, pady=5)
            r3 = ttk.Frame(f3); r3.pack(fill=tk.X, pady=2)
            for txt, cmd in [("Subnet", lambda: self._r(str(subnet_info(simpledialog.askstring("Subnet","CIDR") or "192.168.1.0/24")))),
                ("IP>Dec", lambda: self._r(ip_to_decimal(simpledialog.askstring("IP","IP") or "0"))),
                ("Dec>IP", lambda: self._r(decimal_to_ip(simpledialog.askstring("Dec","Decimal") or "0"))),
                ("URL Encode", lambda: self._r(url_encode(simpledialog.askstring("URL","Text") or ""))),
                ("Base64 Encode", lambda: self._r(base64_encode(simpledialog.askstring("B64","Text") or "")))]:
                ttk.Button(r3, text=txt, command=cmd).pack(side=tk.LEFT, padx=2)
            canvas.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
            self.res = tk.Text(self, height=8, font=("Consolas",9))
            self.res.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        def _r(self, s): self.res.delete("1.0", tk.END); self.res.insert(tk.END, str(s))
        def _port_scan(self):
            h = simpledialog.askstring("Port Scan", "Host")
            if h:
                self._r("Scanning...")
                threading.Thread(target=lambda: self.after(0, lambda: self._r(f"Open: {scan_ports(h, list(COMMON_PORTS.keys()))}")), daemon=True).start()
        def _ping_sweep(self):
            b = simpledialog.askstring("Ping Sweep", "Base IP", initialvalue="192.168.1")
            if b:
                self._r("Scanning...")
                threading.Thread(target=lambda: self.after(0, lambda: self._r(f"Alive: {ping_sweep(b)}")), daemon=True).start()
        def _traceroute(self):
            h = simpledialog.askstring("Traceroute", "Host")
            if h:
                self._r("Tracing...")
                threading.Thread(target=lambda: self.after(0, lambda: self._r("\n".join(traceroute(h)[:20]))), daemon=True).start()

    class MainApp(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(TITLE); self.minsize(920, 620); self.geometry("1024x680")
            self._style(); self._ui()

        def _style(self):
            style = ttk.Style()
            if platform.system() == "Windows":
                for t in ("vista", "xpnative", "winnative", "clam"):
                    if t in style.theme_names(): style.theme_use(t); break
            elif "clam" in style.theme_names(): style.theme_use("clam")

        def _ui(self):
            hdr = ttk.Frame(self, padding=(10,8)); hdr.pack(fill=tk.X)
            ttk.Label(hdr, text=APP_NAME, font=("Segoe UI",16,"bold")).pack(side=tk.LEFT)
            ttk.Label(hdr, text=f"  {APP_TAGLINE}", font=("Segoe UI",11,"bold")).pack(side=tk.LEFT)
            sf = ttk.Frame(hdr); sf.pack(side=tk.RIGHT, padx=10)
            try:
                ttk.Label(sf, text=f"IP: {get_my_ip()}", foreground="blue").pack(side=tk.LEFT, padx=5)
                gw = get_gateway_windows()
                if gw: ttk.Label(sf, text=f"GW: {gw}", foreground="green").pack(side=tk.LEFT, padx=5)
            except: pass
            ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0,5))
            nb = ttk.Notebook(self); nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=5)
            for tab, name in [(ScannerTab(nb), "Scanner"), (PerformanceTab(nb), "Performance"),
                (WhosOnNetworkTab(nb), "Chkon m3ak f WiFi"), (AITab(nb), "AI Assistant"),
                (SecurityTab(nb), "Security"), (ToolsTab(nb), "Tools")]:
                nb.add(tab, text=f"  {name}  ")
            ftr = ttk.Frame(self, padding=(8,6)); ftr.pack(fill=tk.X)
            ttk.Label(ftr, text=f"{APP_NAME}  {APP_TAGLINE}", font=("Segoe UI",10,"bold")).pack()
            ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X)
            sb = ttk.Frame(self, padding=(8,4)); sb.pack(fill=tk.X)
            ttk.Label(sb, text=f"{APP_TAGLINE}  |  Ready  |  {APP_NAME} v{APP_VERSION}").pack()

    app = MainApp()
    app.mainloop()

# ====================================================================
# LAUNCHER
# ====================================================================

def main():
    parser = argparse.ArgumentParser(description=f"{APP_NAME} - WiFi & Network Security Scanner")
    parser.add_argument("--cli", action="store_true", help="CLI mode")
    parser.add_argument("--gui", action="store_true", help="GUI mode")
    args = parser.parse_args()

    if args.gui:
        gui_main()
    elif args.cli:
        cli_main()
    else:
        # Ask user
        try:
            choice = input(f"[{APP_NAME}] Choose mode: (1) CLI  (2) GUI  : ").strip()
            if choice == "2":
                gui_main()
            else:
                cli_main()
        except (KeyboardInterrupt, EOFError):
            cli_main()

if __name__ == "__main__":
    main()
