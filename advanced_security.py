"""
Advanced Security Features - حماية متقدمة
Anti-Hacking, Anti-Spyware, Intrusion Detection
"""

import os
import json
import subprocess
import platform
import psutil
import threading
import time
from datetime import datetime
from pathlib import Path
import hashlib


class AntiHackingProtection:
    """Anti-Hacking Protection - حماية من الاختراق"""
    
    def __init__(self):
        self.suspicious_processes = []
        self.blocked_ips = set()
        self.blocked_ports = set()
        self.blocked_mac_addresses = set()
        self.intrusion_attempts = []
        self.auto_block_enabled = True
        self.monitoring_active = False
        self.connection_history = {}  # Track connections per IP
        self.db_file = "hacking_protection.json"
        self.load_data()
    
    def load_data(self):
        """Load protection data"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    data = json.load(f)
                    self.blocked_ips = set(data.get('blocked_ips', []))
                    self.blocked_ports = set(data.get('blocked_ports', []))
                    self.intrusion_attempts = data.get('intrusion_attempts', [])
            except:
                pass
    
    def save_data(self):
        """Save protection data"""
        try:
            with open(self.db_file, 'w') as f:
                json.dump({
                    'blocked_ips': list(self.blocked_ips),
                    'blocked_ports': list(self.blocked_ports),
                    'blocked_mac_addresses': list(self.blocked_mac_addresses),
                    'intrusion_attempts': self.intrusion_attempts,
                    'auto_block_enabled': self.auto_block_enabled,
                    'connection_history': self.connection_history,
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)
        except:
            pass
    
    def detect_suspicious_activity(self):
        """Detect suspicious network activity"""
        suspicious = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    remote_ip = conn.raddr[0] if conn.raddr else None
                    if remote_ip:
                        # Check for suspicious IPs
                        if self.is_suspicious_ip(remote_ip):
                            suspicious.append({
                                'type': 'suspicious_connection',
                                'ip': remote_ip,
                                'port': conn.raddr[1] if conn.raddr else None,
                                'pid': conn.pid,
                                'timestamp': datetime.now().isoformat()
                            })
        except:
            pass
        
        return suspicious
    
    def is_local_ip(self, ip):
        """Check if IP is local/private"""
        return (ip.startswith('127.') or 
                ip.startswith('192.168.') or 
                ip.startswith('10.') or
                ip.startswith('172.16.') or
                ip.startswith('169.254.'))
    
    def is_suspicious_ip(self, ip):
        """Check if IP is suspicious"""
        # Check if in blocked list
        if ip in self.blocked_ips:
            return True
        
        # Check for private/local IPs (usually safe)
        if self.is_local_ip(ip):
            return False
        
        # Check connection history for suspicious patterns
        if ip in self.connection_history:
            recent = self.connection_history[ip]
            if len(recent) > 10:  # Many connections = suspicious
                return True
        
        # Check for known malicious IP ranges (example)
        # In production, this would query threat intelligence feeds
        malicious_ranges = [
            # Add known malicious IP ranges here
        ]
        
        return False
    
    def block_ip(self, ip):
        """Block IP address"""
        if ip in self.blocked_ips:
            return  # Already blocked
        
        self.blocked_ips.add(ip)
        self.save_data()
        
        # Try to block via firewall (Windows)
        if platform.system() == 'Windows':
            try:
                # Block incoming connections
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                              f'name=BlockIP_{ip.replace(".", "_")}', 
                              'dir=in', 'action=block',
                              f'remoteip={ip}'], 
                             check=False, capture_output=True, timeout=5)
                
                # Also block outgoing to that IP (optional, for extra security)
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                              f'name=BlockIP_Out_{ip.replace(".", "_")}', 
                              'dir=out', 'action=block',
                              f'remoteip={ip}'], 
                             check=False, capture_output=True, timeout=5)
            except:
                pass
        
        return True
    
    def get_mac_address(self, ip=None):
        """Get MAC address for IP or local interfaces"""
        if platform.system() == 'Windows':
            try:
                if ip:
                    # Get MAC for specific IP (requires ARP table)
                    result = subprocess.run(['arp', '-a', ip],
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if ip in line:
                                parts = line.split()
                                if len(parts) > 1:
                                    return parts[1]  # MAC address
                else:
                    # Get local MAC addresses
                    result = subprocess.run(['getmac'],
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        macs = []
                        for line in lines:
                            if '-' in line and 'Physical' not in line:
                                parts = line.split()
                                for part in parts:
                                    if '-' in part and len(part) == 17:
                                        macs.append(part)
                        return macs
            except:
                pass
        return None
    
    def detect_mac_spoofing(self):
        """Detect MAC address spoofing attempts"""
        suspicious = []
        
        try:
            # Get current MAC addresses
            current_macs = self.get_mac_address()
            if not current_macs:
                return suspicious
            
            # Check for duplicate MAC addresses (spoofing indicator)
            # This would require network monitoring
            # For now, we'll check for suspicious MAC patterns
            
            # Check for known malicious MAC address patterns
            # (This is a simplified check - real detection requires network analysis)
            
        except:
            pass
        
        return suspicious
    
    def block_mac_address(self, mac):
        """Block MAC address"""
        self.blocked_mac_addresses.add(mac.upper())
        self.save_data()
        
        # Note: Blocking MAC addresses at firewall level is complex
        # This mainly tracks blocked MACs for monitoring
        
        return True
    
    def start_monitoring(self):
        """Start continuous monitoring for hacking attempts"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        
        def monitor_loop():
            while self.monitoring_active:
                try:
                    # Detect suspicious activity
                    suspicious = self.detect_suspicious_activity()
                    
                    # Auto-block if enabled
                    if suspicious and self.auto_block_enabled:
                        for item in suspicious:
                            if 'ip' in item:
                                self.block_ip(item['ip'])
                    
                    time.sleep(5)  # Check every 5 seconds
                except:
                    time.sleep(10)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring_active = False
    
    def get_blocked_ips_count(self):
        """Get count of blocked IPs"""
        return len(self.blocked_ips)
    
    def get_blocked_macs_count(self):
        """Get count of blocked MAC addresses"""
        return len(self.blocked_mac_addresses)
    
    def scan_for_hacking_tools(self):
        """Scan for common hacking tools"""
        hacking_tools = [
            'nmap', 'wireshark', 'metasploit', 'burpsuite', 'sqlmap',
            'john', 'hashcat', 'aircrack', 'ettercap', 'cain'
        ]
        
        detected = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name'].lower()
                for tool in hacking_tools:
                    if tool in proc_name:
                        detected.append({
                            'process': proc.info['name'],
                            'pid': proc.info['pid'],
                            'tool': tool,
                            'timestamp': datetime.now().isoformat()
                        })
            except:
                continue
        
        return detected


class AntiSpywareAdvanced:
    """Advanced Anti-Spyware - مضاد التجسس المتقدم"""
    
    def __init__(self):
        self.spyware_signatures = []
        self.keyloggers_detected = []
        self.screen_capture_detected = []
        self.db_file = "spyware_protection.json"
        self.load_signatures()
    
    def load_signatures(self):
        """Load spyware signatures"""
        self.spyware_signatures = [
            'keylogger', 'spy', 'monitor', 'tracker', 'recorder',
            'capture', 'screen', 'webcam', 'microphone', 'keystroke',
            'log', 'stealer', 'sniffer', 'eavesdrop'
        ]
    
    def detect_keyloggers(self):
        """Detect keylogger processes"""
        keyloggers = []
        
        suspicious_names = [
            'keylog', 'keystroke', 'keycapture', 'keymonitor',
            'keyrecorder', 'keytrack', 'keyhook', 'keylogger'
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                proc_name = proc.info['name'].lower()
                for suspicious in suspicious_names:
                    if suspicious in proc_name:
                        keyloggers.append({
                            'process': proc.info['name'],
                            'pid': proc.info['pid'],
                            'path': proc.info.get('exe', 'Unknown'),
                            'type': 'keylogger',
                            'timestamp': datetime.now().isoformat()
                        })
            except:
                continue
        
        return keyloggers
    
    def detect_screen_capture(self):
        """Detect screen capture software"""
        screen_capture = []
        
        suspicious_names = [
            'screenshot', 'screen capture', 'screen recorder',
            'capture', 'recorder', 'snapshot', 'grab'
        ]
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name'].lower()
                for suspicious in suspicious_names:
                    if suspicious in proc_name:
                        # Check if it's a legitimate app (like built-in Windows tools)
                        if 'snipping' not in proc_name and 'xbox' not in proc_name:
                            screen_capture.append({
                                'process': proc.info['name'],
                                'pid': proc.info['pid'],
                                'type': 'screen_capture',
                                'timestamp': datetime.now().isoformat()
                            })
            except:
                continue
        
        return screen_capture
    
    def detect_remote_access(self):
        """Detect remote access tools"""
        remote_tools = []
        
        suspicious_names = [
            'teamviewer', 'anydesk', 'remote', 'vnc', 'rdp',
            'logmein', 'gotomypc', 'chrome remote', 'ultravnc'
        ]
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name'].lower()
                for suspicious in suspicious_names:
                    if suspicious in proc_name:
                        remote_tools.append({
                            'process': proc.info['name'],
                            'pid': proc.info['pid'],
                            'type': 'remote_access',
                            'timestamp': datetime.now().isoformat()
                        })
            except:
                continue
        
        return remote_tools
    
    def scan_registry_for_spyware(self):
        """Scan Windows registry for spyware"""
        spyware_registry_keys = [
            r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
            r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run',
        ]
        
        detected = []
        if platform.system() == 'Windows':
            for key_path in spyware_registry_keys:
                try:
                    result = subprocess.run(['reg', 'query', key_path],
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            for sig in self.spyware_signatures:
                                if sig.lower() in line.lower():
                                    detected.append({
                                        'registry_key': key_path,
                                        'entry': line,
                                        'type': 'spyware_registry',
                                        'timestamp': datetime.now().isoformat()
                                    })
                except:
                    continue
        
        return detected


class IntrusionDetectionSystem:
    """Intrusion Detection System - نظام كشف التسلل"""
    
    def __init__(self):
        self.intrusion_log = []
        self.suspicious_activities = []
        self.db_file = "intrusion_detection.json"
        self.load_log()
    
    def load_log(self):
        """Load intrusion log"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    data = json.load(f)
                    self.intrusion_log = data.get('intrusions', [])
            except:
                self.intrusion_log = []
    
    def save_log(self):
        """Save intrusion log"""
        try:
            with open(self.db_file, 'w') as f:
                json.dump({
                    'intrusions': self.intrusion_log[-1000:],  # Keep last 1000
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)
        except:
            pass
    
    def detect_intrusion(self):
        """Detect intrusion attempts"""
        intrusions = []
        
        # Check for suspicious network connections
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    remote_ip = conn.raddr[0] if conn.raddr else None
                    if remote_ip and not self.is_local_ip(remote_ip):
                        # Check for suspicious ports
                        if conn.raddr and conn.raddr[1] in [4444, 5555, 6666, 1234, 31337]:
                            intrusions.append({
                                'type': 'suspicious_port',
                                'ip': remote_ip,
                                'port': conn.raddr[1],
                                'pid': conn.pid,
                                'severity': 'high',
                                'timestamp': datetime.now().isoformat()
                            })
        except:
            pass
        
        # Check for unauthorized file access
        # This would require file system monitoring
        
        if intrusions:
            self.intrusion_log.extend(intrusions)
            self.save_log()
        
        return intrusions
    
    def is_local_ip(self, ip):
        """Check if IP is local"""
        return (ip.startswith('127.') or 
                ip.startswith('192.168.') or 
                ip.startswith('10.') or
                ip.startswith('172.16.'))


class KeyloggerDetector:
    """Keylogger Detection - كشف مسجلات المفاتيح"""
    
    def __init__(self):
        self.detected_keyloggers = []
        self.db_file = "keylogger_detection.json"
    
    def scan_for_keyloggers(self):
        """Scan for keylogger processes and files"""
        keyloggers = []
        
        # Check processes
        suspicious_processes = [
            'keylog', 'keystroke', 'keycapture', 'keymonitor',
            'keyrecorder', 'keytrack', 'keyhook', 'logger'
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                proc_name = proc.info['name'].lower()
                cmdline = ' '.join(proc.info.get('cmdline', [])).lower()
                
                for suspicious in suspicious_processes:
                    if suspicious in proc_name or suspicious in cmdline:
                        keyloggers.append({
                            'type': 'process',
                            'name': proc.info['name'],
                            'pid': proc.info['pid'],
                            'path': proc.info.get('exe', 'Unknown'),
                            'timestamp': datetime.now().isoformat()
                        })
            except:
                continue
        
        # Check for keylogger files in common locations
        common_locations = [
            os.path.expanduser('~/AppData/Roaming'),
            os.path.expanduser('~/AppData/Local'),
            'C:\\Windows\\System32',
            'C:\\Windows\\Temp'
        ]
        
        for location in common_locations:
            if os.path.exists(location):
                try:
                    for root, dirs, files in os.walk(location):
                        for file in files:
                            file_lower = file.lower()
                            for suspicious in suspicious_processes:
                                if suspicious in file_lower:
                                    keyloggers.append({
                                        'type': 'file',
                                        'name': file,
                                        'path': os.path.join(root, file),
                                        'timestamp': datetime.now().isoformat()
                                    })
                except:
                    continue
        
        return keyloggers


class ScreenCaptureProtection:
    """Screen Capture Protection - حماية من التقاط الشاشة"""
    
    def __init__(self):
        self.blocked_processes = set()
        self.allowed_processes = {'snippingtool', 'xbox', 'msedge', 'chrome', 'firefox'}
    
    def detect_screen_capture(self):
        """Detect screen capture attempts"""
        detected = []
        
        suspicious_names = [
            'screenshot', 'capture', 'recorder', 'snapshot',
            'grab', 'screen', 'record'
        ]
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name'].lower()
                if proc_name in self.allowed_processes:
                    continue
                
                for suspicious in suspicious_names:
                    if suspicious in proc_name:
                        detected.append({
                            'process': proc.info['name'],
                            'pid': proc.info['pid'],
                            'timestamp': datetime.now().isoformat()
                        })
            except:
                continue
        
        return detected
    
    def block_process(self, pid):
        """Block screen capture process"""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            self.blocked_processes.add(pid)
            return True
        except:
            return False


class DataLeakPrevention:
    """Data Leak Prevention - منع تسريب البيانات"""
    
    def __init__(self):
        self.sensitive_patterns = [
            r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # Credit card
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'password\s*[:=]\s*\S+',  # Password
            r'api[_-]?key\s*[:=]\s*\S+',  # API key
        ]
        self.monitored_directories = []
        self.db_file = "data_leak_prevention.json"
    
    def detect_data_leak(self, file_path):
        """Detect potential data leaks in file"""
        leaks = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for pattern in self.sensitive_patterns:
                    import re
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        leaks.append({
                            'file': file_path,
                            'pattern': pattern,
                            'matches': len(matches),
                            'timestamp': datetime.now().isoformat()
                        })
        except:
            pass
        
        return leaks
    
    def monitor_network_transfers(self):
        """Monitor network data transfers"""
        # This would require network packet inspection
        # Placeholder for network monitoring
        return []


class NetworkIntrusionDetection:
    """Network Intrusion Detection - كشف التسلل الشبكي"""
    
    def __init__(self):
        self.suspicious_ports = [4444, 5555, 6666, 1234, 31337, 8080, 8888]
        self.blocked_connections = []
        self.db_file = "network_intrusion.json"
    
    def detect_suspicious_connections(self):
        """Detect suspicious network connections"""
        suspicious = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_port = conn.raddr[1]
                    remote_ip = conn.raddr[0]
                    
                    # Check for suspicious ports
                    if remote_port in self.suspicious_ports:
                        suspicious.append({
                            'ip': remote_ip,
                            'port': remote_port,
                            'pid': conn.pid,
                            'type': 'suspicious_port',
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    # Check for multiple connections from same IP
                    same_ip_count = sum(1 for c in connections 
                                      if c.raddr and c.raddr[0] == remote_ip)
                    if same_ip_count > 10:
                        suspicious.append({
                            'ip': remote_ip,
                            'connections': same_ip_count,
                            'type': 'multiple_connections',
                            'timestamp': datetime.now().isoformat()
                        })
        except:
            pass
        
        return suspicious
    
    def block_connection(self, ip, port):
        """Block network connection"""
        if platform.system() == 'Windows':
            try:
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                              f'name=Block_{ip}_{port}', 'dir=in', 'action=block',
                              f'remoteip={ip}', f'remoteport={port}'],
                             check=False, capture_output=True)
                return True
            except:
                return False
        return False


class PrivacyProtectionAdvanced:
    """Advanced Privacy Protection - حماية الخصوصية المتقدمة"""
    
    def __init__(self):
        self.webcam_blocked = False
        self.microphone_blocked = False
        self.location_tracking_blocked = True
        self.db_file = "privacy_protection.json"
    
    def block_webcam(self):
        """Block webcam access"""
        self.webcam_blocked = True
        # Try to disable webcam via registry (Windows)
        if platform.system() == 'Windows':
            try:
                subprocess.run(['reg', 'add', 
                              r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam',
                              '/v', 'Value', '/t', 'REG_SZ', '/d', 'Deny', '/f'],
                             check=False, capture_output=True)
            except:
                pass
    
    def block_microphone(self):
        """Block microphone access"""
        self.microphone_blocked = True
        # Try to disable microphone via registry (Windows)
        if platform.system() == 'Windows':
            try:
                subprocess.run(['reg', 'add',
                              r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone',
                              '/v', 'Value', '/t', 'REG_SZ', '/d', 'Deny', '/f'],
                             check=False, capture_output=True)
            except:
                pass
    
    def scan_for_tracking(self):
        """Scan for tracking software"""
        tracking_software = []
        
        suspicious_names = [
            'tracker', 'tracking', 'analytics', 'telemetry',
            'spy', 'monitor', 'surveillance'
        ]
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name'].lower()
                for suspicious in suspicious_names:
                    if suspicious in proc_name:
                        tracking_software.append({
                            'process': proc.info['name'],
                            'pid': proc.info['pid'],
                            'type': 'tracking',
                            'timestamp': datetime.now().isoformat()
                        })
            except:
                continue
        
        return tracking_software
