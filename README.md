# 🔒 Security Network - شبكة الأمان

**WiFi & Network Security Scanner** | **i7tarafiya mn jami3 nawa7i** 🛡️

## 📋 Overview

Security Network is a comprehensive **WiFi and network security toolkit** for Windows.  
It offers **62+ tools** for network scanning, WiFi analysis, security auditing, and more.  
**Chkon m3ak f WiFi?** — Find out who's connected to your network! 🔍

## ✨ Features

### 📡 WiFi Scanner
- Access point discovery (SSID, BSSID, signal, channel, security) 🎯
- Signal strength visualization & channel spectrum 📊
- WiFi channel finder (least crowded) 📶

### 🌐 Network Tools
- Port scanner (multi-threaded) 🚪
- Ping sweep & latency test 🏓
- DNS lookup / Reverse DNS 🌍
- Traceroute, Whois, TCP connect test 🔗
- Netcat-style client/server 📨

### 🛡️ Security Tools
- ARP Guard — detect spoofing & kick attempts 🚨
- WiFi security scan (open/WEP/WPA2) 🔐
- DNS leak check 🕵️
- Security headers & SSL certificate check ✅
- Firewall status & listening ports 🔥
- Quick security audit 📋

### 🔧 Advanced Security Module
- Anti-Hacking protection 🚫
- Anti-Spyware (keylogger, screen capture detection) 👁️
- Intrusion Detection System ⚠️
- Data Leak Prevention 🔏
- Privacy protection (webcam/mic blocking) 📵

### 🧰 Utilities
- IP/Decimal, Hex/Binary, Base64, URL encode/decode 🔢
- Hash (MD5, SHA256), password generator & strength checker 🔑
- UUID, timestamp, JSON validator 🕐
- MAC vendor lookup, IP geolocation 🌍
- And many more... bzaaaaaaf! 🎉

## 🚀 Quick Start

### Prerequisites
- Python 3.8+ 🐍
- Windows (recommended) / Linux / macOS

### Installation
```bash
# Clone or download
cd Network-Security-Scanner

# Install dependencies
pip install -r requirements.txt

# Optional: rich for colorful CLI
pip install rich
```

### Run 🔌

**CLI version:**
```bash
python main.py
# or
python src/security_scanner/cli.py
```

**GUI version:**
```bash
python main.py --gui
# or
python src/security_scanner/gui.py
```

## 📁 Project Structure

```
Network-Security-Scanner/
├── main.py                         # 🚀 Entry point (CLI or GUI)
├── requirements.txt                # 📦 Dependencies
├── pyproject.toml                  # 📦 Package config
├── README.md                       # 📖 This file
├── src/
│   ├── security_scanner/
│   │   ├── __init__.py             # 📦 Package init
│   │   ├── core.py                 # ⚙️ Shared core logic (all tools)
│   │   ├── advanced.py             # 🔐 Advanced security classes
│   │   ├── cli.py                  # 💻 CLI application
│   │   └── gui.py                  # 🖥️ GUI application (tkinter)
├── SecurityNetwork.py              # 🗑️ Legacy (original CLI)
├── SecurityNetworkGUI.py           # 🗑️ Legacy (original GUI)
└── advanced_security.py            # 🗑️ Legacy (original advanced)
```

## 🖥️ Screenshots

### CLI Dashboard
```
==================================================
  Security Network  |  v2.0
  i7tarafiya mn jami3 nawa7i
==================================================
  DASHBOARD | 7stat
  My IP       : 192.168.1.100
  Public IP   : 86.xx.xxx.xxx
  Gateway     : 192.168.1.1
  Devices     : 12
  Connections : 45
```

### GUI Tabs
| Tab | Description |
|-----|-------------|
| 🔍 Scanner | WiFi scanner with spectrum chart |
| ⚡ Performance | Speed test |
| 👥 Chkon m3ak f WiFi | Who's on your network |
| 🤖 AI Assistant | Security analysis & recommendations |
| 🛡️ Security | Firewall, encryption, WiFi security |
| 🧰 Tools | All 62+ tools in one place |

## 🌍 Language

Interface labels include **Moroccan Arabic (Darija)** terms:
- **Chkon m3ak f WiFi?** — Who's with you on WiFi?
- **7stat** — Status / Dashboard
- **i7tarafiya mn jami3 nawa7i** — Professionalism from all sides
- **bzaaf dyal l7wyj** — A lot of things (many tools)

## ⚠️ Disclaimer

This tool is for **educational purposes** and **authorized security testing only**.  
Only scan networks and devices you own or have permission to test. 🔒

## 📜 License

MIT License

---

**Security Network** — *i7tarafiya mn jami3 nawa7i* 🏆
