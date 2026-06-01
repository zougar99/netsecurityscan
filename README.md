# 🔍 netsecurityscan — SNS — WiFi & Network Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/zougar99/netsecurityscan/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/zougar99/netsecurityscan?style=social)](https://github.com/zougar99/netsecurityscan)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue)](https://github.com/zougar99/netsecurityscan)

> SNS — WiFi & Network Security Scanner. 78 tools for network analysis, anti-hacking, IDS, port scanning, and security auditing.

---

## 📖 Table of Contents
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Tech Stack](#-tech-stack)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage Guide](#-usage-guide)
- [Screenshots](#-screenshots)
- [Roadmap](#-roadmap)
- [FAQ](#-faq)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features
- ✔ **78 Network Tools** — WiFi scanning, port scanning, packet analysis, IDS, vulnerability checks
- ✔ **Intrusion Detection** — Real-time IDS monitoring with alerts
- ✔ **WiFi Security** — Scan for rogue APs, weak encryption, deauth attacks
- ✔ **Port Scanner** — Fast multi-threaded port scanning with service detection
- ✔ **Vulnerability Scanner** — Checks for common CVEs and misconfigurations
- ✔ **Traffic Analysis** — Real-time bandwidth monitoring per device
- ✔ **Report Generation** — Detailed HTML/PDF security reports

---

## 🔮 How It Works

```
  Input ──► Processing Pipeline ──► Output
  ┌────────┐   ┌────────┐   ┌────────┐
  │ Data   │──►│ Engine │──►│ Result │
  │ Source │   │ Logic  │   │        │
  └────────┘   └────────┘   └────────┘
```

1. **Input** — Load data from file, API, or user input
2. **Process** — Core engine applies logic/analysis/transformation
3. **Output** — Results displayed in UI, saved to file, or sent via API

---

## 💻 Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ |
| UI | CustomTkinter |
| Network | scapy + nmap + socket |
| Database | SQLite + CVE DB |
| Platform | Windows / Linux (Admin) |

---

## 🚀 Installation

```bash
git clone https://github.com/zougar99/netsecurityscan.git
cd netsecurityscan
pip install -r requirements.txt
# Install Nmap: https://nmap.org/download.html
```

---

## 📄 Configuration

Create a `config.yaml` or `.env` file in the project root:

```yaml
# Application settings
debug: false
port: 8080
theme: dark
language: en
```

---

## 🧰 Usage Guide

1. Run as Administrator: `python main.py`
2. Select scan type (WiFi / Port / IDS / Vulnerability)
3. Configure targets and parameters
4. Start scan
5. Review results and export report

---

## 🖼 Screenshots

> *(Screenshots coming soon. PRs welcome!)*

---

## 🔄 Roadmap

- 🟢 Web dashboard
- 🟡 Mobile companion app
- ⚫ API access
- ⚫ Plugin system
- ⚫ Multi-language support

---

## ❓ FAQ

### Is Nmap required?
Nmap is optional but recommended for advanced port scanning.

### Can it detect zero-day exploits?
No — only known CVEs from public databases.

---

## 🚧 Troubleshooting

| Problem | Solution |
|---------|----------|
| **App won't start** | Check Python version (3.10+); run `pip install -r requirements.txt` |
| **No output** | Check logs in `logs/` folder; enable debug mode in config |
| **Performance issues** | Close other applications; reduce batch size in config |
| **Dependency errors** | Create fresh venv: `python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt` |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📐 License
Distributed under the **MIT License**. See [`LICENSE`](https://github.com/zougar99/netsecurityscan/blob/main/LICENSE) for more information.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/zougar99">zougar99</a>
</p>
