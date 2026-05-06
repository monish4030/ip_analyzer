# 🔍 URL IP Analyzer

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Ethics](https://img.shields.io/badge/Use-Ethical%20Only-red?style=for-the-badge)

**A powerful Python-based cybersecurity recon tool for Kali Linux**

Made with ❤️ by **Monish Paramasivam**

</div>

---

## 📌 What It Does

**URL IP Analyzer** takes any URL and performs a full recon pipeline:

1. 🌐 **Parses** the URL — extracts scheme, root domain, and subdomain
2. 🔎 **Resolves** the domain to its IP address via DNS
3. 🗺️ **Fetches IP intelligence** from [ipinfo.io](https://ipinfo.io) — location, ISP, ASN
4. 🛡️ **Optionally runs an nmap scan** — detects open ports and services
5. 📊 **Scores risk level** — Low / Medium / High based on exposed ports
6. 📝 **Explains findings** in plain English — what each port means and security insights
7. 💾 **Saves results** to `.json` and `.txt` report files

---

## 🖥️ Preview

```
① TARGET INFO
  Original URL  : https://sub.example.com
  Full Domain   : sub.example.com
  Root Domain   : example.com
  Subdomain     : sub

② IP DETAILS
  IP Address    : 93.184.216.34
  Country       : US
  City          : Norwell
  ISP / Org     : Edgecast Inc.
  ASN           : AS15133

③ SCAN RESULTS
  Risk Level    : MEDIUM
  ┌──────┬──────────┬───────┬─────────┬──────────────────┐
  │ Port │ Protocol │ State │ Service │ Version          │
  ├──────┼──────────┼───────┼─────────┼──────────────────┤
  │   80 │ tcp      │ open  │ http    │ Apache 2.4.41    │
  │  443 │ tcp      │ open  │ https   │ OpenSSL 1.1.1    │
  │   22 │ tcp      │ open  │ ssh     │ OpenSSH 8.2p1    │
  └──────┴──────────┴───────┴─────────┴──────────────────┘

④ EXPLANATION
  Plain-English breakdown of findings + security insights
```

---

## ⚙️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/url-ip-analyzer.git
cd url-ip-analyzer
```

### 2. Install Python dependencies
```bash
pip install requests rich
```

### 3. Install nmap (optional — for port scanning)
```bash
sudo apt install nmap
```

> Python 3.8 or higher is required.

---

## 🚀 Usage

### Interactive mode (recommended for beginners)
```bash
python3 url_ip_analyzer.py
```

### Pass a URL directly
```bash
python3 url_ip_analyzer.py --url https://example.com
```

### With nmap scan
```bash
python3 url_ip_analyzer.py --url https://example.com --nmap
```

### Full nmap scan (top 1000 ports) + save results
```bash
python3 url_ip_analyzer.py --url https://example.com --nmap --full --save
```

---

## 🏳️ CLI Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--url` | `-u` | Target URL to analyze |
| `--nmap` | `-n` | Run an nmap scan on the resolved IP |
| `--full` | `-f` | Full scan (top 1000 ports) instead of fast mode |
| `--save` | `-s` | Save results to `.json` and `.txt` files |

---

## 🗂️ Output Files

When `--save` is used (or you choose yes when prompted), two files are created:

| File | Format | Contents |
|------|--------|----------|
| `url_ip_report_<domain>_<timestamp>.txt` | Plain text | Human-readable full report |
| `url_ip_report_<domain>_<timestamp>.json` | JSON | Machine-readable structured data |

---

## 🔐 Risk Levels Explained

| Level | Meaning |
|-------|---------|
| 🟢 **LOW** | No critical ports exposed |
| 🟡 **MEDIUM** | Some notable ports open (SSH, HTTP, etc.) |
| 🔴 **HIGH** | Critical ports exposed — RDP, Telnet, MySQL, Redis, MongoDB, FTP, SMB |

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `requests` | Fetch IP intelligence from ipinfo.io |
| `rich` | Colored CLI output, tables, panels |
| `socket` | DNS resolution (built-in) |
| `subprocess` | Run nmap (built-in) |
| `nmap` *(system)* | Port scanning — install separately |

---

## 🧠 How It Works

```
URL Input
   │
   ▼
Parse URL ──► Extract domain + subdomain
   │
   ▼
DNS Resolution ──► socket.gethostbyname()
   │
   ▼
IP Intelligence ──► ipinfo.io API (free)
   │
   ▼
nmap Scan ──► subprocess → parse output
   │
   ▼
Risk Scoring ──► Based on open port analysis
   │
   ▼
Explanation ──► Plain-English security insights
   │
   ▼
Display + Save Report
```

---

## ⚠️ Disclaimer

> This tool is intended **for ethical cybersecurity testing and educational purposes only**.
>
> - ✅ Only scan systems you **own** or have **explicit written permission** to test.
> - ❌ Scanning systems without authorisation may be **illegal** in your country.
> - The author takes **no responsibility** for misuse of this tool.

---

## 👤 Author

**Monish Paramasivam**

---

## 📄 License

This project is licensed under the **MIT License** — free to use, modify, and distribute with attribution.

---

<div align="center">

⭐ **If you found this useful, please star the repo!** ⭐

</div>
