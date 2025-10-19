# 🕵️ YorHa 9S Security Scanner  
### Android Unit 9S - Advanced Security Assessment Tool

![YorHa](https://img.shields.io/badge/YoRHa-9S-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![Security](https://img.shields.io/badge/Security-Scanner-red)
![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20Windows-lightgrey)

## ⚠️ Legal Notice
**Tool ini hanya untuk:**
✅ Testing website milik sendiri  
✅ Penetration testing dengan IZIN  
✅ Tujuan edukasi & pembelajaran  
✅ Security research  

**❌ DILARANG untuk:**
- Aktivitas illegal
- Hack tanpa izin  
- Tujuan jahat
- Melanggar hukum

## 🎯 Features
- **Port Scanning** - Deteksi port terbuka
- **Vulnerability Assessment** - SQLi, XSS, Security Headers
- **WAF Bypass** - Advanced evasion techniques
- **Stealth Scanning** - Anti-detection mechanisms
- **Service Detection** - Identifikasi layanan
- **Endpoint Discovery** - Temukan path tersembunyi
- **Comprehensive Reporting** - Laporan detail

## 🚀 Installation

### **📱 Termux (Android)**
```bash

pkg update && pkg upgrade
pkg install python git -y


pip install requests urllib3


git clone https://github.com/XersesAnalyz/YorHa-9S-Scanner.git
cd YorHa-9S-Scanner

# Run the scanner
python3 YorHa.py

# Linux

sudo apt update && sudo apt install python3 python3-pip git -y

  
pip3 install requests urllib3


git clone https://github.com/XersesAnalyz/YorHa-9S-Scanner.git
cd YorHa-9S-Scanner
python3 YorHa.py

#Windows
pip install requests urllib3
git clone https://github.com/XersesAnalyz/YorHa-9S-Scanner.git
cd YorHa-9S-Scanner
python YorHa.py

#macOS
# Install Homebrew (jika belum ada)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

brew install python git
pip3 install requests urllib3

git clone https://github.com/XersesAnalyz/YorHa-9S-Scanner.git
cd YorHa-9S-Scanner
python3 YorHa.py
