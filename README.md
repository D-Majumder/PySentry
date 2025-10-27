<h1 align="center" id="title">🛡️ PySentry 🛡️</h1>

<p align="center">
  <i>“A simple, educational Endpoint Detection & Response (EDR) tool — where Python meets Cyber Defense.”</i>
</p>

<p align="center">
  <img src="https://images.unsplash.com/photo-1591696205602-2f950c417cb9?auto=format&fit=crop&w=2000&q=80" alt="Cybersecurity Visual" style="max-width:100%;height:auto;border-radius:12px;box-shadow:0 0 15px rgba(0,150,255,0.3);">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python" alt="Python Badge">
  <img src="https://img.shields.io/badge/psutil-Library-green" alt="psutil Badge">
  <img src="https://img.shields.io/badge/Platform-Windows-blueviolet" alt="Platform Badge">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey" alt="License Badge">
</p>

---

<div align="center">
  <img src="https://img.shields.io/badge/🧠_Learn_Cyber_Defense_by_Doing_-blue?style=for-the-badge" alt="Learn Cyber Defense">
</div>

---

## ⚙️ About The Project

**PySentry** is a lightweight **educational Endpoint Detection & Response (EDR)** system written entirely in Python.  
It was built to **demonstrate defensive cybersecurity principles** for a college technology exhibition.  

> 🧩 *It’s not a real antivirus — but it thinks like one.*

PySentry operates on a **Zero Trust** model: it assumes every unknown process or registry entry could be suspicious until proven safe.  
It includes two primary modules:  
- 🔍 **Active Network Scan:** Monitors all running processes that maintain active internet connections.  
- 🧠 **Persistence Scan:** Examines Windows Registry “Run” keys for unauthorized startup entries.  

---

## 🚨 Features

PySentry uses a **multi-layered detection approach** to identify potential threats:

✅ **Unknown Process Detection:** Flags processes not listed in the pre-defined safe list (`KNOWN_GOOD_PATHS`).  
✅ **Process Impersonation Detection:** Checks for legitimate process names (like `svchost.exe`) running from untrusted directories.  
✅ **Suspicious Port Heuristics:** Identifies processes using **non-standard network ports** (other than 80/443).  
✅ **Registry Persistence Scan:** Detects unauthorized programs in the Windows “Run” key.  
✅ **Active Response:** Prompts the user for permission to **terminate suspicious processes in real-time.**

---

## 🚀 Getting Started

### 🧩 Prerequisites
- Python 3.x  
- `psutil` library  

Install it using:
```bash
pip install psutil
```
---
## 💻 Installation
Clone this repository and enter the project directory:

```bash
git clone https://github.com/YourUsername/PySentry.git
cd PySentry
```
---
## ⚡ Usage
This script must be run as Administrator for full functionality.

> *Open PowerShell or CMD → Right-click → Run as Administrator*

Navigate to the project directory
Run:

```bash
python py_sentry.py
```
The main menu will appear — choose from:
```
Option 1: Network Scan

Option 2: Persistence Scan

Option 3: Full System Audit
```
---
## ⚠️ Tuning Required
PySentry is intentionally strict — it will flag legitimate software (like Steam, Discord, or even your antivirus).
To fine-tune:
```
Run Option 3 (Full System Audit)
```
Review the “SUSPICIOUS” alerts

Open py_sentry.py and add safe entries to:

python
```
KNOWN_GOOD_PATHS = []       # For network scan
KNOWN_SAFE_STARTUPS = []    # For persistence scan
Save and re-run the scan — the report should now be cleaner and more accurate.
```
---
## 🧪 How to Demo This Project
### 🧠 Demo 1: The "Unknown Attacker"
Run PySentry in Terminal 1 (as Admin):

```bash
python py_sentry.py
In Terminal 2, simulate a “malicious” connection:
```
```bash
python -c "import socket, time; s=socket.socket(); s.connect(('google.com', 80)); time.sleep(300)"
In Terminal 1, select Option 1 (Network Scan)
→ PySentry flags python.exe as UNKNOWN
→ Press y to block the threat — the attacker process terminates instantly.
```
### 🎭 Demo 2: The "Impersonator" (Advanced)
Copy python.exe from your installation folder to Downloads
Rename it to `svchost.exe`
Run it as a fake “system process”:

```bash
cd C:\Users\YourName\Downloads
.\svchost.exe -c "import socket, time; s=socket.socket(); s.connect(('google.com', 80)); time.sleep(300)"
In PySentry, choose Option 1 (Network Scan)
→ It detects “svchost.exe running from Downloads” as a HIGH-SEVERITY ALERT.
```

---

## 🧩 Project Philosophy
### 🧠 Learn by simulating real-world security defense scenarios.

PySentry helps beginners understand:
How EDR tools monitor system behavior
How heuristics and process analysis can detect intrusions

Why whitelisting and zero trust matter in security

---

## 📜 Disclaimer

This project is for educational purposes only.
It is not a professional antivirus and should not be used for real-world protection.
Use responsibly and only in controlled environments.

---
## 🛠️ Built With

`Python` 🐍
`psutil` ⚙️
`Windows OS Registry APIs` 🪟

---
## 🤝 Connect With Us

<p align="center">
  <a href="mailto:dhrubamajumder@proton.me" target="_blank">
    <img src="https://img.shields.io/badge/Email-Dhruba%20Majumder-blue?logo=gmail" alt="Email Badge">
  </a>
  <a href="https://www.linkedin.com/in/iamdhrubamajumder/" target="_blank">
    <img src="https://img.shields.io/badge/LinkedIn-Dhruba%20Majumder-blue?logo=linkedin" alt="LinkedIn Badge">
  </a>
  <a href="https://github.com/D-Majumder" target="_blank">
    <img src="https://img.shields.io/badge/GitHub-D--Majumder-black?logo=github" alt="GitHub Badge">
  </a>
</p>

<div align="center"> 
  <img src="https://img.shields.io/badge/🚀_Built_for_Tech_Exhibitions_-_Learn_Securely_-green?style=for-the-badge" alt="Tech Exhibition Badge"> 
</div> 
<p align="center"> 
  <img src="https://capsule-render.vercel.app/api?type=waving&color=1E90FF&height=100&section=footer&text=Stay+Alert,+Stay+Secure.&fontSize=22&fontColor=111111&animation=fadeIn" /> </p>
