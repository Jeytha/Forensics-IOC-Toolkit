# 🔍 Forensics IOC Toolkit (PowerShell DFIR Suite)
A safe, -only digital forensics toolkit built using PowerShell.  
Designed for learning, triage practice, and cybersecurity mini-projects.

This toolkit performs **IOC-based scanning on Disk + Memory**, generates **HTML/CSV/JSON reports**, and works fully offline.  
No malware included — only safe fake training samples.

---

# 🧠 What Are IOCs? 

**IOC = Indicator of Compromise.**  
These are *clues* that a system may be infected or tampered with.

Think of IOCs like “digital fingerprints” left behind by malware or attackers.

Common IOC examples:
- Suspicious filenames (e.g., `ransomware_loader.exe`)
- File hashes known to belong to malware
- Abnormal file locations (e.g., `C:\Users\Public\backdoor.ps1`)
- DLLs injected into processes
- Strange parent-child process relationships (e.g., Word → PowerShell)
- Recently created `.exe` or `.ps1` files
- Known malicious scripts or JS/VBS droppers

**What this toolkit does:**  
It scans your computer looking for anything that matches your IOC list.  
If something matches, it reports it — just like a DFIR investigator would.

This toolkit does **NOT** remove or modify anything.  
It simply detects, analyzes, and reports suspicious activity.

---

## 🚀 Features

- **Disk IOC Scanner v1**
  - Directory-based scanner (fast)
  - Checks: filename, path, SHA256 hash
  - Generates CSV + HTML reports

- **Disk IOC Scanner v2 (DFIR Grade)**
  - Scan specific folder or full system
  - Checks:
    - Filename / Path IOCs
    - Hash IOCs
    - Suspicious recent executable files
  - Generates CSV + JSON + HTML reports

- **Memory IOC Scanner**
  - Live process inspection
  - Extracts:
    - Process name
    - Path
    - PID / ParentPID
    - SHA256 hash
    - Loaded modules
  - Flags:
    - Name/Path/Hash IOCs
    - Suspicious parent→child behavior (Office → PowerShell, Browser → Script host, etc.)
  - Generates CSV + JSON + HTML reports

- **HTML Report Generator**
  - Clean, color-coded DFIR reports
  - Easy for documentation, assignments, demonstrations

---

## 📁 Project Structure

```
ForensicsIOC_Toolkit_Full.ps1      # Main toolkit (scanners + report generator)
ioc_list.txt                       # IOC database (editable)
ME_ForensicsIOC_Toolkit_Full       # Local help file
fake_malware_pack/                 # Optional training files
```

---

## 🔧 Installation

1. Download or clone this repo:

```bash
git clone https://github.com/<yourname>/Forensics-IOC-Toolkit.git
cd Forensics-IOC-Toolkit
```

2. Ensure PowerShell allows script execution:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

---

## ▶️ Running the Toolkit

Open PowerShell **inside the toolkit folder**:

```powershell
cd C:\Users\<you>\Desktop\ForensicsIOC
.\ForensicsIOC_Toolkit_Full.ps1
```

You will see an interactive menu:

```
============== MAIN MENU ==============
1. Disk IOC Scanner v1 (simple)
2. Disk IOC Scanner v2 (enhanced DFIR)
3. Memory IOC Scanner
4. Exit
```

---

## 🧪 Usage Examples

### 🔹 Disk Scan – Specific Directory
```powershell
1
C:\Users\<you>\Downloads
```

### 🔹 Disk Scan – Full System
```powershell
2
2
```

### 🔹 Memory IOC Scan
```powershell
3
```

---

## 📝 Sample IOC List (`ioc_list.txt`)

You can add:

- Filenames  
- Full paths  
- SHA256 hashes  
- DLL names  

Example:

```
# Example filename IOCs
ransomware_loader.exe
evilshim.dll

# Example full path
C:\Users\Public\Downloads\backdoor.ps1

# Example SHA256 hash
d2b02f0f6cb9b2e07b3bb7da293c28f0af901e2ccd1ba94f10f3c6d0ac555831
```

---

## 📊 Output Files

Every scan automatically creates reports in the toolkit folder:

| Scan Type | CSV | HTML | JSON |
|----------|------|------|------|
| Disk v1 | ✔️ | ✔️ | ❌ |
| Disk v2 | ✔️ | ✔️ | ✔️ |
| Memory Scan | ✔️ | ✔️ | ✔️ |

Examples:

```
ioc_hits_v1.csv
ioc_hits_v1.html

ioc_hits_v2.csv
ioc_hits_v2.json
ioc_hits_v2.html

memory_ioc_hits.csv
memory_ioc_hits.json
memory_ioc_hits.html
```

---

## 🧩 Fake Malware Training Pack (Optional)

A downloadable pack of harmless “fake malware” files:

- Fake ransomware EXEs  
- Fake DLL payloads  
- Fake PowerShell loaders  
- Fake JS droppers  
- Fake ransom note  

Use them for testing your IOC list and generating reports.

---

## ⚠️ Safety Disclaimer

This toolkit is:

- **Safe**
- **Offline**
- **-only**
- **Does not modify or delete files**
- **Does not contain malware**

All training samples are **empty or text-only placeholders**.

---

## 📚 Good For

- Cybersecurity assignments  
- DFIR lab projects  
- IOC-based detection demos  
- Windows forensics practice  
- WiCyS / NCL / academic portfolio  
- GitHub portfolio projects  

---


## ❤️ Author

Created by **Jeytha Sahana**  
For learning, DFIR practice, and cybersecurity skill development. 
