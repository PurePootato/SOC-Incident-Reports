# 🛡️ SOC-Incident-Reports
[![Focus](https://img.shields.io/badge/Focus-SOC%20%7C%20SIEM%20%7C%20EDR-critical)](#)
[![Tools](https://img.shields.io/badge/Tools-QRadar%20%7C%20Splunk%20%7C%20CrowdStrike-blueviolet)](#)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-informational)](#)
[![Certification](https://img.shields.io/badge/Certification-Security%2B-success)](#)
[![Language](https://img.shields.io/badge/Language-English/Russian-darkblue)](#)


Collection of SOC investigation reports and cybersecurity incident analyses.  
Each report is sanitized for public sharing and demonstrates hands-on triage, analysis, and containment recommendations.  
Tools used: **QRadar, Splunk, Suricata, VirusTotal, MITRE ATT&CK**.

---

## 🔍 About
This repository contains real-style SOC investigation examples based on simulated or lab incidents.  
Each case demonstrates triage, analysis, and containment recommendations following MITRE ATT&CK mapping.

---

## 🧰 Tools Used
- 🟦 **IBM QRadar** — SIEM alert correlation and offense triage  
- 🟧 **Splunk** — log analysis and search queries  
- 🟥 **Suricata** — IDS/IPS alert detection  
- 🟨 **VirusTotal, Talos, Cencys, GreyNoise, AbuseIPDB** — threat intelligence enrichment  
- 🟩 **MITRE ATT&CK** — technique mapping and classification  
- 🟣 **CrowdStrike Falcon** — EDR / endpoint detection, process & file telemetry
---

## 📁 Incident Examples

### SIEM Cases (QRadar / Splunk / Suricata)
| Incident | Description | Tools | MITRE ATT&CK |
|-----------|--------------|-------|----------------|
| 1 | [ColdFusion Reconnaissance](ColdFusion-Reconnaissance.pdf) | Probing `/CFIDE/componentutils/` — ColdFusion reconnaissance (404s observed) | **T1595.002** (Active Scanning) | QRadar, Splunk, Suricata |
| 2 | [Reflected XSS (SearchPHP)](Reflected-XSS.pdf) | Automated reflected XSS probes via `searchdata` parameter | **T1059.007** (Script) / **T1595** (Recon) | Splunk, Suricata, VirusTotal |
| 3 | [CGI-Bin Shell Execution Attempt](CGI-Bin-Shell-Execution-Attempt.pdf) | Attempted path traversal to execute `/bin/sh` via `/cgi-bin/` (double-encoded payloads observed) | **T1190** (Exploit Public-Facing Application), **T1059.004** (Unix Shell) | QRadar, Suricata, Splunk, VirusTotal |
| 4 | [LFI Probe — /proc/self/environ Reconnaissance](Local-File-Inclusion-(LFI)-Probe.pdf) | Automated probe attempting to read `/proc/self/environ` (environment disclosure / LFI reconnaissance). All observed requests returned HTTP 403. | T1595.002 (Active Scanning), T1083 (File and Directory Discovery) | QRadar, Suricata, Splunk |
| 5 | [SQL Injection Attempt — UNION & Time-Based Blind](sql-injection-union-timebased-blind.pdf) | Automated SQLi attempts against `/admin/update-issue-bookdeails.php` using `UNION SELECT` and `SLEEP(5)` (data exfiltration & time-based blind checks). All observed requests returned HTTP 403. | T1190 (Exploit Public-Facing Application), T1595.002 (Active Scanning) | Suricata, Splunk, QRadar |
| 6 | [RCE Attempt — CGI Command Injection & Mozi Botnet Download](rce-cgi-mozi-botnet-probe.pdf) | Outbound RCE attempt via `/setup.cgi` using `wget` + `sh` to download/execute `Mozi.m` (botnet payload). Request blocked (HTTP 403). | T1190 (Exploit Public-Facing Application), T1105 (Ingress Tool Transfer), T1059.004 (Unix Shell) | Suricata, Splunk, QRadar |
| 7 | [PHP RCE & Directory Traversal Attempt](php-rce-directory-traversal.pdf) | Dual attack combining PHP config abuse (`allow_url_include=1`, `auto_prepend_file=php://input`) and directory traversal via `/index.php?lang=../../`. Both attempts blocked (HTTP 403). | T1190 (Exploit Public-Facing Application), T1006 (Path Traversal), T1059.004 (Unix Shell) | Suricata, Splunk, QRadar |
| 8 | [Multi-stage Campaign: SQLi & XSS](Multi-stage-SQLi-XSS-Analysis.pdf) | **Advanced Analysis:** Detected WAF bypass via **PCRE limit exhaustion**. Correlation of morning SQLi probes with afternoon XSS exploitation. Identified critical **"Detection Only"** WAF misconfiguration (HTTP 200 response for malicious payloads). | **T1190** (Exploit), **T1059.007** (Script) | Suricata, Splunk, QRadar, ModSecurity |
### EDR Cases (CrowdStrike Falcon)
| Incident | Description | Tools | MITRE ATT&CK |
|-----------|--------------|-------|----------------|
| 1 | [PowerShell Process Injection](CrowdStrike_PowerShell_ProcessInjection.pdf)| Exploitation via PowerShell ExecutionPolicy Bypass → download Start-Hollow.ps1 → process hollowing; EDR blocked and quarantined.  | T1055 (Process Injection), T1059.001 (PowerShell), T1105 (Ingress Tool Transfer) |
| 2 | [Double-Extension Dropper via Firefox-PowerShell Bypass](./Double-Extension_Dropper_via_Firefox—PowerShell_Bypass.pdf) | Masqueraded `.pdf.exe` delivered via Firefox → PowerShell `-ExecutionPolicy Bypass`; EDR blocked and quarantined. | T1036 (Masquerading), T1059.001 (PowerShell), T1105 (Ingress Tool Transfer) |
| 3 | [PowerShell ExecutionPolicy Bypass on Server](./PowerShell_ExecutionPolicy_Bypass_on_Server.pdf) | Unsigned PowerShell script executed under Administrator via remote interactive session; blocked and quarantined. | T1059.001 (PowerShell), T1562.001 (Execution Policy Tampering) |
| 4 | [Targeted RAT Intrusion & EDR Evasion](./Targeted_RAT_Intrusion&EDR_Evasion.pdf) | Multi-stage RDP intrusion → EDR sensor impairment & debugger evasion → fileless Cobalt Strike beacon via `dllhost.exe` (stdin mode) → SYSTEM persistence; full compromise. | T1622 (Debugger Evasion), T1562.001 (Impair Defenses), T1021.001 (RDP), T1071 (C2), T1543.003 (Persistence) |
| 5 | [Linux Infra Compromise and Espionage](Linux_Infra_Compromise_and_Espionage.pdf) | WordPress SEO poisoning → `curl` masquerading (Googlebot UA) → C2 communication → unauthorized Suricata source compilation in `/root` for network espionage; Detection Only (full compromise). | T1036 (Masquerading), T1059.004 (Unix Shell), T1071 (C2), T1587.001 (Malware Development), T1083 (File Discovery) |
| 6 | [Domain Controller: Defense Evasion & Full Compromise Attempt](./Domain_Controller_ Defense Evasion&Full_Compromise_Attempt.pdf) | Multi-stage DC intrusion → Defense evasion via Defender impairment (wevtutil) → Scheduled Task persistence (healthcheck.ps1) → blocked SAM/SYSTEM hive dumping via reg.exe; AD reconnaissance successful. | T1003.002 (OS Credential Dumping), T1053.005 (Scheduled Task), T1562.001 (Impair Defenses), T1069.002 (Discovery) |
| 7 | [SOC-AWS-Host-Compromise-Incident](SOC-AWS-Host-Compromise-Incident.pdf) | Valid AWS Console login (temp-admin) → SSH using valid key → sudo escalation → fileless `curl ; bash` → outbound C2 → systemd persistence (silent-shell.service). Full host & cloud compromise. | T1078 (Valid Accounts), T1059.004 (Unix Shell), T1105 (Ingress Tool Transfer), T1543.002 (Systemd Service), T1071 (C2 Communication) |
---

## 👨‍💻 Author
**Alexander Isoev (PurePootato)**  
Security Operations Center Analyst  
[🔗LinkedIn](https://www.linkedin.com/in/alexanderisoev/) | [GitHub](https://github.com/PurePootato)


**Note:** Reports are sanitized for public sharing. Internal links, hostnames, and exact host IPs were redacted.

_Full raw artifacts are private. Contact: alexanderisoevf@gmail.com to request vetted access._
