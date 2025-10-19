# 🛡️ SOC-Incident-Reports

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

---

## 📁 Incident Examples
| Incident | Description | Tools | MITRE ATT&CK |
|-----------|--------------|-------|----------------|
| 1 | [ColdFusion Reconnaissance](ColdFusion-Reconnaissance.pdf) | Probing `/CFIDE/componentutils/` — ColdFusion reconnaissance (404s observed) | **T1595.002** (Active Scanning) | QRadar, Splunk, Suricata |
| 2 | [Reflected XSS (SearchPHP)](Reflected-XSS.pdf) | Automated reflected XSS probes via `searchdata` parameter | **T1059.007** (Script) / **T1595** (Recon) | Splunk, Suricata, VirusTotal |
| 3 | [CGI-Bin Shell Execution Attempt](CGI-Bin-Shell-Execution-Attempt.pdf) | Attempted path traversal to execute `/bin/sh` via `/cgi-bin/` (double-encoded payloads observed) | **T1190** (Exploit Public-Facing Application), **T1059.004** (Unix Shell) | QRadar, Suricata, Splunk, VirusTotal |
| 4 | [LFI Probe — /proc/self/environ Reconnaissance](Local-File-Inclusion-(LFI)-Probe.pdf) | Automated probe attempting to read `/proc/self/environ` (environment disclosure / LFI reconnaissance). All observed requests returned HTTP 403. | T1595.002 (Active Scanning), T1083 (File and Directory Discovery) | QRadar, Suricata, Splunk |
| 5 | [SQL Injection Attempt — UNION & Time-Based Blind](sql-injection-union-timebased-blind.pdf) | Automated SQLi attempts against `/admin/update-issue-bookdeails.php` using `UNION SELECT` and `SLEEP(5)` (data exfiltration & time-based blind checks). All observed requests returned HTTP 403. | T1190 (Exploit Public-Facing Application), T1595.002 (Active Scanning) | Suricata, Splunk, QRadar |
| 6 | [RCE Attempt — CGI Command Injection & Mozi Botnet Download](rce-cgi-mozi-botnet-probe.pdf) | Outbound RCE attempt via `/setup.cgi` using `wget` + `sh` to download/execute `Mozi.m` (botnet payload). Request blocked (HTTP 403). | T1190 (Exploit Public-Facing Application), T1105 (Ingress Tool Transfer), T1059.004 (Unix Shell) | Suricata, Splunk, QRadar |
---

## 👨‍💻 Author
**Alexander (PurePootato)**  
Security Operations Center Analyst  
[🔗LinkedIn](https://www.linkedin.com/in/alexanderisoev/) | [GitHub](https://github.com/PurePootato)


**Note:** Reports are sanitized for public sharing. Internal links, hostnames, and exact host IPs were redacted.
