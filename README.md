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

---

## 👨‍💻 Author
**Alexander (PurePootato)**  
Security Operations Center Analyst  
[🔗LinkedIn](https://www.linkedin.com/in/alexanderisoev/) | [GitHub](https://github.com/PurePootato)


**Note:** Reports are sanitized for public sharing. Internal links, hostnames, and exact host IPs were redacted.
