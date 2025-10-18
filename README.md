# 🛡️ SOC-Incident-Reports

Collection of SOC investigation reports and cybersecurity incident analyses  
*(QRadar, Splunk, Suricata, VirusTotal, MITRE ATT&CK)*

---

## 🔍 About
This repository contains real-style SOC investigation examples based on simulated or lab incidents.  
Each case demonstrates triage, analysis, and containment recommendations following MITRE ATT&CK mapping.

---

## 🧰 Tools Used
- 🟦 **IBM QRadar** — SIEM alert correlation and offense triage  
- 🟧 **Splunk** — log analysis and search queries  
- 🟥 **Suricata** — IDS/IPS alert detection  
- 🟨 **VirusTotal, Talos, AbuseIPDB** — threat intelligence enrichment  
- 🟩 **MITRE ATT&CK** — technique mapping and classification  

---

## 📁 Incident Examples
| Incident | Description | Tools | MITRE ATT&CK |
|-----------|--------------|-------|----------------|
| **ColdFusion-Web-Reconnaissance_QRadar-55269** | Probe for `/CFIDE/componentutils/` suggesting ColdFusion reconnaissance attempt | QRadar, Splunk, Suricata, VirusTotal | T1595.002 (Active Scanning), T1190 (Exploit Public-Facing Application – potential) |

---

## 📈 Future Additions
- Phishing email triage example (with IOC extraction)
- PowerShell malware analysis lab
- Scheduled task persistence detection
- Credential hygiene checklist

---

## 👨‍💻 Author
**Alexander (PurePootato)**  
Security Operations Center Analyst  
[LinkedIn](https://www.linkedin.com/in/alexanderisoev/) | [GitHub](https://github.com/PurePootato)
