# Phishing Email Analysis

This repo documents my hands-on labs where I dissect real-world phishing attempts. I look past the "From" address to analyze headers, extract malicious payloads, and understand the attack vector—all without infecting my own machine.

## Who Am I?
I am **Rohit Sahani**, a Computer Science student focused on defensive security. This repository documents my hands-on labs where I analyze real-world phishing attempts to better understand attack vectors and defense mechanisms.

I am currently seeking **internships** in **Blue Teaming** and **Security Analysis** roles.

## 🔗 Connect with Me
* **LinkedIn:** [Rohit Sahani](https://www.linkedin.com/in/rohit-sahani-200938259)
* **Email:** rohitsahaniwork@gmail.com

---

## 🚀 Core Competencies (Skills Demonstrated)
* **Email Security:** Deep understanding of SPF, DKIM, and DMARC verification mechanisms.
* **Malware Triage:** Safely extracting and hashing attachments (OLE streams, macros) for reputation checks.
* **OSINT:** Using tools like VirusTotal and urlscan.io to pivot on IOCs.
* **Documentation:** Writing clear, actionable incident reports suitable for technical and non-technical stakeholders.

---

## Main Points
* **Goal:** Practice and demonstrate phishing email analysis: spot spoofing, social engineering, malicious attachments, and verify authentication (SPF/DKIM/DMARC).
* **Key Techniques:** Static analysis, URL defanging, header inspection, hash calculation.
* **Tools Used:** `emldump.py`, `oledump.py`, `extract_urls.py`, ZSH/grep, VirusTotal, urlscan.io, mha.azurewebsites.net.

## 📂 Repo Structure
```text
phishing-analysis/
├── README.md               # Project overview (this file)
├── scripts/                # Reusable scripts
│   ├── emldump.py
│   ├── oledump.py
├── analysis.md             # Detailed case analyses
└── cases/
    ├── case-1/             # Wedding Invitation Phishing
    │   ├── Invitation.eml
    │   ├── WEDDOC.docm
    │   └── ...
    └── case-2/             # Account Reactivation Email
        ├── REACTIVATE.eml
        └── ...