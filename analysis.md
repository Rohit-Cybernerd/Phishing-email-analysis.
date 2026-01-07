# Analysis & Technical Findings

## Overview
This document details the technical analysis of specific phishing scenarios found in the `cases/` directory. The primary objective was to determine the legitimacy of the emails using static analysis techniques, header inspection, and reputation checks.

## Methodology
The following standard procedure was applied to all cases:
1.  **Header Analysis:** Parsing `.eml` files to verify SPF, DKIM, and DMARC records to identify spoofing.
2.  **Static Inspection:** Extracting attachments and URLs without execution to prevent infection.
3.  **Payload Analysis:** Using tools like `oledump.py` to inspect OLE streams for malicious macros.
4.  **Reputation Check:** Cross-referencing extracted Indicators of Compromise (IOCs) with VirusTotal and urlscan.io.

---

## 📝 Case Studies

### Case 1: Wedding Invitation (Malicious)
**Directory:** `cases/case-1/`

#### 1. Scenario
The user received an email titled "Invitation" with a generic body text urging the recipient to open an attached document named `WEDDOC.docm`.

#### 2. Technical Analysis
* **Header Inspection:** The sender domain did not align with the context of the email, but no immediate spoofing of a major brand was detected in the headers.
* **Attachment Analysis:**
    * File: `WEDDOC.docm`
    * Tool: `oledump.py` revealed streams containing VBA macros.
    * Macros are a common vector for dropping malware.
* **Payload Extraction:**
    * Static analysis of the macro code revealed an attempt to reach an external URL.
    * **Defanged URL:** `hxxps://github[.]com/TCWUS/Pastebin-Uploader[.]exe`
* **Reputation Check:**
    * The file hash was calculated and submitted to VirusTotal.
    * Result: Flagged by multiple vendors as a Trojan/Downloader.

#### 3. Verdict
**Confirmed Phishing / Malware Delivery.** The email uses social engineering (curiosity about a wedding) to entice the user to enable macros, which then executes a script to download a malicious executable.

---

### Case 2: Account Reactivation (Legitimate)
**Directory:** `cases/case-2/`

#### 1. Scenario
An email purporting to be from Chase Bank requested "Account Reactivation" due to suspicious activity. The sense of urgency is a common phishing indicator.

#### 2. Technical Analysis
* **Header Inspection:**
    * **Observation:** The `Return-Path` address differed from the `From` address, which is often a red flag.
    * **Verification:** Ran the headers through `check_headers.py` and *mha.azurewebsites.net*.
    * **Result:** SPF, DKIM, and DMARC checks **PASSED**. The email originated from an authorized IP address belonging to the institution's marketing/notification infrastructure.
* **URL Analysis:**
    * Extracted links using `extract_urls.py`.
    * Links pointed to legitimate Chase domains.
    * Urlscan.io and VirusTotal scans returned clean results (0 detections).

#### 3. Verdict
**False Positive (Legitimate Email).** While the `Return-Path` mismatch and urgency were suspicious, the cryptographic verification (DKIM/SPF) confirmed the email originated from the authorized sender.

---

## 💡 Key Takeaways
1.  **Macro-Enabled Documents are High Risk:** Any unsolicited email containing `.docm` or `.xlsm` files should be treated as malicious until proven otherwise.
2.  **Return-Path is not absolute:** Legitimate marketing emails often use third-party mailers, causing a mismatch between `From` and `Return-Path`. Always rely on SPF/DKIM/DMARC for final verification.
3.  **Static Analysis is Safer:** Analyzing code structure and hashes provides a verdict without the risk of detonating malware in a live environment.

---
### Author
**Rohit Sahani** Cybersecurity Student | Blue Team & SOC Analyst Aspirant  
[Connect on LinkedIn](https://www.linkedin.com/in/rohit-sahani-200938259)