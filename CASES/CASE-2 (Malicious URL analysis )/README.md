# Case 2 – Potential Phishing Email Analysis (Account Reactivation)

## Overview
This case involves a suspicious email claiming that the user's bank account was temporarily suspended due to unusual activity. The email asks the recipient to verify their account through a provided URL.

## Email Details
- Subject: Your Bank Account has been blocked due to unusual activities
- Sender Address: alerts@chase.com
- Recipient Address: kellyellin426@proton.me
- Date Received: Wed, 01 May 2024 20:04:05 +0000

## Initial Observation
The email looks like a phishing attempt because of fear-based social engineering, URL redirection for credentials, and possible sender spoofing. It required analysis to verify authenticity.

## Analysis Methodology

### 1. Email Inspection
The email was checked directly in the email client for visible indicators such as sender name, subject, and attachments.

**Evidence:** Screenshot 01

### 2. Header Extraction
Full email headers were extracted using Thunderbird’s **View Source** feature.

**Evidence:** Screenshot 02

### 3. Online Header Analysis
Headers were analyzed with an online tool to find anomalies in routing and authentication.

Tool used:
- hxxps://mha[.]azurewebsites[.]net/

Observation:
- All received email servers appeared verified and trusted.

**Evidence:** Screenshot 03

### 4. Authentication Header Verification
The email was downloaded as `REACTIVATE.eml`, and headers were checked in the ZSH terminal.

Checks performed:
- SPF
- DKIM
- DMARC
- Received SMTP server domains
- Return-Path

Key point:
- Return-Path is different from the sender domain, requiring further verification.

**Evidence:** Screenshot 04

### 5. URL Extraction (Static)
`emldump.py` was used to extract the HTML content from `REACTIVATE.eml`. URLs were manually extracted from `html.txt`.

Tool used:
- emldump.py

Extracted URLs (defanged):
- hxxps://raw[.]githubusercontent[.]com/MalwareCube/SOC101/main/assets/01_Phishing_analysis/34c8f34e-64a8-4ad7-874a-a9b70ee648e2_0_0_0_0_0_0[.]jpg
- hxxps://dsgo[.]to/CQWCQWCnpqY3NDSGtDt9ft2qtxzcXGUveTV5fRYmtYAZsQCnqpY3NDSGtODt9ft2qtxzcXGUveTV5fRYmtYAZsQCQECnpqY3NDSGtoDt9ft2qtxzcXGUveTV5fRYmtYAZsQ

**Evidence:** Screenshot 05

### 6. Domain Verification
`urlscan.io` was used to verify the URLs. The domains led to a login page and were reported as legitimate.

**Evidence:** Screenshot 06

### 7. URL Verification
The URLs were also checked on VirusTotal. No security vendors flagged them as malicious.

Observation:
- Domains and URLs appear safe and legitimate.

**Evidence:** Screenshot 07

---

## Findings
- The email is genuine and sent by Chase Bank.
- SPF, DKIM, and DMARC checks passed, confirming legitimate sending infrastructure.
- Extracted URLs and domains were verified as safe.
- This was a practice email provided by the SOC101 course.

## Conclusion
Although the email initially seemed suspicious, analysis confirmed it is legitimate. All suspicious elements, including headers and URLs, were verified. This email is a **false positive** and not a phishing attempt.
