# Case 1 – Phishing Email Analysis (Wedding Invitation)

## Overview
This case involves a suspicious email claiming to be a wedding invitation. The email contained a macro-enabled Word document (`.docm`), which raised suspicion due to the use of macros and the presence of an embedded external link.

## Email Details
- Subject: You're Invited!
- Sender Address: abarry@live.com
- Recipient Address: emily.nguyen@glblogistics.co
- Date Received: Tue, 14 May 2024 23:31:08 +0000
- Attachment Name: AR_wedding_RSVP.docm
- Attachment Type: DOCM (Macro-enabled Microsoft Word document)

## Initial Observation
The email appeared legitimate at first glance; however, the use of a macro-enabled document for a wedding invitation is unusual and aligns with common malware delivery techniques.

## Analysis Methodology

### 1. Email Inspection
The email was reviewed directly in the email client to assess visual indicators such as sender name, subject, and attachment type.

**Evidence:** Screenshot 01

### 2. Header Extraction
The full email headers were extracted using the **View Source** option in Thunderbird for deeper analysis.

**Evidence:** Screenshot 02

### 3. Online Header Analysis
The extracted headers were analyzed using an online email analysis tool to identify anomalies in message routing and authentication results.

Tool used:
- hxxps://mha[.]azurewebsites[.]net/

**Evidence:** Screenshot 03

### 4. Authentication Header Verification
The email was downloaded as an `.eml` file (`Invitation.eml`) and authentication-related headers were manually verified using the ZSH terminal.

Checks performed:
- SPF
- DKIM
- DMARC

**Evidence:** Screenshot 04

### 5. Attachment Extraction and Static Analysis
The script `emldump.py` was used to analyze and extract the attachment from `Invitation.eml`. The extracted attachment was saved as `WEDDOC.docm`.

The following steps were performed:
1. Extraction of the `.docm` attachment
2. Calculation of the file hash
3. Macro inspection using `oledump.py`

Tools used:
- emldump.py
- oledump.py

**Evidence:** Screenshot 05

### 6. Hash Reputation Check
The calculated hash of the extracted `.docm` file was checked on VirusTotal to determine prior malicious activity. The file was flagged as malicious by over 45 security vendors.

Tool used:
- virustotal.com

**Evidence:** Screenshot 06

### 7. Static Macro Analysis
Static analysis of the macro code using `oledump.py` revealed an embedded external URL. The macro attempted to retrieve and execute an executable file (`shost.exe`) from a GitHub-hosted location.

Extracted defanged URL:
- hxxps://github[.]com/TCWUS/Pastebin-Uploader[.]exe

**Evidence:** Screenshot 07

---

## Findings
- The email used social engineering by posing as a personal wedding invitation.
- Email authentication checks (SPF, DKIM, DMARC) passed, indicating the sender infrastructure was legitimate or compromised.
- A macro-enabled document was used as the infection vector.
- The document hash was reported as malicious by multiple security vendors.
- Macros contained an external URL leading to a suspected executable payload.

## Conclusion
This case demonstrates a common phishing technique in which benign-looking personal content is used to deliver malicious macro-enabled documents. Static analysis of both the email headers and the attachment was sufficient to identify multiple indicators of malicious intent without executing the payload.
