# Investigation Report

**Case:** PhishNet
**Category:** SOC
**Analyst:** Marco Austin
**Date:** 2026-11-11

---

## 1. Scenario and Evidence Provided

An accounting team receives an urgent payment request from a known vendor. The email appears legitimate but contains a suspicious link and a .zip attachment hiding malware. Your task is to analyze the email headers and uncover the attacker's scheme.

| Artifact | Type | Notes |
|---|---|---|
| email.eml | Email message (.eml) | The phishing email provided for analysis |

---

## 2. Tools Used

| Tool | Used for |
|---|---|
| Mousepad | Reading the raw `.eml` headers and HTML body |
| mpack (`munpack`) | Extracting the attachment from the `.eml` |
| shasum | Computing the SHA-256 hash of the attachment |
| Archive Manager | Inspecting the ZIP attachment |
| chmod | Adjusting file permissions to open the ZIP |

---

## 3. Executive Summary

The accounting team received a phishing email disguised as an urgent overdue-invoice notice from a vendor calling itself "Business Finance Ltd." The message used classic social-engineering pressure (final-notice language, threats of penalties) and set a `Reply-To` of `support@business-finance.com` so that any replies would reach the attacker rather than the real sender. It carried two payloads: a phishing link on the look-alike domain `secure.business-finance.com`, and a ZIP attachment, `Invoice_2025_Payment.zip`, which concealed a malicious batch file disguised as a PDF (`invoice_document.pdf.bat`). The activity maps to MITRE ATT&CK **T1566.001 (Spearphishing Attachment)**. This engagement analyzed a single captured email; the provided artifact shows no evidence of execution, but the attachment should be treated as malicious, and the sending domain and URL should be blocked.

---

## 4. Walkthrough

Upon opening the scenario file, we can see we are provided an email file. This `.eml` file stores a saved email message in a universal, plain-text format that preserves the original text, HTML layout, headers, and attachments.

![email.eml on the desktop](<images/Screenshot 2026-11-11 175544.png>)

Opening it in a text editor shows the full message — headers, HTML body, and the MIME-encoded attachment.

![Full email opened in Mousepad](<images/Screenshot 2026-11-11 180555.png>)

---

### 4.1 What is the originating IP address of the sender?
**Answer:** 45.67.89.10

When you open the file, the answer is near the top of the header, in the `X-Originating-IP` field (line 4).

![X-Originating-IP header field](<images/Screenshot 2026-11-11 180936.png>)
![Task 1 answer](<images/Screenshot 2026-11-11 181027.png>)

---

### 4.2 Which mail server relayed this email before reaching the victim?
**Answer:** 203.0.113.25

By reading the email header we can trace the mail hops in the `Received:` lines. The last relay before the victim's server (`mail.target.com`) was `mail.business-finance.com`, at IP address 203.0.113.25.

![Received chain showing the last relay](<images/Screenshot 2026-11-11 181827.png>)
![Task 2 answer](<images/Screenshot 2026-11-11 181856.png>)

---

### 4.3 What is the sender's email address?
**Answer:** finance@business-finance.com

This is an easy one — just look at who the message is `From:` (line 30).

![From header field](<images/Screenshot 2026-11-11 182115.png>)
![Task 3 answer](<images/Screenshot 2026-11-11 182125.png>)

---

### 4.4 What is the 'Reply-To' email address specified in the email?
**Answer:** support@business-finance.com

The `Reply-To` is near the top of the header (line 2). Note that it differs from the `From` address — a common phishing tell, since replies get redirected to a different inbox.

![Reply-To header field](<images/Screenshot 2026-11-11 182256.png>)
![Task 4 answer](<images/Screenshot 2026-11-11 182314.png>)

---

### 4.5 What is the SPF (Sender Policy Framework) result for this email?
**Answer:** pass

SPF is an authentication protocol that lets domain owners declare which mail servers and IP addresses are allowed to send on their behalf. We can see this one passed on line 7 (`Received-SPF: Pass`) — the attacker controls the look-alike domain, so it authenticates cleanly.

![Received-SPF: Pass](<images/Screenshot 2026-11-11 182633.png>)
![Task 5 answer](<images/Screenshot 2026-11-11 182652.png>)

---

### 4.6 What is the domain used in the phishing URL inside the email?
**Answer:** secure.business-finance.com

Here we get into the actual email body. The phishing URL and its domain are on line 55, inside the "Download Invoice" link.

![Phishing URL in the email body](<images/Screenshot 2026-11-11 182907.png>)
![Task 6 answer](<images/Screenshot 2026-11-11 183010.png>)

---

### 4.7 What is the fake company name used in the email?
**Answer:** Business Finance Ltd.

In the phishing email's sign-off (line 58), we can see the name the attacker chose to impersonate.

![Email sign-off with the fake company name](<images/Screenshot 2026-11-11 183315.png>)
![Task 7 answer](<images/Screenshot 2026-11-11 183324.png>)

---

### 4.8 What is the name of the attachment included in the email?
**Answer:** Invoice_2025_Payment.zip

In the MIME attachment entity we can see the name of the attachment on lines 65 and 66 (`Content-Type` / `Content-Disposition`).

![MIME attachment headers](<images/Screenshot 2026-11-11 183804.png>)
![Task 8 answer](<images/Screenshot 2026-11-11 183838.png>)

---

### 4.9 What is the SHA-256 hash of the attachment?
**Answer:** `8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a`

To solve this one, we first need to extract the file from the email. We can do this with a tool called `munpack` from the `mpack` package. After installing the package, run `munpack email.eml`.

![munpack extracting the attachment](<images/Screenshot 2026-11-11 185415.png>)

Then get the hash of the extracted file using `shasum -a 256`.

![shasum of the attachment](<images/Screenshot 2026-11-11 185522.png>)
![Task 9 answer](<images/Screenshot 2026-11-11 185538.png>)

---

### 4.10 What is the filename of the malicious file contained within the ZIP attachment?
**Answer:** invoice_document.pdf.bat

When we try to open the archive, Archive Manager reports a "Permission denied" error (`errno=13`).

![Permission denied opening the ZIP](<images/Screenshot 2026-11-11 185858.png>)

Running `chmod 777` on the ZIP gives us permission to open it.

![chmod on the ZIP](<images/Screenshot 2026-11-11 190101.png>)

Inside, we find the malicious file: `invoice_document.pdf.bat` — a Windows batch file using a double extension to masquerade as a PDF.

![Malicious file inside the ZIP](<images/Screenshot 2026-11-11 190114.png>)

---

### 4.11 Which MITRE ATT&CK techniques are associated with this attack?
**Answer:** T1566.001 (Spearphishing Attachment)

Search for the MITRE ATT&CK phishing technique. Phishing (T1566) has several sub-techniques; the one associated with a malicious file attachment is **T1566.001, Spearphishing Attachment**.

![Task 11 answer](<images/Screenshot 2026-11-11 190403.png>)

---

Sherlock solved.

![PhishNet solved](<images/Screenshot 2026-11-11 190219.png>)
