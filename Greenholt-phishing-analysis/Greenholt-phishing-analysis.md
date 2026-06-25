# Incident Response: Phishing & Email Forensic Analysis (Greenholt PLC)

This repository documents my hands-on forensic analysis of a suspicious email sample (`challenge.eml`) escalated by a sales executive at Greenholt PLC. The objective was to inspect the raw email message source, evaluate sender authentication records (SPF/DMARC), extract underlying indicator artifacts, and perform threat reputation lookups on weaponized attachments.

---

## Task 1: Dissecting Core Header Telemetry

### 1. The Scenario
A sales executive reported receiving an unexpected money transfer request from a known customer. The message breached normal communication patterns by leveraging a generic greeting and carrying an unsolicited attachment.

### 2. Analysis & Detection Strategy
I initialized the triage by opening the raw file source inside Mozilla Thunderbird to inspect hidden envelope data past the visual display pane. This step immediately separates the visible user fields from true routing flags.

![Thunderbird Envelope Header Metadata View](Images/lab_screenshot_10_32_24.png)

### 3. Forensic Discovery
Auditing the top-level technical fields and message blocks exposed the following identification components:
* **Subject Line Reference Number:** `09674321`
* **Sender Display Name:** `Mr. James Jackson`
* **Sender Email Address:** `info@mutawamarine.com`
* **Reply-To Address:** `info@mutawamarine.com`

---

## Task 2: Tracking Originating Infrastructure & Mail Authentication

### 1. The Scenario
Threat actors regularly compromise valid external email infrastructure or mask their tracking endpoints within complex server relays to impersonate legitimate clients.

### 2. Analysis & Detection Strategy
I audited the cascading `Received:` lines inside the message headers to identify the absolute first server node that pushed the transmission payload. Following infrastructure extraction, I queried **MxToolBox** and **WhatIsMyIP** to verify structural alignment against security policies.

![Raw Internal Received Routing Hops](Images/lab_screenshot_10_23_57.png)

### 3. Forensic Discovery
Tracing the server hops isolated the rogue delivery infrastructure alongside failed security evaluations:
* **Originating IP Address:** `192.119.71.157`
* **Infrastructure Owner (IP WHOIS):** `HostPapa`

![IP WHOIS Infrastructure Lookup](Images/lab_screenshot_10_53_32.png)

* **Authentication Validation (Return-Path Domain):** `mutawamarine.com`
* **Published SPF Record:** `v=spf1 include:spf.protection.outlook.com -all`
* **Published DMARC Record:** `v=DMARC1; p=quarantine; fo=1`

The underlying authentication engine explicitly triggered an **SPF Fail** status code. The receiving server executed an authorization lookup against the sender domain's DNS entries and confirmed that the originating server IP (`192.119.71.157`) was completely omitted from the authorized outbound mail nodes.



![MxToolBox Domain SPF Record Query](Images/lab_screenshot_10_47_22.png)

![MxToolBox Domain DMARC Record Query](Images/lab_screenshot_10_56_56.png)

---

## Task 3: Weaponized Attachment Extraction & Triage

### 1. The Scenario
The message included an unexpected file attachment configured inside a multi-part MIME container. Analysts must safely compute a file signature before detonation to check for historical multi-vendor detection profiles.

### 2. Analysis & Detection Strategy
I extracted the raw multi-part attachment metadata from the message source to identify the filename and transfer packaging rules. I then pulled up the system terminal to generate a cryptographic file hash.

![MIME Multi-part Boundary Content Fields](Images/lab_screenshot_10_39_52.png)

```bash
sha256sum SWT_#09674321_____PDF___.CAB
```

![Terminal SHA256 Hash Computation Output](Images/lab_screenshot_10_43_48.png)

### 3. Forensic Discovery
The extraction routine exposed an attempt to disguise a functional container format as a standard document asset:
* **Attachment Filename:** `SWT_#09674321_____PDF___.CAB`
* **Calculated SHA256 Signature:** `2e91c53315a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f`

I submitted the extracted file signature to **VirusTotal** to run real-time threat categorization engine metrics:
* **File Size Metrics:** `400.26 KB`
* **True File Type:** `RAR` archive container (v5)
* **Threat Intelligence Status:** 50 out of 63 global endpoint protection vendors classified the signature as explicitly malicious, pointing toward known generic trojan droppers (`trojan.msil/loki`).

![VirusTotal Threat Classification Summary](Images/lab_screenshot_10_55_08.png)

![VirusTotal Technical Properties and Magic Headers](Images/lab_screenshot_10_55_38.png)

---

## Task 4: Incident Response & Remediation

### 1. Immediate Containment
Upon confirming malicious intent, the first priority is stopping active damage before any further investigation:
* **Isolate the endpoint** — If the sales executive opened the attachment, quarantine the workstation from the network immediately to prevent lateral movement or C2 beacon establishment by the `trojan.msil/loki` payload.
* **Block the originating IP at the perimeter firewall** — Add `192.119.71.157` to the deny list to cut off any active connections from the same infrastructure.
* **Block the sender domain at the email gateway** — Add `mutawamarine.com` to the inbound blocklist. The domain is either compromised or controlled by the threat actor.
* **Deploy the file hash to EDR** — Push `2e91c53315a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` to the endpoint detection and response platform as an explicit quarantine rule to catch the payload if it surfaced on any other machine.

### 2. Scope Assessment
Determine whether this was a single-target attempt or part of a wider campaign:
* Pull mail gateway logs and search for any other internal recipients that received messages from `info@mutawamarine.com` or from the same originating IP range.
* Scan endpoint telemetry across the environment for file creation events matching the attachment filename `SWT_#09674321_____PDF___.CAB` or the computed SHA256 hash.
* If the attachment was executed, extract memory artifacts and review outbound network connections for known Loki C2 callback patterns.

### 3. Hardening & Prevention
Address the structural weaknesses this attack exposed:
* **Enforce SPF at the gateway** — The domain's published SPF record uses `-all` (hard fail), yet the message was delivered. Review the inbound mail gateway configuration to ensure SPF fail results in outright rejection rather than a header flag.
* **Escalate internal DMARC policy** — If Greenholt PLC operates its own mail domain, push the DMARC policy from `p=quarantine` to `p=reject` to prevent lookalike domain abuse.
* **Enable double-extension detection** — Configure the email gateway or DLP rules to flag and strip attachments where the filename contains a misleading extension pattern (e.g., `.PDF___.CAB`, `.exe.pdf`).
* **User awareness** — Brief the sales team on unsolicited payment transfer requests. The generic greeting and unexpected attachment should have been an immediate red flag.

### 4. Reporting
* Notify HostPapa's abuse team (`abuse@hostpapa.com`) with the originating IP and message headers so the compromised or malicious server can be taken down.
* Document the full IOC set and file an internal incident report.

---

## IOC Summary

| Type | Value | Verdict |
|---|---|---|
| Sender IP | `192.119.71.157` | Malicious — HostPapa-hosted delivery node |
| Sender Domain | `mutawamarine.com` | Spoofed / Compromised — SPF Hard Fail |
| Attachment Filename | `SWT_#09674321_____PDF___.CAB` | Malicious — Double-extension masquerading |
| SHA256 Hash | `2e91c53315a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` | 50/63 VT vendors — `trojan.msil/loki` |
| True File Type | RAR archive (v5) disguised as CAB/PDF | Obfuscated container |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Observed Behavior |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Unsolicited email with malicious attachment targeting a sales executive |
| T1036.007 | Masquerading: Double File Extension | `.PDF___.CAB` filename exploiting hidden extension defaults |
| T1204.002 | User Execution: Malicious File | Payload requires the recipient to open the attachment |
| T1071 | Application Layer Protocol | Potential C2 communication channel established post-execution by Loki trojan |

---

## The Real-World Lesson
Adversaries frequently layer obfuscation mechanisms—such as naming a nested `RAR/CAB` archive container with an extended trailing whitespace and `.PDF` extension string—to exploit default operating system configurations that hide file extensions from users. When inspecting phishing indicators, defenders must systematically cross-reference structural layer fields like `Authentication-Results` against active threat intelligence metrics to expose spoofed sender infrastructures before interacting with payloads.