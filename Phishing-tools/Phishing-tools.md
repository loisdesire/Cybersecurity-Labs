# Incident Response: Threat Intelligence & Dynamic Sandbox Analysis

This repository documents hands-on analysis of malicious documents and phishing emails using enterprise threat intelligence and dynamic sandboxes. The goal is to move beyond static header inspection, leverage Cisco Talos for infrastructure profiling, and detonate weaponized payloads in ANY.RUN to extract live Command-and-Control (C2) telemetry.

---

## Task 1: Threat Intelligence & Indicator Profiling

### 1. Overview
Before interacting with potential malware, an analyst must establish a risk baseline. Threat actors frequently register new, unrated domains to bypass legacy secure email gateways (SEGs) that rely on blacklist-based detection. Additionally, hashing files instead of executing them helps prevent accidental local infection.

### 2. Findings
Cisco Talos was used to profile the infrastructure of a suspected campaign and verify the cryptographic signature of a suspicious attachment.

- **Target Domain:** `malware-test.com`  
- **Talos Verdict (Domain):** `Neutral`  
  - Indicates use of unrated infrastructure for evasion

![Cisco Talos Domain Lookup](Images/talos_domain_lookup.png)

- **Target File Hash (SHA256):** `025ba9ce4a2118a9ca7b115c8869ff73bc16bad3732ba359cef1e60ad8f961f9`  
- **Talos Verdict (File):** `Malicious`  
  - Identified under signature `Phishing/PDF.Malurl.XG5`

![Cisco Talos Hash Reputation](Images/talos_hash_lookup.png)

---

## Task 2: Dissecting Credential Harvesting (Phish3Case1.eml)

### 1. Overview
An end-user reported an email impersonating a Netflix payment error. The message relied on urgency and brand impersonation to trigger fast user action before inspection of sender details.

![Case 1 Rendered Email View](Images/case1_rendered_email.png)

### 2. Findings
Raw `.eml` header analysis revealed inconsistencies across Mail Transfer Agents (MTAs), indicating spoofing.

- **Originating IP:** `209.85.167.226`  
- **Return-Path:** `etekno.xyz`  
- **Observation:** Header routing indicated irregular infrastructure (e.g., `gogolecloud.com`), confirming spoofing activity  

![Case 1 Raw Message Headers](Images/case1_headers.png)

### 3. Analysis
Inspection of the email HTML revealed a credential-harvesting mechanism hidden behind a shortened URL (`https://t.co/yuxfZm8KPg?amp=1`). The use of URL shortening helped evade basic filtering mechanisms while redirecting victims to a phishing endpoint.

---

## Task 3: Dynamic Detonation of Weaponized PDF (Payment-updateid.pdf)

### 1. Overview
PDF-based malware often uses embedded scripts or external process calls. The sample was detonated in the ANY.RUN sandbox to observe runtime behavior and process activity safely.

![VirusTotal PDF Hash](Images/pdf_vt_hash.png)

### 2. Findings
Execution within Adobe Acrobat Reader (`AcroRd32.exe`) triggered secondary processes.

- **Initial Process:** `AcroRd32.exe`  
- **Spawned Process:** `RdrCEF.exe`  
- **Observation:** Immediate outbound communication attempts detected  

![ANY.RUN PDF Runtime Analysis](Images/pdf_sandbox_analysis.jpg)

### 3. Analysis
Network telemetry revealed malicious behavior:

- **Anomalous Traffic:** `svchost.exe` triggered `ET INFO TLS Handshake Failure` alerts  
- **Behavior:** Attempted non-standard encrypted communication  
- **C2 Connection:** `185.221.16.143`  

![ANY.RUN PDF Network Connections](Images/pdf_sandbox_network.png)

---

## Task 4: Tracking Memory Corruption Exploits (CBJ200620039539.xlsx)

### 1. Overview
This attack bypassed macro-based defenses by exploiting a legacy Microsoft Office vulnerability (**CVE-2017-11882**) at the memory level.

![ANY.RUN Excel Hash Extraction](Images/excel_sandbox_hashes.png)

### 2. Findings
Sandbox analysis revealed a clear exploitation chain:

- **Initial Process:** `EXCEL.EXE`  
- **Dropped Process:** `EQNEDT32.EXE` (Microsoft Equation Editor)  
- **Result:** Buffer overflow leading to control flow hijack  
- **Final Payload Execution:** `ntvdm.exe`  

![ANY.RUN Excel Process Tree](Images/excel_sandbox_analysis.png)

### 3. Analysis
Post-exploitation behavior included DNS-based infrastructure communication:

- **Primary C2:** `biz9holdings.com` → `204.11.56.48`  
- **Secondary Staging:** `findresults.site` → `103.224.182.251`  

![ANY.RUN Excel DNS Telemetry](Images/excel_sandbox_dns.png)

---

## Real-World Lesson

Modern phishing campaigns increasingly bypass traditional macro-based detection and instead exploit application memory and trusted system utilities. 

A key SOC indicator of compromise is when legitimate applications (e.g., Excel) spawn legacy or abnormal processes that immediately initiate outbound network traffic.