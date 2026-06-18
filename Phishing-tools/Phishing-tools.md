# Phishing Triage & Sandbox Malware Analysis

This project walks through my forensic workflow for pulling apart phishing emails and malicious documents. We'll start by looking at how to verify threats using intelligence tools (like Cisco Talos), and then move into a sandbox environment (ANY.RUN) to safely detonate the malware and track its Command-and-Control (C2) infrastructure.

---

## Part 1: Threat Intelligence (Cisco Talos)

Before touching a suspicious file or clicking a link, you have to know what you are dealing with. Running our initial findings (like domains and file hashes) through a threat intelligence feed keeps us from flying blind.

### 1. Domain Profiling
Attackers love to use brand-new, unregistered domains. Why? Because legacy web filters usually only block sites that are explicitly flagged as malicious. If a site is unrated, it often slips right through.

*   **Target Domain:** `malware-test.com`
*   **Talos Verdict:** `Neutral` (This perfectly highlights why unrated domains are suspicious).

![Cisco Talos Domain Lookup](Images/talos_domain_lookup.png)

### 2. File Fingerprinting
You never want to open a shady file on your actual machine. Instead, the safest route is to generate its unique cryptographic hash and check if global security vendors have already flagged it.

    # Generating a file signature inside a secure Linux environment
    sha256sum shady_attachment.pdf

*   **Target Hash:** `025ba9ce4a2118a9ca7b115c8869ff73bc16bad3732ba359cef1e60ad8f961f9`
*   **Talos Verdict:** `Malicious` (Flagged as `Phishing/PDF.Malurl.XG5`).

![Cisco Talos Hash Reputation](Images/talos_hash_lookup.png)

---

## Part 2: SOC Triage Case — The Netflix Spoofer

### 1. The Incident
A user reported a highly convincing email that looked like a payment error from Netflix. This is standard social engineering: use a trusted brand and create artificial panic to make the user click quickly.

![Case 1 Rendered Email View](Images/case1_rendered_email.png)

### 2. Checking the Headers
The display name said `Netflix`, but the raw `.eml` source code told the real story. I checked the Mail Transfer Agents (MTAs) to see where the email actually came from:

*   **True Originating IP:** `209.85.167.226`
*   **Return-Path:** `etekno.xyz`
*   **The Catch:** The routing infrastructure showed the email originated from a weird `gogolecloud.com` server and bounced back to `etekno.xyz`. This is a classic spoofing mismatch.

![Case 1 Raw Message Headers](Images/case1_headers.png)

### 3. Unmasking the Link
The "UPDATE ACCOUNT NOW" button was hiding a redirected link: `https://t.co/yuxfZm8KPg?amp=1`. Attackers frequently use legitimate public shorteners (like Twitter's `t.co`) to mask their final payload and trick default email security gateways.

---

## Part 3: Interactive Sandbox Detonation (ANY.RUN)

When static analysis confirms a file is dangerous, the next step is to safely detonate it inside an isolated sandbox to watch its process tree and network behavior in real time.

### Case A: The Weaponized PDF (`Payment-updateid.pdf`)

PDFs aren't just flat text—they can run scripts and interactive elements. This file was built to quietly force a network connection the second it was opened.

![VirusTotal PDF Hash](Images/pdf_vt_hash.png)

#### What Happened Upon Execution:
Opening the document launched Adobe Acrobat Reader (`AcroRd32.exe`). However, the parent application immediately spawned background web-browser components (`RdrCEF.exe`) to reach out to the internet.

![ANY.RUN PDF Runtime Analysis](Images/pdf_sandbox_analysis.jpg)

*   **Network Anomalies:** The native Windows network process `svchost.exe` triggered a **Potentially Bad Traffic** alert for a `TLS Handshake Failure`. This means the malware was trying to set up a hidden, encrypted tunnel.
*   **Flagged C2 Destination:** We caught the process making an unauthorized connection to an external server at `185.221.16.143`.

![ANY.RUN PDF Network Connections](Images/pdf_sandbox_network.png)

### Case B: Excel Memory Corruption (`CBJ200620039539.xlsx`)

This attack was much more sophisticated. Instead of tricking the user into clicking a link, the spreadsheet was engineered to exploit a known legacy vulnerability (**CVE-2017-11882**) inside Microsoft Office to completely bypass macro security rules.

![ANY.RUN Excel Hash Extraction](Images/excel_sandbox_hashes.png)

#### What Happened Upon Execution:
The sandbox process tree caught the exact exploitation cycle:
1.  **The Hijack:** The moment `EXCEL.EXE` opened the file, it reached outside of its normal processes to launch an outdated, vulnerable utility: `EQNEDT32.EXE` (Microsoft Equation Editor).
2.  **The Exploit:** Because Equation Editor lacks modern memory protections, the payload forced a buffer overflow, took control of the application, and spawned `ntvdm.exe` to execute the actual malware.

![ANY.RUN Excel Process Tree](Images/excel_sandbox_analysis.png)

#### Tracking the Infrastructure:
Once the malware compromised the system's memory, the hijacked process started firing off DNS queries to connect with its Command & Control (C2) servers:
*   **Primary C2 Target:** `biz9holdings.com` (Resolved to IP: `204.11.56.48`)
*   **Secondary Staging Zone:** `findresults.site` (Resolved to IP: `103.224.182.251`)

![ANY.RUN Excel DNS Telemetry](Images/excel_sandbox_dns.png)

---

## The Big Takeaway
Phishing defense requires looking way past the inbox. In modern attacks, threat actors easily bypass macro controls by targeting the host application's memory directly. As an analyst, process monitoring is everything: **if a standard app like Excel suddenly launches an old background tool that immediately tries to connect to the open internet, you are looking at an active exploit.**