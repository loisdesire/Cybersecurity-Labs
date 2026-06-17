# PicoSecure Threat Simulation & Detection Lab

This repository documents my hands-on experience acting as a Detection Engineer during an iterative threat simulation exercise against an adversary named "Sphinx".

---

## Task 1: Breaking File Hashes (The Bottom of the Pyramid)

### 1. The Threat
The adversary executed a malicious binary named `sample1.exe`.

### 2. Analysis & Detection Strategy
I focused on the cryptographic signature of the file since file names are easily changed:
* **SHA256 Hash:** `9c550591a25c6228cb7d74d970d133d75c961ffed2ef7180144859cc09efca8c`

![Malware Sandbox Analysis Report for Sample 1](PicoSecure_Threat_Detection/Images/lab_screenshot_3.png)

### 3. Implementation
I utilized the **Manage Hashes** tool in PicoSecure to block the signature, neutralizing execution.

![Hash Manager Blocklist Rule](PicoSecure_Threat_Detection/Images/lab_screenshot_6.png)

### 4. The Real-World Lesson
While hashes are precise, they are fragile. The attacker altered a single bit and recompiled the code, generating an entirely new hash signature that bypassed the static rule.

---

## Task 2: Escalating to Network Indicators (Moving Up the Pyramid)

### 1. The Threat
The adversary deployed `sample2.exe` with a modified signature, rendering the previous hash rule useless.

### 2. Analysis & Detection Strategy
I analyzed live runtime telemetry in the sandbox to look for outbound network infrastructure indicators:
* **Malicious Destination:** `154.35.10.113:4444`

![Malware Sandbox Network Activity and Connections for Sample 2](PicoSecure_Threat_Detection/Images/lab_screenshot_10.png)

### 3. Implementation
I configured a network-level block inside the **Firewall Rule Manager**:
* **Type:** Egress (Outbound)
* **Source:** Any
* **Destination IP:** `154.35.10.113`
* **Action:** Deny

![Firewall Rule Configuration](PicoSecure_Threat_Detection/Images/lab_screenshot_11.png)

### 4. The Real-World Lesson
Moving up the Pyramid of Pain to network indicators creates a more resilient defense; the malware remains blocked regardless of signature changes as long as it phones home to that IP.

---

## Task 3: Defeating IP Rotation via Domain Names

### 1. The Threat
The adversary bypassed the firewall block by deploying `sample3.exe`, dynamically cycling through backup public cloud IP addresses.

### 2. Analysis & Detection Strategy
Instead of playing whack-a-mole with shifting IPs, I targeted the underlying DNS resolution network indicator:
* **Malicious Domain:** `emudyn.bresonicz.info`

![Sandbox DNS Requests Telemetry for Sample 3](PicoSecure_Threat_Detection/Images/lab_screenshot_13.png)

### 3. Implementation
I applied a centralized domain-filtering block inside the **DNS Rule Manager**:
* **Domain Name:** `emudyn.bresonicz.info`
* **Action:** Deny

![DNS Rule Manager Blocked Domain](PicoSecure_Threat_Detection/Images/lab_screenshot_14.png)

### 4. The Real-World Lesson
Domains sit higher on the pyramid because forcing an attacker to re-register infrastructure and update code increases their operational friction.

---

## Task 4: Monitoring Host Artifacts (Sigma & Registry Modifications)

### 1. The Threat
The adversary shifted away from network indicators to execute `sample4.exe`, which attempts to blind local host security.

### 2. Analysis & Detection Strategy
I reviewed host telemetry and discovered the malware making unauthorized changes directly to the endpoint registry configuration:
* **Registry Key:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`
* **Name:** `DisableRealtimeMonitoring`
* **Value:** `1`

![Sandbox Registry Activity Logs for Sample 4](PicoSecure_Threat_Detection/Images/lab_screenshot_16.png)

### 3. Implementation
I leveraged the **Sigma Rule Builder** to monitor Sysmon event logs and flag this exact behavior mapping to **MITRE ATT&CK T1562.001** (Impair Defenses: Disable or Modify Tools).

![Sigma Rule Builder Registry Configuration & Validation](PicoSecure_Threat_Detection/Images/lab_screenshot_20.png)

![Sigma Rule Builder Registry Output](PicoSecure_Threat_Detection/Images/ip-10-82-95-11 - Amazon DCV - Google Chrome 6_17_2026 9_17_34 PM.png)

### 4. The Real-World Lesson
Detecting host artifacts focuses on the state changes an application leaves on a filesystem or registry, preventing malware from hiding its footprint locally.

---

## Task 5: Identifying Behavioral Patterns (C2 Beaconing)

### 1. The Threat
The adversary deployed `sample5.exe`, conducting all execution on back-end systems while dynamically varying network protocols and host changes to evade fixed-rule indicators.

### 2. Analysis & Detection Strategy
I audited Sysmon network logs over a 12-hour window and identified a clear, automated **Command & Control (C2) Beaconing** heartbeat profile:
* **Target IP:** Dynamic / Wildcard (`any`)
* **Fixed Connection Size:** `97 bytes`
* **Interval Frequency:** Exactly every 1800 seconds (30 minutes)

![12-Hour Outbound Network Traffic Logs Analysis](PicoSecure_Threat_Detection/Images/lab_screenshot_1.png)

### 3. Implementation
I created a behavioral analytics rule under Sysmon Network Connections matching these precise structural parameters, mapping to **MITRE ATT&CK T1071** (Standard Application Layer Protocol).

![Sigma Rule Builder Network Connection Rule Configuration](PicoSecure_Threat_Detection/Images/lab_screenshot_22.png)

![Sigma Rule Builder Network Connection Detail](PicoSecure_Threat_Detection/Images/lab_screenshot_23.png)

### 4. The Real-World Lesson
At the higher echelons of the Pyramid of Pain, you stop chasing static values (hashes, IPs) and start detecting the fundamental, unavoidable behavior of the attacker's tools.

---

## Task 6: Disrupting Adversary TTPs (The Peak of the Pyramid)

### 1. The Threat
The adversary deployed `sample6.exe` with modular backend capabilities, attempting to execute host reconnaissance scripts completely detached from predictable file signatures or fixed network behaviors.

### 2. Analysis & Detection Strategy
Rather than tracking malware code, I audited the human adversary's procedural habits via `commands.log`. Upon gaining remote access, the attacker subconsciously executed an automated sequence of local system discovery commands, appending all outputs to a localized staging file:
* **Subconscious Signature:** `>> %temp%\exfiltr8.log`

![Adversary Reconnaissance Command Logs Profile](PicoSecure_Threat_Detection/Images/lab_screenshot_24.png)

### 3. Implementation
I built a process-behavioral rule utilizing the **Sigma Rule Builder** to track Sysmon Event ID 1 (Process Creation):
* **Process Name:** `cmd.exe`
* **CommandLine String:** `exfiltr8.log`
* **MITRE ATT&CK ID:** `T1119` (Automated Collection)

![Final Process Creation Sigma Rule Deployment](PicoSecure_Threat_Detection/Images/lab_screenshot_2.png)

### 4. The Real-World Lesson
Targeting Tactics, Techniques, and Procedures (TTPs) represents the absolute pinnacle of defense. By engineering a detection rule around the attacker's fundamental operational habits, the entire playbook is burned. The cost and training friction required for the adversary to design entirely new behaviors completely destroys their return on investment (ROI), successfully forcing them off the network.
