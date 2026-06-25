# Packet Analysis & Email Security Lab
This repository documents my hands-on analysis of network packet captures (`.pcap`) to investigate malicious mail server communications, map adversarial behavior, and extract indicators of compromise (IoCs) using Wireshark. By analyzing SMTP metrics and IMF structural attributes, I isolated specific attack vectors, identified security system bypasses, and mapped out how automated mail payloads function.

---

## Task 6: Analyzing SMTP Traffic (Response Codes)

### 1. The Threat
The mail server was hitting a wall with repeated delivery failures and automated filtering blocks, signaling potential spam abuse, misconfigured forwarding, or an active phishing campaign trying to drop malicious payloads across the network.

### 2. Analysis & Detection Strategy
I targeted the structural layers of the SMTP protocol using specific display filters to drill down into the server's return codes. Instead of wading through raw data, isolating conversational checkpoints between the mail transfer agents (MTAs) let me track exactly where connection negotiations succeeded and where centralized external defensive tools actively rejected the inbound traffic:
* **Display Filter:** `smtp.response.code`
* **Response Code 220 Count:** `19`
* **Response Code 552 Count:** `6`

![SMTP Response Code 220 Filter View](Images/smtp_220_filter.png)

### 3. Implementation
I isolated multiple communication behaviors across the packet capture. First, applying the `smtp.response.code == 220` rule confirmed the server successfully initiated connections 19 times. Shifting focus to perimeter rejections, I uncovered external threat intelligence blocks where a server returned a `553` code, completely dropping an email because the sender's origin reputation was explicitly flagged by a public blocklist. 

* **Extracted Spamhaus Error:** `553 5.3.0 Email blocked using spamhaus.org - see <http://www.spamhaus.org> 173.66.46.112`

Finally, tracking the `552` status code revealed 6 distinct messages blocked outright for presenting potential security issues due to violating content or attachment guidelines.

![Spamhaus Blocked Response Details showing Code 553](Images/spamhaus_block.png)

![Security Issue Content Blocks under Code 552](Images/smtp_552_block.png)

### 4. The Real-World Lesson
Monitoring edge return codes provides immediate health metrics for mail networks. Relying entirely on simple domain blocks is a losing game because attackers spin up new staging layers constantly, but analyzing reputation blocks like Spamhaus at the protocol level stops delivery dead at the initial handshake before a malicious attachment can even touch an inbox.

---

## Task 7: Analyzing SMTP Traffic (Email Content & Attachments)

### 1. The Threat
An adversary successfully initiated an inbound session to deliver a multi-part email payload carrying a hidden, potentially malicious compressed archive designed to execute code upon extraction.

### 2. Analysis & Detection Strategy
I dropped broad status filters and pivoted to deep content inspection. By isolating the full application layer protocol and analyzing the structural breakdown of individual mail bodies, I looked for anomalies in encoding mechanisms, embedded attachments, and internal delivery subsystem diagnostics:
* **Total SMTP Packets:** `512`
* **Target Payload Key:** `document.zip`
* **Failed Routing Footprint:** `212.253.25.152`
* **Malicious Mail Client:** `Microsoft Outlook Express 6.00.2600.0000`
* **Encoding Routine:** `base64`

![Packet 270 Analysis covering Undeliverable Mail Subsystem Header](Images/packet_270_undelivered.png)

### 3. Implementation
I applied a blanket `smtp` filter to verify the overall conversational surface area, which exposed a distinct subset of 512 packets available for analysis. Drills into packet `270` exposed an automated bounce message from a mail delivery subsystem detailing a routing failure because the host at `212.253.25.152` refused to respond. Inspecting the raw MIME headers nested inside that packet revealed a staged attachment string pointing to an archive named `document.zip`.

To trace parallel activity, I shifted filters to `imf` (Internet Message Format) and looked for specific malicious attachment signatures like `attachment.scr`. This extracted the exact structural signature of a wave where the attacker used a legacy `Microsoft Outlook Express` instance to generate the message, leveraging `base64` encoding to obfuscate the executable content inside the transport stream.

![Packet 270 MIME Part Detail showing Attachment Zip and Base64 Structural Attributes](Images/packet_270_details.png)

![IMF Filter isolating X-Mailer Metadata and Attachment.scr Client Signature](Images/imf_metadata.png)

### 4. The Real-World Lesson
Attackers rely heavily on binary-to-text encoding configurations like Base64 to smuggle malicious binaries cleanly past basic network string filters. True defense requires deeply decapsulating application layers and checking metadata like `X-Mailer` headers—variations from enterprise standards instantly point to automated scripts or legacy software commonly abused during targeted phishing attacks.