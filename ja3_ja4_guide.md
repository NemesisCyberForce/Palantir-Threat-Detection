# TLS Fingerprinting with JA3/JA4: The Defender's Lens

**TLS Fingerprinting** is one of the most reliable ways to detect advanced or "white-labeled" agents, as it identifies the unique cryptographic "personality" of the client software, regardless of the IP address, domain, or User-Agent string. This guide covers detection theory, implementation, and practical hunting strategies.

---

## What are JA3 and JA4?

| Fingerprint | Focus | Protocol Layer | Best Used For |
| :--- | :--- | :--- | :--- |
| **JA3** | Original, MD5-based | TLS 1.2 (and below) | Identifying classic agents and known tools (e.g., Mimikatz, C2 Frameworks, legacy applications) |
| **JA4** | **Modern, more granular** | TLS 1.3 + Client/Server distinction | **Superior** detection for modern beaconing, custom applications, and encrypted traffic analysis |

### How It Works

A TLS client (such as `polis-agent.exe`) initiates a **Client Hello** message during the handshake. This message encodes:
- **TLS Version**
- **Cipher Suites** (supported encryption algorithms)
- **Extensions** (additional features requested)
- **Elliptic Curves** (for ECDHE key exchange)
- **Supported Signature Algorithms**

The **JA3/JA4 hash** is a standardized hash (MD5 for JA3, proprietary for JA4) derived from concatenating these values. The result is a fixed-length fingerprint unique to each TLS client implementation.

**Key Insight for Defense:** Two pieces of software built with different network stacks (e.g., Python's `requests` library vs. C# `HttpClient` vs. Go's `crypto/tls`) will produce *different* JA3/JA4 hashes, even if they connect to the identical server. This immutability makes fingerprinting ideal for detecting custom surveillance tools.

---

## Implementation Steps for Analysts

To effectively hunt using TLS fingerprinting, you need three components: **Data Source**, **Collection Tool**, and **Detection Logic**.

### Step 1: Data Source & Collection Tool

TLS fingerprinting requires network logging with cryptographic handshake details. Choose based on your infrastructure:

| Platform | Recommended Tool / Feature | Setup Complexity | Collection Notes |
| :--- | :--- | :--- | :--- |
| **Suricata (IDS)** | Built-in `ja3` keyword | Low | Rule-based alerting; generates immediate notifications. Limited to JA3 only. |
| **Zeek (NSM)** | Built-in `ja3` / `ja4` script; `ssl.log` output | Medium | **Recommended for comprehensive hunting.** Creates structured JSON/TSV logs with both JA3 and JA4. Requires log forwarding to SIEM. |
| **Packet Capture (Offline Analysis)** | Python tools: `ja3er`, `JA4-Python`, `pyshark` | High | For forensic analysis of existing PCAP files. Useful for incident response. |
| **Firewall / Proxy** | Commercial NGFWs (Palo Alto, Fortinet, Cisco) | Medium | Vendor-dependent; check documentation for JA3/JA4 export capabilities. Often requires licensing. |
| **Network Telemetry (Cloud)** | AWS VPC Flow Logs (limited), Azure NSG Logs | Low | Limited TLS metadata; best combined with Zeek appliance. |

**Critical Setup Detail:** Ensure your SIEM (Elasticsearch, Splunk, Wazuh) ingests network logs with fields named `tls.ja3_hash` and/or `tls.ja4_hash` in a normalized format. If using Zeek, the `ssl.log` must be parsed and mapped correctly.

#### Zeek Configuration Example
```
@load base/protocols/ssl
@load policy/protocols/ssl/validate-certs
```

This enables JA3 logging in `ssl.log` with fields: `ja3`, `ja3s`, and (if using JA4-enabled Zeek branch) `ja4`.

---

### Step 2: Detection Logic (Sigma Rules)

Sigma rules for TLS fingerprinting are simple but exceptionally high-fidelity because the hash is a static cryptographic property.

#### Rule 1: Known White-Label Hash (CRITICAL - Use Only with Verified Hashes)

```yaml
title: Detection of Known Surveillance Agent - TLS Fingerprint
description: |
  CRITICAL: This rule should only be enabled after obtaining verified TLS hashes 
  from trusted threat intelligence sources or internal security assessments.
  False hashes will cause high false positive rates.
logsource:
  category: network_connection
  product: zeek
detection:
  selection:
    tls.ja4_hash:
      - 't13d39000a68d...'  # EXAMPLE ONLY - Replace with verified hash
      - 't13d39000b12c...'  # EXAMPLE ONLY - Replace with verified hash
  condition: selection
level: critical
tags:
  - threat_hunting
  - tls_fingerprint
  - government_surveillance
  
falsepositives:
  - Legitimate enterprise tools with identical TLS stacks (rare)
```

**Important:** Never deploy this rule without verified hashes. Incorrect hashes will generate false positives and alert fatigue.

---

#### Rule 2: Anomalous TLS Characteristics (Hunting Rule)

This rule hunts for clients with suspicious TLS properties that may indicate custom or minimalist implementations.

```yaml
title: Anomalous TLS Client Fingerprint - Hunting Rule
description: |
  Detects TLS clients with minimal extension lists or non-standard cipher configurations.
  Common in custom-built agents, IoT devices, or legacy systems.
  High false positive rate; use for hunting, not alerting.
logsource:
  category: network_connection
  product: zeek
detection:
  selection:
    tls.version:
      - 'TLSv12'
      - 'TLSv13'
    # Suspiciously short extension list (typical custom agents have < 5 extensions)
    tls.client_extensions_count: '<5'
    # Exclude known benign applications
    tls.ja3_hash|not:
      - '44c9213122c8...'  # Chrome on Windows
      - 'e4f20653df32...'  # Windows native TLS
      - '6734a7f1aff2...'  # macOS native TLS
      - '...add org baseline hashes here...'
  filter:
    # Exclude internal infrastructure (adjust to your network)
    dest_ip|startswith:
      - '10.'
      - '172.16.'
      - '192.168.'
  condition: selection and not filter
level: medium
tags:
  - threat_hunting
  - custom_agent_detection
  
falsepositives:
  - IoT devices and embedded systems
  - Legacy VPN clients
  - Minimalist HTTP clients (curl, wget, Python requests with limited extensions)
```

---

#### Rule 3: Beaconing Detection via TLS Fingerprint Consistency

This rule correlates TLS fingerprint, destination, and timing to detect beaconing patterns.

```yaml
title: Beaconing Pattern via Consistent TLS Fingerprint
description: |
  Detects the same TLS fingerprint repeatedly connecting to the same destination 
  at regular intervals, indicative of automated agent beaconing.
logsource:
  category: network_connection
  product: zeek
detection:
  selection:
    # Same TLS fingerprint
    tls.ja4_hash: '*'
    # Same destination (IP or domain)
    dest_ip: '*'
  condition: selection
  timeframe: 5m
  # Alert if the same ja4_hash + dest_ip appears 10+ times in 5 minutes
  count_condition: count(tls.ja4_hash, dest_ip) >= 10
level: high
tags:
  - beaconing
  - c2_detection
  - government_surveillance
  
falsepositives:
  - Legitimate SaaS heartbeat traffic
  - Health check services
  - API polling applications
```

---

## 🔬 Analyst Field Guide: Practical Hunting Strategy

### Phase 1: Baseline Establishment (Week 1-2)

1. **Collect JA3/JA4 Hashes:** Export all unique TLS fingerprints from Zeek `ssl.log` for 7-14 days.
   ```bash
   # Extract unique ja4 hashes and their frequency
   cat ssl.log | jq -r '.ja4' | sort | uniq -c | sort -rn > ja4_baseline.txt
   ```

2. **Group by Application:** Manually identify hashes by common source processes and destinations:
   - Corporate browsers (Chrome, Firefox, Edge)
   - VPN clients (Cisco, Fortinet, PulseSecure)
   - Monitoring agents (Wazuh, SplunkUF, DataDog)
   - OS-level TLS (Windows HTTP stack, macOS CFNetwork)

3. **Build Allowlist:** Create a whitelist of "approved" hashes with metadata:
   ```json
   {
     "allowlist": [
       {
         "hash": "44c9213122c8...",
         "application": "Chrome 120+",
         "reason": "corporate_browser",
         "verified": true,
         "added_date": "2025-01-15"
       },
       {
         "hash": "e4f20653df32...",
         "application": "Windows HTTP.sys",
         "reason": "os_native_tls",
         "verified": true,
         "added_date": "2025-01-15"
       }
     ]
   }
   ```

### Phase 2: Tiered Hunting (Ongoing)

#### **Tier 1: Critical – Known White-Label Hashes**
- **Action:** Immediate investigation and escalation
- **Data Source:** Threat intelligence feeds, law enforcement alerts, verified IOC lists
- **Indicator:** Exact JA3/JA4 hash match from known surveillance tools
- **Response Time:** < 1 hour

**Important:** Only add hashes to this tier if they come from authoritative sources (government advisories, peer-reviewed research, law enforcement notifications).

#### **Tier 2: High – Anomalous + Beaconing**
- **Action:** Manual investigation; check process origin, destination, user context
- **Data Source:** Anomalous TLS Characteristics rule + Beaconing Pattern rule
- **Indicator:** Unknown hash with suspicious characteristics (few extensions, non-standard ciphers) + regular connection intervals
- **Response Time:** < 24 hours

**Example Investigation Checklist:**
- [ ] Verify hash against VirusTotal / threat intelligence platforms
- [ ] Correlate with process creation logs (Sysmon EventID 3 or EDR data)
- [ ] Check destination IP geolocation and reputation
- [ ] Review user who initiated the connection
- [ ] Analyze network payload (if TLS is decryptable)

#### **Tier 3: Medium – Baseline Deviation**
- **Action:** Log and monitor; hunt if other risk factors present
- **Data Source:** New hashes not in allowlist; entropy analysis
- **Indicator:** Hash outside 30-day baseline with < 5 TLS extensions
- **Response Time:** Weekly review

---

### Phase 3: Advanced Correlation (Optional, High Effort)

For mature security operations, correlate TLS fingerprints with other layers:

```
TLS Fingerprint Match (Medium)
  + Process Execution Anomaly (Host-based)
  + Data Exfiltration Pattern (Network-based)
  + Registry Persistence (Host-based)
  = CRITICAL Incident
```

Use a SIEM correlation engine (Splunk SPL, Elastic ES|QL, Wazuh rules) to combine signals:

```
# Pseudocode for Splunk correlation
index=network ja4_hash="*" 
| join type=inner [
    search index=host process_name="suspicious_agent.exe"
  ]
| join type=inner [
    search index=network dest_port=443 bytes_out > 1GB timeframe=5m
  ]
| stats count by source_ip, ja4_hash, process_name
| where count > 10
```

---

## Limitations & Edge Cases

### What TLS Fingerprinting Can't Detect

1. **HTTP Traffic:** No TLS = no fingerprint. Agents using HTTP or cleartext protocols are invisible to this detection.
2. **Proxied Traffic:** If traffic routes through a corporate proxy, you'll see the proxy's TLS fingerprint, not the agent's.
3. **DNS Tunneling:** DNS queries (port 53) have no TLS component; agents using DNS exfiltration bypass this detection entirely.
4. **Custom TLS Stacks:** A sufficiently sophisticated attacker could build a custom TLS library that mimics legitimate application fingerprints.

### False Positive Sources

- **Auto-update mechanisms:** Software updaters often use minimalist TLS implementations
- **IoT devices:** Smart devices, printers, and industrial equipment typically have limited TLS extensions
- **VPN clients:** Legacy or open-source VPN software may have unusual TLS profiles
- **Mobile apps:** iOS/Android apps may use different TLS stacks than desktop browsers

### Mitigation for False Positives

1. Create a **negative allowlist** of known-benign anomalous hashes
2. Use **context filters** (exclude internal IPs, trusted destinations)
3. Implement **confidence scoring** (combine TLS fingerprint with other indicators)
4. Schedule **monthly baseline updates** to account for new legitimate applications

---

## Tools & Resources

### Open-Source Tools for TLS Fingerprinting

| Tool | Purpose | Language | Notes |
| :--- | :--- | :--- | :--- |
| **Zeek** | Network monitoring + JA3/JA4 logging | C++ / Zeek Script | Industry-standard NSM. Generates structured logs. |
| **Suricata** | IDS with JA3 detection | C | Lightweight alternative to Zeek. JA3 only (no JA4). |
| **ja3er** | Python library for JA3 calculation | Python | For custom scripts and offline PCAP analysis. |
| **JA4-Python** | JA4 fingerprinting library | Python | Newer, more granular than JA3. |
| **Arkime** | Full packet capture and search | JavaScript/Node.js | Excellent for forensic analysis of PCAP files. |

### Reference Documentation

- **JA3 Specification:** [engineering.salesforce.com](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)
- **JA4 Specification:** [github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)
- **Zeek SSL Analysis:** [zeek.org/docs](https://zeek.org/docs)
- **Threat Intelligence Feeds:** Check with ISACs, government CERTS (e.g., BSI, CISA), or commercial threat intelligence providers

---

## Operational Security Considerations

1. **Protect Your Allowlist:** If an adversary knows your allowlist, they can craft JA3/JA4 hashes to match legitimate applications.
2. **Hash Leakage:** Don't publicize known-bad hashes in public databases; this helps attackers fingerprint your defenses.
3. **Baseline Rotation:** Update your baseline hashes quarterly to account for OS patches, browser updates, and new applications.
4. **Log Retention:** Retain Zeek `ssl.log` for at least 90 days for forensic analysis.

---

## Summary Checklist

- [ ] Deploy Zeek or Suricata with TLS logging enabled
- [ ] Configure SIEM to ingest and normalize `tls.ja3_hash` / `tls.ja4_hash` fields
- [ ] Build a 7-14 day baseline of your environment's TLS fingerprints
- [ ] Create allowlists of approved applications
- [ ] Deploy Sigma hunting rules (start with Tier 2 + Tier 3 only; Tier 1 requires verified IOCs)
- [ ] Establish incident response procedures for anomalous TLS detections
- [ ] Schedule monthly reviews of new hashes and baseline updates
- [ ] Document false positives and refine allowlists iteratively
