#### `ja3_ja4_guide.md`

# to point 7. TLS Fingerprinting with JA3/JA4: The Defender's Lens

**TLS Fingerprinting** is one of the most reliable ways to detect advanced or "white-labeled" agents, as it identifies the unique cryptographic "personality" of the client software, regardless of the IP address, domain, or User-Agent string.

## What are JA3 and JA4?

| Fingerprint | Focus | Protocol Layer | Best Used For |
| :--- | :--- | :--- | :--- |
| **JA3** | Original | TLS 1.2 (and below) | Identifying classic agents and known tools (e.g., Mimikatz, C2 Frameworks) |
| **JA4** | **Modern** | TLS 1.3 + Client/Server | **Superior** detection for modern, subtle beaconing and custom applications |

A TLS client (like the alleged `polis-agent.exe`) sends a **Client Hello** message during the handshake. This message contains a unique set of preferences, cipher suites, extensions, and elliptic curves. The **JA3/JA4 hash** is a standardized MD5 hash calculated from the concatenated values of these elements.

The key benefit for defense is that **two pieces of software built with different network stacks (e.g., Python vs. C\#) will have different hashes, even if they connect to the same site.** This makes it ideal for finding custom government tools.

-----

## Implementation Steps for Analysts

To effectively hunt for these indicators, you need three things: **Data Source**, **Collection Tool**, and **Detection Logic**.

### Step 1: Data Source & Collection Tool

You must enable TLS logging on your network monitoring platform to calculate the hash on the fly.

| Platform | Recommended Tool / Feature | Collection Note |
| :--- | :--- | :--- |
| **Suricata (IDS)** | Built-in `ja3` keyword | Simple rule matching; generates alerts on the hash. |
| **Zeek (Network Security Monitor)** | Built-in `ja3` script / `ssl.log` | Creates a comprehensive log file containing the `ja3` and `ja4` fields. **Recommended Data Source.** |
| **Packet Capture** | Python tools like `ja3er` or `JA4-Python` | For offline analysis of Pcap files. |
| **Firewall / Proxy** | Some commercial NGFWs (e.g., Palo Alto, Fortinet) | Check vendor documentation; may offer logging/filtering. |

**Goal:** Ensure your SIEM (Elastic/Splunk/Wazuh) ingests network logs that contain the fields `tls.ja3_hash` and/or `tls.ja4_hash`.

### Step 2: Detection Logic (Sigma Rules)

Since the `ja3_hash` or `ja4_hash` is a static string, the Sigma rule is highly simple but exceptionally high-fidelity.

#### Example 1: Known White-Label Hash (High-Fidelity Alert)

```yaml
title: High-Fidelity Known Palantir White-Label Hash
description: Detects the specific, known JA4 hash for the 'TRITON-X' agent.
logsource:
  category: network
  product: zeek
detection:
  selection:
    tls.ja4_hash: 't13d39000a68d...' # Example hash for a highly customized client
  condition: selection
level: critical
tags:
  - palantir
  - white_label
  - tls_fingerprint
```

#### Example 2: Hunting for Unknown/New Agents (Hunting Rule)

Use the TLS characteristics to find agents that are *likely* automated or custom, but whose hash is not yet known.

```yaml
title: Custom Agent TLS Hunting - Missing Extensions
description: Looks for clients using TLS 1.2/1.3 but sending an unusually short list of TLS extensions, common in small, custom agent stacks.
logsource:
  category: network
  product: zeek
detection:
  selection:
    # Look for connections using a standard protocol but lacking common features
    tls.version:
      - 'TLSv12'
      - 'TLSv13'
    # Field from Zeek's ssl.log - length of the extensions array
    tls.client_extensions_length:
      - 0
      - 1
      - 2
    # Filter out common benign traffic (e.g., known OS or browser hashes)
    tls.ja3_hash|not:
      - '44c9213122c8...' # Standard Chrome Hash
      - 'e4f20653df32...' # Standard Windows Hash
  condition: selection
level: medium
tags:
  - palantir
  - threat_hunting
```

-----

## 🔬 Analyst Field Guide: Hunting Strategy

The goal is to **build a baseline** of "allowed" JA3/JA4 hashes and alert on deviations.

1.  **Baseline:** Collect all unique `ja4_hash` values for the last 30 days from your log data. Group them by `source.ip` and `dest.ip`.
2.  **Allowlisting:** Identify and document the hashes belonging to common, authorized applications (e.g., corporate browsers, monitoring agents, VPN clients).
3.  **Tiered Hunting:**
      * **Tier 1 (Critical):** Any traffic matching a hash in the **"Known White-Label Implementations"** list (Section 5 of the main guide) – **Immediate Alert.**
      * **Tier 2 (High):** Any new hash communicating with an unusual target (e.g., unknown cloud IP, foreign infrastructure) that appears with high frequency (beaconing pattern) – **Investigate.**
      * **Tier 3 (Medium):** Hashes with low entropy (few extensions, limited ciphers) that are not in the allowlist – **Hunt/Monitor.**

By focusing on these cryptographic fingerprints, you move the detection point away from easily mutable indicators (like names or paths) toward the immutable core of the agent's network stack.
