# Palantir Threat Detection 
#### Open SIEM Labs with Sigma Rules

### **Disclaimer**

This repository is intended **for educational and research purposes only**.
It is **not** a 100% protection against Palantir-related activity or any other advanced threats.
Security is about **reducing risk**, not eliminating it.

---

#### 🛑 OPERATIONAL SECURITY (OPSEC) & LEGAL NOTICE 🛑
READ THIS FIRST. This section supersedes all other documentation.

This toolkit, including all rules, fingerprints, and simulation scripts, is provided EXCLUSIVELY for educational, research, and defensive purposes.

#### ABSOLUTELY NO OFFENSIVE USE IS PERMITTED.

- Legal Authority is MANDATORY: You must have explicit, written, and verifiable legal authority and proper authorization from the network owner before performing any monitoring, testing, or analysis on any target network, especially those associated with government or corporate entities.
- Strictly Defensive: This repository is intended for defending networks you are authorized to protect, such as your organization's infrastructure or personal research labs.
- Consequences: Unauthorized access, monitoring, or testing is illegal and can lead to severe civil and criminal penalties, including imprisonment.

By using this repository, you acknowledge and agree that you are solely responsible for adhering to all applicable laws and regulations. The project contributors are not liable for any misuse or damage caused by this toolkit.

**Think before you type!**

## **Table of Contents**

1. [Disclaimer](#disclaimer)
2. [Background & Mission](#1-background--mission)
3. [SIEM Basics](#2-siem-basics)
4. [Setup Options](#3-setup-options)
5. [Installing Sigma Tools](#4-installing-sigma-tools)
6. [Known White-Label Implementations](#5-known-white-label-implementations)
7. [Detection Labs](#6-detection-labs)
8. [TLS Fingerprinting](#7-tls-fingerprinting-with-ja3ja4)
9. [Sigma Rule Generator](#8-sigma-rule-generator)
10. [Test Data Simulation](#9-test-data-simulation)
11. [BSI-Compliant Hardening](#10-bsi-compliant-hardening-guide)
12. [Threat Hunting Playbook](#11-threat-hunting-playbook)
13. [Automated Testing](#12-automated-testing-with-cicd)
14. [Learning Resources](#13-learning-resources)
15. [Analyst Field Guide](#14-analyst-field-guide)
16. [Interactive Training](#15-interactive-training)
17. [Operational Security Notice](#operational-security-opsec-notice)
18. [Support This Project](#support-this-project)
19. [Credits](#credits)






---

### **1. Background & Mission**

Technology is never neutral. This project was born from that understanding.

Powerful data analysis and surveillance technology, like that developed by Palantir, is now a globally traded commodity. It is sold to governments and organizations with little to no ethical oversight regarding their human rights records or political objectives. In the hands of democratic states, it promises security. In the hands of authoritarian regimes, it becomes a weapon for the oppression of minorities, journalists, and political dissenters.

**This fundamental imbalance of power is the reason this repository exists.**

Our mission is to help level the playing field. We provide **open-source tools and hands-on labs** to detect the digital fingerprints of these powerful surveillance platforms. By using vendor-agnostic **Sigma rules** and free **SIEM platforms**, we make these detection capabilities accessible to everyone—not just those with nation-state budgets.

This is more than a technical exercise; it is an act of **digital transparency**. The goal is to **empower security analysts, researchers, and defenders** to recognize these patterns, understand their implications, and hold powerful actors accountable. We believe that the best defense against the abuse of surveillance technology is a well-informed, prepared, and ethically-minded community.

---

### **2. SIEM Basics**

**Security Information & Event Management (SIEM)** tools collect, normalize, and analyze logs from multiple sources (firewalls, servers, endpoints).
Popular options:

* **Elastic Security** – Open source, flexible.
* **Splunk Free** – Industry standard, free tier (500 MB/day).
* **Wazuh** – All-in-one open-source XDR.

---

### **3. Setup Options**

| Tool        | Setup Guide                                                                          | Best For                |
| ----------- | ------------------------------------------------------------------------------------ | ----------------------- |
| Elastic     | [Elastic Security VM](https://www.elastic.co/)    | Open-source deployments |
| Splunk Free | [Splunk Free Download](https://www.splunk.com/) | Industry familiarity    |
| Wazuh       | [Wazuh VM](https://wazuh.com/)                                                | Combined SIEM + XDR     |

---

### **4. Installing Sigma Tools**

```bash
pip install sigmatools
```

Sigma rules are **vendor-agnostic** detection rules. Convert them to your SIEM format with `sigmatools`.

---

### **5. Known White-Label Implementations**

**Disclaimer:** The indicators below are derived from OSINT research and serve as high-fidelity examples of artifacts analysts should look for. They may change over time and should be verified in your specific environment.

| Agency/Country       | Cover Name      | Technical Fingerprints                                                                 |
|----------------------|-----------------|----------------------------------------------------------------------------------------|
| **Hessian Police (DE)** | POLiS           | User-Agent: `HessPol/2.0`, JA3: `a387c3a7a4d...`, Path: `/polis/v1/heartbeat`          |
| **BKA (DE)**         | BDA-Analytik    | Certificate Issuer: `CN=BKA-INTERNAL-CA`, Chunk Size: `131072 bytes`                   |
| **Verfassungsschutz**| VS-Datarium     | Process: `vs-dataharvester.exe`, TLS ALPN: `h2`                                        |
| **France DGSE**      | ATLAS-Nexus     | HTTP Header: `X-ATLAS-Auth: ENC[base64]`, Port: `58444`                                |
| **UK MI5**           | MINERVA         | DNS Pattern: `minerva-*.internal-gov.uk`, TLS SNI: `secure-gchq`                       |
| **NSA (USA)**        | TRITON-X        | User-Agent: `TritonX/3.1`, JA3: `5d4a...`, HTTP Header: `X-TX-Auth: [rot13]`, Port `8443` |
| **GCHQ (UK)**        | MORPHEUS        | DNS-Tunneling via `*.morph-tech.uk`, Process: `morpheus_loader.dll` (injected in `svchost.exe`) |
| **BND (DE)**         | BERLIN-7        | Data Chunks: `262144 bytes`, Registry Key: `HKLM\SOFTWARE\Berlin7\Config`, Mutex: `Global\B7_DataLock` |
| **DGSE (FR)**        | LYRA-9          | UDP Beaconing on Port `4789`, Process: `lyra_service.exe`, CLI Arg: `--no-netlog`      |
| **AISE (IT)**        | SPECTRE-V       | ICMP Payloads (Type=69), File Path: `C:\Windows\Temp\spv_[RANDOM].tmp`, JA4: `t13d...` |


The technical indicators listed are snapshots and may change. Your contributions are welcome to keep this knowledge up-to-date


### **6. Detection Labs**

#### **Lab 1 – Palantir Beaconing to AWS**

**File:** `rules/palantir_beaconing.yml`

```yaml
title: Palantir Beaconing to AWS
logsource:
  category: firewall
detection:
  selection:
    destination.ip:
      - '52.0.0.0/8'  # AWS US-East
    destination.port: 443
  timeframe: 5m
  condition: selection | count(destination.ip) by source.ip > 15
level: high
```

Convert for Elastic:
```bash
sigma convert -t es-rule rules/palantir_beaconing.yml
```

---

#### **Lab 2 – Suspicious Government Process Execution**

**File:** `rules/suspicious_gov_process.yml`

```yaml
title: Suspicious Government Process Execution
description: Detects potential white-labeled agents with multiple indicators
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: 
      - '\polis-agent.exe'
      - '\bda-analytics.exe'
      - '\vs-dataharvester.exe'
      - '\lyra_service.exe'
    ParentImage|endswith: '\explorer.exe'
    CommandLine|contains: 
      - '--stealth'
      - '--no-log'
    CurrentDirectory|contains: 
      - '\Public\\'
      - '\Temp\\'
  condition: selection
level: high
```

---

#### **Lab 3 – German Agency-Specific Detection (POLiS)**

**File:** `rules/hessen_polis.yml`
```yaml
title: Hessen POLiS Beaconing
description: Detects 5-min intervals of Hessian police system
logsource:
  product: firewall
detection:
  selection:
    dst_port: 443
    http.uri: '/polis/v1/heartbeat'
    http.user_agent: 'HessPol/*'
  timeframe: 5m
  condition: selection | count > 3
level: critical
tags:
  - palantir
  - white_label
  - germany
```

---

#### **Lab 4 – Data Exfiltration Pattern**

**File:** `rules/gov_dataexfil.yml`
```yaml
title: Government-Style Data Chunking
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains: '/upload'
    content_length: '131072'  # Exact chunk size
  condition: selection
level: high
```

---

#### **Lab 5 – MORPHEUS DNS Tunneling Detection**

**File:** `rules/morpheus_dns.yml`
```yaml
title: MORPHEUS DNS Tunneling
logsource:
  category: dns
detection:
  selection:
    query|re: '.*\.morph-tech\.uk$'
    query_length > 60
  condition: selection
level: high
```

---

### **7. TLS Fingerprinting with JA3/JA4**

**What it is:** TLS fingerprinting identifies clients based on unique characteristics of their TLS handshake configuration.

**Implementation:**
```yaml
title: Known POLiS JA3 Fingerprint
logsource:
  category: firewall
detection:
  selection:
    ja3_hash: 'a387c3a7a4d...'  # Example fingerprint
  condition: selection
level: high
```

**Tools to capture JA3:**
- Suricata with `ja3` keyword
- Zeek with `JA3` script
- Custom Python: `pip install ja3er`

Advanced usage needed? Have a look on [ja3_ja4_guide.md](ja3_ja4_guide.md)

---

### **8. Sigma Rule Generator**
Create custom detection rules for white-labeled instances:

```python
# tools/generate_sigma.py
agency = input("Agency name: ")
codename = input("Cover name: ")
signature = input("Unique signature (JA3/path/etc): ")

sigma_rule = f"""
title: {agency} {codename} Detection
logsource:
  category: network
detection:
  selection:
    http.user_agent: '*{codename}*'
    ja3_hash: '{signature}'  # Use strongest available indicator
  condition: selection
level: critical
"""

print(f"Generated rule:\n{sigma_rule}")
```

---

### **9. Test Data Simulation**

#### Basic Python Simulator:
```python
# tools/simulate_palantir.py
import requests, time

target_url = "https://gotham.palantir.com/beacon"
headers = {"User-Agent": "Palantir-Custom-Agent/1.0"}

while True:
    requests.post(target_url, headers=headers, data="SIMULATED")
    time.sleep(300)  # 5 minutes
```

#### Advanced Simulation:
```bash
docker run -it --rm palantir-simulator:latest
```

---

### **10. BSI-Compliant Hardening Guide**

### Security Measures for German Organizations

1. **Certificate Pinning**  
   ```bash
   # Extract server certificate fingerprint
   openssl s_client -connect target:443 | openssl x509 -fingerprint -sha256
   ```

2. **Network Segmentation**  
   - Isolate systems communicating with government networks
   - Implement strict egress filtering

3. **Audit Requirements (§ 26 BDSG)**  
   - Log all access to sensitive data repositories
   - Retention period: minimum 6 months


---

### **11. Threat Hunting Playbook**

```yaml
name: Palantir-Like Activity Hunt
steps:
  - phase: Network Anomalies
    actions:
      - "Search for periodic 5-min connections"
      - "Identify JA3 fingerprints not in allowlist"
      - "Detect unusual DNS patterns (*.morph-tech.uk)"
  - phase: Process Analysis
    tools:
      - "Sysmon EventID 1 (Process Creation)"
      - "Check for unsigned binaries in temp locations"
  - phase: Data Flow
    indicators:
      - "131072/262144 byte upload chunks"
      - "Unusual data transfers to cloud providers"
```

---

### **12. Automated Testing with CI/CD**

```yaml
# .github/workflows/test_rules.yml
name: Sigma Rule Validation
on: [push]

jobs:
  sigma-test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Test Sigma Rules
      run: |
        pip install sigmatools
        sigma test -f rules/
```

---

### **13. Learning Resources**

* **Sigma Documentation:** [sigmahq.io](https://sigmahq.io/)
* **BSI SIEM Guide (German):** [BSI Leitfaden](https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/baustein/B05.02_SIEM.html)
* **DetectionLab:** [detectionlab.network](https://detectionlab.network/)
* **German Threat Intel:** [BSI CERT Reports](https://www.bsi.bund.de/DE/Service-Navi/Publikationen/CERT-Berichte/cert-berichte_node.html)
* **TLS Fingerprinting Guide:** [Engineering JA3](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)

---

### **14. Analyst Field Guide**

1. **Detection Priority Stack**  
   ```mermaid
   graph LR
   A[TLS Fingerprints] --> B[Behavioral Patterns]
   B --> C[Process Anomalies]
   C --> D[Network Signatures]
   ```

2. **Investigation Checklist**
   - [ ] Verify JA3/JA4 fingerprints
   - [ ] Check for known white-label indicators
   - [ ] Review data chunking patterns
   - [ ] Document chain of custody

---

### **15. Interactive Training**

[![Palantir Detection Challenge](https://img.shields.io/badge/Train%20Online-LetsDefend-blue)](https://app.letsdefend.io/challenge/)

---

## **Operational Security (OPSEC) Notice**

**Warning:** Always ensure you have explicit legal authority and proper authorization before monitoring any network, especially those associated with government or corporate entities. Unauthorized monitoring is illegal and can have severe consequences. This toolkit is for defending networks you are authorized to protect, not for offensive operations. Think before you type.

---

## **Support This Project**

If you find this repository useful, please give it a star ⭐ on GitHub.

Starring a repository is the best way to show your appreciation and helps increase its visibility. It tells the GitHub algorithm that this project is significant, which means it will be recommended to more users and appear higher in search results. Unlike influencers, we don't have sponsors; our currency is community support.

Your star helps us help more people. Thank you!

---

## **Credits**
Mr. Chess!
