# The Pre-Attack Phase: A Complete Guide to OSINT and Active Reconnaissance

**Educational / Defensive Security Reference**

---

## Overview

This is a comprehensive guide to pre-attack phase intelligence gathering methodology, covering passive OSINT techniques, active reconnaissance, social engineering reconnaissance, and automation. It is designed as a structured, multi-part educational resource for security professionals who need to understand how adversaries collect information before an attack -- and how to defend against it.

All IP addresses, domains, and examples used throughout this guide are fictional and use RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) to ensure no real-world systems are referenced.

---

## Table of Contents

### Part I: Understanding OSINT vs Reconnaissance
| Chapter | Title |
|---------|-------|
| 0 | Definitions, Scope, and the Intelligence Lifecycle |

### Part II: The Reconnaissance Blind Spot
| Chapter | Title |
|---------|-------|
| 1 | Why Organizations Fail to Detect Reconnaissance |
| 2 | The Attacker's Information Advantage |

### Part III: OSINT Techniques -- Passive
| Chapter | Title |
|---------|-------|
| 3 | ASN and BGP Intelligence |
| 4 | DNS Intelligence |
| 5 | Service Discovery |
| 6 | IP Enrichment |
| 7 | Human Intelligence (HUMINT via OSINT) |
| 8 | Document Intelligence |
| 9 | ICS/SCADA Reconnaissance |
| 10 | Network Monitoring and WHOIS Analysis |
| 11 | Cloud Infrastructure Enumeration |

### Part IV: Active Reconnaissance
| Chapter | Title |
|---------|-------|
| 12 | Email Infrastructure and CDN Bypass |
| 13 | POST-Based Fingerprinting |

### Part V: Social Engineering Reconnaissance
| Chapter | Title |
|---------|-------|
| 14 | Profiling Targets for Social Engineering Campaigns |

### Part VI: Building the Target Package
| Chapter | Title |
|---------|-------|
| 15 | Assembling and Prioritizing Collected Intelligence |

### Part VII: Automation and Operations
| Chapter | Title |
|---------|-------|
| 16 | Automating Reconnaissance Workflows |
| 17 | Operational Security for Reconnaissance Teams |

### Part VIII: Advanced Topics (NEW)
| Chapter | Title |
|---------|-------|
| 18 | MITRE ATT&CK Mapping for Reconnaissance |
| 19 | GitHub and GitLab Secret Scanning |
| 20 | Defensive Countermeasures |
| 21 | Dark Web and Tor OSINT |
| 22 | Supply Chain Intelligence |
| 23 | AI-Assisted Reconnaissance |
| 24 | Cloud-Native Enumeration |
| 25 | Real-World APT Case Studies |

---

## Scripts

The `scripts/` directory contains reference implementations that accompany the guide chapters. Each script is documented and intended for use in authorized testing environments only.

| Script | Description |
|--------|-------------|
| `asn_enum.py` | Enumerates ASN ownership, announced prefixes, and peer relationships using public BGP data sources. |
| `dns_deep_dive.py` | Performs comprehensive DNS reconnaissance including zone transfer attempts, record enumeration, and subdomain brute-forcing. |
| `service_fingerprint.py` | Identifies services and versions on discovered hosts through banner grabbing and protocol-specific probes. |
| `ip_enrichment.py` | Enriches IP addresses with geolocation, hosting provider, reputation data, and historical WHOIS records. |
| `document_harvester.py` | Extracts metadata from publicly available documents (PDF, DOCX, XLSX) to identify internal usernames, software versions, and file paths. |
| `cloud_enum.py` | Discovers cloud resources across AWS, Azure, and GCP including exposed storage buckets, public snapshots, and misconfigured services. |
| `cdn_bypass.py` | Identifies origin server IP addresses behind CDN and WAF providers using historical DNS records and certificate transparency logs. |
| `social_recon.py` | Aggregates publicly available information about personnel from professional networks, code repositories, and social platforms. |
| `target_packager.py` | Consolidates all collected reconnaissance data into structured target packages with severity scoring and attack surface mapping. |
| `recon_automate.py` | Orchestrates the full reconnaissance pipeline with configurable modules, rate limiting, and output formatting. |

---

## Prerequisites and Dependencies

- **Python**: 3.10 or later
- **Operating System**: Linux recommended; macOS and WSL2 also supported
- **Network Tools**: `nmap`, `dig`, `whois`, `traceroute` (for active reconnaissance chapters)
- **Python Libraries**: Listed in `requirements.txt` (includes `dnspython`, `requests`, `shodan`, `censys`, `python-whois`, `beautifulsoup4`)
- **API Keys** (optional, for enriched results):
  - Shodan
  - Censys
  - VirusTotal
  - SecurityTrails
  - Hunter.io

---

## Intended Audience

This guide is written for:

- **Penetration testers** preparing for engagements who need a structured reconnaissance methodology.
- **Red team operators** building comprehensive target packages before active operations.
- **Blue team and SOC analysts** who want to understand attacker reconnaissance techniques to improve detection capabilities.
- **Security students and researchers** studying offensive security methodology in an academic or lab setting.
- **Bug bounty hunters** performing authorized reconnaissance within program scope.

This is not a beginner's introduction to networking or security. Readers should have a working knowledge of TCP/IP, DNS, HTTP, and basic command-line usage.

---

## Legal and Ethical Use

This repository is an **educational resource for defensive security purposes**. All techniques described are intended to help security professionals understand reconnaissance methodology so they can better defend their organizations.

Please read [DISCLAIMER.md](DISCLAIMER.md) before using any material from this guide.

**Do not use any technique from this guide against systems you do not own or have explicit written authorization to test.**

---

## Documentation IP Ranges

All examples in this guide use addresses from the following IANA-reserved documentation ranges, as specified in [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737):

- `192.0.2.0/24` (TEST-NET-1)
- `198.51.100.0/24` (TEST-NET-2)
- `203.0.113.0/24` (TEST-NET-3)

Domain examples use `example.com`, `example.org`, and other IANA-reserved domains per [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606).

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
