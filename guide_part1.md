# THE PRE-ATTACK PHASE

**A Complete Guide to OSINT and Active Reconnaissance**

Document Classification: Educational / Defensive Security Reference
Purpose: Pre-Attack Phase Intelligence Gathering Methodology

---

**For Threat Intelligence Professionals**

- **Document Classification:** Educational / Defensive Security Reference
- **Intended Audience:** Threat Intelligence Analysts, Red Team Operators, Security Researchers, Penetration Testers
- **Purpose:** Pre-Attack Phase - Reconnaissance and Intelligence Gathering Methodology

---

## DISCLAIMER

**Legal Notice:**

This document is meant for:

- Authorized security professionals
- Defensive security assessments
- Red team operations with proper authorization
- Threat intelligence analysis
- Educational purposes

You should only use these techniques:

- Against systems you own
- Against systems you've got written authorization to test
- For defensive research and understanding how attackers work

**Unauthorized access to computer systems is illegal.**

### Scope of This Document

This document doesn't try to cover every recon tool and technique out there. We're NOT getting into:

- Well-known reconnaissance tools (Nmap, Nikto, Burp Suite, etc.)
- Vulnerability scanning methodologies
- Exploitation techniques
- Complete penetration testing workflows

**What this document DOES cover:**

We're here to show you how attackers think during the pre-attack phase. The focus is on the mindset and methodology behind sophisticated threat actors -- how adversaries gather OSINT before making any direct contact, the basic recon concepts that explain WHY these techniques work, and the intelligence-driven approach to sizing up a target. Think of it as getting into the attacker's head so you can defend better.

> This is an educational resource about attacker methodology, not a complete reconnaissance toolkit reference.

---

## TABLE OF CONTENTS

- **PREFACE**
- **PART I: UNDERSTANDING OSINT vs RECONNAISSANCE**
  - Chapter 0: The Critical Distinction
    - 0.1 Defining the Phases
    - 0.2 Why This Distinction Matters
    - 0.3 The Intelligence Pipeline
    - 0.4 Quick Reference Guide
    - 0.5 The "Ping Test" Rule
- **PART II: THE RECONNAISSANCE BLIND SPOT**
  - Chapter 1: Why Your Security Stack Cannot See This
  - Chapter 2: How Advanced Adversaries Think
- **PART III: OSINT TECHNIQUES (Passive - No Target Contact)**
  - Chapter 3: ASN and BGP Intelligence
  - Chapter 4: DNS Intelligence
  - Chapter 5: Service Discovery via Scan Databases
  - Chapter 6: IP Enrichment Pipeline
  - Chapter 7: Human Intelligence (HUMINT)
  - Chapter 8: Document Intelligence
  - Chapter 9: ICS/SCADA Discovery
  - Chapter 10: Advanced Network Monitoring & WHOIS
  - Chapter 11: Cloud Infrastructure Discovery

---

## Preface: Why This Book Exists

Organizations with multi-million dollar security budgets get breached every single day. They've got WAFs, IDS/IPS, next-gen firewalls, SIEM platforms, EDR solutions, SOCs running around the clock. The whole nine yards.

Breaches keep happening anyway.

> **Here's the uncomfortable part:** all those security controls? They're operating at the wrong phase of the attack lifecycle. They catch attacks in progress or after the initial compromise. But they're completely blind to reconnaissance -- and that's where sophisticated adversaries spend 70-80% of their time.

This document goes after that blind spot. We dig into the pre-attack phase -- the intelligence gathering, infrastructure mapping, and recon techniques that happen before a single malicious packet ever touches your network.

---

# Part I: Understanding OSINT vs Reconnaissance

## Chapter 0: The Critical Distinction

### 0.1 Defining the Phases

Before we get into techniques, there's a distinction most practitioners get wrong:

> **OSINT and Reconnaissance are NOT the same thing.**

| Category | OSINT (Open Source Intelligence) | RECONNAISSANCE (Active Intelligence) |
|---|---|---|
| **Target Contact** | NO contact with target systems | DIRECT contact with target systems |
| **Data Sources** | Uses ONLY third-party data sources | Sends packets/requests to target infrastructure |
| **Visibility** | Target has ZERO visibility into your activities | Target CAN detect, log, and trace activities |
| **Traceability** | Cannot be detected, logged, or traced | May trigger security alerts |
| **Legality** | Legal in virtually all jurisdictions | Requires authorization for legal operation |
| **Detection Risk** | ZERO | LOW to HIGH (depending on technique) |

**OSINT Examples:**

- Searching Shodan/Censys databases
- Querying Certificate Transparency logs
- Analyzing BGP routing tables
- Reading LinkedIn profiles
- Searching breach databases
- Google dorking for exposed files

**Reconnaissance Examples:**

- DNS queries to target's nameservers
- Port scanning target IPs
- Sending HTTP/POST requests to target websites
- Banner grabbing from services
- POST request fingerprinting
- Triggering error responses for stack traces

### 0.2 Why This Distinction Matters

#### For Offensive Operations

Order matters here. OSINT should ALWAYS come first:

| Approach | Phase | Activities | Outcome |
|---|---|---|---|
| CORRECT | Phase 1: OSINT Collection | No target interaction, build comprehensive intelligence, map attack surface from public data | Zero detection risk |
| CORRECT | Phase 2: Targeted Reconnaissance | Informed by OSINT findings, surgical focused queries, minimal footprint | Know exactly what to look for |
| CORRECT | Phase 3: Exploitation | Precise, intelligence-driven attack | High success probability |
| INCORRECT | Phase 1: Blind Scanning | Noisy, detectable, triggers alerts | Burns the operation |
| INCORRECT | Phase 2: Target Alerted | Increased monitoring, patching, blocking | Operation compromised |

#### For Defensive Operations

If you're on the blue team, understanding this split changes how you allocate resources:

- **OSINT exposure can't be monitored** -- so focus on shrinking your public footprint
- **Reconnaissance CAN be detected** -- so focus on monitoring and alerting
- Different mitigations for each phase

### 0.3 The Intelligence Pipeline

#### STAGE -1: OSINT (Passive) - NO TARGET CONTACT

**Detection Risk: ZERO**

Data Sources (all third-party):

- Shodan, Censys, ZoomEye (internet scan databases)
- crt.sh, Censys Certs (certificate transparency)
- BGPView, RIPE Stat, Hurricane Electric (routing data)
- SecurityTrails, ViewDNS (historical DNS)
- LinkedIn, Glassdoor, Indeed (human intelligence)
- WHOIS databases (registration data)
- Google, Bing, DuckDuckGo (search engines)
- GitHub, GitLab, Bitbucket (code repositories)
- HaveIBeenPwned, breach databases (credential exposure)
- Wayback Machine (historical snapshots)
- News articles, press releases, SEC filings

#### STAGE 0: RECONNAISSANCE (Active) - TARGET CONTACT REQUIRED

**Detection Risk: LOW to HIGH**

Techniques (packets sent to target):

- DNS queries to target's authoritative nameservers
- HTTP/HTTPS GET requests to target websites
- HTTP POST requests for fingerprinting
- Port scanning target IP ranges
- Service banner grabbing
- TLS/SSL certificate retrieval
- Error triggering for information disclosure
- WAF/IDS fingerprinting
- API endpoint enumeration
- Virtual host discovery

#### STAGE 1+: EXPLOITATION (Outside scope of this document)

### 0.4 Quick Reference: Is It OSINT or Recon?

| Technique | OSINT or Recon? | Target Contact | Detection Risk |
|---|---|---|---|
| Shodan search by org | OSINT | None | Zero |
| Censys certificate query | OSINT | None | Zero |
| crt.sh subdomain lookup | OSINT | None | Zero |
| Google dorking site:target.com | OSINT | None | Zero |
| LinkedIn employee research | OSINT | None | Zero |
| BGPView ASN lookup | OSINT | None | Zero |
| SecurityTrails DNS history | OSINT | None | Zero |
| GitHub code search | OSINT | None | Zero |
| Wayback Machine snapshots | OSINT | None | Zero |
| WHOIS via third-party | OSINT | None | Zero |
| DNS query to target's NS | Recon | YES | Low |
| HTTP GET to target website | Recon | YES | Low |
| HTTP POST fingerprinting | Recon | YES | Low-Medium |
| Port scanning target IPs | Recon | YES | Medium-High |
| Banner grabbing | Recon | YES | Medium |
| Vulnerability scanning | Recon | YES | High |
| Brute force attempts | Recon | YES | Very High |

### 0.5 The "Ping Test" Rule

Dead simple rule:

> **"If I need to send a single packet to the target's infrastructure, it's Reconnaissance, not OSINT."**

| Type | Flow | Target Awareness |
|---|---|---|
| OSINT | You --> Third-Party Database --> Information about Target | Target never knows |
| Recon | You --> Target's Systems --> Response from Target | Target can log your IP, detect patterns, block you |

### 0.6 Document Organization

Here's how we've laid this out:

| Part | Title | Coverage |
|---|---|---|
| Part I | Understanding OSINT vs Reconnaissance | This chapter |
| Part II | The Reconnaissance Blind Spot | Why security stacks cannot detect pre-attack |
| Part III | OSINT Techniques (Passive) | ASN/BGP Intelligence, Certificate Transparency, Search Engine OSINT, Human Intelligence, Document Metadata |
| Part IV | Active Reconnaissance Techniques | DNS Interrogation, Service Fingerprinting, POST Request Fingerprinting, CDN/WAF Detection, Error-Based Intelligence |
| Part V | Social Engineering Reconnaissance | Human-focused techniques |
| Part VI | Building the Target Package | Intelligence synthesis |
| Part VII | Operational Considerations | Automation and tradecraft |

---

# Part II: The Reconnaissance Blind Spot

## Chapter 1: Why Your Security Stack Cannot See This

### 1.1 The Perimeter Illusion

Organizations pour money into perimeter security. A lot of money.

| Security Component | Investment |
|---|---|
| Next-Generation Firewall | $500K+ |
| Web Application Firewall | $200K+ |
| Intrusion Detection/Prevention | $300K+ |
| SIEM Platform | $400K+ |
| EDR/XDR Solution | $300K+ |
| DDoS Protection | $150K+ |
| Email Security Gateway | $100K+ |
| 24/7 SOC Operations | $2M+/year |
| **Total Investment** | **$4M+ annually** |

All of that protects against known attack signatures, anomalous network traffic, malware execution, lateral movement (when detected), and data exfiltration (when detected).

**What none of it can see:**

An adversary querying public DNS records. Searching Shodan. Reading your job postings. Analyzing your SSL certs. Mapping BGP announcements. Stalking your employees on LinkedIn. Finding subsidiaries through business registries. Pulling vendor names from press releases. Ripping metadata out of your public documents. Watching your certificate transparency logs. Picking apart your SPF/DKIM/DMARC records. Correlating infrastructure patterns. Building a complete target package.

**Detection by Security Stack: ZERO**

> **The root issue:** your security controls watch your network. Reconnaissance doesn't touch your network. Adversaries pull intelligence from third-party sources, public databases, cached data. Your firewall never sees a packet. Your IDS never fires. Your SIEM has nothing to chew on.

This isn't something you can fix with better configuration. It's not a vendor problem either. It's structural. The internet was built for connectivity and information sharing -- not secrecy. Every service you run needs public registration, DNS resolution, certificate issuance, network routing. All of that leaves intelligence artifacts sitting in public databases. Indefinitely.

### 1.2 The Information Asymmetry Problem

Think about what the other side knows compared to what you know about them.

**What Adversaries Can Discover About You:**

Your complete IP inventory. Every registered domain and subdomain. Email server configs. VPN gateway locations. Remote access portals. Cloud infrastructure details. Vendor relationships. Your whole technology stack. Employee names and roles, org structure, physical facility locations. What security tools you run (thanks, job postings). Your expansion plans (same). Recent infrastructure changes from DNS and BGP monitoring. Internal project names buried in document metadata.

**What You Know About Their Reconnaissance: Nothing**

> Here's the thing -- this asymmetry can't be fixed. The internet requires these public registrations to function. You can't hide BGP announcements; routers worldwide need them to deliver your traffic. You can't hide DNS records; clients need them to find your services. You can't hide certificates; browsers need them to establish trust.

### 1.3 The Attack Surface You Don't Measure

Security teams track vulnerability scan results, patch compliance, firewall rules, alert volumes. But how often do they measure information exposure -- what an adversary can learn without ever touching the network?

Almost never.

> **The unmeasured surface is the exploited surface.**

---

## Chapter 2: How Advanced Adversaries Think

### 2.1 The Intelligence-Driven Approach

Sophisticated adversaries don't just fire off port scans against your network. That's noisy, it's detectable, and it's lazy. What they actually do is build deep intelligence before making any direct contact.

Here's why that matters.

When an adversary already knows your VPN gateway IP and version, your security team's size and expertise, your patch management cadence, your vendor relationships, your network topology -- they don't need to scan. They already know where the weak spots are. They've pulled CVE lists for your exact software versions. They've figured out which entry points get the least monitoring. The attack, when it comes, is precise. Not spray-and-pray.

| Phase | Duration | Activities |
|---|---|---|
| Phase 1: Strategic Intelligence | Weeks to Months | Understand target's business, map organizational structure, identify key personnel, determine technology landscape, locate physical facilities, map network topology, identify third-party relationships |
| Phase 2: Tactical Intelligence | Days to Weeks | Enumerate specific services, identify authentication mechanisms, discover version information, find configuration weaknesses, locate forgotten assets, identify trust relationships, build attack paths |
| Phase 3: Operational Planning | Hours to Days | Select optimal entry points, prepare backup options, time operations appropriately, establish infrastructure, execute with precision |

> **The ratio is what kills you:** advanced actors burn 80% of their time in Phase 1 and 2. The actual attack? Brief, targeted, and backed by weeks of homework.

### 2.2 The Target Package Concept

Professional intelligence operations build what's called a "target package" -- basically a comprehensive dossier with everything needed to run a successful operation. The whole thing gets assembled from open sources. No direct contact with the target required.

| Intelligence Category | Components |
|---|---|
| **Organizational Intelligence** | Corporate structure and subsidiaries, key decision makers, technical staff profiles, security team composition, vendor relationships, business processes |
| **Network Intelligence** | ASN and IP allocations, domain inventory, DNS configuration details, email infrastructure, remote access points, cloud presence |
| **Technical Intelligence** | Technology stack, version information, configuration patterns, security tool deployment, patch management practices, development practices |
| **Physical Intelligence** | Facility locations, data center details, network interconnects, geographic distribution |
| **Operational Intelligence** | Business hours, maintenance windows, staffing patterns, incident response capabilities, security awareness levels |

### 2.3 Patience as a Weapon

> Your detection capabilities are tuned for the noisy attackers -- the ones who scan and exploit on day one. Sophisticated actors stay under your radar because they've already mapped your monitoring capabilities through recon. They know what you'll catch and what you won't.

| Actor Type | Timeline | Activity |
|---|---|---|
| Unsophisticated | Day 1 | Scan, Exploit, Compromise, Detection |
| Sophisticated | Week 1-4 | Passive intelligence gathering |
| Sophisticated | Week 5-8 | Infrastructure correlation and analysis |
| Sophisticated | Week 9-12 | Limited active reconnaissance |
| Sophisticated | Week 13-16 | Operational planning |
| Sophisticated | Week 17 | Precise, targeted operation |
| Sophisticated | Week 18+ | Persistent access (often undetected for months/years) |

---

# Part III: OSINT Techniques (Passive - No Target Contact)

## Chapter 3: ASN and BGP Intelligence

### 3.1 Understanding the Concept

Every organization on the internet participates in the global routing system. Not optional -- it's mandatory, and it's public. An ASN (Autonomous System Number) is basically an org's identity in the routing world. It groups all their IP addresses together and tells the internet how to get traffic to them.

So why should you care from a recon perspective?

Find an org's ASN and you instantly know ALL their registered IP addresses. That's not a hack. That's how the internet works. Routers need this data to deliver traffic, which means it has to be publicly queryable.

BGP (Border Gateway Protocol) announcements go even deeper -- they reveal who provides the org's internet connectivity, what redundancy they've got, when their infrastructure shifts, and the overall network topology.

### 3.2 Walkthrough: Finding an Organization's Network Footprint

**Objective:** Map all IP ranges controlled by a target organization.

#### Step 1: Identify the ASN

```bash
# Method 1: Search by organization name
whois -h whois.radb.net "Target Organization"

# Method 2: If you know one IP address
whois -h whois.cymru.com 192.0.2.1

# Method 3: Web interface
# Navigate to: bgp.he.net
# Search: "Target Organization"
```

**Expected Output:**

```
aut-num:    AS12345
as-name:    TARGET-AS
descr:      Target Organization
org:        ORG-TARGET1-RIPE
```

#### Step 2: Enumerate All Prefixes

Got the ASN? Now pull every IP range it announces.

```bash
# Get all IP ranges announced by this ASN
whois -h whois.radb.net -- '-i origin AS12345'
```

**Expected Output:**

```
route:      192.0.2.0/24
origin:     AS12345
descr:      Target Organization - Primary

route:      198.51.100.0/24
origin:     AS12345
descr:      Target Organization - Secondary
```

#### Step 3: Map Related ASNs (Subsidiaries)

Big organizations often sit on multiple ASNs -- acquisitions, regional ops, that sort of thing.

```bash
# Search for related organizations
whois -h whois.radb.net "Target"

# Look for patterns:
# - Similar naming conventions
# - Same maintainer (mnt-by)
# - Same organization reference
```

#### Step 4: Analyze BGP Relationships

```bash
# Web interface provides relationship data
# Navigate to: bgp.he.net/AS12345

# Information available:
# - Upstream providers (who provides their internet)
# - Peers (who they connect with directly)
# - Downstream (who they provide service to)
# - Prefixes announced
# - Historical changes
```

#### Intelligence Output Example

```
Target Organization Network Map:

+-- Primary ASN: AS12345
|   +-- 192.0.2.0/24 (256 IPs) - Primary datacenter
|   +-- 198.51.100.0/24 (256 IPs) - DR site
|
+-- Subsidiary ASN: AS23456 (Acquired company)
|   +-- 203.0.113.0/24 (256 IPs)
|
+-- Upstream Providers:
|   +-- AS174 (Cogent) - Primary
|   +-- AS3356 (Lumen) - Secondary
|
+-- Single Points of Failure:
|   +-- Both providers in same geographic region
|
+-- Total discoverable IPs: 768
    Time to discover: ~5 minutes
```

---

## Chapter 4: DNS Intelligence

### 4.1 Understanding the Concept

DNS is the internet's phone book. It turns human-readable names into IP addresses, and that translation has to be public -- otherwise clients can't find your services. Simple as that.

But here's where it gets interesting for recon.

DNS records contain way more than just IP addresses. You'll find mail server configs, third-party service usage, internal naming conventions, security posture details, infrastructure patterns. Every subdomain, every mail server, every verification token -- all of it publicly queryable.

Certificate Transparency logs make things worse. Every SSL cert issued for your domain gets logged in public, searchable databases. That includes certs for internal subdomains you never meant to expose.

### 4.2 Walkthrough: Complete DNS Enumeration

**Objective:** Extract all DNS information for a target domain.

#### Step 1: Query All Record Types

```bash
# A record (IPv4 addresses)
dig +short A target.com
dig +short A www.target.com

# AAAA record (IPv6 addresses)
dig +short AAAA target.com

# MX records (mail servers)
dig +short MX target.com

# NS records (name servers)
dig +short NS target.com

# TXT records (SPF, DKIM, verification tokens)
dig +short TXT target.com

# SOA record (administrative info)
dig +short SOA target.com

# CAA record (certificate authority restrictions)
dig +short CAA target.com
```

#### Step 2: SPF Record Deep Extraction

SPF records list every server authorized to send email for a domain. Organizations accidentally leak a ton of infrastructure through these.

```bash
# Get SPF record
dig +short TXT target.com | grep spf

# Example output:
# "v=spf1 ip4:192.0.2.0/24 include:_spf.google.com include:spf.protection.outlook.com -all"
```

**Parsing the SPF:**

```
SPF Record Analysis:

+-- ip4:192.0.2.0/24
|   +-- Direct mail servers in this range
|
+-- include:_spf.google.com
|   +-- They use Google Workspace
|   +-- Query: dig +short TXT _spf.google.com
|
+-- include:spf.protection.outlook.com
|   +-- They also use Microsoft 365
|   +-- Query: dig +short TXT spf.protection.outlook.com
|
+-- -all (hardfail)
    +-- Strict SPF policy (good security practice)
```

#### Step 3: Recursive SPF Expansion

Each "include" in an SPF record points to another SPF record. You'll want to chase them all down.

```bash
# Expand Google SPF
dig +short TXT _spf.google.com
# Output: "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com ..."

# Continue expanding
dig +short TXT _netblocks.google.com
# Output: "v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ..."
```

#### Step 4: Zone Transfer Attempt

Zone transfers hand you the complete DNS zone. They're usually disabled, but always worth a shot.

```bash
# Get nameservers
dig +short NS target.com

# Attempt zone transfer against each NS
dig AXFR target.com @ns1.target.com
dig AXFR target.com @ns2.target.com
```

### 4.3 Walkthrough: Subdomain Discovery

**Objective:** Find all subdomains associated with the target.

#### Method 1: Certificate Transparency

Every publicly trusted SSL cert gets logged. That means any subdomain with HTTPS is exposed.

```bash
# Query crt.sh for all certificates
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sort -u | \
  grep -v "^\*"
```

#### Method 2: Using Amass (Passive Mode)

```bash
# Passive enumeration only (no direct contact)
amass enum -passive -d target.com -o subdomains.txt

# View results
cat subdomains.txt
```

#### Method 3: Using Subfinder

```bash
# Passive subdomain enumeration
subfinder -d target.com -silent -o subfinder_results.txt
```

#### Method 4: Search Engine Mining with Wildcards

Search engines have wildcard operators that can be surprisingly effective for finding subdomains.

**Google Dorks for Subdomain Discovery:**

```
# Basic subdomain search
site:target.com -www

# Wildcard variations (% interpreted as any characters)
site:*.target.com

# Environment-specific searches
site:dev.target.com
site:staging.target.com
site:test.target.com
site:uat.target.com

# Infrastructure-specific
site:vpn.target.com
site:mail.target.com
site:webmail.target.com
site:remote.target.com

# Admin/management interfaces
site:admin.target.com
site:portal.target.com
site:manage.target.com
site:dashboard.target.com

# API endpoints
site:api.target.com
site:api-*.target.com

# Regional variations
site:eu.target.com
site:us.target.com
site:asia.target.com

# Legacy/old systems
site:old.target.com
site:legacy.target.com
site:v1.target.com
site:www2.target.com
```

> **Pro Tip - Certificate Transparency Wildcard:**
>
> The crt.sh query uses `%` as a SQL wildcard (URL-encoded as `%25`). Different from Google wildcards, but extremely powerful:

```bash
# The % wildcard in crt.sh matches any characters
# Query: %.target.com finds ALL subdomains with certificates
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Explanation:
# %25 = URL-encoded %
# % = SQL LIKE wildcard meaning "any characters"
# %.target.com = anything.target.com

# You can also use multiple wildcards:
# %25.%25.target.com = finds multi-level subdomains
curl -s "https://crt.sh/?q=%25.%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Example results:
# dev.target.com
# staging.target.com
# api.prod.target.com
# internal.corp.target.com
```

**Bing IP Search:**

Bing lets you search by IP directly -- something Google won't do:

```
ip:192.0.2.100
# Find all domains hosted on an IP
# Useful for shared hosting and virtual hosts
```

#### Consolidate and Validate

```bash
# Combine all sources
cat subdomains.txt subfinder_results.txt crt_results.txt | sort -u > all_subdomains.txt

# Resolve to check which are live
cat all_subdomains.txt | while read sub; do
  ip=$(dig +short A $sub | head -1)
  if [ -n "$ip" ]; then
    echo "$sub -> $ip"
  fi
done
```

#### Intelligence Output Example

```
Subdomain Discovery Results:

+-- www.target.com -> 192.0.2.10
+-- mail.target.com -> 192.0.2.20
+-- vpn.target.com -> 192.0.2.30
+-- api.target.com -> 192.0.2.40
+-- dev.target.com -> 192.0.2.50 (development environment!)
+-- staging.target.com -> 192.0.2.51
+-- admin.target.com -> 192.0.2.60 (admin interface!)
+-- helpdesk.target.com -> 198.51.100.10 (different range - subsidiary?)
+-- legacy.target.com -> 203.0.113.5 (acquired company infrastructure?)

Patterns Identified:
+-- Environment prefixes: dev-, staging-
+-- Naming convention: [function].target.com
+-- Multiple IP ranges indicate distributed infrastructure

Total subdomains found: 47
Time to discover: ~10 minutes
```

---

## Chapter 5: Service Discovery via Scan Databases

### 5.1 Understanding the Concept

Shodan and Censys crawl the entire internet nonstop, indexing every exposed service, banner, certificate, and configuration they find. The result is a searchable database of basically everything that's publicly reachable.

This changes the recon game completely.

Old-school recon meant active scanning -- throwing packets at target systems, generating logs, maybe tripping an alert. Scan databases make that unnecessary. You're searching their database, not poking at the target's network. The target has zero visibility into your queries because you never touch their systems.

> To be clear: this isn't a vulnerability or a misconfiguration. These databases index publicly accessible services. If your box is reachable from the internet, it's already been indexed.

### 5.2 Walkthrough: Using Shodan

**Objective:** Discover services running on target infrastructure without scanning.

#### Method 1: Web Interface

Navigate to: `shodan.io`

**Search Queries:**

```
# By organization name
org:"Target Organization"

# By domain
hostname:target.com

# By IP range
net:192.0.2.0/24

# By SSL certificate
ssl.cert.subject.cn:"target.com"

# Combined query
org:"Target Organization" port:22,80,443,3389

# ICS/SCADA protocols
org:"Target Organization" port:502,102,2404,47808
```

#### Method 2: Shodan CLI

```bash
# Install Shodan CLI
pip install shodan

# Initialize with API key
shodan init YOUR_API_KEY

# Search by organization
shodan search "org:Target Organization" --fields ip_str,port,org,hostnames

# Search by IP range
shodan search "net:192.0.2.0/24" --fields ip_str,port,product,version

# Get detailed info on specific IP
shodan host 192.0.2.10
```

#### Method 3: Shodan API (Python)

```python
import shodan

api = shodan.Shodan('YOUR_API_KEY')

# Search for organization
results = api.search('org:"Target Organization"')

for result in results['matches']:
    print(f"IP: {result['ip_str']}")
    print(f"Port: {result['port']}")
    print(f"Product: {result.get('product', 'Unknown')}")
    print(f"Version: {result.get('version', 'Unknown')}")
    print("---")
```

#### Intelligence Output Example

```
Shodan Results for Target Organization:

+-- 192.0.2.10
|   +-- Port 22: OpenSSH 8.2p1 (Ubuntu)
|   +-- Port 80: nginx/1.18.0 (redirect to HTTPS)
|   +-- Port 443: nginx/1.18.0
|       +-- SSL: *.target.com (Let's Encrypt)
|
+-- 192.0.2.20
|   +-- Port 25: Postfix SMTP
|   +-- Port 143: Dovecot IMAP
|   +-- Port 993: Dovecot IMAPS
|
+-- 192.0.2.30
|   +-- Port 443: Cisco ASA SSL VPN
|       +-- Version: 9.12(4) - Check CVE-2023-20269!
|
+-- 192.0.2.40
|   +-- Port 443: API Gateway
|   +-- Headers: X-Powered-By: Express
|
+-- 192.0.2.100
|   +-- Port 502: Modbus/TCP (!)
|       +-- Device: Schneider Electric Modicon M340
|       +-- No authentication - directly accessible!
|
+-- Intelligence Summary:
    +-- Linux servers (Ubuntu based on SSH banner)
    +-- nginx web servers
    +-- Cisco VPN with potentially vulnerable version
    +-- Node.js API (Express framework)
    +-- EXPOSED ICS: Modbus PLC directly on internet
```

### 5.3 Walkthrough: Using Censys

**Objective:** Certificate and host discovery via Censys.

Navigate to: `search.censys.io`

```
# Search by organization
autonomous_system.name:"Target Organization"

# Search by domain in certificate
services.tls.certificates.leaf.subject.common_name:target.com

# Search by certificate SAN
services.tls.certificates.leaf.names:target.com

# Find origin servers behind CDN
services.tls.certificates.leaf.names:target.com AND NOT services.http.response.headers.server:cloudflare
```

---

## Chapter 6: IP Enrichment Pipeline

### 6.1 Understanding the Concept

One IP address. That's all you need to start pulling a surprising amount of intelligence -- if you're systematic about it. Each query adds context, and when you start correlating across multiple IPs, patterns jump out.

The key isn't just collecting data. It's connecting it. Three IPs sharing the same SSL cert? That's a service cluster. Historical DNS showing an IP used to belong to a different company? Acquisition. An IP in the same /24 as your target running Modbus? Potentially ICS infrastructure sitting right next to their production boxes.

### 6.2 Walkthrough: Complete IP Analysis

**Starting Point:** 192.0.2.100

#### Step 1: Basic WHOIS

```bash
whois 192.0.2.100
```

**Output Analysis:**

```
NetRange:       192.0.2.0 - 192.0.2.255
CIDR:           192.0.2.0/24
NetName:        TARGET-NET
Organization:   Target Organization (TARGET)
City:           Ashburn
StateProv:      VA
Country:        US
```

#### Step 2: Reverse DNS

```bash
dig -x 192.0.2.100
```

**Output:**

```
100.2.0.192.in-addr.arpa. PTR   server1.target.com.
```

#### Step 3: ASN Lookup

```bash
whois -h whois.cymru.com 192.0.2.100
```

**Output:**

```
AS      | IP               | AS Name
12345   | 192.0.2.100      | TARGET-AS Target Organization
```

#### Step 4: Geolocation

```bash
curl -s "https://ipinfo.io/192.0.2.100/json" | jq .
```

**Output:**

```json
{
  "ip": "192.0.2.100",
  "city": "Ashburn",
  "region": "Virginia",
  "country": "US",
  "loc": "39.0438,-77.4874",
  "org": "AS12345 Target Organization"
}
```

> Ashburn, VA -- known data center hub (Equinix, AWS us-east-1). This IP is almost certainly sitting in a major datacenter.

#### Step 5: Historical DNS

Navigate to: `securitytrails.com`

Search: `192.0.2.100`

Historical records show:

- 2024: server1.target.com
- 2023: web-prod-01.target.com
- 2022: webserver.oldcompany.com (pre-acquisition!)

That last one is gold. You've just uncovered an acquisition and a legacy hostname.

#### Step 6: Shodan Host Details

```bash
shodan host 192.0.2.100
```

#### Step 7: Certificate Analysis

```bash
# Get certificate fingerprint
echo | openssl s_client -connect 192.0.2.100:443 2>/dev/null | \
  openssl x509 -fingerprint -noout

# Search for same certificate on other IPs
shodan search "ssl.cert.fingerprint:AA:BB:CC:DD..."
```

#### Step 8: Network Neighbors

```bash
# What else is in the same /24?
shodan search "net:192.0.2.0/24" --fields ip_str,port,hostnames
```

#### Complete IP Profile

```
IP Enrichment Report: 192.0.2.100

+-- Identity
|   +-- Reverse DNS: server1.target.com
|   +-- Organization: Target Organization
|   +-- ASN: AS12345
|   +-- Historical: Previously webserver.oldcompany.com
|
+-- Location
|   +-- City: Ashburn, VA, US
|   +-- Coordinates: 39.0438, -77.4874
|   +-- Likely datacenter: Equinix/AWS region
|
+-- Services
|   +-- SSH (22): OpenSSH 8.2p1
|   +-- HTTP (80): nginx/1.18.0 -> redirects to HTTPS
|   +-- HTTPS (443): nginx/1.18.0
|   +-- MySQL (3306): 5.7.32 - EXPOSED DATABASE
|
+-- SSL Certificate
|   +-- CN: *.target.com
|   +-- Issuer: Let's Encrypt
|   +-- Also on: 192.0.2.101, 192.0.2.102 (server cluster)
|   +-- Expires: 2024-04-14
|
+-- Network Context
|   +-- Same /24: 12 other hosts discovered
|   +-- ICS device found: 192.0.2.150 (Modbus)
|   +-- Same certificate on 3 hosts
|
+-- Key Findings
    +-- MySQL exposed to internet (critical)
    +-- Part of acquired company infrastructure
    +-- ICS device in same network segment
```

---

## Chapter 7: Human Intelligence

### 7.1 Understanding the Concept

People are the biggest attack surface, and their information is all over the internet. LinkedIn profiles lay out org structure, technical expertise, potential social engineering angles. Job postings? Those are basically a shopping list of what technologies the company runs.

Think about it. A job posting that says "5+ years with Palo Alto firewalls" just told every adversary on the planet what firewall vendor they use. A security engineer's LinkedIn showing Splunk certification? Now you know their SIEM. A posting that says "help us build our first SOC"? They just broadcast that they don't have 24/7 monitoring yet.

> All of this is volunteered publicly. Most organizations never stop to think about the intelligence value of their HR activities.

### 7.2 Walkthrough: LinkedIn Intelligence

**Objective:** Map org structure and identify key personnel.

**Search Operators:**

```
# Find all employees
site:linkedin.com/in "Target Organization"

# Find specific roles
site:linkedin.com/in "Target Organization" "network engineer"
site:linkedin.com/in "Target Organization" "security"
site:linkedin.com/in "Target Organization" "SCADA" OR "ICS"
site:linkedin.com/in "Target Organization" "database administrator"

# Find IT leadership
site:linkedin.com/in "Target Organization" "CTO" OR "CISO" OR "IT Director"
```

#### Intelligence Extraction Framework

```
Profile Analysis:

+-- Current Role
|   +-- Job title, department, responsibilities
|
+-- Skills Listed
|   +-- Technologies they work with
|   +-- Certifications (vendor relationships)
|   +-- Tools mentioned in descriptions
|
+-- Work History
|   +-- How long at organization
|   +-- Previous employers (similar tech stack?)
|   +-- Career progression
|
+-- Activity
|   +-- Posts about work projects
|   +-- Conference presentations
|   +-- Articles written (technical details!)
|
+-- Connections
    +-- Who else works there (expand search)
```

### 7.3 Walkthrough: Job Posting Analysis

**Objective:** Extract technology stack from job requirements.

```
# LinkedIn Jobs
site:linkedin.com/jobs "Target Organization"

# Indeed
site:indeed.com "Target Organization"

# Company careers page
site:target.com/careers
```

#### Analysis Framework

**Job Posting: "Senior Security Engineer"**

```
Requirements Analysis:

+-- "5+ years with Palo Alto firewalls"
|   +-- Intel: Palo Alto Networks is firewall vendor
|
+-- "Splunk certification preferred"
|   +-- Intel: Splunk is SIEM platform
|
+-- "Experience with CrowdStrike Falcon"
|   +-- Intel: CrowdStrike EDR deployed
|
+-- "AWS Solutions Architect certification"
|   +-- Intel: Primary cloud is AWS
|
+-- "Kubernetes and Docker experience"
|   +-- Intel: Container infrastructure in use
|
+-- "ISO 27001 implementation experience"
|   +-- Intel: Pursuing/maintaining ISO 27001
|
+-- "Help us build our first SOC"
|   +-- Intel: Currently NO 24/7 monitoring!
|
+-- Location: "Ashburn, VA"
    +-- Intel: Confirms datacenter location
```

---

## Chapter 8: Document Intelligence

### 8.1 Understanding the Concept

Documents sitting on public websites carry metadata that nobody remembered to strip out. Usernames, internal server paths, software versions, org structure -- it's all embedded in there.

Here's the problem. When someone creates a Word doc, Microsoft helpfully bakes in their username, computer name, file path, and more. That document gets published to the website, and all that metadata tags along for the ride. How often do orgs sanitize documents before posting them? Rarely.

### 8.2 Walkthrough: Metadata Extraction

#### Step 1: Find Documents

**Google Dorks:**

```
site:target.com filetype:pdf
site:target.com filetype:docx
site:target.com filetype:xlsx
site:target.com filetype:pptx
```

#### Step 2: Extract Metadata

```bash
# Install exiftool
apt install libimage-exiftool-perl

# Extract all metadata
exiftool annual-report.pdf

# Batch extraction
exiftool -csv *.pdf > metadata_report.csv
```

#### Output Analysis

```
Metadata Extraction Results:

+-- Authors Discovered:
|   +-- John Smith (Marketing)
|   +-- Jane Doe (Marketing)
|   +-- Bob Wilson (Engineering)
|   +-- Alice Brown (IT)
|
+-- Software Versions:
|   +-- Microsoft Word 2019
|   +-- Adobe Acrobat Pro DC
|   +-- Microsoft PowerPoint 2019
|
+-- File Paths Discovered:
|   +-- \\FILESERVER01\Marketing\Reports\2024\
|       +-- Server name: FILESERVER01
|       +-- Share name: Marketing
|       +-- Windows file server environment
|
+-- Intelligence Value:
    +-- Employee names for social engineering
    +-- Internal naming conventions
    +-- Server names for targeting
    +-- Software versions for vulnerability research
```

---

## Chapter 9: ICS/SCADA Discovery

### 9.1 Understanding the Concept

Industrial Control Systems and SCADA were designed decades ago, back when nobody imagined these things would be on the internet. The protocols have no authentication. No encryption. They'll happily identify themselves to anyone who asks.

Why is ICS exposure such a big deal? Because unlike IT systems where a breach means data loss, ICS breaches can cause physical damage. Explosions. Power outages. Water contamination. Manufacturing shutdowns. And these systems keep getting connected to the internet for "remote monitoring" without anyone thinking hard enough about security.

> The protocols themselves are the vulnerability. Modbus will respond to any query with device identification, register values, config data. There's no auth to bypass -- it was never built in.

### 9.2 Walkthrough: Finding Industrial Systems

**Shodan Queries for ICS Protocols:**

```
# Modbus (most common ICS protocol)
port:502

# Siemens S7
port:102

# DNP3 (power utilities)
port:20000

# IEC 60870-5-104 (power grid)
port:2404

# BACnet (building automation)
port:47808

# EtherNet/IP (Rockwell/Allen-Bradley)
port:44818

# Combined with organization
org:"Target Organization" port:502,102,2404,47808,20000

# Find specific vendors
product:"Siemens" port:102
product:"Schneider Electric"
product:"Allen-Bradley"
```

**HMI Web Interface Discovery:**

```
# Find web-based HMI systems
http.title:"HMI"
http.title:"SCADA"
http.title:"Wonderware"
http.title:"FactoryTalk"
http.title:"Ignition"
```

#### Example Modbus Output Analysis

```
Modbus Device Information:

+-- IP: 192.0.2.100
+-- Port: 502
+-- Protocol: Modbus/TCP
|
+-- Device Identification:
|   +-- Vendor: Schneider Electric
|   +-- Product Code: BMX P34 2020
|   +-- Product Name: Modicon M340
|   +-- Revision: 2.60
|   +-- Vendor URL: www.schneider-electric.com
|
+-- Intelligence Value:
    +-- Exact PLC model and firmware version
    +-- Can research known vulnerabilities
    +-- Indicates industrial/manufacturing operations
    +-- No authentication - anyone can query/control
```

---

## Chapter 10: Advanced Network Monitoring and WHOIS Intelligence

### 10.1 Understanding the Concept

Discovery is just the beginning. Ongoing network monitoring shows you operational patterns, infrastructure changes, potential security events. BGP monitoring, WHOIS analysis, outage detection -- all of it feeds continuous intelligence about a target's infrastructure.

Why bother with continuous monitoring? Networks change all the time. New servers spin up. Configs get updated. Routing shifts. Catching these changes can reveal new infrastructure before it's fully hardened, maintenance windows when defenses are weaker, outages that might indicate incidents, upstream provider switches, expansion into new regions.

### 10.2 Walkthrough: BGP Monitoring

**Objective:** Monitor target's BGP announcements for infrastructure changes.

#### Real-Time BGP Monitoring

```python
# RIPE RIS Live - WebSocket feed of global BGP updates
# Connect to: wss://ris-live.ripe.net/v1/ws/?client=research

# Using Python to monitor specific ASN:
import websocket
import json

def on_message(ws, message):
    data = json.loads(message)
    if data.get('type') == 'ris_message':
        msg = data.get('data', {})
        print(f"Type: {msg.get('type')}")
        print(f"Peer: {msg.get('peer')}")
        print(f"Path: {msg.get('path')}")
        print(f"Announcements: {msg.get('announcements')}")
        print("---")

ws = websocket.WebSocketApp(
    "wss://ris-live.ripe.net/v1/ws/?client=research",
    on_message=on_message
)

# Subscribe to specific ASN
subscribe_msg = {
    "type": "ris_subscribe",
    "data": {
        "type": "UPDATE",
        "require": "announcements",
        "path": "12345"  # Target ASN
    }
}

ws.send(json.dumps(subscribe_msg))
ws.run_forever()
```

#### BGP Historical Analysis

```bash
# RIPE Stat Widget - View BGP updates over time
# https://stat.ripe.net/widget/bgp-updates#w.resource=AS12345

# BGPStream (command line)
# Install: pip install pybgpstream
bgpstream -w 1704067200,1704153600 \
          -p announcements \
          -p withdrawals \
          -f 'peer AS12345'

# What to look for:
# - Prefix withdrawals: May indicate outage
# - New announcements: New infrastructure
# - AS path changes: Provider changes
# - MOAS (Multiple Origin AS): Potential hijacking
```

#### BGP Intelligence Output

```
BGP Monitoring Report: AS12345

+-- Current Prefixes
|   +-- 192.0.2.0/24 - Stable (announced 2+ years)
|   +-- 198.51.100.0/24 - Stable
|
+-- Recent Changes (Last 30 Days)
|   +-- 2024-03-10: New prefix 203.0.113.0/24 announced
|   |   +-- New infrastructure - investigate!
|   +-- 2024-03-05: AS path change for 192.0.2.0/24
|   |   +-- Switched from Cogent to Lumen
|   +-- 2024-02-28: Brief withdrawal of 198.51.100.0/24 (3 min)
|       +-- Possible maintenance or incident
|
+-- Upstream Analysis
|   +-- Primary: AS174 (Cogent) - 60% of routes
|   +-- Secondary: AS3356 (Lumen) - 40% of routes
|   +-- No IPv6 upstreams (IPv6 not deployed)
|
+-- Intelligence Value
    +-- New prefix = new datacenter or expansion
    +-- Provider switch = contract/relationship change
    +-- Brief withdrawals = maintenance windows
```

### 10.3 Walkthrough: Internet Outage Detection

**Objective:** Monitor for outages affecting target infrastructure.

#### Outage Detection Sources

```
Internet Outage Detection Resources:

+-- IODA (Internet Outage Detection and Analysis)
|   +-- URL: ioda.inetintel.cc.gatech.edu
|   +-- Monitors: BGP, Active Probing, Darknet
|   +-- Query: /country/PL (Poland) or /asn/12345
|   +-- Real-time alerts available
|
+-- Cloudflare Radar
|   +-- URL: radar.cloudflare.com
|   +-- Monitors: HTTP traffic patterns
|   +-- Query: /pl (country) or specific ASN
|   +-- Shows traffic anomalies
|
+-- ThousandEyes Outage Map
|   +-- URL: thousandeyes.com/outages
|   +-- Global internet health monitoring
|   +-- Enterprise-focused
|
+-- Downdetector
|   +-- URL: downdetector.com
|   +-- User-reported outages
|   +-- Good for major services
|
+-- BGP Monitoring (as above)
    +-- Prefix withdrawals indicate routing outages
```

#### Power Grid Specific - Frequency Monitoring

For power grid targets, grid frequency tells you about operational state:

```
+-- Normal Operation
|   +-- Europe: 50.00 Hz +/- 0.02 Hz
|   +-- North America: 60.00 Hz +/- 0.02 Hz
|
+-- Stress Indicators
|   +-- +/- 0.1 Hz: Minor load/generation imbalance
|   +-- +/- 0.2 Hz: Significant event (generator trip)
|   +-- +/- 0.5 Hz: Emergency conditions
|
+-- Monitoring Sources
|   +-- gridradar.net/en/mains-frequency (Real-time Europe)
|   +-- mainsfrequency.com (Multiple regions)
|   +-- power-grid-frequency.org (Historical data)
|   +-- transparency.entsoe.eu (European grid operator)
|
+-- Intelligence Value
    +-- Frequency deviation during suspected attack
        indicates physical grid impact
```

### 10.4 Walkthrough: WHOIS Organizational Intelligence

**Objective:** Extract organizational intelligence from WHOIS records.

#### WHOIS Deep Analysis

```bash
# Query RIPE database for organization details
whois -h whois.ripe.net "AS12345"

# Parse organizational information
whois -h whois.ripe.net "ORG-TARGET1-RIPE"

# Find all resources owned by organization
whois -h whois.ripe.net "-i org ORG-TARGET1-RIPE"
```

#### WHOIS Fields and Intelligence Value

```
WHOIS Record Analysis:

+-- Organization Fields
|   +-- org-name: Official legal name
|   +-- address: Physical location (HQ or data center)
|   +-- country: Jurisdiction (legal implications)
|   +-- org-type: LIR, EU-PI, etc.
|
+-- Contact Fields
|   +-- admin-c: Administrative contact
|   |   +-- Query: whois -h whois.ripe.net "PERSON-HANDLE"
|   |   +-- Reveals: Name, phone, email
|   +-- tech-c: Technical contact
|   |   +-- Often IT/Network staff
|   +-- abuse-c: Abuse contact
|       +-- Security team email
|
+-- Maintainer Fields
|   +-- mnt-by: Who manages this record
|   |   +-- May reveal IT service provider
|   +-- mnt-lower: Who can create sub-allocations
|   +-- mnt-routes: Who manages routing
|
+-- Network Fields
|   +-- inetnum: IP range
|   +-- netname: Network name (internal naming!)
|   +-- descr: Description (may reveal purpose)
|   +-- status: ALLOCATED PA, ASSIGNED PI, etc.
|
+-- Historical Fields
    +-- created: When allocated (age of presence)
    +-- last-modified: Recent changes
    +-- source: Registry (RIPE, ARIN, etc.)
```

#### WHOIS Intelligence Extraction Script

```bash
#!/bin/bash
# whois_intel.sh - Extract intelligence from WHOIS

ASN=$1
echo "=== WHOIS Intelligence for AS$ASN ==="

# Get ASN details
echo -e "\n[*] ASN Details:"
whois -h whois.ripe.net "AS$ASN" | grep -E "^(as-name|descr|org|admin-c|tech-c|mnt):"

# Get organization
ORG=$(whois -h whois.ripe.net "AS$ASN" | grep "^org:" | awk '{print $2}')
if [ -n "$ORG" ]; then
    echo -e "\n[*] Organization Details ($ORG):"
    whois -h whois.ripe.net "$ORG" | grep -E "^(org-name|address|phone|e-mail|country):"
fi

# Get all prefixes
echo -e "\n[*] Announced Prefixes:"
whois -h whois.radb.net -- "-i origin AS$ASN" | grep "^route:" | awk '{print $2}'

# Get admin contact details
ADMIN=$(whois -h whois.ripe.net "AS$ASN" | grep "^admin-c:" | awk '{print $2}')
if [ -n "$ADMIN" ]; then
    echo -e "\n[*] Admin Contact ($ADMIN):"
    whois -h whois.ripe.net "$ADMIN" | grep -E "^(person|address|phone|e-mail):"
fi

# Get tech contact details
TECH=$(whois -h whois.ripe.net "AS$ASN" | grep "^tech-c:" | awk '{print $2}')
if [ -n "$TECH" ]; then
    echo -e "\n[*] Technical Contact ($TECH):"
    whois -h whois.ripe.net "$TECH" | grep -E "^(person|address|phone|e-mail):"
fi
```

#### Output Example

```
WHOIS Intelligence Report: AS12345

+-- Organization
|   +-- Name: Target Organization Inc.
|   +-- Address: 123 Business Park, Anytown, US
|   +-- Country: US
|   +-- Type: End User (direct allocation)
|
+-- Contacts
|   +-- Admin: John Smith
|   |   +-- Phone: +1-555-123-4567
|   |   +-- Email: jsmith@target.com
|   +-- Technical: IT Operations
|       +-- Phone: +1-555-123-4568
|       +-- Email: netops@target.com
|
+-- Network Resources
|   +-- 192.0.2.0/24 (netname: TARGET-PROD)
|   +-- 198.51.100.0/24 (netname: TARGET-DR)
|   +-- 203.0.113.0/24 (netname: TARGET-DEV)
|
+-- Management
|   +-- Maintainer: MNT-TARGET-OPS
|   +-- Last Modified: 2024-02-15
|
+-- Intelligence Value
    +-- Contact names for social engineering
    +-- Phone numbers for vishing
    +-- Network naming reveals purpose (PROD, DR, DEV)
    +-- Recent modification = active management
```

---

## Chapter 11: Cloud Infrastructure Discovery

### 11.1 Understanding the Concept

Cloud providers love their predictable naming patterns. If you know an org's name, you can often guess their cloud resource names and check whether they exist. Not hard.

Cloud resources need globally unique names, and organizations almost always use their name or project names when creating them. A bucket called "target-backup" or "target-data"? Easily guessable. Easily verified.

### 11.2 Walkthrough: Cloud Resource Discovery

#### S3 Bucket Discovery

```bash
# Check if common bucket names exist
for name in target target-backup target-data target-logs target-assets target-dev target-staging; do
  if curl -s -I "https://${name}.s3.amazonaws.com" | grep -q "200\|403"; then
    echo "Bucket exists: ${name}"
  fi
done
```

- **200 response:** Bucket exists and may be publicly accessible
- **403 response:** Bucket exists but is private
- **404 response:** Bucket doesn't exist

#### DNS-Based Cloud Discovery

```bash
# Look for CNAME records pointing to cloud services
dig +short CNAME assets.target.com
# Output: d1234.cloudfront.net (CloudFront CDN)

dig +short CNAME api.target.com
# Output: xyz123.execute-api.us-east-1.amazonaws.com (API Gateway)

dig +short CNAME files.target.com
# Output: target-files.s3.amazonaws.com (S3 bucket)
```

#### Intelligence Output

```
Cloud Infrastructure Discovery:

+-- AWS Resources:
|   +-- S3 Buckets:
|   |   +-- target-public (200 - publicly accessible!)
|   |   +-- target-assets (403 - exists, private)
|   |   +-- target-backup (403 - exists, private)
|   +-- CloudFront: d1234.cloudfront.net
|   +-- API Gateway: xyz123.execute-api.us-east-1.amazonaws.com
|
+-- Azure Resources:
|   +-- Blob Storage: target.blob.core.windows.net
|   +-- Web App: target-portal.azurewebsites.net
|
+-- Intelligence:
    +-- Multi-cloud environment (AWS + Azure)
    +-- Publicly accessible S3 bucket (investigate!)
    +-- API infrastructure on AWS
    +-- Portal application on Azure
```
