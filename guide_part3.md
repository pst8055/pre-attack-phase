# Part VIII: Advanced Topics

---

## Chapter 18: MITRE ATT&CK Mapping for Reconnaissance

### 18.1 Introduction to MITRE ATT&CK Reconnaissance Tactic

MITRE ATT&CK is basically the industry's playbook -- a globally accessible knowledge base of adversary tactics and techniques pulled straight from real-world observations. **Reconnaissance (TA0043)** sits right at the start of the enterprise attack lifecycle. It covers everything adversaries do to gather intel before they actually pull the trigger on an operation.

Why does mapping recon techniques to ATT&CK matter? Three reasons.

1. **Offense**: Red teams and pentesters can use ATT&CK mappings to make sure they aren't leaving gaps in the pre-attack phase.
2. **Defense**: Blue teams get to build detection strategies around known recon techniques and the indicators those techniques leave behind.
3. **Communication**: ATT&CK gives everyone -- across teams, orgs, and sectors -- a shared vocabulary for talking about adversary behavior.

> The Reconnaissance tactic (TA0043) was introduced in ATT&CK v8 (October 2020) as part of the PRE-ATT&CK migration into the Enterprise matrix. It contains 10 top-level techniques with numerous sub-techniques that describe the full spectrum of pre-compromise intelligence gathering.

### 18.2 TA0043 Techniques Overview

Here's the full breakdown of all ten Reconnaissance techniques in ATT&CK Enterprise:

| Technique ID | Name | Sub-Techniques | Description |
|---|---|---|---|
| T1595 | Active Scanning | .001 Scanning IP Blocks, .002 Vulnerability Scanning, .003 Wordlist Scanning | Adversaries probe victim infrastructure directly to gather information |
| T1592 | Gather Victim Host Information | .001 Hardware, .002 Software, .003 Firmware, .004 Client Configurations | Collecting details about victim hosts including installed software and hardware specs |
| T1589 | Gather Victim Identity Information | .001 Credentials, .002 Email Addresses, .003 Employee Names | Gathering information about victim personnel and their credentials |
| T1590 | Gather Victim Network Information | .001 Domain Properties, .002 DNS, .003 Network Trust Dependencies, .004 Network Topology, .005 IP Addresses, .006 Network Security Appliances | Collecting details about victim network configuration and topology |
| T1591 | Gather Victim Org Information | .001 Determine Physical Locations, .002 Business Relationships, .003 Identify Business Tempo, .004 Identify Roles | Collecting information about the victim organization itself |
| T1593 | Search Open Websites/Domains | .001 Social Media, .002 Search Engines, .003 Code Repositories | Using publicly accessible websites to collect victim information |
| T1594 | Search Victim-Owned Websites | N/A | Searching websites owned by the victim for useful information |
| T1596 | Search Open Technical Databases | .001 DNS/Passive DNS, .002 WHOIS, .003 Digital Certificates, .004 CDNs, .005 Scan Databases | Querying publicly available technical databases for victim data |
| T1597 | Search Closed Sources | .001 Threat Intel Vendors, .002 Purchase Technical Data | Searching closed or commercial data sources for victim information |
| T1598 | Phishing for Information | .001 Spearphishing Service, .002 Spearphishing Attachment, .003 Spearphishing Link, .004 Spearphishing Voice | Using social engineering to elicit information from targets |

### 18.3 Mapping Guide Chapters to ATT&CK Techniques

Every chapter in this guide maps to one or more ATT&CK Reconnaissance techniques. The cross-reference table below lays it all out:

| Guide Chapter | ATT&CK Technique(s) | Sub-Techniques |
|---|---|---|
| Ch 0: Definitions & Lifecycle | TA0043 (overall tactic) | Framework-level mapping |
| Ch 1: Why Orgs Fail to Detect Recon | TA0043 (detection gaps) | All techniques (detection perspective) |
| Ch 2: Attacker's Info Advantage | TA0043 (adversary perspective) | All techniques (offensive perspective) |
| Ch 3: ASN & BGP Intelligence | T1590 Gather Victim Network Info | .004 Network Topology, .005 IP Addresses |
| Ch 4: DNS Intelligence | T1590 Gather Victim Network Info, T1596 Search Open Technical Databases | T1590.002 DNS, T1596.001 DNS/Passive DNS |
| Ch 5: Service Discovery | T1595 Active Scanning, T1592 Gather Victim Host Info | T1595.001 Scanning IP Blocks, T1595.002 Vulnerability Scanning, T1592.002 Software |
| Ch 6: IP Enrichment | T1590 Gather Victim Network Info, T1596 Search Open Technical Databases | T1590.005 IP Addresses, T1596.002 WHOIS, T1596.005 Scan Databases |
| Ch 7: HUMINT via OSINT | T1589 Gather Victim Identity Info, T1591 Gather Victim Org Info, T1593 Search Open Websites | T1589.002 Email Addresses, T1589.003 Employee Names, T1591.004 Identify Roles, T1593.001 Social Media |
| Ch 8: Document Intelligence | T1592 Gather Victim Host Info, T1593 Search Open Websites | T1592.002 Software, T1592.004 Client Configurations, T1593.002 Search Engines |
| Ch 9: ICS/SCADA Recon | T1596 Search Open Technical Databases, T1592 Gather Victim Host Info | T1596.005 Scan Databases, T1592.003 Firmware |
| Ch 10: WHOIS Analysis | T1596 Search Open Technical Databases | T1596.002 WHOIS |
| Ch 11: Cloud Infra Enumeration | T1590 Gather Victim Network Info, T1596 Search Open Technical Databases | T1590.001 Domain Properties, T1596.003 Digital Certificates |
| Ch 12: Email & CDN Bypass | T1595 Active Scanning, T1596 Search Open Technical Databases | T1595.001 Scanning IP Blocks, T1596.004 CDNs |
| Ch 13: POST-Based Fingerprinting | T1595 Active Scanning, T1592 Gather Victim Host Info | T1595.002 Vulnerability Scanning, T1592.002 Software |
| Ch 14: Social Engineering Profiling | T1589 Gather Victim Identity Info, T1598 Phishing for Information | T1589.001 Credentials, T1589.003 Employee Names, T1598.001-.004 |
| Ch 15: Building the Target Package | TA0043 (aggregation) | All techniques (synthesis) |
| Ch 16: Automating Recon | T1595 Active Scanning (automated) | T1595.001-.003 (at scale) |
| Ch 17: Operational Security | TA0043 (OPSEC perspective) | All techniques (evasion perspective) |

### 18.4 Deep Dive: T1595 -- Active Scanning

Active scanning means you're directly poking at victim infrastructure. That makes it the noisiest recon technique out there -- it generates actual network traffic hitting the target's boxes.

#### T1595.001 -- Scanning IP Blocks

This is scanning ranges of IPs to find what's alive and what services are running. Maps directly to Chapter 5 (Service Discovery) and Chapter 12 (CDN Bypass).

```bash
# Example: Scanning a target's known CIDR block for web services
nmap -sS -p 80,443,8080,8443 --open -T3 192.0.2.0/24 -oX scan_results.xml

# Example: Using masscan for high-speed enumeration of large ranges
masscan 198.51.100.0/24 -p0-65535 --rate=1000 --banners -oJ masscan_output.json
```

**Detection Opportunity**: NIDS can catch sequential connection attempts across multiple IPs or ports in a short window. Firewall logs showing denied connections from one source fanning out to many destinations? Strong indicator.

#### T1595.002 -- Vulnerability Scanning

This goes beyond port scanning. We're talking version detection, banner grabbing, and actively probing for known CVEs. Adversaries fire off vuln scanners to find what's exploitable.

```bash
# Example: Targeted vulnerability scan with Nmap NSE scripts
nmap -sV --script=vuln 203.0.113.10 -oN vuln_scan.txt

# Example: Nuclei scan against discovered web assets
nuclei -u https://www.example.com -t cves/ -severity critical,high -o nuclei_results.txt
```

#### T1595.003 -- Wordlist Scanning

Brute-forcing content discovery against web apps -- hunting for hidden directories, backup archives, admin interfaces, forgotten files. The usual suspects.

```bash
# Example: Directory enumeration with ffuf
ffuf -u https://www.example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,403 -o ffuf_results.json -of json

# Example: Subdomain enumeration via DNS brute-force
ffuf -u https://FUZZ.example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200 -o subdomain_results.json
```

### 18.5 Deep Dive: T1596 -- Search Open Technical Databases

Querying publicly available technical databases. This is one of the most productive recon methods you'll use -- and one of the hardest to detect because you never touch the target directly.

#### T1596.001 -- DNS/Passive DNS

```bash
# Query passive DNS records via SecurityTrails API
curl -s "https://api.securitytrails.com/v1/domain/example.com/subdomains" \
  -H "APIKEY: ${SECURITYTRAILS_KEY}" | jq '.subdomains[]'

# Historical DNS lookups via VirusTotal
curl -s "https://www.virustotal.com/api/v3/domains/example.com/resolutions" \
  -H "x-apikey: ${VT_API_KEY}" | jq '.data[].attributes'
```

#### T1596.002 -- WHOIS

```bash
# WHOIS lookup with parsing
whois example.com | grep -E '(Registrant|Admin|Tech|Name Server|Creation|Expiry)'

# Reverse WHOIS lookup by registrant organization
# Identifies all domains registered by the same entity
curl -s "https://api.whoisxmlapi.com/v2?apiKey=${WHOIS_KEY}&domainName=example.com&outputFormat=JSON"
```

#### T1596.005 -- Scan Databases

Services like Shodan, Censys, and ZoomEye continuously scan the internet and catalog what they find. You just query their databases:

```bash
# Shodan search for organization's assets
shodan search "org:\"Example Corporation\"" --fields ip_str,port,product,version

# Censys search for certificates issued to target domain
censys search "parsed.subject.common_name: example.com" --index-type certificates

# Querying Shodan for specific service banners
shodan search "ssl.cert.subject.cn:example.com" --fields ip_str,port,hostnames
```

### 18.6 Deep Dive: T1589 -- Gather Victim Identity Information

This one's about people. Collecting info on individuals inside the target org, which feeds directly into social engineering campaigns (Chapter 14).

#### T1589.001 -- Credentials

Digging through breach databases, paste sites, dark web marketplaces for leaked creds:

```bash
# Check if corporate email domain appears in known breaches (via Have I Been Pwned API)
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/user@example.com" \
  -H "hibp-api-key: ${HIBP_KEY}" \
  -H "user-agent: OSINT-Assessment" | jq '.[].Name'
```

#### T1589.002 -- Email Addresses

```bash
# Harvest email addresses using theHarvester
theHarvester -d example.com -b google,bing,linkedin -l 500 -f emails_output

# Hunter.io API for email pattern discovery
curl -s "https://api.hunter.io/v2/domain-search?domain=example.com&api_key=${HUNTER_KEY}" \
  | jq '.data.emails[].value'
```

#### T1589.003 -- Employee Names

```bash
# LinkedIn enumeration via search engine dorking
# Note: Only use for authorized engagements within scope
# Google dork: site:linkedin.com/in "Example Corporation"

# CrossLinked for LinkedIn employee enumeration
crosslinked -f '{first}.{last}@example.com' "Example Corporation" -o employees.txt
```

### 18.7 Building an ATT&CK-Aligned Reconnaissance Plan

If you want a structured recon engagement, map your planned activities to ATT&CK techniques. It keeps things comprehensive and makes reporting cleaner. Here's a template:

```
RECONNAISSANCE PLAN - ATT&CK ALIGNED
=====================================
Target: example.com (Example Corporation)
Scope: External reconnaissance only
Authorization: [Reference engagement letter]

Phase 1 - Passive Collection (No target interaction)
-----------------------------------------------------
[ ] T1596.001 - Passive DNS enumeration
[ ] T1596.002 - WHOIS and reverse WHOIS
[ ] T1596.003 - Certificate transparency log search
[ ] T1596.005 - Shodan/Censys/ZoomEye queries
[ ] T1593.001 - Social media profiling
[ ] T1593.002 - Search engine dorking
[ ] T1593.003 - Code repository searching
[ ] T1589.002 - Email address harvesting
[ ] T1589.003 - Employee name enumeration
[ ] T1591.001 - Physical location identification
[ ] T1591.002 - Business relationship mapping
[ ] T1590.002 - DNS record enumeration
[ ] T1590.005 - IP address space mapping

Phase 2 - Active Scanning (Direct target interaction)
------------------------------------------------------
[ ] T1595.001 - Port scanning of discovered hosts
[ ] T1595.002 - Vulnerability scanning
[ ] T1595.003 - Web content discovery
[ ] T1594     - Victim-owned website analysis
[ ] T1592.002 - Software version fingerprinting

Phase 3 - Targeted Collection
------------------------------
[ ] T1589.001 - Credential leak checking
[ ] T1590.004 - Network topology mapping
[ ] T1590.006 - Security appliance identification
[ ] T1597.001 - Threat intel vendor queries
```

### 18.8 Using ATT&CK Navigator for Visualization

ATT&CK Navigator is a web-based tool for building custom heatmaps of technique coverage. For recon engagements, it gives you a visual way to track what you've hit and what's still outstanding.

```json
{
  "name": "Recon Coverage - Example Corp Engagement",
  "versions": {
    "attack": "14",
    "navigator": "4.9.1",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "filters": {
    "platforms": ["PRE"]
  },
  "techniques": [
    {
      "techniqueID": "T1595",
      "tactic": "reconnaissance",
      "score": 100,
      "color": "#31a354",
      "comment": "Completed: Full port scan and vulnerability scan of external perimeter"
    },
    {
      "techniqueID": "T1596",
      "tactic": "reconnaissance",
      "score": 75,
      "color": "#addd8e",
      "comment": "Partial: DNS and WHOIS complete, Shodan pending"
    }
  ]
}
```

> When you report recon findings, always tag each one with the ATT&CK technique ID. Defenders can then immediately look up corresponding mitigations and detections in the knowledge base. Don't skip this.

### 18.9 Detection Mapping: From Reconnaissance to Defense

Every ATT&CK technique comes with associated detections. Here's how recon techniques map to their primary detection data sources:

| Technique | Detection Data Source | Detection Method |
|---|---|---|
| T1595.001 Scanning IP Blocks | Network Traffic: Network Traffic Flow | Monitor for unusual connection volumes from single sources |
| T1595.002 Vulnerability Scanning | Network Traffic: Network Traffic Content | Detect known scanner signatures in request payloads |
| T1595.003 Wordlist Scanning | Application Log: Web Server Logs | Alert on high volumes of 404/403 responses to a single source |
| T1592 Host Info Gathering | N/A (passive) | Limited direct detection; monitor for data exposure |
| T1589 Identity Info Gathering | N/A (passive) | Monitor breach notification services |
| T1590 Network Info Gathering | Network Traffic: DNS Logs | Detect excessive DNS queries for organization's domains |
| T1593 Search Open Websites | N/A (passive) | Monitor for scraping of corporate web properties |
| T1596 Technical Databases | N/A (third-party) | Monitor Shodan/Censys for your own exposure |
| T1598 Phishing for Info | Application Log: Email Logs | Detect phishing attempts targeting employees |

---

## Chapter 19: GitHub and GitLab Secret Scanning

### 19.1 The Scale of the Problem

Code repos are an absolute goldmine for adversaries doing recon. Developers commit sensitive stuff to version control all the time -- API keys, database creds, private keys, internal hostnames, infrastructure details. The numbers are staggering: millions of secrets are sitting exposed in public repos right now.

But here's what people miss. The recon value of leaked secrets goes way beyond credential reuse. One leaked AWS access key can unravel an org's entire cloud architecture. A committed `.env` file might expose internal service URLs, database connection strings, and third-party API integrations all at once. And even secrets that got "removed" in later commits? They're still in the Git history forever -- unless someone rebuilds the repo from scratch.

> Every public commit is permanent. Git's immutable history means that a secret pushed even briefly to a public repository should be considered compromised. Rotating the credential is the only safe response.

### 19.2 GitHub Dorking for Secrets

GitHub's search is a seriously powerful recon tool. The advanced search operators let you zero in on specific file types, code patterns, and org-scoped results.

#### Common GitHub Dork Queries

```
# Search for AWS keys associated with a target domain
org:example-corp "AKIA" language:yaml
org:example-corp "aws_secret_access_key" language:python

# Database connection strings
org:example-corp "jdbc:mysql://" OR "jdbc:postgresql://"
org:example-corp "mongodb+srv://"
org:example-corp filename:.env "DB_PASSWORD"

# Private keys
org:example-corp "BEGIN RSA PRIVATE KEY"
org:example-corp "BEGIN OPENSSH PRIVATE KEY"
org:example-corp filename:id_rsa

# API keys and tokens
org:example-corp "api_key" OR "apikey" OR "api-key" filename:.env
org:example-corp "slack_token" OR "xoxb-" OR "xoxp-"
org:example-corp "ghp_" OR "gho_" OR "github_pat_"
org:example-corp "sk-" filename:.env  # OpenAI keys

# Internal infrastructure
org:example-corp "internal." OR "staging." OR "dev." filename:.env
org:example-corp "10.0." OR "172.16." OR "192.168." filename:config

# CI/CD secrets
org:example-corp filename:.github/workflows "secrets."
org:example-corp filename:.gitlab-ci.yml "variables"

# Terraform state and configs
org:example-corp filename:terraform.tfstate
org:example-corp filename:*.tf "access_key"
org:example-corp filename:*.tfvars

# Docker and Kubernetes secrets
org:example-corp filename:docker-compose.yml "password"
org:example-corp filename:*.yaml "kind: Secret"
org:example-corp filename:Dockerfile "ENV" "PASSWORD"
```

#### Systematic Organization-Wide Search

```python
#!/usr/bin/env python3
"""
github_secret_dorker.py - Systematic GitHub dork search for an organization.
For authorized security assessments only.
"""

import requests
import time
import json
import sys

GITHUB_TOKEN = "YOUR_GITHUB_PAT"  # Use a read-only token
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3.text-match+json"
}

DORK_PATTERNS = [
    '"{org}" "AKIA"',
    '"{org}" "aws_secret_access_key"',
    '"{org}" "BEGIN RSA PRIVATE KEY"',
    '"{org}" filename:.env "password"',
    '"{org}" filename:.env "secret"',
    '"{org}" filename:.env "token"',
    '"{org}" "jdbc:" "password"',
    '"{org}" "mongodb+srv://"',
    '"{org}" filename:wp-config.php "DB_PASSWORD"',
    '"{org}" filename:.npmrc "_authToken"',
    '"{org}" filename:.dockercfg "auth"',
    '"{org}" filename:id_rsa',
    '"{org}" filename:credentials "aws_access_key_id"',
    '"{org}" "sk_live_"',
    '"{org}" "ghp_"',
]

def search_github(query, page=1):
    """Execute a GitHub code search query."""
    url = "https://api.github.com/search/code"
    params = {"q": query, "per_page": 30, "page": page}
    response = requests.get(url, headers=HEADERS, params=params)

    if response.status_code == 403:
        reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
        wait = max(reset_time - int(time.time()), 10)
        print(f"[!] Rate limited. Waiting {wait}s...")
        time.sleep(wait)
        return search_github(query, page)

    return response.json()

def run_dorks(org_name):
    """Run all dork patterns against a target organization."""
    results = []
    for pattern in DORK_PATTERNS:
        query = pattern.format(org=org_name)
        print(f"[*] Searching: {query}")
        data = search_github(query)
        count = data.get("total_count", 0)

        if count > 0:
            print(f"    [+] Found {count} results")
            for item in data.get("items", []):
                results.append({
                    "query": query,
                    "repo": item["repository"]["full_name"],
                    "path": item["path"],
                    "url": item["html_url"],
                    "text_matches": [
                        m.get("fragment", "")
                        for m in item.get("text_matches", [])
                    ]
                })

        # Respect GitHub's search rate limit (30 requests/minute)
        time.sleep(3)

    return results

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <organization-name>")
        sys.exit(1)

    findings = run_dorks(sys.argv[1])
    output_file = f"{sys.argv[1]}_github_secrets.json"
    with open(output_file, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"\n[*] {len(findings)} total findings written to {output_file}")
```

### 19.3 Automated Secret Scanning Tools

#### TruffleHog

TruffleHog digs through Git repos looking for high-entropy strings and known secret patterns. Version 3 packs over 800 credential detectors and can actually verify whether discovered secrets are still live.

```bash
# Scan a specific repository
trufflehog git https://github.com/example-corp/webapp.git --json --output results.json

# Scan an entire GitHub organization
trufflehog github --org=example-corp --token=${GITHUB_TOKEN} --json > org_secrets.json

# Scan only recent commits (last 50)
trufflehog git https://github.com/example-corp/webapp.git --max-depth=50

# Scan with verification (checks if secrets are still active)
trufflehog github --org=example-corp --token=${GITHUB_TOKEN} --only-verified

# Scan a local repository including all branches
trufflehog filesystem --directory=/path/to/repo --json
```

#### Gitleaks

Gitleaks relies on regex patterns and entropy analysis to catch secrets. It plays nicely with CI/CD pipelines and you can define custom rules.

```bash
# Scan a remote repository
gitleaks detect --source="https://github.com/example-corp/webapp" -v --report-path=gitleaks_report.json

# Scan a local repository
gitleaks detect --source="/path/to/repo" --report-format=json --report-path=findings.json

# Scan only staged changes (useful in pre-commit hooks)
gitleaks protect --staged

# Use a custom configuration with additional patterns
gitleaks detect --source="/path/to/repo" --config=custom_gitleaks.toml
```

Custom Gitleaks config example:

```toml
# custom_gitleaks.toml
title = "Custom rules for Example Corp assessment"

[[rules]]
id = "example-corp-internal-url"
description = "Internal URL for Example Corp"
regex = '''https?://(internal|staging|dev|uat)\.(example\.com|example-corp\.local)'''
tags = ["infrastructure", "internal"]

[[rules]]
id = "example-corp-jwt"
description = "JWT token"
regex = '''eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'''
tags = ["token", "jwt"]

[[rules]]
id = "generic-password-assignment"
description = "Password assignment in code"
regex = '''(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^\s'\"]{8,}['\"]'''
tags = ["password"]

[allowlist]
paths = [
    '''(.*?)test(.*?)''',
    '''(.*?)example(.*?)''',
]
```

#### git-secrets

Amazon's `git-secrets` works as a Git hook to prevent committing secrets in the first place. But you can also point it at existing repos to scan for what's already there:

```bash
# Install git-secrets
git clone https://github.com/awslabs/git-secrets.git
cd git-secrets && make install

# Register AWS patterns
git secrets --register-aws

# Scan a repository for secrets
git secrets --scan -r /path/to/repo

# Scan specific files
git secrets --scan /path/to/repo/config/*.yml
```

### 19.4 Exposed .git Directories on Web Servers

Finding an exposed `.git` directory on a production web server is one of those recon wins that can blow a target wide open. When someone deploys a site by copying the whole repo -- `.git` folder and all -- to the web root, you've got full source code and complete commit history just sitting there.

#### Detection

```bash
# Check for .git directory exposure
curl -s -o /dev/null -w "%{http_code}" https://www.example.com/.git/HEAD
# HTTP 200 indicates the .git directory is accessible

curl -s -o /dev/null -w "%{http_code}" https://www.example.com/.git/config
# This file may contain remote repository URLs and author info
```

#### Extraction with git-dumper

```bash
# Install git-dumper
pip install git-dumper

# Dump the exposed repository
git-dumper https://www.example.com/.git/ ./dumped_repo

# After dumping, examine the full commit history
cd ./dumped_repo
git log --all --oneline

# Search commit history for secrets
git log --all -p | grep -E '(password|secret|api_key|token)\s*[=:]'

# Check for configuration files with credentials
git log --all --diff-filter=D -- "*.env" "*.cfg" "*.conf" "*.ini"
```

#### Manual .git Reconstruction

Sometimes the automated tools choke. When that happens, you can reconstruct things manually by fetching individual Git objects:

```bash
# Fetch the HEAD reference
curl -s https://www.example.com/.git/HEAD
# Output: ref: refs/heads/main

# Fetch the branch reference
curl -s https://www.example.com/.git/refs/heads/main
# Output: a1b2c3d4e5f6... (commit hash)

# Fetch the commit object
curl -s https://www.example.com/.git/objects/a1/b2c3d4e5f6... | python3 -c "
import sys, zlib
print(zlib.decompress(sys.stdin.buffer.read()).decode('utf-8', errors='replace'))
"
```

### 19.5 Commit History Mining

Secrets that got removed from the current codebase? Still living in Git history. Mining commit diffs is how you pull them back out.

```bash
# Search all commit diffs for high-value patterns
git log --all -p --diff-filter=D | grep -B5 -A5 -iE \
  '(password|secret|api.?key|token|credential|private.?key)'

# Find commits that modified sensitive files
git log --all --follow -- ".env" "config/secrets.yml" "credentials.json"

# Show the full diff for a specific commit where secrets were removed
git show <commit-hash> -- ".env"

# List all files ever deleted from the repository
git log --all --diff-filter=D --name-only --pretty=format:""

# Search for specific patterns across all historical file versions
git rev-list --all | while read rev; do
  git grep -l "AKIA" "$rev" 2>/dev/null
done
```

### 19.6 CI/CD Configuration Leaks

CI/CD configs are sneaky. They reference secrets, internal infrastructure, deployment targets -- and even when the actual secret values live in the CI/CD platform's secret manager, the config files tell you what secrets exist and how they're wired up. That's intel.

#### GitHub Actions

```yaml
# Example .github/workflows/deploy.yml that leaks information
name: Deploy to Production
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to production
        env:
          # These variable names reveal infrastructure details:
          AWS_ACCOUNT_ID: ${{ secrets.AWS_PROD_ACCOUNT_ID }}
          DEPLOY_BUCKET: ${{ secrets.S3_DEPLOY_BUCKET }}
          DATABASE_HOST: ${{ secrets.RDS_PROD_HOST }}
          SLACK_WEBHOOK: ${{ secrets.SLACK_DEPLOY_WEBHOOK }}
        run: |
          # Deployment commands reveal architecture:
          aws s3 sync ./dist s3://$DEPLOY_BUCKET/
          aws cloudfront create-invalidation --distribution-id ${{ secrets.CF_DIST_ID }}
          # This reveals: S3 + CloudFront architecture, production database uses RDS,
          # Slack integration exists, and the deployment pattern
```

#### GitLab CI

```yaml
# Example .gitlab-ci.yml leaking infrastructure details
stages:
  - build
  - test
  - deploy

variables:
  DOCKER_REGISTRY: registry.example-corp.internal:5000  # Internal registry exposed
  KUBE_NAMESPACE: production                              # Kubernetes namespace

deploy_production:
  stage: deploy
  environment:
    name: production
    url: https://app.example.com  # Production URL confirmed
  script:
    - kubectl set image deployment/webapp webapp=$DOCKER_REGISTRY/webapp:$CI_COMMIT_SHA
    - kubectl rollout status deployment/webapp -n $KUBE_NAMESPACE
  only:
    - main
```

> CI/CD config files are a goldmine. Even without the actual secret values, they hand you the infrastructure architecture, deployment patterns, third-party integrations, and internal naming conventions on a platter.

### 19.7 GitLab-Specific Reconnaissance

Self-hosted GitLab instances can leak even more than GitHub since they expose additional API endpoints:

```bash
# Check for public GitLab instance and enumerate public projects
curl -s "https://gitlab.example.com/api/v4/projects?visibility=public&per_page=100" | jq '.[].name'

# Enumerate public snippets (often contain configuration fragments)
curl -s "https://gitlab.example.com/api/v4/snippets/public?per_page=100" | jq '.[] | {title, web_url}'

# Check for public groups and their projects
curl -s "https://gitlab.example.com/api/v4/groups?visibility=public&per_page=100" \
  | jq '.[].full_path'

# Examine CI/CD job artifacts (if publicly accessible)
curl -s "https://gitlab.example.com/api/v4/projects/<project_id>/jobs" | jq '.[].artifacts_file'
```

---

## Chapter 20: Defensive Countermeasures

### 20.1 Shifting Perspective: The Defender's Reconnaissance Challenge

Every technique in this guide? It's also an opportunity for defenders. If you understand how adversaries collect information about your org, you can systematically shrink your attack surface, catch recon activity in progress, and make the attacker's job a lot harder.

This chapter flips the offensive perspective on its head. Concrete, actionable countermeasures -- organized by the recon categories we covered in Parts III through VII.

> The goal isn't to become invisible. That's impossible for any org with an internet presence. The goal is to make recon more expensive and more detectable. Raise the cost, improve your visibility.

### 20.2 DNS Hygiene

DNS is one of the richest intel sources for adversaries (Chapter 4). Cleaning it up takes discipline.

#### Minimize Public DNS Records

```bash
# Audit your public DNS records for unnecessary exposure
dig example.com ANY +noall +answer
dig example.com AXFR @ns1.example.com  # Verify zone transfers are blocked

# Common issues to remediate:
# - TXT records with internal version numbers or infrastructure details
# - CNAME records pointing to decommissioned services (dangling CNAMEs)
# - MX records exposing internal mail routing
# - Overly descriptive hostnames (e.g., dc01.internal.example.com)
```

**Countermeasures:**

| Exposure | Countermeasure |
|---|---|
| Zone transfers enabled | Restrict AXFR to authorized secondary nameservers only |
| Descriptive internal hostnames in public DNS | Use opaque naming conventions (e.g., `svc-01` instead of `exchange-server`) |
| Dangling CNAME records | Implement regular DNS record auditing; remove records for decommissioned services |
| Excessive TXT records | Remove SPF, DKIM, and DMARC records that leak internal infrastructure details beyond what is necessary |
| Reverse DNS revealing hostnames | Use generic PTR records that do not reveal server function |
| DNS history in passive databases | Cannot be removed retroactively; focus on preventing future exposure |

#### Automated DNS Monitoring

```python
#!/usr/bin/env python3
"""
dns_monitor.py - Monitor public DNS records for unexpected changes.
Run on a schedule to detect unauthorized modifications.
"""

import dns.resolver
import json
import hashlib
from datetime import datetime
from pathlib import Path

MONITORED_DOMAINS = [
    "example.com",
    "example.org",
]

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
STATE_FILE = Path("dns_state.json")

def get_dns_records(domain):
    """Collect all DNS records for a domain."""
    records = {}
    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = sorted([str(r) for r in answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            records[rtype] = []
    return records

def load_state():
    """Load the previous DNS state."""
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}

def save_state(state):
    """Save the current DNS state."""
    STATE_FILE.write_text(json.dumps(state, indent=2))

def compare_states(old, new):
    """Compare DNS states and return changes."""
    changes = []
    for domain in new:
        if domain not in old:
            changes.append(f"NEW DOMAIN: {domain}")
            continue
        for rtype in new[domain]:
            old_records = set(old.get(domain, {}).get(rtype, []))
            new_records = set(new[domain][rtype])
            added = new_records - old_records
            removed = old_records - new_records
            for r in added:
                changes.append(f"ADDED {domain} {rtype}: {r}")
            for r in removed:
                changes.append(f"REMOVED {domain} {rtype}: {r}")
    return changes

def main():
    old_state = load_state()
    new_state = {}

    for domain in MONITORED_DOMAINS:
        new_state[domain] = get_dns_records(domain)

    changes = compare_states(old_state, new_state)

    if changes:
        print(f"[!] DNS changes detected at {datetime.utcnow().isoformat()}Z:")
        for change in changes:
            print(f"    {change}")
        # In production: send alert via email, Slack, PagerDuty, etc.
    else:
        print(f"[*] No DNS changes detected at {datetime.utcnow().isoformat()}Z")

    save_state(new_state)

if __name__ == "__main__":
    main()
```

### 20.3 Certificate Transparency Monitoring

CT logs are public, append-only logs of every TLS certificate that participating CAs issue. Adversaries use them for subdomain enumeration (Chapters 4 and 11) -- but you can use them too, to catch unauthorized certificate issuance for your domains.

```bash
# Monitor CT logs for your domain using certspotter
# https://sslmate.com/certspotter/
curl -s "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names" \
  | jq '.[].dns_names[]'

# Using crt.sh for historical certificate monitoring
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | sort -u
```

**What to watch for:** certificates showing up for subdomains you don't recognize (possible takeover or phishing), certs from CAs you don't use, wildcard certs you didn't request, and anything with a weird validity period.

### 20.4 Shodan and Censys Self-Monitoring

If your assets show up in internet scanning databases, adversaries will find them. You need to check your own exposure before they do.

```bash
# Monitor your organization's Shodan exposure
shodan alert create "Example Corp Monitoring" 192.0.2.0/24 198.51.100.0/24
shodan alert enable <alert-id> new_service,open_database,vulnerability,ssl_expired

# Query Shodan for your own assets
shodan search "org:\"Example Corporation\"" --fields ip_str,port,product,version,vulns

# Censys monitoring for your certificate footprint
censys search "parsed.subject.organization: \"Example Corporation\"" \
  --index-type certificates

# Check for exposed databases
shodan search "org:\"Example Corporation\" product:mongodb" --fields ip_str,port
shodan search "org:\"Example Corporation\" product:elasticsearch" --fields ip_str,port
shodan search "org:\"Example Corporation\" port:6379" --fields ip_str,port
```

### 20.5 Employee OSINT Awareness Training

People are the softest target. Human intel gathering (Chapters 7 and 14) is often the most productive recon technique, period. But employees who understand how their online presence gets weaponized? They're way harder to social engineer.

**Training should cover:**

LinkedIn hygiene -- don't list exact technologies, tool names, or internal project names in job descriptions. Lock down profile visibility for non-connections. Social media discipline means not posting photos of workspaces (whiteboards, screens, badges, building interiors) and being careful with location check-ins near sensitive sites.

For public-facing communications, use role-based addresses like `security@example.com` instead of personal emails that make targeted phishing trivial. Before anyone presents at a conference or publishes a paper, review the materials for accidental disclosure of internal infrastructure, tools, or architecture.

And work with HR on job postings. Instead of "Looking for an engineer experienced with CrowdStrike Falcon, Palo Alto PA-5260, and Splunk Enterprise 9.x," just say "Looking for an engineer experienced with endpoint protection, next-generation firewalls, and SIEM platforms." That small change denies adversaries a free shopping list of your security stack.

### 20.6 Reducing Digital Footprint

#### Web Server Hardening

```nginx
# nginx.conf - Remove version information from headers and error pages
server_tokens off;

# Remove unnecessary headers
proxy_hide_header X-Powered-By;
proxy_hide_header X-AspNet-Version;
proxy_hide_header X-AspNetMvc-Version;
proxy_hide_header Server;

# Custom error pages that do not reveal server software
error_page 404 /custom_404.html;
error_page 500 502 503 504 /custom_50x.html;
```

```apache
# Apache httpd.conf - Minimize information exposure
ServerTokens Prod
ServerSignature Off
Header unset X-Powered-By
Header unset X-AspNet-Version
FileETag None
```

#### robots.txt Discipline

Here's the thing about `robots.txt` -- it's meant to guide web crawlers, but adversaries read it like a treasure map of sensitive paths:

```
# BAD: Reveals sensitive directory structure
User-agent: *
Disallow: /admin/
Disallow: /api/v2/internal/
Disallow: /backup/
Disallow: /wp-admin/
Disallow: /phpmyadmin/
Disallow: /jenkins/
Disallow: /grafana/

# BETTER: Minimal robots.txt
User-agent: *
Disallow:
# Use authentication and network controls to protect sensitive paths
# Do not rely on robots.txt for security
```

> `robots.txt` isn't a security control. Every path you put in a `Disallow` directive becomes a target. Use proper authentication, network segmentation, and access controls instead.

#### Metadata Stripping

```bash
# Strip metadata from documents before publishing
exiftool -all= document.pdf
exiftool -all= presentation.pptx

# Verify metadata has been removed
exiftool document.pdf

# Batch strip metadata from all files in a directory
find /path/to/public/docs -type f \( -name "*.pdf" -o -name "*.docx" -o -name "*.xlsx" \) \
  -exec exiftool -all= {} \;
```

### 20.7 Honeypots and Deception for Reconnaissance Detection

Honeypots catch recon that would otherwise fly completely under the radar -- especially passive techniques that don't leave footprints on production systems.

#### DNS Honeytokens

Set up DNS records for fake subdomains that no legitimate system ever references. If anyone queries them, that's recon activity. Full stop.

```bash
# Create honeytoken DNS records
# In your DNS zone file, add records that look enticing but serve no real purpose:
# vpn-legacy.example.com    A    192.0.2.250
# dev-staging.example.com   A    192.0.2.251
# admin-portal.example.com  A    192.0.2.252
# backup-server.example.com A    192.0.2.253

# Monitor DNS query logs for any resolution of these records
# Any query = reconnaissance activity (legitimate systems never query these)
```

#### Web Honeypots

```python
#!/usr/bin/env python3
"""
web_honeypot.py - Lightweight web honeypot for detecting reconnaissance.
Logs all requests to paths that look like common reconnaissance targets.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import json
import logging

logging.basicConfig(
    filename="honeypot_access.log",
    level=logging.INFO,
    format="%(message)s"
)

# Paths that attract reconnaissance tools
HONEYPOT_PATHS = [
    "/.env", "/.git/HEAD", "/wp-admin/", "/wp-login.php",
    "/admin/", "/phpmyadmin/", "/api/swagger.json",
    "/actuator/health", "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml", "/server-status",
    "/backup/", "/.svn/entries", "/config.php.bak",
    "/.DS_Store", "/web.config", "/crossdomain.xml",
]

class HoneypotHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_ip": self.client_address[0],
            "method": "GET",
            "path": self.path,
            "user_agent": self.headers.get("User-Agent", ""),
            "headers": dict(self.headers),
            "is_honeypot_hit": self.path in HONEYPOT_PATHS,
        }
        logging.info(json.dumps(log_entry))

        if self.path in HONEYPOT_PATHS:
            # Return plausible but fake content to waste attacker time
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"# Nothing to see here\n")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_ip": self.client_address[0],
            "method": "POST",
            "path": self.path,
            "body_preview": body[:500].decode("utf-8", errors="replace"),
        }
        logging.info(json.dumps(log_entry))
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default logging

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), HoneypotHandler)
    print("[*] Honeypot listening on port 8080")
    server.serve_forever()
```

#### Credential Honeytokens

Plant fake credentials where adversaries look. Fake `.env` files on web servers (accessible but monitored), fake AWS keys that trigger alerts when someone tries to use them (AWS Canary Tokens), fake database credentials that log authentication attempts, and fake API keys seeded into public repos that you monitor for use.

```bash
# Generate an AWS canary token using Thinkst Canary
# When anyone attempts to use this fake AWS key, you receive an alert
# Deploy in: robots.txt-referenced paths, fake .env files, decoy Git repos

# Example canary token deployment in a decoy .env file
# Place at a robots.txt-referenced path to attract scanners
# .env contents:
# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
# AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
# (These are AWS documentation example keys - use real canary tokens in practice)
```

### 20.8 Defensive Countermeasures Summary Matrix

| Reconnaissance Technique | Detection Capability | Reduction Capability | Deception Capability |
|---|---|---|---|
| DNS enumeration | DNS query logging | Minimize records, opaque naming | DNS honeytokens |
| Certificate transparency search | CT log monitoring | Cannot prevent (public logs) | N/A |
| Shodan/Censys scanning | Monitor own exposure | Reduce exposed services | Honeypot services |
| Social media profiling | Limited | Employee training, privacy settings | Fake personas (legal considerations) |
| GitHub secret scanning | Monitor own repos | Pre-commit hooks, secret rotation | Canary tokens in decoy repos |
| Email harvesting | Monitor for phishing | Role-based addresses, SPF/DKIM/DMARC | Honeytoken email addresses |
| Web scraping/crawling | Web server access logs | Rate limiting, CAPTCHAs | Fake content in honeypot paths |
| Document metadata analysis | Limited | Metadata stripping before publishing | Decoy documents with tracking |
| Port scanning | IDS/IPS, firewall logs | Minimize exposed ports | Port-based honeypots |
| Vulnerability scanning | WAF logs, IDS signatures | Patch management, version hiding | Fake vulnerability responses |

---

## Chapter 21: Dark Web and Tor OSINT

### 21.1 The Dark Web as an Intelligence Source

The dark web -- mostly Tor hidden services -- is a major intel source during recon. Both adversaries and security researchers dig into it for leaked creds, stolen data, vulnerability intel, and org-specific intelligence that you won't find on the surface web.

For authorized assessments, dark web OSINT gives you visibility into credential leaks from breaches sold or shared on forums, stolen corporate documents and database dumps, zero-day markets and exploit discussions, data published by ransomware operators, and threat actor chatter about targeting specific organizations or sectors.

> Dark web OSINT should be passive. Don't create accounts on criminal forums, don't buy stolen data, don't interact with threat actors. Passive observation of publicly accessible dark web resources is generally legal; active participation isn't. Always talk to legal counsel before you start poking around.

### 21.2 Dark Web Search Engines

Several search engines index `.onion` sites and offer searchable interfaces -- some accessible from the regular web.

#### Ahmia

Ahmia is the most well-known legit dark web search engine. It filters out CSAM and provides a surface-web interface for searching Tor hidden services.

```
# Surface web access (no Tor required)
https://ahmia.fi/search/?q=example.com

# Onion address (requires Tor Browser or Tor proxy)
http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q=example.com
```

#### Other Dark Web Search Engines

| Search Engine | Description | Access Method |
|---|---|---|
| Ahmia | Filtered search of Tor hidden services | Surface web + Tor |
| Torch | One of the oldest Tor search engines; large index | Tor only |
| Haystack | Claims to index over 1.5 billion onion pages | Tor only |
| Kilos | Search engine focused on dark web marketplace listings | Tor only |
| Recon | Dark web search focused on vendor and market listings | Tor only |
| DarkSearch | API-accessible dark web search | Surface web API |

```bash
# Using DarkSearch API for programmatic dark web searching
curl -s "https://darksearch.io/api/search?query=example.com&page=1" \
  | jq '.data[] | {title, link, description}'
```

### 21.3 Monitoring Paste Sites

Paste sites get used constantly for dumping stolen data -- creds, database exports, config files, you name it. You need to watch both surface web and dark web paste sites.

#### Surface Web Paste Sites

```bash
# Key paste sites to monitor:
# - Pastebin (pastebin.com) - largest, most commonly used
# - GitHub Gists (gist.github.com) - often overlooked
# - Rentry (rentry.co)
# - Paste.ee
# - PrivBin instances

# Google dorking for paste site leaks
# site:pastebin.com "example.com" "password"
# site:gist.github.com "example.com" "api_key"
```

#### Automated Paste Monitoring

```python
#!/usr/bin/env python3
"""
paste_monitor.py - Monitor paste sites for mentions of target domains.
Uses the Pastebin scraping API (requires PRO account).
"""

import requests
import time
import re
import json
from datetime import datetime

# Keywords to monitor (customize per engagement)
KEYWORDS = [
    "example.com",
    "example.org",
    "Example Corporation",
    "@example.com",  # Email addresses
]

# Patterns indicating leaked credentials
CREDENTIAL_PATTERNS = [
    r'[\w.+-]+@example\.com[:\s]+\S+',           # email:password format
    r'(?i)password\s*[=:]\s*\S+',                 # password assignments
    r'(?i)(api[_-]?key|token)\s*[=:]\s*\S{20,}',  # API keys
]

def check_paste(paste_content, paste_url):
    """Check a paste for keywords and credential patterns."""
    findings = []
    for keyword in KEYWORDS:
        if keyword.lower() in paste_content.lower():
            findings.append({
                "type": "keyword_match",
                "keyword": keyword,
                "url": paste_url,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })

    for pattern in CREDENTIAL_PATTERNS:
        matches = re.findall(pattern, paste_content)
        if matches:
            findings.append({
                "type": "credential_pattern",
                "pattern": pattern,
                "match_count": len(matches),
                "url": paste_url,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })

    return findings

def monitor_pastebin_scraping_api(api_key):
    """
    Monitor Pastebin via the scraping API.
    Requires Pastebin PRO with scraping API access.
    """
    scrape_url = "https://scrape.pastebin.com/api_scraping.php"
    params = {"limit": 100}

    seen_keys = set()
    all_findings = []

    while True:
        try:
            response = requests.get(scrape_url, params=params)
            pastes = response.json()

            for paste in pastes:
                paste_key = paste.get("key", "")
                if paste_key in seen_keys:
                    continue
                seen_keys.add(paste_key)

                # Fetch paste content
                content_url = f"https://scrape.pastebin.com/api_scrape_item.php?i={paste_key}"
                content_response = requests.get(content_url)
                content = content_response.text

                findings = check_paste(content, f"https://pastebin.com/{paste_key}")
                if findings:
                    print(f"[!] Finding in paste {paste_key}:")
                    for f in findings:
                        print(f"    {f['type']}: {f.get('keyword', f.get('pattern', 'N/A'))}")
                    all_findings.extend(findings)

            # Pastebin rate limit: 1 request per second for scraping
            time.sleep(60)

        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(120)

if __name__ == "__main__":
    print("[*] Starting paste site monitoring...")
    print("[*] Note: Requires Pastebin PRO scraping API access")
    # monitor_pastebin_scraping_api("YOUR_API_KEY")
```

### 21.4 Credential Leak Databases

You need to know what's already out there from historical breaches. Credential leak monitoring tells you exactly how exposed an org is.

#### Legitimate Services

```bash
# Have I Been Pwned - Check domain-wide breach exposure
# Requires HIBP API key with domain search capability
curl -s "https://haveibeenpwned.com/api/v3/breacheddomain/example.com" \
  -H "hibp-api-key: ${HIBP_KEY}" | jq 'to_entries | length'

# Check specific email addresses
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/admin@example.com" \
  -H "hibp-api-key: ${HIBP_KEY}" \
  -H "user-agent: OSINT-Assessment" | jq '.[].Name'

# Intelligence X - Historical breach data search
curl -s "https://2.intelx.io/intelligent/search" \
  -H "x-key: ${INTELX_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"term": "example.com", "buckets": ["leaks", "darknet"], "maxresults": 100}'
```

#### Assessing Credential Exposure

When you find credential leaks, document these five things: which breach exposed them, when the breach happened (older breaches may have rotated passwords), whether creds are plaintext or hashed (and what hash -- MD5, SHA1, bcrypt), the reuse risk for corporate systems, and total volume of affected accounts.

```
CREDENTIAL EXPOSURE ASSESSMENT
================================
Domain: example.com
Date Assessed: 2026-02-19
Breaches Found: 7

| Breach Name       | Date     | Accounts | Data Types           |
|-------------------|----------|----------|----------------------|
| LinkedInScrape    | 2021-04  | 47       | Email, Name, Title   |
| Collection #1     | 2019-01  | 12       | Email, Password hash |
| AdobeBreach       | 2013-10  | 3        | Email, Password (enc)|
| DropboxBreach     | 2012-07  | 8        | Email, Password hash |

Risk Assessment:
- 12 accounts with password hashes may enable password spraying
- 47 LinkedIn scrape records provide current employee enumeration
- Recommend: Force password reset for all identified accounts
- Recommend: Enable MFA on all external-facing services
```

### 21.5 Ransomware Leak Site Monitoring

Ransomware groups publish stolen data when victims don't pay. Monitoring these leak sites gives you early warning of supply chain compromises -- and can surface data about your org even if you weren't directly targeted.

#### Known Ransomware Leak Site Categories

| Group Type | Intelligence Value | Monitoring Approach |
|---|---|---|
| Ransomware-as-a-Service (RaaS) operators | Victim lists, stolen data samples | Monitor known leak site URLs |
| Initial Access Brokers (IABs) | Network access listings that include your organization or suppliers | Dark web forum monitoring |
| Data brokers | Aggregated stolen data for sale | Marketplace monitoring |

#### Monitoring Tools and Services

```bash
# RansomWatch - Open-source ransomware leak site monitoring
# https://github.com/joshhighet/ransomwatch
# Tracks 100+ ransomware group leak sites

# RansomLook - Another open-source monitoring project
# Provides API access to monitored leak sites

# Commercial services:
# - Recorded Future - Comprehensive dark web monitoring
# - Flashpoint - Threat intelligence including dark web
# - DarkOwl - Dark web data indexing and monitoring
# - Kela - Cyber threat intelligence focused on dark web
```

> There's a dual purpose here. You're checking whether your own org has been compromised, but also assessing your supply chain. If a key vendor shows up on a leak site, their compromised data might include info about you.

### 21.6 Tools for Dark Web OSINT

#### OnionScan

OnionScan investigates dark web hidden services, analyzing `.onion` sites for misconfigs that could deanonymize the operators.

```bash
# Install OnionScan
go install github.com/s-rah/onionscan@latest

# Scan an onion address
onionscan --torProxyAddress=127.0.0.1:9050 exampleonion123.onion

# OnionScan checks for:
# - Apache mod_status exposure
# - Open directories
# - EXIF data in images
# - Server fingerprinting
# - SSH public keys
# - Related clearnet connections
# - PGP identity information
```

#### Tor-Based OSINT Workflow

```bash
# Start Tor as a SOCKS proxy
tor --SocksPort 9050 &

# Route curl through Tor
curl --socks5-hostname 127.0.0.1:9050 http://exampleonion123.onion/

# Route Python requests through Tor
python3 -c "
import requests
session = requests.Session()
session.proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}
# Verify Tor connectivity
response = session.get('https://check.torproject.org/api/ip')
print(response.json())
"

# Use torsocks for transparent Tor routing
torsocks wget http://exampleonion123.onion/page.html
torsocks nmap -sT -Pn -p 80,443 exampleonion123.onion
```

### 21.7 Operational Security for Dark Web Research

OPSEC isn't optional when you're doing dark web research. Follow these practices or you're putting yourself and your org at risk.

Use a dedicated research environment -- a VM with no connection to the corporate network, no personal accounts, nothing identifying. Stick with Tor Browser Bundle for web browsing; don't roll your own Tor setup, because the Browser Bundle includes anti-fingerprinting protections that you'd otherwise miss.

Never enable JavaScript on unknown sites. Tor Browser's "Safest" security level kills JavaScript entirely. Don't download files directly either -- if you absolutely must grab something, do it in a sandbox and analyze offline.

Don't create accounts. Period. Passive observation only. Creating accounts on criminal forums may constitute participation in criminal activity, and that's a line you don't want to cross. Screenshot everything immediately -- dark web content disappears without warning.

For sensitive research, force a new Tor circuit each session:

```bash
# Force a new Tor circuit
# Send NEWNYM signal to Tor control port
echo -e 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT' | nc 127.0.0.1 9051
```

---

## Chapter 22: Supply Chain Intelligence

### 22.1 The Supply Chain Attack Surface

Modern orgs sit on top of massive dependency trees -- third-party vendors, open-source libraries, cloud services, managed service providers. Every one of those dependencies is a potential way in. Supply chain intelligence means systematically mapping and assessing an org's external dependencies, and it's become a critical piece of thorough recon.

We've seen the impact firsthand. Compromising a single vendor can open the door to thousands of downstream targets. The recon phase of supply chain attacks involves finding those dependencies and sizing up their security posture.

> An org's security is only as strong as its weakest vendor. Comprehensive recon has to look beyond the target's own infrastructure to include their vendors, dependencies, and service providers.

### 22.2 Identifying Third-Party Vendors

#### Technology Stack Fingerprinting

```bash
# Identify third-party services loaded by the target website
# Analyze HTTP responses for third-party domains
curl -sL https://www.example.com | grep -oE 'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
  sort -u | grep -v "example.com"

# Check for third-party JavaScript includes
curl -sL https://www.example.com | grep -oE 'src="https?://[^"]+' | \
  grep -v "example.com"

# Wappalyzer CLI for technology detection
wappalyzer https://www.example.com --pretty

# BuiltWith for comprehensive technology profiling
# https://builtwith.com/example.com
```

#### DNS-Based Vendor Discovery

DNS records leak vendor relationships all over the place. SPF, MX, DMARC, NS, CNAME -- all of them can tell you who a target is using for what.

```bash
# SPF records reveal email infrastructure vendors
dig example.com TXT | grep "v=spf1"
# Example output: "v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all"
# This reveals: Google Workspace AND Microsoft 365 (possibly migration in progress)

# MX records reveal email providers
dig example.com MX
# Example output: 10 aspmx.l.google.com
# This reveals: Google Workspace for email

# DMARC records may reveal reporting vendors
dig _dmarc.example.com TXT
# Example output: "v=DMARC1; p=reject; rua=mailto:dmarc@vendor-analytics.example.org"

# NS records reveal DNS hosting
dig example.com NS
# Example output: ns1.cloudflare.com  (reveals Cloudflare for DNS)

# CNAME records reveal SaaS and CDN providers
dig www.example.com CNAME
dig status.example.com CNAME
dig docs.example.com CNAME
# Common CNAME targets:
# *.cloudfront.net     -> AWS CloudFront
# *.azurewebsites.net  -> Azure App Service
# *.herokuapp.com      -> Heroku
# *.zendesk.com        -> Zendesk
# *.statuspage.io      -> Statuspage (Atlassian)
```

#### Job Posting Analysis

Job postings are one of the richest supply chain intel sources you'll find. They hand you the tech stack, vendor relationships, and org priorities on a silver platter.

```
# Example job posting analysis:
#
# "Required Skills:
#   - Experience with Salesforce administration and Apex development
#   - Proficiency in Terraform and AWS CloudFormation
#   - Familiarity with Datadog monitoring and PagerDuty alerting
#   - Experience with Okta SSO integration
#   - Knowledge of Snowflake data warehouse"
#
# Intelligence extracted:
#   CRM: Salesforce
#   IaC: Terraform + CloudFormation (multi-tool, likely AWS primary)
#   Monitoring: Datadog
#   Incident Management: PagerDuty
#   Identity: Okta
#   Data Warehouse: Snowflake
```

### 22.3 Software Supply Chain Analysis

#### Open Source Dependency Mapping

```bash
# If target has public repositories, analyze dependencies
# JavaScript/Node.js projects
curl -s "https://raw.githubusercontent.com/example-corp/webapp/main/package.json" \
  | jq '.dependencies, .devDependencies'

# Python projects
curl -s "https://raw.githubusercontent.com/example-corp/webapp/main/requirements.txt"

# Ruby projects
curl -s "https://raw.githubusercontent.com/example-corp/webapp/main/Gemfile"

# Java/Maven projects
curl -s "https://raw.githubusercontent.com/example-corp/webapp/main/pom.xml"

# Go projects
curl -s "https://raw.githubusercontent.com/example-corp/webapp/main/go.mod"
```

#### Dependency Vulnerability Analysis

```bash
# Scan JavaScript dependencies for known vulnerabilities
npm audit --json < package.json

# Python dependency scanning with pip-audit
pip-audit -r requirements.txt --format=json

# Universal dependency scanning with Snyk
snyk test --all-projects --json

# SBOM generation with Syft
syft packages dir:/path/to/project -o spdx-json > sbom.json

# Vulnerability scanning of SBOM with Grype
grype sbom:sbom.json -o json > vulnerabilities.json
```

#### Typosquatting Detection

Adversaries spin up malicious packages with names that look like legitimate dependencies -- off by a character or two. Worth checking.

```python
#!/usr/bin/env python3
"""
typosquat_check.py - Check for potential typosquatting packages
targeting an organization's dependencies.
"""

import itertools
import requests
import json

def generate_typosquats(package_name):
    """Generate common typosquat variations of a package name."""
    variants = set()

    # Character substitution
    substitutions = {'a': ['@', '4'], 'e': ['3'], 'i': ['1', 'l'], 'o': ['0'],
                     's': ['5', 'z'], 'l': ['1', 'i'], '-': ['_', ''], '_': ['-', '']}
    for i, char in enumerate(package_name):
        for sub in substitutions.get(char, []):
            variants.add(package_name[:i] + sub + package_name[i+1:])

    # Character omission
    for i in range(len(package_name)):
        variants.add(package_name[:i] + package_name[i+1:])

    # Character duplication
    for i in range(len(package_name)):
        variants.add(package_name[:i] + package_name[i] + package_name[i:])

    # Adjacent character swap
    for i in range(len(package_name) - 1):
        swapped = list(package_name)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        variants.add(''.join(swapped))

    # Common prefixes/suffixes
    for affix in ['py', 'python', 'lib', 'pkg', 'core', 'utils']:
        variants.add(f"{package_name}-{affix}")
        variants.add(f"{affix}-{package_name}")

    variants.discard(package_name)
    return variants

def check_pypi(package_name):
    """Check if a package exists on PyPI."""
    response = requests.get(f"https://pypi.org/pypi/{package_name}/json")
    if response.status_code == 200:
        data = response.json()
        return {
            "exists": True,
            "name": data["info"]["name"],
            "version": data["info"]["version"],
            "author": data["info"]["author"],
            "summary": data["info"]["summary"],
        }
    return {"exists": False}

def check_npm(package_name):
    """Check if a package exists on npm."""
    response = requests.get(f"https://registry.npmjs.org/{package_name}")
    if response.status_code == 200:
        data = response.json()
        return {
            "exists": True,
            "name": data.get("name"),
            "description": data.get("description", ""),
            "maintainers": [m["name"] for m in data.get("maintainers", [])],
        }
    return {"exists": False}

if __name__ == "__main__":
    target_packages = ["requests", "flask", "django"]  # Example packages

    for pkg in target_packages:
        print(f"\n[*] Checking typosquats for: {pkg}")
        variants = generate_typosquats(pkg)
        for variant in sorted(variants):
            result = check_pypi(variant)
            if result["exists"]:
                print(f"    [!] FOUND on PyPI: {variant} (v{result['version']}) by {result['author']}")
                print(f"        Summary: {result['summary']}")
```

### 22.4 Vendor Security Posture Assessment

You can assess a vendor's security posture using the same OSINT techniques from earlier chapters -- just pointed at vendor infrastructure instead.

```
VENDOR SECURITY POSTURE ASSESSMENT TEMPLATE
=============================================

Vendor: [Vendor Name]
Assessment Date: YYYY-MM-DD
Relationship: [SaaS provider / MSP / Hosting / Software vendor]

1. External Infrastructure Assessment
   [ ] DNS configuration (SPF, DKIM, DMARC, DNSSEC)
   [ ] SSL/TLS certificate management (expiry, CA, key strength)
   [ ] Open port exposure (Shodan/Censys)
   [ ] Web server header exposure

2. Public Data Exposure
   [ ] Credential breaches involving vendor domain
   [ ] Exposed code repositories (GitHub/GitLab)
   [ ] Leaked internal documents
   [ ] Job postings revealing security maturity

3. Security Program Indicators
   [ ] Published security policy (security.txt)
   [ ] Vulnerability disclosure program / bug bounty
   [ ] SOC 2 / ISO 27001 certifications
   [ ] Security-focused job postings (indicates investment)

4. Supply Chain Risk Indicators
   [ ] Vendor's own dependencies and sub-processors
   [ ] Past security incidents (news search, breach databases)
   [ ] Geographic and jurisdictional risks
   [ ] Single points of failure in service delivery
```

### 22.5 Shared Hosting and Infrastructure Risks

When a target runs on shared infrastructure, the other tenants become relevant. Who else is on that box?

```bash
# Reverse IP lookup - find other domains on the same server
curl -s "https://api.hackertarget.com/reverseiplookup/?q=192.0.2.10"

# Check if the target uses shared hosting
dig www.example.com A
# Then perform reverse IP on the resolved address

# Identify shared SSL certificates (SAN entries)
echo | openssl s_client -connect www.example.com:443 2>/dev/null \
  | openssl x509 -noout -text | grep "DNS:"

# Shodan: find all services on the same IP
shodan host 192.0.2.10
```

Shared infrastructure risks are real. Cross-tenant attacks mean a vuln in the hosting platform hits everyone. If another tenant on the same IP gets compromised, the shared IP can end up blacklisted (reputation contamination). DoS attacks against co-tenants can take your target down too. And sensitive data might be sitting on the same physical hardware as some poorly secured tenant next door.

### 22.6 Case Studies in Supply Chain Attacks

#### SolarWinds (2020)

**Recon phase**: APT29 (Cozy Bear) zeroed in on SolarWinds because Orion was deployed across thousands of enterprise and government networks. Their recon likely included pulling customer lists from SolarWinds' own marketing materials and SEC filings, digging into the build and deployment pipeline, and mapping out the Orion update mechanism and code signing process.

**Lesson**: Don't just assess your direct vendors -- assess the software supply chain of your most privileged tools. Monitoring platforms, security tools, management consoles. Those are the crown jewels.

#### Kaseya VSA (2021)

**Recon phase**: REvil went after Kaseya's VSA tool knowing that MSPs use it to manage hundreds of client environments. They found Kaseya VSA instances exposed to the internet (Shodan/Censys), mapped out the MSP-to-client trust model, and identified a zero-day in VSA's auth mechanism.

**Lesson**: Cascading trust relationships -- vendor to MSP to end customer -- create exponential blast radius from a single compromise.

#### 3CX (2023)

**Recon phase**: The 3CX desktop app attack was itself the result of a prior supply chain compromise (a trojanized trading application). This cascading attack shows that adversaries conduct multi-stage supply chain recon, that the "supply chain of the supply chain" is a real attack path, and that build infrastructure and developer workstations are high-value targets.

---

## Chapter 23: AI-Assisted Reconnaissance

### 23.1 The Role of AI in Modern Reconnaissance

AI -- particularly LLMs and ML systems -- is changing how recon gets done. It can speed up analysis, spot patterns in huge datasets, generate search queries you wouldn't have thought of, and pull together intel from totally different sources into something coherent. But it also comes with real limitations and risks that you need to understand before you lean on it.

This chapter is about practical applications. AI isn't replacing established techniques -- it's a force multiplier that makes human analysis faster and broader.

> AI is a tool, not an oracle. Every AI-generated finding must be verified independently. LLMs produce plausible but sometimes completely wrong information (hallucinations), and basing security assessment conclusions on unverified AI output creates risk for everyone involved.

### 23.2 Using LLMs for Query Refinement

One of the quickest wins with LLMs in recon is generating and refining search queries. Give it a target description and it can crank out diverse queries that you might not have considered.

#### Search Query Generation

```
# Example prompt for generating reconnaissance search queries:

"I am conducting an authorized security assessment of Example Corporation
(example.com). They are a mid-size financial services company based in
the United States. Generate 20 diverse Google dork queries that could
reveal:
1. Exposed internal documents
2. Employee information
3. Infrastructure details
4. Third-party service integrations
5. Potential security misconfigurations

Use proper Google dork syntax. Include site:, filetype:, intitle:,
inurl:, and intext: operators."
```

#### Analyzing Large DNS Datasets

```python
#!/usr/bin/env python3
"""
ai_dns_analyzer.py - Use an LLM to analyze DNS enumeration results
and identify patterns that warrant further investigation.
"""

import json

def prepare_dns_analysis_prompt(dns_records):
    """
    Prepare a prompt for LLM analysis of DNS records.
    The DNS records should be pre-collected using traditional tools.
    """
    prompt = f"""Analyze the following DNS records for example.com and identify:
1. Infrastructure patterns (cloud providers, CDNs, hosting)
2. Internal naming conventions that reveal organizational structure
3. Potentially sensitive services (VPN, mail, admin panels, dev/staging)
4. Anomalies or misconfigurations
5. Subdomains that warrant further investigation

DNS Records:
{json.dumps(dns_records, indent=2)}

Provide a structured analysis with findings ranked by reconnaissance value."""

    return prompt

# Example usage with collected DNS data
sample_records = {
    "A_records": [
        {"name": "www.example.com", "value": "192.0.2.10"},
        {"name": "mail.example.com", "value": "192.0.2.20"},
        {"name": "vpn.example.com", "value": "198.51.100.5"},
        {"name": "dev-api.example.com", "value": "203.0.113.50"},
        {"name": "staging.example.com", "value": "203.0.113.51"},
        {"name": "jenkins.example.com", "value": "203.0.113.52"},
        {"name": "grafana.example.com", "value": "203.0.113.53"},
        {"name": "k8s-master.example.com", "value": "198.51.100.100"},
    ],
    "CNAME_records": [
        {"name": "docs.example.com", "value": "example-corp.gitbook.io"},
        {"name": "status.example.com", "value": "example-corp.statuspage.io"},
        {"name": "support.example.com", "value": "example-corp.zendesk.com"},
    ],
    "MX_records": [
        {"name": "example.com", "priority": 1, "value": "aspmx.l.google.com"},
        {"name": "example.com", "priority": 5, "value": "alt1.aspmx.l.google.com"},
    ],
    "TXT_records": [
        {"name": "example.com", "value": "v=spf1 include:_spf.google.com ~all"},
        {"name": "_dmarc.example.com", "value": "v=DMARC1; p=none; rua=mailto:dmarc@example.com"},
    ]
}

prompt = prepare_dns_analysis_prompt(sample_records)
print(prompt)
# Feed this prompt to your preferred LLM API for analysis
```

### 23.3 AI-Powered OSINT Tools

A few tools are starting to bake AI into OSINT workflows. Here's what that looks like in practice.

#### Automated Report Generation

```python
#!/usr/bin/env python3
"""
ai_report_synthesizer.py - Synthesize reconnaissance findings into
a structured intelligence report using an LLM.
"""

import json

def generate_report_prompt(findings):
    """
    Generate a prompt that synthesizes multiple reconnaissance
    findings into a coherent intelligence report.
    """
    prompt = f"""You are a senior security analyst. Based on the following
reconnaissance findings from an authorized security assessment of
Example Corporation (example.com), produce a structured intelligence
report that includes:

1. EXECUTIVE SUMMARY (3-5 sentences)
2. ATTACK SURFACE OVERVIEW
   - External-facing services
   - Cloud infrastructure
   - Third-party dependencies
3. KEY FINDINGS (ranked by risk)
   - Finding description
   - Evidence
   - Potential impact
   - Recommended remediation
4. RECOMMENDED NEXT STEPS for active testing phase

Findings data:
{json.dumps(findings, indent=2)}

Write in a professional, technical tone suitable for a security
assessment deliverable. Do not speculate beyond what the evidence supports."""

    return prompt

# Example findings to synthesize
findings = {
    "dns_enumeration": {
        "total_subdomains": 47,
        "notable": ["jenkins.example.com", "grafana.example.com", "dev-api.example.com"],
        "cloud_infrastructure": "AWS (primary), some Azure services"
    },
    "port_scanning": {
        "hosts_scanned": 12,
        "open_ports": {
            "192.0.2.10": [80, 443, 8080],
            "203.0.113.52": [8080, 50000],  # Jenkins
            "203.0.113.53": [3000],          # Grafana
        }
    },
    "credential_leaks": {
        "breaches_found": 3,
        "total_accounts": 23,
        "with_passwords": 8
    },
    "github_exposure": {
        "public_repos": 15,
        "secrets_found": 4,
        "types": ["AWS key", "Slack webhook", "JWT secret", "DB password"]
    }
}
```

### 23.4 Automating Intelligence Synthesis

Where AI really shines is pulling together information from multiple sources into coherent intelligence products. Here's a workflow that combines automated collection with AI-assisted analysis:

```
RECONNAISSANCE PIPELINE WITH AI INTEGRATION
=============================================

Phase 1: Automated Collection (Traditional Tools)
  |
  ├── DNS enumeration (dns_deep_dive.py)
  ├── Port scanning (nmap, masscan)
  ├── WHOIS analysis
  ├── Certificate transparency
  ├── Shodan/Censys queries
  ├── GitHub secret scanning
  ├── Credential breach checking
  └── Web technology fingerprinting
  |
  v
Phase 2: Data Normalization
  |
  ├── Convert all outputs to structured JSON
  ├── Deduplicate findings
  ├── Enrich with cross-references
  └── Tag findings by ATT&CK technique
  |
  v
Phase 3: AI-Assisted Analysis
  |
  ├── Pattern identification across data sources
  ├── Anomaly detection in DNS/network data
  ├── Natural language summarization of findings
  ├── Attack path hypothesis generation
  └── Priority ranking of findings
  |
  v
Phase 4: Human Review and Validation
  |
  ├── Verify all AI-generated conclusions
  ├── Remove hallucinated or incorrect findings
  ├── Add contextual knowledge AI may lack
  ├── Make risk assessments based on experience
  └── Produce final deliverable
```

### 23.5 Limitations and Risks of AI in OSINT

#### Hallucination Risk

LLMs generate text that's statistically likely -- not factually verified. In a recon context, that means AI might "discover" vulnerabilities that don't exist, attribute infrastructure to the wrong org, invent plausible-sounding IP addresses or domain names, or confuse similarly named companies.

**Mitigation**: Verify everything independently. Use AI for generating hypotheses and assisting analysis. Never treat it as a primary source of facts.

#### Data Leakage Risk

Sending recon data to cloud-hosted AI services introduces real problems. The target org's information might get logged by the AI provider, recon data could end up in model training, and sensitive findings like credentials or internal IPs should never touch third-party AI services.

**Mitigation**: Run locally hosted models for sensitive analysis. If you're using cloud APIs, redact sensitive details before submission and make sure your API agreement prohibits data retention.

#### Adversarial Use of AI

The other side uses AI too. Automated spearphishing content generation (T1598), deepfake audio and video for vishing, automated OSINT synthesis for target profiling, AI-assisted code analysis for finding vulns. Understanding how adversaries leverage AI is essential if you're building detection capabilities on the blue team side.

### 23.6 Prompt Engineering for Intelligence Gathering

Good LLM output starts with well-structured prompts. Here are the patterns that work best for OSINT:

#### The Analyst Persona Pattern

```
"You are a senior threat intelligence analyst with 15 years of experience
in OSINT collection and analysis. You are conducting an authorized
security assessment. Based on the following [data type], provide your
professional analysis of [specific question]."
```

#### The Structured Output Pattern

```
"Analyze the following data and provide output in this exact format:

FINDING: [One-sentence description]
EVIDENCE: [Specific data points supporting the finding]
CONFIDENCE: [HIGH/MEDIUM/LOW]
ATT&CK MAPPING: [Relevant technique ID]
NEXT STEPS: [Recommended follow-up actions]

Data to analyze:
[paste data]"
```

#### The Adversary Emulation Pattern

```
"From the perspective of a threat actor conducting reconnaissance
against Example Corporation, what are the three most valuable pieces
of information in the following dataset, and how would each be used
to advance an attack?

[paste reconnaissance data]

Note: This is for an authorized red team exercise. Focus on realistic
adversary decision-making."
```

---

## Chapter 24: Cloud-Native Enumeration

### 24.1 Cloud Reconnaissance Landscape

Cloud infrastructure has changed the recon game entirely. The old perimeter-based thinking doesn't cut it when an org's assets are spread across multiple cloud providers, regions, and service types. Cloud-native enumeration means understanding provider-specific services, APIs, metadata endpoints, and the misconfigurations people keep making.

This chapter digs deep into recon techniques for the big three: AWS, Azure, and GCP.

> Cloud enumeration carries the same legal and ethical constraints as every other recon technique. Cloud provider ToS may add more restrictions on top of that. Make sure your authorization explicitly covers cloud infrastructure testing, and know that some enumeration techniques will trip alerts in the target's cloud security monitoring.

### 24.2 AWS-Specific Enumeration

#### S3 Bucket Discovery

S3 buckets are probably the single most commonly misconfigured cloud resource. Bucket names are globally unique, which makes them discoverable through pattern-based guessing.

```bash
# Common bucket naming patterns to test
# {company}-{env}: example-corp-prod, example-corp-dev, example-corp-staging
# {company}-{service}: example-corp-logs, example-corp-backup, example-corp-assets
# {company}-{region}: example-corp-us-east-1, example-corp-eu-west-1

# Check if a bucket exists and is publicly accessible
aws s3 ls s3://example-corp-public --no-sign-request 2>&1
# "An error occurred (NoSuchBucket)" = does not exist
# "An error occurred (AccessDenied)" = exists but not public
# Listed files = exists AND publicly readable

# Check bucket ACL
aws s3api get-bucket-acl --bucket example-corp-public --no-sign-request 2>&1

# Check bucket policy
aws s3api get-bucket-policy --bucket example-corp-public --no-sign-request 2>&1

# Enumerate bucket contents if readable
aws s3 ls s3://example-corp-public --no-sign-request --recursive \
  | head -100

# Check for specific sensitive files
aws s3 cp s3://example-corp-public/.env - --no-sign-request 2>&1
aws s3 cp s3://example-corp-public/backup.sql.gz - --no-sign-request 2>&1
```

#### S3 Bucket Enumeration Script

```bash
#!/bin/bash
# s3_enum.sh - Enumerate S3 buckets based on organization name patterns
# For authorized security assessments only

ORG_NAME="example-corp"
ENVIRONMENTS=("prod" "production" "dev" "development" "staging" "stage" "test" "uat" "qa")
SERVICES=("backup" "backups" "logs" "assets" "static" "media" "uploads" "data" "config" "db" "database")
REGIONS=("us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1")

check_bucket() {
    local bucket=$1
    result=$(aws s3 ls "s3://${bucket}" --no-sign-request 2>&1)

    if echo "$result" | grep -q "NoSuchBucket"; then
        return
    elif echo "$result" | grep -q "AccessDenied"; then
        echo "[EXISTS-PRIVATE] s3://${bucket}"
    elif echo "$result" | grep -q "AllAccessDisabled"; then
        echo "[EXISTS-DISABLED] s3://${bucket}"
    else
        echo "[EXISTS-PUBLIC] s3://${bucket}"
        echo "$result" | head -5
    fi
}

echo "[*] Enumerating S3 buckets for: ${ORG_NAME}"

# Base name
check_bucket "${ORG_NAME}"

# Environment patterns
for env in "${ENVIRONMENTS[@]}"; do
    check_bucket "${ORG_NAME}-${env}"
    check_bucket "${ORG_NAME}.${env}"
    check_bucket "${env}-${ORG_NAME}"
    check_bucket "${env}.${ORG_NAME}"
done

# Service patterns
for svc in "${SERVICES[@]}"; do
    check_bucket "${ORG_NAME}-${svc}"
    check_bucket "${ORG_NAME}.${svc}"
done

# Region patterns
for region in "${REGIONS[@]}"; do
    check_bucket "${ORG_NAME}-${region}"
done

# Combined patterns
for env in "${ENVIRONMENTS[@]}"; do
    for svc in "${SERVICES[@]}"; do
        check_bucket "${ORG_NAME}-${env}-${svc}"
    done
done
```

#### AWS Account ID Enumeration

An AWS account ID is a 12-digit number. Once you have it, you can start enumerating resources within the account.

```bash
# Enumerate AWS account ID from a public S3 bucket
# Using s3:GetBucketAcl
aws s3api get-bucket-acl --bucket example-corp-public --no-sign-request 2>&1 \
  | grep -oP '"ID":\s*"\K[a-f0-9]{64}'

# Enumerate account ID from error messages
# Some AWS services leak the account ID in error responses

# Using IAM role enumeration (if you have any valid AWS credentials)
# This technique queries whether an IAM role exists in the target account
aws sts get-caller-identity  # Verify your own identity first

# Pacu - AWS exploitation framework for authorized testing
# https://github.com/RhinoSecurityLabs/pacu
# pacu > run iam__enum_roles --account-id 123456789012 --word-list roles.txt
```

#### EC2 Metadata Service Enumeration

The EC2 Instance Metadata Service (IMDS) is accessible from inside EC2 instances. Got an SSRF vuln? You can reach the metadata endpoint and pull back credentials and config. This is where it gets interesting.

```bash
# IMDSv1 endpoint (no authentication required)
# These commands would be executed via an SSRF vulnerability
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
curl -s http://169.254.169.254/latest/user-data/

# IMDSv2 requires a token (PUT request first)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Key metadata endpoints for reconnaissance:
# /latest/meta-data/hostname          - Internal hostname
# /latest/meta-data/local-ipv4        - Internal IP address
# /latest/meta-data/public-ipv4       - Public IP address
# /latest/meta-data/security-groups   - Security group names
# /latest/meta-data/iam/              - IAM role credentials
# /latest/user-data/                  - Instance bootstrap scripts (often contain secrets)
# /latest/dynamic/instance-identity/document - Region, account ID, instance type
```

#### Lambda Function Enumeration

```bash
# If AWS credentials are obtained (e.g., from leaked keys or IMDS):
aws lambda list-functions --region us-east-1 --output json \
  | jq '.Functions[] | {FunctionName, Runtime, Handler, Description}'

# Check function environment variables (often contain secrets)
aws lambda get-function-configuration --function-name example-function --region us-east-1 \
  | jq '.Environment.Variables'

# List Lambda layers (shared code/dependencies)
aws lambda list-layers --region us-east-1 \
  | jq '.Layers[] | {LayerName, LatestMatchingVersion}'
```

### 24.3 Azure Enumeration

#### Azure Blob Storage Discovery

Azure Blob Storage containers follow a predictable URL pattern: `https://<storage-account>.blob.core.windows.net/<container>`.

```bash
# Check if a storage account exists
curl -s -o /dev/null -w "%{http_code}" \
  "https://examplecorpstorage.blob.core.windows.net/?comp=list"
# 200 = exists and publicly listable
# 403 = exists but not public
# 404 = does not exist

# Enumerate public blob containers
curl -s "https://examplecorpstorage.blob.core.windows.net/?comp=list&include=metadata" \
  | xmllint --format -

# List blobs in a public container
curl -s "https://examplecorpstorage.blob.core.windows.net/public?restype=container&comp=list" \
  | xmllint --format -

# Download a specific blob
curl -s "https://examplecorpstorage.blob.core.windows.net/public/config.json" -o config.json
```

#### Azure AD Enumeration

Azure AD (now Entra ID) enumeration reveals org structure and user accounts. Surprisingly chatty.

```bash
# Check if a tenant exists for a domain
curl -s "https://login.microsoftonline.com/example.com/.well-known/openid-configuration" \
  | jq '.token_endpoint'
# If this returns a valid response, the organization uses Azure AD

# Extract tenant ID from OpenID configuration
curl -s "https://login.microsoftonline.com/example.com/.well-known/openid-configuration" \
  | jq -r '.token_endpoint' | grep -oP '[a-f0-9-]{36}'

# Check user existence via Azure AD (GetCredentialType endpoint)
# This endpoint reveals whether a user exists without authentication
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"Username": "admin@example.com"}' \
  | jq '.IfExistsResult'
# 0 = user exists
# 1 = user does not exist
# 5 = user exists but in different tenant
# 6 = user exists on different identity provider

# Enumerate Azure AD apps and service principals
# Using Microsoft Graph API (requires authentication)
# az ad app list --query "[].{name:displayName, appId:appId}" --output table
```

#### Azure Subdomain Enumeration

Azure services use predictable subdomain patterns. You can just iterate through them:

```bash
# Azure service subdomain patterns to enumerate
PATTERNS=(
    "examplecorp.blob.core.windows.net"       # Blob Storage
    "examplecorp.file.core.windows.net"       # File Storage
    "examplecorp.queue.core.windows.net"      # Queue Storage
    "examplecorp.table.core.windows.net"      # Table Storage
    "examplecorp.azurewebsites.net"           # App Service
    "examplecorp.scm.azurewebsites.net"       # App Service SCM (Kudu)
    "examplecorp.azurefd.net"                 # Azure Front Door
    "examplecorp.database.windows.net"        # Azure SQL
    "examplecorp.vault.azure.net"             # Key Vault
    "examplecorp.redis.cache.windows.net"     # Redis Cache
    "examplecorp.servicebus.windows.net"      # Service Bus
    "examplecorp.azurecr.io"                  # Container Registry
    "examplecorp.search.windows.net"          # Azure Search
    "examplecorp.cognitiveservices.azure.com" # Cognitive Services
)

for subdomain in "${PATTERNS[@]}"; do
    result=$(dig +short "$subdomain" 2>/dev/null)
    if [ -n "$result" ]; then
        echo "[+] FOUND: $subdomain -> $result"
    fi
done
```

### 24.4 GCP Enumeration

#### Google Cloud Storage Discovery

```bash
# Check if a GCS bucket exists
curl -s -o /dev/null -w "%{http_code}" \
  "https://storage.googleapis.com/example-corp-public"
# 200 = public and listable
# 403 = exists but not public
# 404 = does not exist

# List public bucket contents
curl -s "https://storage.googleapis.com/storage/v1/b/example-corp-public/o" \
  | jq '.items[] | {name, size, contentType, updated}'

# Alternative: gsutil (GCP CLI)
gsutil ls gs://example-corp-public/
gsutil ls -la gs://example-corp-public/
```

#### Firebase Enumeration

Firebase databases are a common source of data exposure. The default config may allow unauthenticated reads -- and people leave it that way more often than you'd think.

```bash
# Check for exposed Firebase Realtime Database
curl -s "https://example-corp-app.firebaseio.com/.json"
# If this returns data, the database is publicly readable

# Check Firebase rules
curl -s "https://example-corp-app.firebaseio.com/.settings/rules.json"

# Common Firebase database URL patterns:
# https://{project-id}.firebaseio.com/.json
# https://{project-id}-default-rtdb.firebaseio.com/.json

# Enumerate Firebase project configuration from web apps
# Firebase config is often embedded in JavaScript:
curl -s "https://www.example.com" | grep -oE 'firebase[A-Za-z]*\.googleapis\.com'
curl -s "https://www.example.com" | grep -oE '"apiKey"\s*:\s*"[^"]*"'
curl -s "https://www.example.com" | grep -oE '"projectId"\s*:\s*"[^"]*"'
```

#### GCP Compute Metadata

```bash
# GCP metadata endpoint (via SSRF)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/"

# Service account token
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Project metadata (may contain startup scripts with secrets)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/"

# Instance metadata
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/hostname"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"

# Kubernetes-specific metadata (GKE)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env"
```

### 24.5 Multi-Cloud Reconnaissance Strategy

Most big orgs run on multiple cloud providers. A systematic approach ensures you don't miss anything.

```
MULTI-CLOUD ENUMERATION CHECKLIST
===================================

1. Identify Cloud Providers in Use
   [ ] DNS CNAME analysis (*.amazonaws.com, *.azure.*, *.googleapis.com)
   [ ] HTTP header analysis (X-Amz-*, X-Ms-*, X-Cloud-Trace-Context)
   [ ] SSL certificate analysis (issued to cloud provider domains)
   [ ] IP range correlation (AWS, Azure, GCP publish their IP ranges)
   [ ] SPF record analysis (include:amazonses.com, etc.)
   [ ] Job posting analysis (cloud-specific skill requirements)

2. AWS Enumeration
   [ ] S3 bucket discovery (pattern-based)
   [ ] CloudFront distribution identification
   [ ] API Gateway endpoints
   [ ] EC2 instances via Shodan/Censys
   [ ] Elastic Beanstalk environments
   [ ] RDS/ElastiCache instances
   [ ] SNS/SQS exposure

3. Azure Enumeration
   [ ] Blob storage discovery
   [ ] Azure AD tenant verification
   [ ] App Service instances
   [ ] Azure SQL endpoints
   [ ] Key Vault endpoints
   [ ] Azure DevOps projects (if public)

4. GCP Enumeration
   [ ] Cloud Storage bucket discovery
   [ ] Firebase database exposure
   [ ] App Engine instances
   [ ] Cloud Functions endpoints
   [ ] BigQuery dataset exposure
   [ ] GKE cluster endpoints
```

### 24.6 Cloud Misconfigurations as Attack Vectors

Here's a rundown of the most common cloud misconfigs you'll encounter during recon:

| Misconfiguration | Cloud Provider | Discovery Method | Risk |
|---|---|---|---|
| Public S3 bucket | AWS | Pattern-based enumeration | Data exposure, data modification |
| Public blob container | Azure | DNS + HTTP probing | Data exposure |
| Public GCS bucket | GCP | DNS + HTTP probing | Data exposure |
| IMDSv1 enabled | AWS | SSRF exploitation | Credential theft |
| Publicly exposed RDS | AWS | Shodan/Censys scan | Database access |
| Public Firebase database | GCP | URL pattern probing | Full database read/write |
| Azure AD user enumeration | Azure | GetCredentialType API | Account identification for spraying |
| Exposed Kubernetes dashboard | All | Port scanning (443, 6443, 8443) | Cluster compromise |
| Public EBS/disk snapshots | AWS/Azure/GCP | API enumeration | Data exposure |
| Overly permissive IAM roles | All | Requires authenticated access | Privilege escalation |
| Exposed cloud metadata | All | SSRF + metadata endpoint | Credential theft |
| Public container registries | All | DNS + API probing | Image analysis, secret extraction |

#### Comprehensive Cloud Enumeration Tool

```bash
# CloudEnum - Multi-cloud enumeration tool
# https://github.com/initstring/cloud_enum
cloud_enum -k "example-corp" -k "examplecorp" -k "example" \
  --disable-gcp --disable-azure  # Focus on AWS only
# OR enumerate all providers:
cloud_enum -k "example-corp" -k "examplecorp" -l cloud_enum_results.txt

# ScoutSuite - Multi-cloud security auditing (requires credentials)
# https://github.com/nccgroup/ScoutSuite
scout suite aws --profile target-account
scout suite azure --cli
scout suite gcp --project-id example-project

# Prowler - AWS security assessment
# https://github.com/prowler-cloud/prowler
prowler aws --profile target-account -M json-ocsf -o prowler_results/
```

---

## Chapter 25: Real-World APT Case Studies

### 25.1 Why Study APT Reconnaissance

APT groups are the top of the food chain. Studying how they approach recon -- patient, disciplined, well-resourced -- teaches you what sophisticated pre-attack work actually looks like. These case studies come from publicly available threat intel reports and serve as both offensive methodology reference and defensive detection guidance.

Each one follows this structure:

1. **Threat Actor Profile**: Attribution, motivation, known capabilities
2. **Reconnaissance Methodology**: How they collected intel before striking
3. **Techniques Mapped to ATT&CK**: Specific recon techniques used
4. **Detection Opportunities**: Where defenders could've caught them
5. **Lessons Learned**: Key takeaways for offense and defense

### 25.2 APT29 (Cozy Bear) -- SolarWinds Supply Chain Attack

#### Threat Actor Profile

- **Attribution**: Russian Foreign Intelligence Service (SVR)
- **Also known as**: Cozy Bear, The Dukes, Nobelium, Midnight Blizzard
- **Motivation**: Intelligence collection, primarily targeting government, think tanks, and technology sectors
- **Active since**: At least 2008

#### Reconnaissance Methodology

The SolarWinds campaign (discovered December 2020) was one of the most sophisticated supply chain attacks ever documented. The recon phase likely spanned months to years -- multiple parallel collection efforts running simultaneously.

**Phase 1 -- Target Selection and Supply Chain Mapping**

APT29 picked SolarWinds Orion because of where it sat in the ecosystem. SolarWinds publicly listed their government and Fortune 500 customers on their website and in SEC filings -- that gave APT29 a comprehensive downstream target list from a single compromise point. Orion is a network management platform that needs privileged access to the networks it monitors by design, so compromising it meant monitoring-level access to victim infrastructure. And the attackers had to understand SolarWinds' build and distribution process to inject SUNBURST in a way that would survive the build and get digitally signed.

**Phase 2 -- Pre-Compromise OSINT**

```
ATT&CK Techniques Used:
- T1591.002 (Business Relationships) - Mapping SolarWinds customer base
- T1592.002 (Software) - Understanding Orion product architecture
- T1593.002 (Search Engines) - Researching SolarWinds infrastructure
- T1593.003 (Code Repositories) - Analyzing any public SolarWinds code
- T1594 (Search Victim-Owned Websites) - SolarWinds customer references
```

**Phase 3 -- Post-Compromise Victim Selection**

After the trojanized Orion update was in the wild, APT29 showed extraordinary discipline. They sat quietly on compromised networks for up to two weeks before taking any action. Out of roughly 18,000 organizations that installed the compromised update, they cherry-picked about 100 for second-stage payloads. They even used the victim's own network management data (collected by Orion) to map internal infrastructure. Brutal efficiency.

#### Detection Opportunities

| Phase | Detection Method | Challenge |
|---|---|---|
| Supply chain targeting | Monitor for unusual interest in your vendor ecosystem | Low signal-to-noise ratio |
| Build pipeline compromise | Code signing verification, build reproducibility | Requires mature DevSecOps |
| Trojanized update deployment | Behavioral analysis of network management software | Trusted software exception |
| Post-compromise recon | Network traffic analysis, anomalous DNS queries | Blended with legitimate Orion traffic |

#### Lessons Learned

Supply chain trust is transitive. SolarWinds' customers trusted Orion implicitly, and that trust got weaponized. You have to assess the security posture of your most privileged software vendors.

Patience defines sophistication. APT29's recon took months, not hours. Detection systems tuned for rapid scanning will miss slow, deliberate reconnaissance.

Public product documentation helps the adversary. Orion's architecture docs gave APT29 a roadmap for exploitation.

### 25.3 APT28 (Fancy Bear) -- Election Infrastructure Reconnaissance

#### Threat Actor Profile

- **Attribution**: Russian Main Intelligence Directorate (GRU), specifically Unit 26165
- **Also known as**: Fancy Bear, Sofacy, Strontium, Forest Blizzard
- **Motivation**: Intelligence collection and influence operations, targeting government, military, and political organizations
- **Active since**: At least 2004

#### Reconnaissance Methodology

APT28's targeting of election infrastructure (2016-2020) shows how a nation-state does systematic recon against a distributed, loosely defended target set.

**Phase 1 -- Target Identification**

US election infrastructure is decentralized across thousands of state and local jurisdictions. APT28's challenge was identifying and prioritizing targets across this sprawl.

```
Intelligence Collection Methods:
- Public records of election technology vendors and their customers
- State and county government websites listing IT contacts and infrastructure
- FEC filings and procurement records revealing technology purchases
- Election technology vendor websites (customer lists, case studies)
- Professional networking sites for election administrators
```

**Phase 2 -- Infrastructure Reconnaissance**

```
ATT&CK Techniques Used:
- T1595.001 (Scanning IP Blocks) - Scanning state/county government IP ranges
- T1595.002 (Vulnerability Scanning) - Probing voter registration systems
- T1589.002 (Email Addresses) - Harvesting election official email addresses
- T1590.002 (DNS) - Enumerating election-related subdomains
- T1596.005 (Scan Databases) - Querying Shodan for election infrastructure
- T1598.003 (Spearphishing Link) - Phishing election officials for credentials
```

**Phase 3 -- Targeted Phishing Campaign**

The recon directly fed their spearphishing:

```
Reconnaissance-Informed Phishing Workflow:
1. OSINT collection identified election officials by name and role (T1589.003)
2. Email address patterns determined from public records (T1589.002)
3. Technology stack identified from job postings and vendor websites (T1592.002)
4. Phishing lures crafted to match targets' professional context (T1598)
   - Fake election vendor security alerts
   - Spoofed password reset requests for known systems
   - Election-themed document lures
```

#### Detection Opportunities

```
DETECTION OPPORTUNITIES FOR ELECTION INFRASTRUCTURE:
=====================================================

1. Network-Level Detection
   - Monitor for scanning activity against voter registration portals
   - Alert on repeated failed authentication attempts from unusual sources
   - Track DNS query patterns for election subdomains

2. Email-Level Detection
   - Implement DMARC enforcement to detect spoofed election vendor emails
   - Monitor for phishing attempts targeting election officials
   - Track email header anomalies in messages claiming to be from vendors

3. OSINT-Level Detection
   - Monitor public exposure of election infrastructure details
   - Audit job postings for inadvertent technology stack disclosure
   - Track social media presence of election officials
```

#### Lessons Learned

Distributed targets need distributed defense. APT28 could go after the weakest link among thousands of jurisdictions. Defense has to be equally broad.

Public records are intelligence gold. Government procurement records, meeting minutes, org charts -- all of it gave APT28 detailed targeting info.

Phishing for information comes before phishing for access. The initial recon made their phishing lures way more convincing.

### 25.4 Lazarus Group -- Financial Sector Targeting

#### Threat Actor Profile

- **Attribution**: North Korea's Reconnaissance General Bureau (RGB)
- **Also known as**: Hidden Cobra, ZINC, Diamond Sleet, Labyrinth Chollima
- **Motivation**: Financial theft (revenue generation for the DPRK regime), espionage, and destructive attacks
- **Active since**: At least 2009

#### Reconnaissance Methodology

Lazarus hit Bangladesh Bank, Banco de Chile, Cosmos Bank, and numerous crypto exchanges. Their recon of financial infrastructure and the SWIFT interbank messaging system was methodical and thorough.

**Phase 1 -- Financial System Research**

```
Intelligence Requirements:
- How SWIFT messaging works (Alliance Lite2, Alliance Access)
- How banks connect to the SWIFT network
- Internal processes for authorizing large transfers
- Timezone and business hour patterns (for timing attacks)
- Vendor and software details for banking platforms
```

**Phase 2 -- Bank-Specific Reconnaissance**

```
ATT&CK Techniques Used:
- T1591.002 (Business Relationships) - Mapping correspondent banking relationships
- T1591.003 (Business Tempo) - Understanding wire transfer windows and approval processes
- T1592.002 (Software) - Identifying banking software (SWIFT Alliance version, core banking platform)
- T1589.003 (Employee Names) - Identifying SWIFT operators and wire transfer approvers
- T1593.001 (Social Media) - Profiling bank employees on LinkedIn
- T1590 (Network Information) - Mapping bank's network architecture
```

**Phase 3 -- Watering Hole and Spearphishing Preparation**

Lazarus used their recon to set up two primary access vectors. Watering hole attacks compromised websites frequented by financial sector employees -- central bank sites, regulatory portals, banking industry forums. Meanwhile, they crafted spearphishing emails that referenced real banking processes, regulatory requirements, and industry events.

```
Example Reconnaissance-Informed Attack Preparation:
====================================================

Target: Example National Bank
SWIFT Connection Type: Alliance Access (determined from job postings)
Core Banking Platform: Flexcube (determined from LinkedIn profiles)
SWIFT Operators: 3 identified via LinkedIn and organizational chart
Wire Transfer Approval: Dual authorization required (determined from regulatory filings)
Business Hours: 09:00-17:00 local time (attack timed for after-hours)
Correspondent Banks: 5 identified (targets for fraudulent transfer destinations)
```

#### Detection Opportunities

| Reconnaissance Activity | Detection Method |
|---|---|
| Research into bank's SWIFT configuration | Monitor for unusual queries about banking infrastructure on public sites |
| Employee profiling on LinkedIn | Educate employees on social engineering indicators |
| Watering hole site compromise | DNS monitoring for connections to compromised industry sites |
| Spearphishing preparation | Email gateway analysis for banking-themed phishing lures |
| After-hours system access | Behavioral analytics for unusual SWIFT terminal access patterns |

#### Lessons Learned

Lazarus invested heavily in understanding banking processes before touching any technical exploit. Business logic was the real target -- understanding wire transfer approvals mattered as much as finding vulns. And timing intelligence was critical: they specifically timed attacks for weekends and holidays when fewer staff would notice anomalies.

### 25.5 FIN7 -- Retail and Hospitality Reconnaissance

#### Threat Actor Profile

- **Attribution**: Eastern European cybercrime group
- **Also known as**: Carbanak, Navigator Group, Sangria Tempest
- **Motivation**: Financial theft, primarily through payment card data theft from retail and hospitality organizations
- **Active since**: At least 2013

#### Reconnaissance Methodology

FIN7 shows what targeted recon at scale looks like when a financially motivated group goes after a specific industry vertical.

**Phase 1 -- Industry-Wide Target Identification**

They systematically identified retail and hospitality orgs processing large volumes of card-present transactions:

```
Target Selection Criteria (Reconstructed from FBI/USSS Reports):
- Large retail chains with many physical locations
- Hotel chains and restaurant groups
- Organizations likely using specific POS systems (observed targets)
- Companies with centralized IT management (single compromise = many locations)

OSINT Sources for Target Identification:
- SEC filings revealing transaction volumes and POS vendor relationships
- Job postings for POS system administrators
- Vendor customer lists (POS manufacturers' case studies)
- Industry conference attendee lists
- News articles about retail technology deployments
```

**Phase 2 -- Organizational Profiling**

```
ATT&CK Techniques Used:
- T1591.004 (Identify Roles) - Identifying POS administrators, IT managers
- T1589.002 (Email Addresses) - Harvesting employee email addresses
- T1589.003 (Employee Names) - Building target lists for spearphishing
- T1593.001 (Social Media) - LinkedIn profiling of IT staff
- T1594 (Victim-Owned Websites) - Analyzing corporate websites for org structure
- T1591.001 (Physical Locations) - Mapping store/hotel locations
```

**Phase 3 -- Spearphishing Infrastructure**

FIN7's recon fed directly into their signature attack: highly targeted spearphishing with malicious attachments.

```
FIN7 Spearphishing Preparation (Derived from Public Indictments):
=================================================================

1. Identify target employee role (e.g., restaurant manager, hotel front desk)
2. Research the organization's business context (upcoming events, promotions)
3. Craft industry-specific lures:
   - Catering orders (for restaurants)
   - Reservation complaints (for hotels)
   - Vendor invoices (for retail)
   - Health inspection notices
   - Gift card activation requests
4. Register lookalike domains for the phishing campaign
5. Set up call-back phone numbers staffed by FIN7 social engineers
   who would call to "confirm" the emailed document
```

#### Detection Opportunities

```
DETECTION FRAMEWORK FOR FIN7-STYLE RECONNAISSANCE:
====================================================

1. Email-Level Controls
   - Implement strict DMARC policies (p=reject)
   - Flag emails from newly registered domains
   - Analyze attachments in sandboxed environments
   - Monitor for emails referencing internal processes with unusual sender domains

2. Employee Awareness
   - Train hospitality/retail staff on industry-specific phishing themes
   - Establish verification procedures for document-based requests
   - Report suspicious phone calls following email receipt

3. Public Information Controls
   - Audit organizational charts and employee directories for public exposure
   - Review vendor references and case studies for excessive detail
   - Monitor job postings for technology stack disclosure
```

#### Lessons Learned

FIN7 targeted hundreds of organizations by systematizing their recon for a specific vertical. Automation at scale. Their phishing worked because the lures came from detailed understanding of their targets' business context -- social engineering requires social intelligence. And their phone call follow-ups to supplement phishing emails? That shows recon extending to understanding how targets verify communications.

### 25.6 Cross-Cutting Analysis: Common Reconnaissance Patterns

Look across all four case studies and several patterns jump out:

#### 1. Reconnaissance Duration Correlates with Impact

| Group | Estimated Recon Duration | Campaign Impact |
|---|---|---|
| APT29 (SolarWinds) | Months to years | 18,000 organizations affected |
| APT28 (Elections) | Months | Multiple state election systems compromised |
| Lazarus (Banks) | Weeks to months | $81M stolen (Bangladesh Bank alone) |
| FIN7 (Retail) | Days to weeks per target | Over $1B in losses across campaign |

#### 2. Public Information is the Primary Source

Every single case study relied heavily on freely available internet information. Job postings, vendor websites, LinkedIn profiles, SEC filings, org charts -- consistently the most productive intel sources.

#### 3. Reconnaissance Informs Social Engineering

All four groups turned recon findings into targeted social engineering campaigns. Better recon meant higher phishing success rates. Simple as that.

#### 4. Detection is Possible but Requires Proactive Effort

Each case study has detection opportunities, but they all require organizations to actively monitor their own exposure and look for recon indicators. Passive defense -- firewalls, antivirus -- doesn't address the recon phase at all.

### 25.7 Applying APT Lessons to Defensive Strategy

Based on these case studies, here's what organizations should be doing.

**Conduct self-reconnaissance regularly.** Use the techniques in this guide against your own org. See what adversaries can see.

**Monitor supply chain exposure.** Map your vendors and assess their security posture (Chapter 22). SolarWinds and Kaseya proved that vendor compromise is a viable and productive attack path.

**Reduce your public information surface.** Audit job postings, vendor references, conference presentations, and social media for accidental disclosure (Chapter 20).

**Assume recon is happening right now.** Every internet-facing org is being continuously scanned and profiled. Design your defenses assuming adversaries already have detailed knowledge of your infrastructure.

**Train employees as sensors.** People who understand how recon feeds social engineering are better at recognizing and reporting phishing attempts.

**Detect at the recon phase.** Don't wait for exploitation. DNS monitoring, honeytokens, and external attack surface monitoring can all catch recon activity before it progresses.

> The recon phase is where the asymmetry between attacker and defender hits hardest. Attackers can spend unlimited time collecting information passively, and defenders often can't see any of it happening. Closing that gap takes deliberate, sustained effort -- but these case studies make it clear what happens when you ignore reconnaissance.

---

**End of Part VIII: Advanced Topics**

*This concludes the Advanced Topics section of "The Pre-Attack Phase: A Complete Guide to OSINT and Active Reconnaissance." For the foundational chapters (0-17), refer to the main guide. All techniques described in this section are intended for authorized security professionals operating under explicit written authorization.*
