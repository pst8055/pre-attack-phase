# Part IV: Active Reconnaissance

## Chapter 12: Email Infrastructure and CDN Bypass

### 12.1 Understanding the Concept

Email infrastructure is a goldmine. Every organization has to accept email — there's no way around it — which means their mail servers are sitting out there, discoverable. But here's what makes it really interesting: you can weaponize email for recon. Send crafted messages that, when they get processed or bounced, leak infrastructure details back to you.

Why bother with email recon?

MX records expose mail infrastructure right off the bat. Email headers give up internal routing and server names. Bounce messages? They'll tell you what software the server runs and how it's configured. Tracking pixels can snag the recipient's IP and what software they're using. And SPF records basically hand you a list of authorized sending infrastructure on a silver platter.

**The CDN bypass problem:**

So here's the deal. Tons of organizations hide their origin servers behind CDNs — Cloudflare, Akamai, you name it. The CDN protects the web server. But email servers often run on that same infrastructure, and email completely sidesteps the CDN. Find the mail server's IP and you've probably just found the origin server too.

### 12.2 Walkthrough: Email Header Analysis

**Objective:** Discover origin infrastructure by analyzing email headers.

#### Step 1: Trigger an Email Response

You need to get them to send you something. A few ways to do that:

- Fire off an email to a non-existent address (you'll get a bounce)
- Email support or info (might trigger an auto-reply)
- Subscribe to their newsletter (confirmation email)
- Hit their contact form (notification email)

#### Step 2: Analyze Received Headers

Every server in the chain slaps on a "Received" header, so you end up with the full routing path.

```
Received: from mail.target.com (192.0.2.50) by mx.yourmail.com
Received: from internal-smtp.target.local (10.0.0.25) by mail.target.com
Received: from app-server-01.target.local (10.0.0.100) by internal-smtp.target.local
```

Here's what you can pull from that:

```
Email Header Analysis:
|
+-- External Mail Server
|   +-- Hostname: mail.target.com
|   +-- IP Address: 192.0.2.50
|   +-- This may be origin server IP!
|
+-- Internal Infrastructure
|   +-- Internal SMTP: internal-smtp.target.local
|   +-- Internal IP: 10.0.0.25
|   +-- Application Server: app-server-01.target.local
|
+-- Software Disclosure
|   +-- X-Mailer: Microsoft Outlook 16.0
|   +-- X-Originating-IP: [192.0.2.100]
|   +-- X-MS-Exchange-Organization headers (Exchange server)
|
+-- Origin Discovery
    +-- 192.0.2.50 is likely same infrastructure as web server
    +-- Try: curl -H "Host: www.target.com" http://192.0.2.50/
```

#### Step 3: Verify Origin Server

```bash
# If mail server is 192.0.2.50, test if it also serves web content
curl -s -H "Host: www.target.com" http://192.0.2.50/ | head -20
# If response matches target website, you've found the origin
# The CDN has been bypassed
```

### 12.3 Walkthrough: Email Tracking for Client Intelligence

**Objective:** Gather intelligence about target's internal systems when they view your email.

#### Tracking Pixel Technique

Simple concept. You drop a tiny invisible image in an HTML email. When the recipient opens it, their email client reaches out to your server to fetch that image — and boom, you've got their IP, user agent, and the exact time they opened it.

```html
<!-- Invisible 1x1 pixel -->
<img src="https://your-server.com/track.php?id=unique123" width="1" height="1">
```

What you get back:

```
Tracking Pixel Intelligence:
|
+-- Client IP Address
|   +-- If corporate IP: Internal network range
|   +-- If VPN IP: VPN provider/exit node
|   +-- If residential: Remote worker
|
+-- User Agent
|   +-- Email client: Outlook, Apple Mail, Gmail
|   +-- OS: Windows 10, macOS, iOS
|   +-- Client version: Indicates patch level
|
+-- Timing
|   +-- When email was opened
|   +-- Multiple opens = forwarded internally
|   +-- Business hours = time zone confirmation
|
+-- Example Request Logged:
    IP: 192.0.2.75
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Outlook/16.0
    Time: 2024-03-15 09:23:15 EST
```

#### Link Tracking

You can also drop in tracked links that redirect to legit content:

```
https://your-server.com/redirect.php?id=abc123&url=https://target.com/resource
```

When they click, you log all the same info plus you now know they were interested enough to follow the link.

### 12.4 Walkthrough: CDN Bypass Techniques

**Objective:** Find origin server IP addresses hidden behind CDN/WAF protection.

#### Method 1: Historical DNS Records

Before a company puts up a CDN, their domain pointed straight at the origin. Historical records don't forget.

```bash
# SecurityTrails, ViewDNS, or similar services
# Search: target.com
```

```
Historical DNS:
+-- 2024 (current): 104.16.x.x (Cloudflare)
+-- 2023: 104.16.x.x (Cloudflare)
+-- 2022: 192.0.2.10 (ORIGIN SERVER!)
+-- 2021: 192.0.2.10
# Origin IP discovered: 192.0.2.10
```

#### Method 2: Subdomain Enumeration

CDN protection costs money. Most orgs only bother protecting the main domain — everything else is fair game.

```bash
# Main site behind CDN
dig +short A www.target.com
# Output: 104.16.x.x (Cloudflare)

# But mail server might not be
dig +short A mail.target.com
# Output: 192.0.2.50 (Origin infrastructure!)

# Direct IP access reveals related services
dig +short A ftp.target.com
dig +short A cpanel.target.com
dig +short A webmail.target.com
dig +short A direct.target.com
dig +short A origin.target.com
```

#### Method 3: SSL Certificate Search

The origin server has its own SSL certs. You can search for every IP out there that presents the same certificate.

```bash
# Get certificate details from CDN-protected site
echo | openssl s_client -connect www.target.com:443 2>/dev/null | \
  openssl x509 -noout -fingerprint

# Search Shodan/Censys for same certificate fingerprint
shodan search "ssl.cert.fingerprint:AA:BB:CC:DD:EE:FF..."

# Results show ALL IPs presenting this certificate
# Including origin servers not behind CDN
```

#### Method 4: SPF Record Analysis

```bash
dig +short TXT target.com | grep spf
# Output: v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -all
#                 ^^^^^^^^^^^^^^
#                 Origin IP range!
```

#### Method 5: Favicon Hash Fingerprinting

Every website has a favicon, and each one produces a unique hash. Calculate it, search Shodan for that hash, and you'll find every server presenting the same favicon — including origin boxes that aren't sitting behind a CDN.

```python
#!/usr/bin/env python3
# favicon_hash.py - Find origin servers by favicon fingerprint

import mmh3
import requests
import codecs
import sys

def get_favicon_hash(domain):
    """Calculate MurmurHash3 of favicon for Shodan search"""
    try:
        # Get favicon
        url = f'https://{domain}/favicon.ico'
        response = requests.get(url, timeout=10, verify=False)
        if response.status_code == 200:
            # Base64 encode and hash
            favicon_b64 = codecs.encode(response.content, 'base64')
            favicon_hash = mmh3.hash(favicon_b64)
            return favicon_hash
    except Exception as e:
        print(f"Error: {e}")
    return None

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "target.com"
    hash_value = get_favicon_hash(domain)
    if hash_value:
        print(f"Domain: {domain}")
        print(f"Favicon Hash: {hash_value}")
        print(f"\nShodan Query: http.favicon.hash:{hash_value}")
        print(f"\nThis query will find ALL servers with the same favicon,")
        print(f"including origin servers not behind CDN protection.")
```

Now take that hash and throw it at Shodan:

```bash
# Search for all IPs with this favicon hash
shodan search "http.favicon.hash:-123456789"

# The results will show:
# - CDN edge servers (expected)
# - Origin servers (CDN bypass!)
# - Development servers
# - Staging environments

# Look for IPs NOT in CDN ranges:
# Cloudflare: 104.16.x.x, 172.64.x.x
# Akamai: 23.x.x.x
# CloudFront: 13.x.x.x
```

#### Method 6: Outbound Connection Triggering

Make the server connect back to you. That reveals the real IP instantly. Some ways to pull this off: SSRF vulnerabilities (if you can find one), webhook callbacks, XML external entity processing, image URLs in user profiles (if the app supports it), and PDF generation features that load external resources.

```
Outbound Connection Analysis:
|
+-- Webhook callback received from: 192.0.2.10
+-- This bypasses CDN completely
+-- 192.0.2.10 is origin server IP
```

**Verification:**

```bash
# Test if discovered IP serves target content
curl -s -k -H "Host: www.target.com" https://192.0.2.10/ | grep -i "target"

# If content matches, origin confirmed
# Direct attacks now bypass CDN/WAF
```

#### CDN Bypass Summary

```
CDN Bypass Techniques:
|
+-- Historical DNS
|   +-- Check pre-CDN DNS records
|
+-- Subdomain Enumeration
|   +-- mail, ftp, cpanel, direct, origin, dev
|
+-- SSL Certificate Search
|   +-- Find all IPs with same cert
|
+-- Email Header Analysis
|   +-- Mail server often on same infra
|
+-- SPF Record Mining
|   +-- Lists authorized IP ranges
|
+-- Outbound Connections
|   +-- SSRF, webhooks, XML entities
|
+-- IPv6 Records
    +-- IPv6 often not behind CDN
```

---

## Chapter 13: Active Reconnaissance - POST Request Fingerprinting

### 13.1 Understanding the Concept

> **Note:** This chapter covers ACTIVE RECONNAISSANCE techniques that require direct contact with target systems. These techniques generate logs on the target and may trigger security alerts.

POST request fingerprinting is seriously underrated. You fire off crafted POST requests, study the responses, and you can fingerprint tech stacks, spot vulnerabilities, and map out the whole application architecture. Best part? It all looks like normal web traffic.

Why does this work so well? POST requests often slip past WAF rules that only watch GET parameters. They trigger completely different code paths. Error responses can dump stack traces, file paths, and version numbers. Framework-specific quirks give away what's running under the hood. And since POST responses rarely get cached, you're always getting fresh data back.

**Detection Risk:** Low to Medium — looks like normal web traffic, but pattern detection is possible if you're too noisy about it.

### 13.2 Walkthrough: Error Response Analysis

**Objective:** Trigger informative error responses by sending malformed data.

#### Method 1: Malformed JSON

```bash
# Send invalid JSON to trigger parsing errors
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"invalid": }' -v

# Send empty JSON body
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '' -v

# Send array instead of object
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '[]' -v
```

The error messages are where it gets good. Different frameworks choke in different ways:

```
Error Response Analysis:
|
+-- Django/Python
|   +-- "JSONDecodeError at /api/endpoint"
|   +-- Stack trace with file paths: /var/www/app/views.py
|   +-- Python version in traceback
|
+-- Express/Node.js
|   +-- "SyntaxError: Unexpected token } in JSON"
|   +-- Stack trace mentioning node_modules
|
+-- Spring/Java
|   +-- "JSON parse error: Unexpected character"
|   +-- Java exception with package names
|   +-- Spring Boot version in error page
|
+-- Laravel/PHP
|   +-- "Whoops!" debug page (if debug mode on)
|   +-- File paths: /var/www/html/app/Http/Controllers
|   +-- PHP version, Laravel version
|
+-- ASP.NET
    +-- Yellow Screen of Death (YSOD)
    +-- Stack trace with namespace
    +-- .NET version
```

#### Method 2: Type Confusion Errors

```bash
# Send string where number expected
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"user_id": "not_a_number"}' -v

# Send object where string expected
curl -X POST https://target.com/api/search \
  -H "Content-Type: application/json" \
  -d '{"query": {"nested": "object"}}' -v

# Send very large numbers
curl -X POST https://target.com/api/calculate \
  -H "Content-Type: application/json" \
  -d '{"amount": 99999999999999999999999999}' -v
```

### 13.3 Walkthrough: Content-Type Fingerprinting

**Objective:** Identify framework and parser configuration by testing Content-Type handling.

```bash
#!/bin/bash
# content_type_fingerprint.sh - Test Content-Type handling

TARGET="https://target.com/api/endpoint"
BODY='{"test":"value"}'

echo "=== Content-Type Fingerprinting ==="
echo "Target: $TARGET"
echo ""

for ct in \
  "application/json" \
  "application/xml" \
  "application/x-www-form-urlencoded" \
  "text/plain" \
  "text/xml" \
  "multipart/form-data" \
  "application/javascript" \
  "text/html"; do

  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$TARGET" \
    -H "Content-Type: $ct" \
    -d "$BODY")

  echo "Content-Type: $ct -> HTTP $RESPONSE"
done
```

So what do the results mean?

```
Content-Type Fingerprinting Results:
|
+-- Only application/json accepted (others get 415)
|   +-- Strict API, likely modern framework
|
+-- application/json AND application/xml accepted
|   +-- Multiple parsers enabled
|   +-- Check for XXE vulnerabilities with XML
|
+-- All Content-Types return 200
|   +-- Permissive parsing, potential type confusion
|   +-- May be vulnerable to content-type attacks
|
+-- application/x-www-form-urlencoded treated as JSON
|   +-- Framework auto-detection (Express, FastAPI)
|
+-- Different errors for different types
    +-- Parse each error for version disclosure
```

### 13.4 Walkthrough: Framework-Specific Fingerprinting

#### Django Detection

```bash
# CSRF token test
curl -X POST https://target.com/admin/ \
  -d "username=test&password=test" -v 2>&1 | grep -i "csrf"

# Expected Django response:
# "CSRF verification failed. Request aborted."
# "CSRF token missing or incorrect."

# Django debug page trigger
curl -X POST https://target.com/nonexistent/ \
  -H "Content-Type: application/json" \
  -d '{}' -v

# If DEBUG=True: Detailed error with Django version
```

#### Laravel Detection

```bash
# CSRF token test
curl -X POST https://target.com/login \
  -d "_token=invalid&email=test@test.com&password=test" -v

# Expected Laravel response:
# HTTP 419 "Page Expired" or "CSRF token mismatch"

# Artisan detection
curl -s https://target.com/artisan
curl -s https://target.com/.env  # Often exposed
```

#### ASP.NET Detection

```bash
# ViewState manipulation
curl -X POST https://target.com/page.aspx \
  -d "__VIEWSTATE=invalid_base64&__EVENTVALIDATION=invalid" -v

# Expected response:
# "Validation of viewstate MAC failed"
# Reveals ASP.NET version in error
```

#### Spring Boot Detection

```bash
# Actuator endpoints
for endpoint in health info env beans mappings; do
  echo "=== /actuator/$endpoint ==="
  curl -s "https://target.com/actuator/$endpoint" | head -5
done

# Error page fingerprint
curl -X POST https://target.com/error \
  -H "Content-Type: application/json" \
  -d '{}' -v

# Whitelabel error page = Spring Boot
```

#### Express/Node.js Detection

```bash
# Prototype pollution test (reveals Node.js)
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"test": 1}}' -v

# Stack trace often mentions:
# - node_modules
# - express
# - at Layer.handle [as handle_request]
```

### 13.5 Walkthrough: WAF/CDN Fingerprinting

**Objective:** Figure out which WAF vendor is in the way by poking at it with payloads that'll trigger signature-based blocks.

```bash
#!/bin/bash
# waf_fingerprint.sh - Identify WAF by response to malicious payloads

TARGET="$1"

echo "=== WAF Fingerprinting: $TARGET ==="

# SQL Injection payload
echo "[*] Testing SQL Injection signature..."
RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "user=admin' OR '1'='1'--&pass=test" \
  -w "\n%{http_code}" | tail -1)
echo "    SQLi test: HTTP $RESPONSE"

# XSS payload
echo "[*] Testing XSS signature..."
RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "comment=<script>alert(document.cookie)</script>" \
  -w "\n%{http_code}" | tail -1)
echo "    XSS test: HTTP $RESPONSE"

# Path traversal
echo "[*] Testing Path Traversal..."
RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "file=../../../etc/passwd" \
  -w "\n%{http_code}" | tail -1)
echo "    Path traversal: HTTP $RESPONSE"

# Check response headers for WAF signatures
echo ""
echo "[*] Checking response headers..."
curl -s -I -X POST "$TARGET" -d "test=value" | grep -iE "server|x-|cf-|via|akamai"
```

Each WAF leaves its own fingerprints. Here's how to tell them apart:

```
WAF Identification by Response:
|
+-- Cloudflare
|   +-- Header: cf-ray: xxxxx
|   +-- Header: server: cloudflare
|   +-- Block page: "Attention Required!"
|   +-- Block page: "Ray ID" in footer
|
+-- AWS WAF
|   +-- Header: x-amzn-RequestId
|   +-- HTTP 403 with minimal body
|   +-- Sometimes "Request blocked" message
|
+-- Akamai
|   +-- Header: X-Akamai-Transformed
|   +-- Reference ID in error page
|   +-- "Access Denied" with reference number
|
+-- Imperva/Incapsula
|   +-- Header: X-CDN: Imperva
|   +-- Block page: "Request unsuccessful"
|   +-- Incident ID in response
|
+-- ModSecurity
|   +-- Often includes rule ID in block
|   +-- "ModSecurity" in error page
|   +-- Apache/nginx with mod_security
|
+-- F5 BIG-IP ASM
|   +-- Header: X-WA-Info
|   +-- Support ID in block page
|   +-- "The requested URL was rejected"
|
+-- Fortinet FortiWeb
    +-- Block page with Fortinet branding
    +-- "FortiWeb" in response
```

### 13.6 Walkthrough: Parameter Pollution Fingerprinting

**Objective:** Identify backend technology by how it handles duplicate parameters.

```bash
# HTTP Parameter Pollution test
curl -X POST https://target.com/search \
  -d "query=first&query=second" -v

# Also test in JSON:
curl -X POST https://target.com/api/search \
  -H "Content-Type: application/json" \
  -d '{"query": "first", "query": "second"}' -v
```

Different backends handle this differently — and that's exactly how you identify what's running:

```
Parameter Pollution Responses:
|
+-- Uses LAST value ("second")
|   +-- PHP (Apache/nginx)
|   +-- Most Apache mod_* modules
|
+-- Uses FIRST value ("first")
|   +-- Python (Flask, Django)
|   +-- Ruby on Rails
|
+-- Concatenates values ("first,second")
|   +-- ASP.NET/IIS
|   +-- Perl CGI
|
+-- Returns ARRAY ["first", "second"]
|   +-- Node.js/Express
|   +-- Python (Werkzeug raw)
|   +-- Go standard library
|
+-- JSON duplicate key behavior
    +-- Last value wins: Most JSON parsers
    +-- First value wins: Some strict parsers
```

### 13.7 Walkthrough: API Discovery via POST

**Objective:** Enumerate API endpoints and methods.

```bash
#!/bin/bash
# api_discover.sh - API endpoint discovery

TARGET="https://target.com/api"

# Common API endpoints
ENDPOINTS=(
  "users" "user" "accounts" "account"
  "login" "logout" "auth" "authenticate" "token"
  "register" "signup" "password" "reset"
  "profile" "settings" "config" "configuration"
  "admin" "dashboard" "status" "health"
  "search" "query" "data" "export" "import"
  "upload" "download" "file" "files"
  "message" "messages" "notification" "notifications"
  "order" "orders" "cart" "checkout" "payment"
  "v1" "v2" "v3" "api" "graphql"
)

echo "=== API Endpoint Discovery ==="
echo "Target: $TARGET"
echo ""

for endpoint in "${ENDPOINTS[@]}"; do
  for method in GET POST PUT DELETE; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      -X $method "$TARGET/$endpoint" \
      -H "Content-Type: application/json" \
      -d '{}')

    if [[ "$CODE" != "404" && "$CODE" != "000" ]]; then
      echo "$method $TARGET/$endpoint -> HTTP $CODE"
    fi
  done
done
```

#### GraphQL Detection

```bash
# GraphQL introspection via POST
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'

# If introspection enabled, full schema is returned
# This reveals all queries, mutations, and types

# Alternative endpoints to try:
for path in graphql api/graphql v1/graphql query; do
  echo "=== Testing /$path ==="
  curl -s -X POST "https://target.com/$path" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}' | head -1
done
```

### 13.8 Walkthrough: Timing-Based Fingerprinting

**Objective:** Identify backend behavior through response timing.

```bash
#!/bin/bash
# timing_fingerprint.sh - Timing-based reconnaissance

TARGET="$1"

# Test processing time for different payloads
echo "=== Baseline (empty POST) ==="
time curl -s -X POST "$TARGET" -d '' -o /dev/null
echo ""

echo "=== Large payload (1MB) ==="
LARGE=$(python3 -c "print('x='+'A'*1000000)")
time curl -s -X POST "$TARGET" -d "$LARGE" -o /dev/null
echo ""

echo "=== Deeply nested JSON ==="
NESTED='{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":"deep"}}}}}}}}}'
time curl -s -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d "$NESTED" -o /dev/null
echo ""

echo "=== Array with many elements ==="
ARRAY=$(python3 -c "import json; print(json.dumps({'items': list(range(10000))}))")
time curl -s -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d "$ARRAY" -o /dev/null
```

What the timing tells you:

```
Timing Analysis:
|
+-- Large payload processed quickly
|   +-- Size limits enforced (good security)
|
+-- Large payload causes timeout
|   +-- No size limit - potential DoS vector
|
+-- Deep nesting causes slow response
|   +-- Recursive parsing - potential DoS
|
+-- Many array elements slow response
|   +-- Iteration without limits - potential DoS
|
+-- Consistent timing regardless of payload
    +-- Robust input handling, hardened target
```

### 13.9 POST Fingerprinting Summary

```
POST Request Fingerprinting Quick Reference:
|
+-- Error Triggering
|   +-- Malformed JSON -> Framework disclosure
|   +-- Type confusion -> Parser behavior
|   +-- Large values -> Limit disclosure
|
+-- Content-Type Testing
|   +-- Multiple types -> Parser enumeration
|   +-- Type confusion -> Vulnerability indicators
|   +-- Rejection patterns -> Security posture
|
+-- Framework Detection
|   +-- CSRF handling -> Django/Laravel/Rails
|   +-- ViewState -> ASP.NET
|   +-- Actuator -> Spring Boot
|   +-- Stack traces -> All frameworks
|
+-- WAF/CDN Detection
|   +-- SQLi payload -> WAF signature
|   +-- XSS payload -> WAF signature
|   +-- Response headers -> CDN identification
|   +-- Block pages -> WAF vendor
|
+-- Parameter Behavior
|   +-- Duplicate handling -> Backend language
|   +-- JSON key handling -> Parser type
|
+-- Detection Risk: Low-Medium
    +-- Appears as normal web traffic
    +-- Pattern detection possible if noisy
```

---

# Part V: Social Engineering Reconnaissance

## Chapter 14: Profiling Targets for SE Campaigns

### 14.1 Understanding the Concept

Social engineering doesn't work without homework. Seriously. The gap between a phishing email that gets trashed and a spear-phishing campaign that actually lands? Intelligence quality. Adversaries build ridiculously detailed profiles, map out who reports to who, and craft pretexts that feel real because they *are* contextually accurate.

Why does this matter? Because humans are the bypass. No amount of technical controls helps when someone hands over credentials willingly. A well-researched pretext exploits trust relationships, authority structures, time pressure, contextual relevance, and personal interests — all at once if it's done right.

The recon phase for SE is entirely passive. You're just gathering publicly available info about people, how they relate to each other, and what the org's culture looks like. No direct contact needed.

### 14.2 Walkthrough: Personal Profile Development

**Objective:** Build comprehensive profiles of target individuals for social engineering campaigns.

#### Social Media Intelligence (SOCMINT)

**Platform-Specific Queries:**

**LinkedIn** is where you start. Professional history, skills, certifications, who they're connected to, what they post and comment on, recommendations (which expose real relationships), and group memberships that reveal interests and affiliations.

**Facebook** can be a treasure trove if their privacy settings are lax — friends lists, check-ins, life events like job changes or moves, photos showing family and hobbies, likes that expose their interests, and group memberships.

**Twitter/X** gives you opinions (people are shockingly candid), their following list shows interests, replies expose relationships, retweets show affiliations, and you can often pick up location patterns.

**Instagram** is all visual intel. Photos reveal lifestyle and travel patterns, stories can give real-time location, tagged photos show relationships, hashtags tell you about interests, and follower/following ratios hint at their social dynamics.

**Other Platforms:**
- GitHub (technical projects, email in commits)
- Reddit (interests, opinions, throwaway confessions)
- Strava/fitness apps (routes, locations, schedule)
- Gaming profiles (Steam, Xbox, PSN)
- Dating profiles (personal details, photos)

#### Search Operators for Personal OSINT

```
# Find all social media for a person
"John Smith" "Target Organization" site:linkedin.com
"John Smith" "Target Organization" site:facebook.com
"John Smith" site:twitter.com "works at"
"jsmith" OR "john.smith" site:github.com

# Find personal email
"John Smith" "@gmail.com" OR "@yahoo.com" OR "@hotmail.com"

# Find username patterns
# If work email is jsmith@target.com, search for:
"jsmith" site:reddit.com
"jsmith" site:github.com
"jsmith" site:instagram.com
```

#### Profile Output Example

```
Target Profile: John Smith
Position: Senior Network Engineer
|
+-- Professional
|   +-- Email: jsmith@target.com
|   +-- LinkedIn: linkedin.com/in/johnsmith-neteng
|   +-- At company since: 2019
|   +-- Previous: Cisco (3 years)
|   +-- Certifications: CCNP, CCIE
|   +-- Responsibilities: VPN, firewall management
|
+-- Personal
|   +-- Personal email: jsmith1985@gmail.com
|   +-- Location: Austin, TX
|   +-- Family: Married, 2 kids
|   +-- Interests: Golf, craft beer, Texas Longhorns
|   +-- Recent: Vacation to Cancun (2 weeks ago)
|
+-- Digital Footprint
|   +-- GitHub: github.com/jsmith85 (personal projects)
|   +-- Twitter: @jsmith_austin (sports commentary)
|   +-- Reddit: u/networkguy85 (r/networking, r/homelab)
|   +-- Strava: Weekly runs, route visible
|
+-- Password Intelligence
|   +-- Likely patterns: texas85, longhorns1985
|   +-- Breached in: LinkedIn 2012, Adobe 2013
|   +-- Reused password likely
|
+-- Social Engineering Vectors
    +-- Authority: Reports to IT Director Sarah Jones
    +-- Interests: Golf tournament sponsorship
    +-- Timing: Kids in school 8am-3pm
    +-- Pretext: Cisco vendor support, golf event
```

### 14.3 Walkthrough: Organizational Relationship Mapping

**Objective:** Map reporting structures, communication patterns, and trust relationships.

#### Org Chart Reconstruction

```
# Find leadership
site:linkedin.com/in "Target Organization" "CEO" OR "CTO" OR "CFO"
site:linkedin.com/in "Target Organization" "Director"
site:linkedin.com/in "Target Organization" "VP" OR "Vice President"

# Find specific departments
site:linkedin.com/in "Target Organization" "IT Manager"
site:linkedin.com/in "Target Organization" "Finance"
site:linkedin.com/in "Target Organization" "Human Resources"

# Find assistants (high-value targets)
site:linkedin.com/in "Target Organization" "Executive Assistant"
site:linkedin.com/in "Target Organization" "Administrative Assistant"
```

#### Relationship Intelligence

```
Organizational Map:
|
+-- C-Suite
|   +-- CEO: Michael Johnson
|   |   +-- Assistant: Lisa Chen (gatekeeper)
|   +-- CFO: Robert Williams
|   |   +-- Controls wire transfers
|   +-- CTO: David Park
|       +-- IT reports to CTO
|
+-- IT Department
|   +-- IT Director: Sarah Jones
|   |   +-- Reports to: CTO
|   |   +-- Manages: 12 staff
|   +-- Security Manager: Tom Brown
|   |   +-- New hire (3 months) - less institutional knowledge
|   +-- Helpdesk Lead: Amy Wilson
|       +-- Password reset authority
|
+-- Finance Department
|   +-- Controller: Jennifer Davis
|   |   +-- Approves payments >$10K
|   +-- AP Clerk: Mike Thompson
|       +-- Processes invoices
|
+-- Key Relationships Identified
    +-- CEO -> CFO (frequent email CC patterns)
    +-- CTO -> IT Director (direct reports)
    +-- Finance -> IT (budget discussions on LinkedIn)
    +-- New Security Manager (vulnerable to authority pretexts)
```

### 14.4 Walkthrough: Communication Pattern Analysis

**Objective:** Understand how the organization communicates internally.

#### Email Format Discovery

```bash
# Common email formats
first.last@target.com     # john.smith@target.com
firstlast@target.com      # johnsmith@target.com
first_last@target.com     # john_smith@target.com
flast@target.com          # jsmith@target.com
firstl@target.com         # johns@target.com
first@target.com          # john@target.com

# Verification methods:
# 1. LinkedIn profile may show email
# 2. GitHub commits contain email
# 3. Google: "jsmith@target.com" (exact match search)
# 4. Hunter.io / email verification services
# 5. WHOIS for domain contacts
# 6. Press releases with contact info
```

#### Email Verification

```bash
# Verify email exists without sending
# SMTP VRFY (often disabled)
telnet mail.target.com 25
VRFY jsmith@target.com

# Alternative: Check bounce
# Send email, analyze bounce message
# "User unknown" vs delayed bounce = exists

# Hunter.io API
curl "https://api.hunter.io/v2/email-verifier?email=jsmith@target.com&api_key=KEY"
```

#### Communication Style Analysis

Dig into their public communications. You're looking for patterns you can mimic:

```
|
+-- Formality Level
|   +-- "Dear Mr. Johnson" vs "Hey Mike"
|   +-- Signature blocks (title, phone, legal disclaimers)
|   +-- Email thread style
|
+-- Terminology
|   +-- Internal project names
|   +-- Department abbreviations
|   +-- System names
|   +-- Jargon and acronyms
|
+-- Response Patterns
|   +-- Typical response time
|   +-- Out-of-office patterns
|   +-- Mobile vs desktop signatures
|
+-- Sources for Analysis
    +-- Press releases
    +-- Public email threads (mailing lists)
    +-- Conference presentations
    +-- Support forum posts
    +-- Social media posts
```

### 14.5 Walkthrough: Pretext Development

**Objective:** Develop contextually accurate pretexts for social engineering.

#### Vendor Impersonation Research

```
# Find vendors/suppliers
"Target Organization" "partner" OR "vendor" OR "supplier"
"Target Organization" "case study" site:vendor.com
"Target Organization" "customer" site:vendor.com

# Find IT vendors specifically
"Target Organization" "Cisco" OR "Microsoft" OR "VMware"
"Target Organization" "support" OR "maintenance"

# Find recent vendor activity
"Target Organization" "contract" OR "agreement" filetype:pdf
```

#### Vendor Pretext Example

```
Pretext: Cisco TAC Support Call
|
+-- Background Research
|   +-- They use Cisco ASA (from Shodan)
|   +-- Version 9.12(4) (from banner)
|   +-- John Smith manages firewalls (LinkedIn)
|   +-- SmartNet contract likely (enterprise customer)
|   +-- Cisco TAC process known
|
+-- Pretext Construction
|   +-- "Hi John, this is Mike from Cisco TAC"
|   +-- "Following up on case SR-12345678"
|   +-- "Regarding the ASA vulnerability advisory"
|   +-- "Need to verify your configuration"
|   +-- "Can you confirm the management IP?"
|
+-- Contextual Elements
    +-- Cisco TAC terminology
    +-- Reference real CVE numbers
    +-- Appropriate urgency level
    +-- Professional but routine tone
```

#### Authority Impersonation Research

```
Internal Authority Pretexts:
|
+-- Executive Impersonation
|   +-- CEO email style from public speeches/interviews
|   +-- Current travel (social media, conferences)
|   +-- Typical requests patterns
|   +-- Assistant's name and role
|
+-- IT Authority
|   +-- Helpdesk ticket system name
|   +-- Standard IT request procedures
|   +-- Internal system names
|   +-- IT team member names
|
+-- External Authority
    +-- Auditor/compliance (annual audit timing)
    +-- Legal/regulatory (lawsuit, subpoena)
    +-- Law enforcement (requires caution)
    +-- Banking/financial institution
```

### 14.6 Walkthrough: Physical Security Reconnaissance

**Objective:** Gather intelligence for physical social engineering.

#### Facility Intelligence

```
Physical Security OSINT:
|
+-- Location Intelligence
|   +-- Google Maps/Street View
|   +-- Satellite imagery (fence lines, gates)
|   +-- Photos on social media (office, building)
|   +-- Real estate listings (floor plans)
|
+-- Access Points
|   +-- Main entrance
|   +-- Loading docks
|   +-- Parking garage
|   +-- Smoking areas (tailgating opportunity)
|   +-- Side/emergency exits
|
+-- Security Observations
|   +-- Guard presence (social media photos)
|   +-- Badge type (photos showing badges)
|   +-- Visitor procedures (job postings, reviews)
|   +-- Delivery procedures
|   +-- Working hours
|
+-- Employee Patterns
    +-- Arrival/departure times
    +-- Lunch locations
    +-- Smoking breaks
    +-- Badge-in locations
```

#### Badge and Uniform Research

```
# Find images of badges/uniforms
site:linkedin.com "Target Organization" (look at profile photos)
site:instagram.com #TargetOrganization
site:glassdoor.com "Target Organization" photos
"Target Organization" "first day" site:linkedin.com
"Target Organization" "office" site:instagram.com
```

Look at what you can pull from badge photos alone: badge design and color scheme, whether it's vertical or horizontal, where the photo sits, barcode or chip location, lanyard color and style, and what type of proximity card they're using. People love posting "first day at the office" shots. Not ideal for them.

### 14.7 Walkthrough: Voice and Writing Sample Collection

**Objective:** Collect samples for impersonation and deepfake creation.

#### Voice Sample Sources

```
Voice Sample Collection:
|
+-- Public Speaking
|   +-- Conference presentations (YouTube)
|   +-- Podcast appearances
|   +-- Webinar recordings
|   +-- Earnings calls (executives)
|   +-- Media interviews
|
+-- Search Queries
|   +-- "John Smith" "Target Organization" site:youtube.com
|   +-- "John Smith" "Target Organization" podcast
|   +-- "Target Organization" "earnings call" (for executives)
|   +-- "Target Organization" site:vimeo.com
|
+-- Usage Considerations
    +-- Voice cloning for vishing
    +-- Deepfake video creation
    +-- Voicemail impersonation
    +-- Voice authentication bypass
```

#### Writing Style Collection

```
Writing Sample Sources:
|
+-- Professional Writing
|   +-- LinkedIn posts and articles
|   +-- Blog posts (company or personal)
|   +-- Conference papers
|   +-- GitHub README files
|   +-- Forum posts (Stack Overflow, Reddit)
|
+-- Analysis Points
|   +-- Vocabulary complexity
|   +-- Sentence structure
|   +-- Punctuation habits
|   +-- Emoji usage
|   +-- Greeting/closing styles
|   +-- Common phrases
|
+-- Impersonation Application
    +-- Email crafting
    +-- Chat/Slack messages
    +-- Text messages
    +-- Document forgery
```

### 14.8 Walkthrough: Business Email Compromise Preparation

**Objective:** Gather intelligence for BEC attacks targeting financial transactions.

#### Financial Process Intelligence

BEC is all about understanding money flow. Who can approve wire transfers, and at what dollar threshold? Who actually processes the payments? What verification steps exist — if any? You also want to map out known vendors and suppliers, figure out regular payment schedules, grab invoice formats from any public docs you can find, and identify what payment methods they use.

Then there's the timing angle. Track executive travel through conference speaking schedules, social media check-ins, and out-of-office patterns. When the boss is on a plane to Singapore, that's when "urgent" requests are hardest to verify. Quarter-end, year-end, M&A announcements, audit periods — these all create pressure that makes people skip steps.

```
BEC Reconnaissance:
|
+-- Payment Authority Chain
|   +-- Who can approve wire transfers?
|   +-- What are the approval thresholds?
|   +-- Who processes payments?
|   +-- What verification exists?
|
+-- Vendor Payment Intelligence
|   +-- Known vendors/suppliers
|   +-- Regular payment schedules
|   +-- Invoice formats (from public docs)
|   +-- Payment methods used
|
+-- Executive Travel
|   +-- Conference schedules (speaking)
|   +-- Social media check-ins
|   +-- Out-of-office patterns
|   +-- Time zone differences
|
+-- Urgency Triggers
    +-- Quarter/year end (financial pressure)
    +-- M&A activity (public announcements)
    +-- Audit periods
    +-- Executive travel (reduced verification)
```

#### BEC Pretext Development

```
Classic BEC Scenarios:
|
+-- CEO Fraud
|   +-- "I'm in a meeting, need urgent wire transfer"
|   +-- Target: CFO, Controller, AP Clerk
|
+-- Vendor Impersonation
|   +-- "Our bank details have changed"
|   +-- Target: Accounts Payable
|
+-- Attorney Impersonation
|   +-- "Confidential acquisition, need escrow funds"
|   +-- Target: CEO, CFO
|
+-- Payroll Diversion
    +-- "Please update my direct deposit info"
    +-- Target: HR, Payroll
```

### 14.9 Walkthrough: Out-of-Band Information Gathering

**Objective:** Gather information through non-traditional channels.

#### Data Broker and People Search Sites

You'd be surprised (or maybe you wouldn't) how much data broker sites have on people. Free resources like Pipl, Whitepages, Spokeo, BeenVerified, ThatsThem, and TruePeopleSearch can turn up current and previous addresses, phone numbers, email addresses, relatives, property records, and court records. Use this to verify identity details, find personal phone numbers, identify family members, dig up past employers, or discover alternative ways to reach the target.

```
People Search Resources:
|
+-- Free Resources
|   +-- Pipl.com (limited free)
|   +-- Whitepages.com
|   +-- Spokeo.com
|   +-- BeenVerified.com
|   +-- ThatsThem.com
|   +-- TruePeopleSearch.com
|
+-- Information Available
|   +-- Current and previous addresses
|   +-- Phone numbers
|   +-- Email addresses
|   +-- Relatives and associates
|   +-- Property records
|   +-- Court records
|
+-- Intelligence Value
    +-- Verify identity information
    +-- Find personal phone numbers
    +-- Identify family members
    +-- Discover previous employers
    +-- Find alternative contact methods
```

#### Public Records

```
Public Record Sources:
|
+-- Property Records
|   +-- County assessor websites
|   +-- Home value and purchase price
|   +-- Property tax records
|   +-- Mortgage information
|
+-- Court Records
|   +-- Civil cases
|   +-- Divorces
|   +-- Bankruptcies
|   +-- Criminal records (where public)
|
+-- Business Records
|   +-- Business registrations
|   +-- Professional licenses
|   +-- Regulatory filings
|   +-- Nonprofit disclosures
|
+-- Vehicle Records
    +-- Registration (some states)
    +-- Boat/aircraft registrations
    +-- License plate lookups
```

#### Social Engineering Intelligence Summary

```
Complete SE Target Package:
|
+-- Personal Profile
|   +-- Full name and aliases
|   +-- Contact information (work/personal)
|   +-- Social media accounts
|   +-- Family members
|   +-- Interests and hobbies
|   +-- Daily patterns
|
+-- Professional Profile
|   +-- Current role and responsibilities
|   +-- Reporting structure
|   +-- Access and authority level
|   +-- Work schedule
|   +-- Travel patterns
|
+-- Communication Profile
|   +-- Email format and style
|   +-- Writing patterns
|   +-- Voice samples
|   +-- Photo samples
|
+-- Relationship Map
|   +-- Colleagues
|   +-- Vendors/partners
|   +-- Authority figures
|   +-- Personal contacts
|
+-- Vulnerability Assessment
    +-- Authority susceptibility
    +-- Urgency response
    +-- Technical sophistication
    +-- Security awareness level
    +-- Best pretext approach
```

---

# Part VI: Building the Target Package

## Chapter 15: Intelligence Synthesis

### 15.1 Understanding the Concept

Raw data is just noise until you connect the dots. A single finding might be mildly interesting. Correlated findings? Those reveal attack paths.

**The correlation mindset:**

Say DNS shows dev.target.com exists. Shodan tells you it's running an outdated Apache version. Job postings reveal they're hiring security staff — meaning there are gaps. LinkedIn confirms the security team is tiny. Individually? Okay, noted. Together? You've got a development environment with weak security, an understaffed security team, and a very real potential entry point.

### 15.2 Walkthrough: Building the Package

#### Collection Checklist

```
Target Package Assembly:
|
+-- [x] Network Intelligence
|   +-- [x] ASN identified: AS12345
|   +-- [x] IP ranges mapped: 192.0.2.0/24, 198.51.100.0/24
|   +-- [x] Upstream providers: Cogent, Lumen
|   +-- [x] BGP relationships documented
|
+-- [x] DNS Intelligence
|   +-- [x] All record types queried
|   +-- [x] SPF fully expanded (reveals Google + Microsoft)
|   +-- [x] Subdomains enumerated: 47 found
|   +-- [x] Zone transfer attempted (failed)
|
+-- [x] Service Intelligence
|   +-- [x] Shodan data collected
|   +-- [x] All IPs enriched
|   +-- [x] Service versions documented
|   +-- [x] SSL certificates analyzed
|
+-- [x] Human Intelligence
|   +-- [x] Org structure mapped
|   +-- [x] Key personnel identified: 23 IT staff
|   +-- [x] Technology stack from job posts
|   +-- [x] Security team: 3 people (small!)
|
+-- [x] ICS Intelligence
|   +-- [x] Modbus devices found: 3
|   +-- [x] HMI interfaces: 2
|   +-- [x] No authentication on any device
|
+-- [x] Cloud Intelligence
    +-- [x] AWS: S3, CloudFront, API Gateway
    +-- [x] Azure: Blob, Web App
    +-- [x] Public S3 bucket discovered
```

#### Entry Point Prioritization

```
Attack Surface Assessment:
|
+-- Tier 1: High Value / Low Friction
|   |
|   +-- Exposed ICS (192.0.2.100-102)
|   |   +-- Modbus PLCs directly accessible
|   |   +-- No authentication required
|   |   +-- CRITICAL: Physical damage possible
|   |
|   +-- VPN Gateway (192.0.2.30)
|   |   +-- Cisco ASA 9.12(4)
|   |   +-- Check CVE-2023-20269
|   |
|   +-- Exposed MySQL (192.0.2.100:3306)
|   |   +-- Database directly on internet
|   |
|   +-- Dev Environment (dev.target.com)
|       +-- Often weaker security controls
|
+-- Tier 2: Moderate Value / Moderate Friction
|   |
|   +-- Public S3 Bucket (target-public)
|   |   +-- Check for sensitive data
|   |
|   +-- API Gateway (api.target.com)
|   |   +-- Test for authentication issues
|   |
|   +-- Helpdesk Portal
|       +-- Potential credential harvesting
|
+-- Tier 3: High Value / High Friction
    |
    +-- Main Website
    |   +-- Behind CDN, WAF protected
    |
    +-- Mail Server
        +-- Likely well-hardened
```

---

# Part VII: Automation and Operations

## Chapter 16: Automation Scripts and Tooling

### 16.1 Understanding the Concept

Doing recon by hand teaches you how things work. That's valuable. But when you're running real operations, you need automation. Scripts that chain tools together, correlate output on the fly, and spit out structured reports — that's what lets you scale. Same methodology every time, done in minutes instead of hours, with automatic data linking and built-in documentation. And you can hit multiple targets in parallel without losing your mind.

### 16.2 Full Domain Reconnaissance Script

```bash
#!/bin/bash
# full_recon.sh - Complete domain reconnaissance pipeline
# Usage: ./full_recon.sh target.com

set -e
TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

OUTPUT="recon_${TARGET}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT"

echo "========================================"
echo " OSINT Reconnaissance: $TARGET"
echo " Output Directory: $OUTPUT"
echo "========================================"

# Phase 1: Subdomain Enumeration
echo -e "\n[Phase 1] Subdomain Enumeration"
echo "================================"

echo "[*] Running Certificate Transparency search..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | sort -u > "$OUTPUT/crt_subdomains.txt"
echo "[+] CT results: $(wc -l < "$OUTPUT/crt_subdomains.txt") subdomains"

if command -v subfinder &> /dev/null; then
    echo "[*] Running subfinder..."
    subfinder -d "$TARGET" -silent -all > "$OUTPUT/subfinder_subdomains.txt" 2>/dev/null
    echo "[+] Subfinder results: $(wc -l < "$OUTPUT/subfinder_subdomains.txt") subdomains"
fi

if command -v amass &> /dev/null; then
    echo "[*] Running amass (passive)..."
    timeout 300 amass enum -passive -d "$TARGET" -o "$OUTPUT/amass_subdomains.txt" 2>/dev/null || true
    echo "[+] Amass results: $(wc -l < "$OUTPUT/amass_subdomains.txt" 2>/dev/null || echo 0) subdomains"
fi

# Combine and deduplicate
cat "$OUTPUT"/*_subdomains.txt 2>/dev/null | sort -u > "$OUTPUT/all_subdomains.txt"
TOTAL_SUBS=$(wc -l < "$OUTPUT/all_subdomains.txt")
echo "[+] Total unique subdomains: $TOTAL_SUBS"

# Phase 2: DNS Resolution
echo -e "\n[Phase 2] DNS Resolution"
echo "========================="

if command -v dnsx &> /dev/null; then
    echo "[*] Resolving subdomains with dnsx..."
    cat "$OUTPUT/all_subdomains.txt" | dnsx -a -resp-only -silent > "$OUTPUT/resolved_ips.txt" 2>/dev/null
else
    echo "[*] Resolving subdomains with dig..."
    while read sub; do
        ip=$(dig +short A "$sub" 2>/dev/null | head -1)
        [ -n "$ip" ] && echo "$ip"
    done < "$OUTPUT/all_subdomains.txt" > "$OUTPUT/resolved_ips.txt"
fi

sort -u "$OUTPUT/resolved_ips.txt" > "$OUTPUT/unique_ips.txt"
TOTAL_IPS=$(wc -l < "$OUTPUT/unique_ips.txt")
echo "[+] Unique IP addresses: $TOTAL_IPS"

# Phase 3: DNS Records
echo -e "\n[Phase 3] DNS Record Analysis"
echo "=============================="

echo "[*] Querying DNS records..."
{
    echo "=== A Records ==="
    dig +short A "$TARGET"
    # ... (additional record types: AAAA, MX, NS, TXT, SOA, CNAME, SRV)
} > "$OUTPUT/dns_records.txt"
```

> **Note:** The full script continues with additional phases for MX analysis, SPF expansion, Shodan enrichment, and report generation. The structure above shows the pipeline pattern that carries through the rest.

### 16.3 ASN Enumeration Script

```bash
#!/bin/bash
# asn_enum.sh - Complete ASN enumeration
# Usage: ./asn_enum.sh AS12345 or ./asn_enum.sh 12345

ASN=$1
if [ -z "$ASN" ]; then
    echo "Usage: $0 <ASN>"
    exit 1
fi

# Remove AS prefix if present
ASN=${ASN#AS}

echo "========================================"
echo " ASN Enumeration: AS$ASN"
echo "========================================"

# Basic Info
echo -e "\n[*] Organization Details"
echo "========================="
curl -s "https://api.bgpview.io/asn/$ASN" | \
    jq -r '.data | "Name: \(.name)\nDescription: \(.description_short)\nCountry: \(.rir_allocation.country_code)"'

# Prefixes
echo -e "\n[*] Announced Prefixes"
echo "======================="

echo "IPv4 Prefixes:"
curl -s "https://api.bgpview.io/asn/$ASN/prefixes" | \
    jq -r '.data.ipv4_prefixes[] | "  \(.prefix) - \(.description)"'

echo -e "\nIPv6 Prefixes:"
curl -s "https://api.bgpview.io/asn/$ASN/prefixes" | \
    jq -r '.data.ipv6_prefixes[] | "  \(.prefix)"' 2>/dev/null || echo "  None"

# Peers
echo -e "\n[*] Peering Relationships"
echo "=========================="

echo "Upstream Providers:"
curl -s "https://api.bgpview.io/asn/$ASN/upstreams" | \
    jq -r '.data.ipv4_upstreams[:5][] | "  AS\(.asn) - \(.name)"'

echo -e "\nPeers:"
curl -s "https://api.bgpview.io/asn/$ASN/peers" | \
    jq -r '.data.ipv4_peers[:5][] | "  AS\(.asn) - \(.name)"'

# Summary
echo -e "\n[*] Quick Stats"
echo "================"
PREFIXES=$(curl -s "https://api.bgpview.io/asn/$ASN/prefixes" | jq '.data.ipv4_prefixes | length')
UPSTREAMS=$(curl -s "https://api.bgpview.io/asn/$ASN/upstreams" | jq '.data.ipv4_upstreams | length')
echo "IPv4 Prefixes: $PREFIXES"
echo "Upstream Providers: $UPSTREAMS"
```

### 16.4 CDN Bypass Automation

```python
#!/usr/bin/env python3
# cdn_bypass.py - Automated CDN origin discovery
# Usage: python3 cdn_bypass.py target.com

import sys
import dns.resolver
import requests
import json
from concurrent.futures import ThreadPoolExecutor

# CDN IP ranges (partial - update as needed)
CDN_RANGES = {
    'cloudflare': ['104.16.', '104.17.', '104.18.', '172.64.', '172.65.', '131.0.72.'],
    'akamai': ['23.', '104.64.', '104.65.'],
    'fastly': ['151.101.', '199.232.'],
    'cloudfront': ['13.32.', '13.224.', '13.225.', '52.46.', '52.84.', '52.85.'],
    'azure': ['13.107.', '204.79.']
}

def is_cdn_ip(ip):
    """Check if IP belongs to known CDN ranges"""
    for cdn, ranges in CDN_RANGES.items():
        for r in ranges:
            if ip.startswith(r):
                return cdn
    return None

def resolve_domain(domain):
    """Resolve domain to IP addresses"""
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [str(r) for r in answers]
    except:
        return []

def check_subdomain(args):
    """Check if subdomain resolves to non-CDN IP"""
    subdomain, domain = args
    fqdn = f"{subdomain}.{domain}"
    ips = resolve_domain(fqdn)
    results = []
    for ip in ips:
        cdn = is_cdn_ip(ip)
        results.append({
            'subdomain': fqdn,
            'ip': ip,
            'cdn': cdn,
            'potential_origin': cdn is None
        })
    return results

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    print(f"\n{'='*50}")
    print(f"  CDN Bypass Analysis: {domain}")
    print(f"{'='*50}\n")

    # Check main domain
    print("[*] Checking main domain...")
    main_ips = resolve_domain(domain)
    for ip in main_ips:
        cdn = is_cdn_ip(ip)
        status = f"CDN ({cdn})" if cdn else "Direct/Origin"
        print(f"    {domain} -> {ip} [{status}]")

    # Common subdomains that often bypass CDN
    subdomains = [
        'mail', 'webmail', 'smtp', 'pop', 'imap',
        'ftp', 'sftp', 'direct', 'origin', 'backend',
        'dev', 'staging', 'test', 'uat', 'qa',
        'api', 'api-internal', 'internal',
        'vpn', 'remote', 'gateway',
        'admin', 'panel', 'cpanel', 'whm',
        'ns1', 'ns2', 'dns',
        'www2', 'www-old', 'old', 'legacy'
    ]

    print(f"\n[*] Checking {len(subdomains)} common subdomains...")
    potential_origins = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        args = [(sub, domain) for sub in subdomains]
        # ... (continues with result collection and reporting)

if __name__ == "__main__":
    main()
```

> **Note:** The script continues with result aggregation, origin verification via HTTP requests with Host headers, and a summary report of all potential origin IPs discovered.

### 16.5 IP Enrichment Pipeline

```python
#!/usr/bin/env python3
# ip_enrich.py - Complete IP enrichment pipeline
# Usage: python3 ip_enrich.py 192.0.2.100

import sys
import json
import requests
import dns.resolver
import dns.reversename

def get_reverse_dns(ip):
    """Get PTR record for IP"""
    try:
        addr = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(addr, 'PTR')
        return str(answers[0]).rstrip('.')
    except:
        return None

def get_ipinfo(ip):
    """Query ipinfo.io for IP details"""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        return r.json()
    except:
        return {}

def get_shodan_host(ip, api_key=None):
    """Query Shodan for host details (requires API key)"""
    if not api_key:
        return {"error": "No Shodan API key provided"}
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=10
        )
        return r.json()
    except:
        return {}

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <IP>")
        sys.exit(1)

    ip = sys.argv[1]

    print(f"\n{'='*60}")
    print(f"  IP Enrichment Report: {ip}")
    print(f"{'='*60}")

    # Reverse DNS
    print("\n[1] Reverse DNS")
    print("-" * 40)
    rdns = get_reverse_dns(ip)
    print(f"    PTR Record: {rdns or 'None'}")

    # IPInfo
    print("\n[2] IP Information")
    print("-" * 40)
    info = get_ipinfo(ip)
    print(f"    City: {info.get('city', 'Unknown')}")
    print(f"    Region: {info.get('region', 'Unknown')}")
    print(f"    Country: {info.get('country', 'Unknown')}")
    print(f"    Organization: {info.get('org', 'Unknown')}")
    print(f"    Location: {info.get('loc', 'Unknown')}")

    # ASN Details
    if 'org' in info:
        org = info['org']
        if org.startswith('AS'):
            asn = org.split()[0]
            print(f"\n[3] ASN Details ({asn})")
            print("-" * 40)
            # Could expand with BGPView API query

    # Summary
    print(f"\n{'='*60}")
    print("  Enrichment Summary")
    print(f"{'='*60}")
    print(f"""
    IP Address:   {ip}
    Hostname:     {rdns or 'N/A'}
    Location:     {info.get('city', '?')}, {info.get('region', '?')}, {info.get('country', '?')}
    Organization: {info.get('org', 'Unknown')}
    Coordinates:  {info.get('loc', 'Unknown')}
    """)

    print("[*] For full service enumeration, use Shodan:")
    print(f"    shodan host {ip}")

if __name__ == "__main__":
    main()
```

---

## Chapter 17: Detection Risk Matrix

### Understanding What Generates Logs

Not all recon is created equal. Some of it is completely invisible to the target, some of it leaves traces, and some of it basically announces you're there. Here's how it breaks down:

| Activity | Detection Risk | Target Logs |
|---|---|---|
| Query Shodan/Censys | ZERO | No |
| Read CT logs (crt.sh) | ZERO | No |
| Analyze BGP (bgp.he.net) | ZERO | No |
| Search LinkedIn | ZERO | No (LinkedIn logs) |
| Google dorking | ZERO | No (Google logs) |
| Query public DNS resolver | ZERO | No (resolver logs) |
| SecurityTrails queries | ZERO | No |
| Query target's DNS server | MINIMAL | Yes, but normal |
| Visit target website | MINIMAL | Yes, but normal |
| Download public documents | MINIMAL | Yes, but normal |
| Port scanning | HIGH | Yes, anomalous |
| Vulnerability scanning | HIGH | Yes, alerts likely |
| Brute force attempts | VERY HIGH | Yes, lockouts |

> **The professional approach:** Stay in the ZERO and MINIMAL categories. Build your intelligence picture without tipping anyone off. Active techniques come later — only when you're authorized, and only after you've squeezed everything you can out of passive collection.

---

# Conclusion

That's the full picture of the pre-attack reconnaissance phase — both the thinking behind it and how to actually execute.

**What you should take away from this:**

Your firewall, IDS, SIEM, and EDR can't see any of this happening. None of it. An adversary gathering intelligence from public sources is completely invisible to your security stack. That's not a configuration problem — it's structural. The internet *requires* public DNS, BGP announcements, certificate transparency, and business registrations. You can't change that.

Sophisticated adversaries know this and they exploit it. They build complete target packages before they ever touch your network. Weeks of quiet research, then a precise attack that walks right past your monitoring.

So what do you do about it? Run these techniques against yourself. See what's out there. Understand your own exposure before someone else maps it out for you.

The pre-attack phase is where sophisticated operations succeed or fail. Whether you're on offense or defense, understanding this stuff isn't optional — it's table stakes.

> This document is intended for authorized security professionals conducting defensive assessments, red team operations, and threat intelligence analysis.
