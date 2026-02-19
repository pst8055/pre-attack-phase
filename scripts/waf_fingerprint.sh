#!/bin/bash
# waf_fingerprint.sh - Identify WAF by response to malicious payloads
# Description: Sends common attack signatures (SQLi, XSS, path traversal,
#              command injection) and analyzes HTTP responses and headers
#              to identify the WAF/CDN vendor protecting the target.
# Usage: ./waf_fingerprint.sh https://target.com
#
# Dependencies: curl
#
# WAF vendors identified: Cloudflare, AWS WAF, Akamai, Imperva/Incapsula,
#                          ModSecurity, F5 BIG-IP ASM, Fortinet FortiWeb

set -e

TARGET="$1"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_url>"
    echo "  Example: $0 https://target.com"
    exit 1
fi

# Check required dependencies
if ! command -v curl &> /dev/null; then
    echo "[!] Required dependency not found: curl"
    exit 1
fi

echo "=== WAF Fingerprinting: $TARGET ==="
echo ""

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

# Command injection
echo "[*] Testing Command Injection..."
RESPONSE=$(curl -s -X POST "$TARGET" \
    -d "cmd=;cat /etc/passwd" \
    -w "\n%{http_code}" | tail -1)
echo "    Command injection: HTTP $RESPONSE"

# Unicode bypass attempt
echo "[*] Testing Unicode bypass..."
RESPONSE=$(curl -s -X POST "$TARGET" \
    -d "user=%u0027%20OR%20%u00271%u0027=%u00271" \
    -w "\n%{http_code}" | tail -1)
echo "    Unicode bypass: HTTP $RESPONSE"

# Check response headers for WAF signatures
echo ""
echo "[*] Checking response headers..."
HEADERS=$(curl -s -I -X POST "$TARGET" -d "test=value" 2>/dev/null)
echo "$HEADERS" | grep -iE "server|x-|cf-|via|akamai" || echo "    No WAF-specific headers found"

# WAF identification logic
echo ""
echo "[*] WAF Identification"
echo "======================"

# Cloudflare detection
if echo "$HEADERS" | grep -qi "cf-ray"; then
    echo "    [+] DETECTED: Cloudflare"
    echo "        Evidence: cf-ray header present"
    CF_RAY=$(echo "$HEADERS" | grep -i "cf-ray" | head -1)
    echo "        $CF_RAY"
fi

if echo "$HEADERS" | grep -qi "server: cloudflare"; then
    echo "    [+] DETECTED: Cloudflare"
    echo "        Evidence: server header = cloudflare"
fi

# AWS WAF detection
if echo "$HEADERS" | grep -qi "x-amzn-requestid"; then
    echo "    [+] DETECTED: AWS WAF / AWS infrastructure"
    echo "        Evidence: x-amzn-RequestId header present"
fi

# Akamai detection
if echo "$HEADERS" | grep -qi "x-akamai"; then
    echo "    [+] DETECTED: Akamai"
    echo "        Evidence: X-Akamai header present"
fi

# Imperva/Incapsula detection
if echo "$HEADERS" | grep -qi "x-cdn: imperva\|incap_ses\|visid_incap"; then
    echo "    [+] DETECTED: Imperva/Incapsula"
    echo "        Evidence: Imperva headers present"
fi

# F5 BIG-IP detection
if echo "$HEADERS" | grep -qi "x-wa-info\|bigipserver"; then
    echo "    [+] DETECTED: F5 BIG-IP ASM"
    echo "        Evidence: F5-specific headers present"
fi

# Check response body for WAF signatures
echo ""
echo "[*] Checking response body for WAF signatures..."
BODY=$(curl -s -X POST "$TARGET" -d "user=admin' OR '1'='1'--" 2>/dev/null)

if echo "$BODY" | grep -qi "attention required\|ray id"; then
    echo "    [+] Cloudflare block page detected"
fi

if echo "$BODY" | grep -qi "request unsuccessful\|incident id"; then
    echo "    [+] Imperva/Incapsula block page detected"
fi

if echo "$BODY" | grep -qi "modsecurity\|mod_security"; then
    echo "    [+] ModSecurity block page detected"
fi

if echo "$BODY" | grep -qi "the requested url was rejected\|support id"; then
    echo "    [+] F5 BIG-IP ASM block page detected"
fi

if echo "$BODY" | grep -qi "fortiweb\|fortinet"; then
    echo "    [+] Fortinet FortiWeb block page detected"
fi

if echo "$BODY" | grep -qi "request blocked\|access denied"; then
    echo "    [+] Generic WAF block detected (vendor unclear)"
fi

echo ""
echo "[*] WAF fingerprinting complete."
echo ""
echo "WAF Signature Reference:"
echo "  Cloudflare  - cf-ray header, server: cloudflare, 'Attention Required!' page"
echo "  AWS WAF     - x-amzn-RequestId, HTTP 403 minimal body"
echo "  Akamai      - X-Akamai-Transformed, reference ID in error"
echo "  Imperva     - X-CDN: Imperva, 'Request unsuccessful' page"
echo "  ModSecurity - Rule ID in block, 'ModSecurity' in error"
echo "  F5 BIG-IP   - X-WA-Info, 'The requested URL was rejected'"
echo "  FortiWeb    - Fortinet branding in block page"
