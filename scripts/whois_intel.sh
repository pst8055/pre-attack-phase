#!/bin/bash
# whois_intel.sh - Extract intelligence from WHOIS records
# Description: Queries WHOIS databases for ASN details, organization info,
#              announced prefixes, and contact details (admin and technical).
#              Uses RIPE and RADB WHOIS servers for comprehensive coverage.
# Usage: ./whois_intel.sh 12345
#        ./whois_intel.sh AS12345
#
# Dependencies: whois
#
# Example output uses RFC 5737 documentation ranges:
#   192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24

set -e

ASN=$1

if [ -z "$ASN" ]; then
    echo "Usage: $0 <ASN>"
    echo "  Example: $0 12345"
    echo "  Example: $0 AS12345"
    exit 1
fi

# Check required dependencies
if ! command -v whois &> /dev/null; then
    echo "[!] Required dependency not found: whois"
    echo "    Install with: apt install whois"
    exit 1
fi

# Remove AS prefix if present
ASN=${ASN#AS}

echo "=== WHOIS Intelligence for AS$ASN ==="

# Get ASN details
echo -e "\n[*] ASN Details:"
whois -h whois.ripe.net "AS$ASN" | grep -E "^(as-name|descr|org|admin-c|tech-c|mnt):" || \
    echo "    No RIPE data found (ASN may be in a different registry)"

# Get organization
ORG=$(whois -h whois.ripe.net "AS$ASN" | grep "^org:" | awk '{print $2}')
if [ -n "$ORG" ]; then
    echo -e "\n[*] Organization Details ($ORG):"
    whois -h whois.ripe.net "$ORG" | grep -E "^(org-name|address|phone|e-mail|country):"
fi

# Get all prefixes
echo -e "\n[*] Announced Prefixes:"
PREFIXES=$(whois -h whois.radb.net -- "-i origin AS$ASN" | grep "^route:" | awk '{print $2}')
if [ -n "$PREFIXES" ]; then
    echo "$PREFIXES"
    PREFIX_COUNT=$(echo "$PREFIXES" | wc -l)
    echo "    Total: $PREFIX_COUNT prefixes"
else
    echo "    No prefixes found in RADB"
fi

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

# Try ARIN as fallback for non-RIPE ASNs
if [ -z "$ORG" ] && [ -z "$ADMIN" ]; then
    echo -e "\n[*] Trying ARIN registry (fallback)..."
    whois -h whois.arin.net "AS$ASN" | grep -iE "^(orgname|orgid|address|city|stateprov|country|phone|email|netrange|cidr):" || \
        echo "    No ARIN data found"
fi

# Try APNIC as fallback
if [ -z "$ORG" ] && [ -z "$ADMIN" ]; then
    echo -e "\n[*] Trying APNIC registry (fallback)..."
    whois -h whois.apnic.net "AS$ASN" | grep -E "^(as-name|descr|admin-c|tech-c|org|country):" || \
        echo "    No APNIC data found"
fi

echo -e "\n[*] WHOIS intelligence gathering complete for AS$ASN"
echo ""
echo "Intelligence Value:"
echo "  - Contact names    -> Social engineering targets"
echo "  - Phone numbers    -> Vishing opportunities"
echo "  - Network naming   -> Reveals purpose (PROD, DR, DEV)"
echo "  - Email addresses  -> Phishing targets, org structure"
echo "  - Prefix count     -> Organization size indicator"
