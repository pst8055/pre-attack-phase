#!/bin/bash
# full_recon.sh - Complete domain reconnaissance pipeline
# Description: Chains multiple OSINT tools together to perform full domain recon
#              including subdomain enumeration, DNS resolution, record analysis,
#              SPF parsing, Shodan lookups, IP enrichment, and summary reporting.
# Usage: ./full_recon.sh target.com
#
# Dependencies: curl, jq, dig
# Optional:     subfinder, amass, dnsx, shodan (CLI)
#
# Output: Creates a timestamped directory with all findings

set -e

TARGET=$1
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Check required dependencies
for cmd in curl jq dig; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[!] Required dependency not found: $cmd"
        exit 1
    fi
done

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

# Phase 3: DNS Record Analysis
echo -e "\n[Phase 3] DNS Record Analysis"
echo "=============================="

echo "[*] Querying DNS records..."
{
    echo "=== A Records ==="
    dig +short A "$TARGET"

    echo -e "\n=== AAAA Records ==="
    dig +short AAAA "$TARGET"

    echo -e "\n=== MX Records ==="
    dig +short MX "$TARGET"

    echo -e "\n=== NS Records ==="
    dig +short NS "$TARGET"

    echo -e "\n=== TXT Records ==="
    dig +short TXT "$TARGET"

    echo -e "\n=== SOA Record ==="
    dig +short SOA "$TARGET"

    echo -e "\n=== CNAME Records ==="
    dig +short CNAME "www.$TARGET"
} > "$OUTPUT/dns_records.txt"

echo "[+] DNS records saved to $OUTPUT/dns_records.txt"

# Phase 4: SPF Record Analysis
echo -e "\n[Phase 4] SPF Record Analysis"
echo "=============================="

echo "[*] Extracting SPF records..."
SPF_RECORD=$(dig +short TXT "$TARGET" | grep -i "spf" || true)

if [ -n "$SPF_RECORD" ]; then
    echo "[+] SPF Record found: $SPF_RECORD"
    {
        echo "=== SPF Record ==="
        echo "$SPF_RECORD"
        echo ""

        # Extract ip4 entries (potential origin IPs)
        echo "=== IPv4 Entries (potential origin IPs) ==="
        echo "$SPF_RECORD" | grep -oP 'ip4:[^\s"]+' | sed 's/ip4://' || true

        # Extract ip6 entries
        echo -e "\n=== IPv6 Entries ==="
        echo "$SPF_RECORD" | grep -oP 'ip6:[^\s"]+' | sed 's/ip6://' || true

        # Extract include entries (third-party senders)
        echo -e "\n=== Include Entries (third-party services) ==="
        echo "$SPF_RECORD" | grep -oP 'include:[^\s"]+' | sed 's/include://' || true

        # Recursively resolve includes
        echo -e "\n=== Resolved Includes ==="
        for include in $(echo "$SPF_RECORD" | grep -oP 'include:[^\s"]+' | sed 's/include://'); do
            echo "  $include:"
            dig +short TXT "$include" 2>/dev/null | head -3
        done
    } > "$OUTPUT/spf_analysis.txt"
    echo "[+] SPF analysis saved to $OUTPUT/spf_analysis.txt"
else
    echo "[-] No SPF record found"
    echo "No SPF record found for $TARGET" > "$OUTPUT/spf_analysis.txt"
fi

# Phase 5: Shodan Lookup (if CLI available)
echo -e "\n[Phase 5] Shodan Lookup"
echo "========================"

if command -v shodan &> /dev/null; then
    echo "[*] Querying Shodan for discovered IPs..."
    {
        echo "=== Shodan Host Data ==="
        echo ""
        while read ip; do
            echo "--- $ip ---"
            shodan host "$ip" 2>/dev/null || echo "  No Shodan data available"
            echo ""
        done < "$OUTPUT/unique_ips.txt"
    } > "$OUTPUT/shodan_results.txt"
    echo "[+] Shodan results saved to $OUTPUT/shodan_results.txt"

    # Also search for the domain
    echo "[*] Searching Shodan for domain references..."
    shodan search "hostname:$TARGET" --fields ip_str,port,org,hostnames 2>/dev/null \
        > "$OUTPUT/shodan_domain_search.txt" || true
    echo "[+] Shodan domain search saved"
else
    echo "[-] Shodan CLI not installed. Skipping."
    echo "    Install with: pip install shodan && shodan init <API_KEY>"
    echo "Shodan CLI not available - skipping" > "$OUTPUT/shodan_results.txt"
fi

# Phase 6: IP Enrichment
echo -e "\n[Phase 6] IP Enrichment"
echo "========================"

echo "[*] Enriching discovered IP addresses..."
{
    echo "=== IP Enrichment Report ==="
    echo "Domain: $TARGET"
    echo "Date: $(date)"
    echo ""

    while read ip; do
        echo "--- $ip ---"

        # Reverse DNS
        RDNS=$(dig +short -x "$ip" 2>/dev/null | head -1)
        echo "  Reverse DNS: ${RDNS:-None}"

        # IPinfo lookup (free tier, no key required)
        IPINFO=$(curl -s "https://ipinfo.io/$ip/json" 2>/dev/null)
        if [ -n "$IPINFO" ]; then
            ORG=$(echo "$IPINFO" | jq -r '.org // "Unknown"' 2>/dev/null)
            CITY=$(echo "$IPINFO" | jq -r '.city // "Unknown"' 2>/dev/null)
            COUNTRY=$(echo "$IPINFO" | jq -r '.country // "Unknown"' 2>/dev/null)
            echo "  Organization: $ORG"
            echo "  Location: $CITY, $COUNTRY"
        fi

        echo ""
        # Rate limit: small delay between requests
        sleep 0.5
    done < "$OUTPUT/unique_ips.txt"
} > "$OUTPUT/ip_enrichment.txt"

echo "[+] IP enrichment saved to $OUTPUT/ip_enrichment.txt"

# Phase 7: Summary Report
echo -e "\n[Phase 7] Summary Report Generation"
echo "====================================="

echo "[*] Generating summary report..."

{
    echo "=============================================="
    echo "  OSINT Reconnaissance Summary Report"
    echo "  Target: $TARGET"
    echo "  Date:   $(date)"
    echo "=============================================="
    echo ""

    echo "[1] Subdomain Enumeration"
    echo "    Total unique subdomains: $TOTAL_SUBS"
    echo "    Sources used: crt.sh$(command -v subfinder &>/dev/null && echo ', subfinder')$(command -v amass &>/dev/null && echo ', amass')"
    echo ""

    echo "[2] DNS Resolution"
    echo "    Unique IPs discovered: $TOTAL_IPS"
    echo ""

    echo "[3] DNS Records"
    echo "    A Records:  $(dig +short A "$TARGET" | wc -l)"
    echo "    MX Records: $(dig +short MX "$TARGET" | wc -l)"
    echo "    NS Records: $(dig +short NS "$TARGET" | wc -l)"
    echo "    TXT Records: $(dig +short TXT "$TARGET" | wc -l)"
    echo ""

    echo "[4] SPF Analysis"
    if [ -n "$SPF_RECORD" ]; then
        IP4_COUNT=$(echo "$SPF_RECORD" | grep -oP 'ip4:[^\s"]+' | wc -l)
        INCLUDE_COUNT=$(echo "$SPF_RECORD" | grep -oP 'include:[^\s"]+' | wc -l)
        echo "    SPF Record: Present"
        echo "    IPv4 entries: $IP4_COUNT"
        echo "    Include entries: $INCLUDE_COUNT"
    else
        echo "    SPF Record: Not found"
    fi
    echo ""

    echo "[5] Shodan"
    if command -v shodan &> /dev/null; then
        echo "    Results: See $OUTPUT/shodan_results.txt"
    else
        echo "    Status: CLI not available (skipped)"
    fi
    echo ""

    echo "[6] IP Enrichment"
    echo "    Enriched IPs: $TOTAL_IPS"
    echo "    Details: See $OUTPUT/ip_enrichment.txt"
    echo ""

    echo "=============================================="
    echo "  Files Generated"
    echo "=============================================="
    ls -la "$OUTPUT/"
    echo ""
    echo "=============================================="
    echo "  Reconnaissance Complete"
    echo "=============================================="
} > "$OUTPUT/summary_report.txt"

# Print summary to stdout as well
cat "$OUTPUT/summary_report.txt"

echo ""
echo "[*] All results saved to: $OUTPUT/"
echo "[*] Reconnaissance complete."
