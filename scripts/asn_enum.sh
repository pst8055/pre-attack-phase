#!/bin/bash
# asn_enum.sh - Complete ASN enumeration using BGPView API
# Description: Queries the BGPView API to enumerate all prefixes, peering
#              relationships, and organizational details for a given ASN.
# Usage: ./asn_enum.sh AS12345
#        ./asn_enum.sh 12345
#
# Dependencies: curl, jq
#
# Example output uses RFC 5737 documentation ranges:
#   192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24

set -e

ASN=$1
if [ -z "$ASN" ]; then
    echo "Usage: $0 <ASN>"
    echo "  Example: $0 AS12345"
    echo "  Example: $0 12345"
    exit 1
fi

# Check required dependencies
for cmd in curl jq; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[!] Required dependency not found: $cmd"
        echo "    Install with your package manager (e.g., apt install $cmd)"
        exit 1
    fi
done

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

# Downstream
echo -e "\nDownstream ASNs:"
curl -s "https://api.bgpview.io/asn/$ASN/downstreams" | \
    jq -r '.data.ipv4_downstreams[:5][] | "  AS\(.asn) - \(.name)"' 2>/dev/null || echo "  None"

# Summary
echo -e "\n[*] Quick Stats"
echo "================"
PREFIXES=$(curl -s "https://api.bgpview.io/asn/$ASN/prefixes" | jq '.data.ipv4_prefixes | length')
UPSTREAMS=$(curl -s "https://api.bgpview.io/asn/$ASN/upstreams" | jq '.data.ipv4_upstreams | length')
PEERS=$(curl -s "https://api.bgpview.io/asn/$ASN/peers" | jq '.data.ipv4_peers | length')
DOWNSTREAMS=$(curl -s "https://api.bgpview.io/asn/$ASN/downstreams" | jq '.data.ipv4_downstreams | length' 2>/dev/null || echo "0")

echo "IPv4 Prefixes: $PREFIXES"
echo "Upstream Providers: $UPSTREAMS"
echo "Peers: $PEERS"
echo "Downstream ASNs: $DOWNSTREAMS"

echo ""
echo "[*] Enumeration complete for AS$ASN"
