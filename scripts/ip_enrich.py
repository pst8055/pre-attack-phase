#!/usr/bin/env python3
# ip_enrich.py - Complete IP enrichment pipeline
# Description: Takes an IP address and enriches it with reverse DNS, geolocation,
#              organization data, and optional Shodan host information.
# Usage: python3 ip_enrich.py 192.0.2.100
#        python3 ip_enrich.py 192.0.2.100 --shodan-key YOUR_API_KEY
#
# Dependencies: dnspython, requests
#   pip install dnspython requests
#
# Example output uses RFC 5737 documentation IPs:
#   192.0.2.x, 198.51.100.x, 203.0.113.x

import sys
import json
import os

try:
    import requests
except ImportError:
    print("[!] Missing dependency: requests")
    print("    Install with: pip install requests")
    sys.exit(1)

try:
    import dns.resolver
    import dns.reversename
except ImportError:
    print("[!] Missing dependency: dnspython")
    print("    Install with: pip install dnspython")
    sys.exit(1)


def get_reverse_dns(ip):
    """Get PTR record for IP"""
    try:
        addr = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(addr, 'PTR')
        return str(answers[0]).rstrip('.')
    except Exception:
        return None


def get_ipinfo(ip):
    """Query ipinfo.io for IP details"""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        return r.json()
    except Exception:
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
    except Exception:
        return {}


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <IP>")
        print(f"       {sys.argv[0]} <IP> --shodan-key <KEY>")
        sys.exit(1)

    ip = sys.argv[1]

    # Parse optional Shodan API key from arguments or environment
    shodan_key = os.environ.get("SHODAN_API_KEY")
    if "--shodan-key" in sys.argv:
        key_idx = sys.argv.index("--shodan-key") + 1
        if key_idx < len(sys.argv):
            shodan_key = sys.argv[key_idx]

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
            try:
                r = requests.get(
                    f"https://api.bgpview.io/asn/{asn.lstrip('AS')}",
                    timeout=10
                )
                asn_data = r.json().get('data', {})
                print(f"    Name: {asn_data.get('name', 'Unknown')}")
                print(f"    Description: {asn_data.get('description_short', 'Unknown')}")
                print(f"    Country: {asn_data.get('rir_allocation', {}).get('country_code', 'Unknown')}")
            except Exception:
                print("    Could not fetch ASN details from BGPView")

    # Shodan lookup (if key available)
    if shodan_key:
        print(f"\n[4] Shodan Host Data")
        print("-" * 40)
        shodan_data = get_shodan_host(ip, shodan_key)
        if "error" not in shodan_data:
            print(f"    OS: {shodan_data.get('os', 'Unknown')}")
            print(f"    Ports: {shodan_data.get('ports', [])}")
            print(f"    Hostnames: {shodan_data.get('hostnames', [])}")
            print(f"    Vulns: {shodan_data.get('vulns', 'None reported')}")
            # Show service banners
            for service in shodan_data.get('data', [])[:5]:
                port = service.get('port', '?')
                product = service.get('product', 'unknown')
                version = service.get('version', '')
                print(f"    Service: {port}/tcp - {product} {version}")
        else:
            print(f"    Error: {shodan_data.get('error', 'Unknown error')}")
    else:
        print(f"\n[4] Shodan Host Data")
        print("-" * 40)
        print("    Skipped (no API key)")
        print("    Set SHODAN_API_KEY env var or use --shodan-key flag")

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
