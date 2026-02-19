#!/usr/bin/env python3
# cdn_bypass.py - Automated CDN origin discovery
# Description: Attempts to discover the true origin IP behind a CDN by checking
#              common subdomains, SPF records, and historical DNS data for IPs
#              that fall outside known CDN ranges.
# Usage: python3 cdn_bypass.py target.com
#
# Dependencies: dnspython, requests
#   pip install dnspython requests
#
# Example output uses RFC 5737 documentation ranges:
#   192.0.2.x, 198.51.100.x, 203.0.113.x

import sys
import json
import socket

try:
    import dns.resolver
except ImportError:
    print("[!] Missing dependency: dnspython")
    print("    Install with: pip install dnspython")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] Missing dependency: requests")
    print("    Install with: pip install requests")
    sys.exit(1)

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
    except Exception:
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


def check_spf_records(domain):
    """Extract IPs from SPF records that may reveal origin servers"""
    origin_ips = []
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if 'spf' in txt.lower():
                print(f"\n[*] SPF Record: {txt}")
                # Extract ip4 entries
                parts = txt.split()
                for part in parts:
                    if part.startswith('ip4:'):
                        ip_or_range = part[4:]
                        cdn = is_cdn_ip(ip_or_range.split('/')[0])
                        if cdn is None:
                            origin_ips.append(ip_or_range)
                            print(f"    [+] Potential origin IP from SPF: {ip_or_range}")
                        else:
                            print(f"    [-] CDN IP in SPF ({cdn}): {ip_or_range}")
    except Exception as e:
        print(f"    [-] Could not retrieve SPF record: {e}")
    return origin_ips


def check_historical_dns(domain):
    """Suggest historical DNS lookup services for finding pre-CDN IPs"""
    print("\n[*] Historical DNS Suggestions")
    print("    Check these services for historical A records (pre-CDN IPs):")
    print(f"    - SecurityTrails: https://securitytrails.com/domain/{domain}/dns")
    print(f"    - ViewDNS:        https://viewdns.info/iphistory/?domain={domain}")
    print(f"    - DNSHistory:     https://completedns.com/dns-history/")
    print(f"    - Wayback/DNS:    Check archive.org for old DNS snapshots")


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
        results = executor.map(check_subdomain, args)

        for result_list in results:
            for result in result_list:
                if result['potential_origin']:
                    potential_origins.append(result)
                    print(f"    [+] {result['subdomain']} -> {result['ip']} [Potential Origin!]")
                elif result['cdn']:
                    print(f"    [-] {result['subdomain']} -> {result['ip']} [CDN: {result['cdn']}]")

    # Check SPF records for origin IPs
    print("\n[*] Checking SPF records for origin IPs...")
    spf_ips = check_spf_records(domain)
    for ip in spf_ips:
        potential_origins.append({
            'subdomain': f'SPF ({domain})',
            'ip': ip,
            'cdn': None,
            'potential_origin': True
        })

    # Suggest historical DNS lookups
    check_historical_dns(domain)

    # Summary of potential origin IPs
    print(f"\n{'='*50}")
    print("  Summary: Potential Origin IPs")
    print(f"{'='*50}")

    if potential_origins:
        # Deduplicate by IP
        seen_ips = set()
        unique_origins = []
        for origin in potential_origins:
            if origin['ip'] not in seen_ips:
                seen_ips.add(origin['ip'])
                unique_origins.append(origin)

        print(f"\n  Found {len(unique_origins)} unique potential origin IP(s):\n")
        for origin in unique_origins:
            print(f"    IP: {origin['ip']}")
            print(f"      Source: {origin['subdomain']}")
            print()

        print("  [*] Next steps:")
        print("      1. Verify by sending HTTP request with Host header:")
        print(f"         curl -H 'Host: {domain}' http://<origin_ip>/")
        print("      2. Compare response with CDN-served content")
        print("      3. Check SSL certificate on origin IP")
        print(f"         openssl s_client -connect <origin_ip>:443 -servername {domain}")
        print("      4. Search Shodan for these IPs for additional context")
    else:
        print("\n  No potential origin IPs found via subdomain or SPF checks.")
        print("  Try:")
        print("    - Historical DNS lookups (see suggestions above)")
        print("    - Favicon hash searching (see favicon_hash.py)")
        print("    - Email header analysis (send email to the domain)")
        print("    - SSL certificate search on censys.io or crt.sh")

    print()


if __name__ == "__main__":
    main()
