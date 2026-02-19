#!/usr/bin/env python3
# favicon_hash.py - Find origin servers by favicon fingerprint
# Description: Calculates the MurmurHash3 of a website's favicon.ico file.
#              The resulting hash can be used in Shodan to find all servers
#              presenting the same favicon, including origin servers not
#              behind CDN protection.
# Usage: python3 favicon_hash.py target.com
#        python3 favicon_hash.py https://target.com/favicon.ico
#
# Dependencies: mmh3, requests
#   pip install mmh3 requests
#
# The Shodan query  http.favicon.hash:<hash>  will reveal:
#   - CDN edge servers (expected)
#   - Origin servers (CDN bypass!)
#   - Development/staging servers

import sys
import codecs
import warnings

try:
    import mmh3
except ImportError:
    print("[!] Missing dependency: mmh3")
    print("    Install with: pip install mmh3")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] Missing dependency: requests")
    print("    Install with: pip install requests")
    sys.exit(1)

# Suppress InsecureRequestWarning when using verify=False
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


def get_favicon_hash(domain):
    """Calculate MurmurHash3 of favicon for Shodan search"""
    try:
        # Build URL - support both domain and full URL input
        if domain.startswith('http://') or domain.startswith('https://'):
            url = domain
        else:
            url = f'https://{domain}/favicon.ico'

        # Get favicon
        response = requests.get(url, timeout=10, verify=False)
        if response.status_code == 200:
            # Base64 encode and hash (Shodan's method)
            favicon_b64 = codecs.encode(response.content, 'base64')
            favicon_hash = mmh3.hash(favicon_b64)
            return favicon_hash, len(response.content)
        else:
            print(f"[-] HTTP {response.status_code} fetching favicon from {url}")
            return None, 0
    except Exception as e:
        print(f"[-] Error: {e}")
        return None, 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        print(f"       {sys.argv[0]} <full_favicon_url>")
        print(f"\nExamples:")
        print(f"  {sys.argv[0]} target.com")
        print(f"  {sys.argv[0]} https://target.com/favicon.ico")
        sys.exit(1)

    domain = sys.argv[1]
    hash_value, size = get_favicon_hash(domain)

    if hash_value:
        print(f"\nDomain:       {domain}")
        print(f"Favicon Size: {size} bytes")
        print(f"Favicon Hash: {hash_value}")
        print(f"\nShodan Query: http.favicon.hash:{hash_value}")
        print(f"Shodan URL:   https://www.shodan.io/search?query=http.favicon.hash%3A{hash_value}")
        print(f"\nThis query will find ALL servers with the same favicon,")
        print(f"including origin servers not behind CDN protection.")
        print(f"\nLook for IPs NOT in known CDN ranges:")
        print(f"  - Cloudflare: 104.16.0.0/12, 172.64.0.0/13")
        print(f"  - Akamai:     23.0.0.0/8 (partial)")
        print(f"  - Fastly:     151.101.0.0/16")
        print(f"  - CloudFront: 13.32.0.0/15, 13.224.0.0/14")
    else:
        print(f"\n[-] Could not calculate favicon hash for {domain}")
        print(f"    Try specifying the full URL to the favicon:")
        print(f"    {sys.argv[0]} https://{domain}/path/to/favicon.ico")
