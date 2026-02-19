#!/bin/bash
# content_type_fingerprint.sh - Test Content-Type handling for framework fingerprinting
# Description: Sends the same POST body with different Content-Type headers to
#              identify the backend framework based on how it parses or rejects
#              each type. Different frameworks have distinctive acceptance patterns.
# Usage: ./content_type_fingerprint.sh https://target.com/api/endpoint
#
# Dependencies: curl
#
# Interpretation guide:
#   - Only application/json accepted (415 for others) -> Strict modern API
#   - JSON and XML both accepted -> Multiple parsers, check for XXE
#   - All types return 200 -> Permissive parsing, potential type confusion
#   - Form data treated as JSON -> Framework auto-detection (Express, FastAPI)
#   - Different errors per type -> Parse each error for version disclosure

set -e

TARGET="${1:-https://target.com/api/endpoint}"
BODY='{"test":"value"}'

if [ "$TARGET" = "https://target.com/api/endpoint" ] && [ -z "$1" ]; then
    echo "Usage: $0 <target_url>"
    echo "  Example: $0 https://target.com/api/endpoint"
    exit 1
fi

# Check required dependencies
if ! command -v curl &> /dev/null; then
    echo "[!] Required dependency not found: curl"
    exit 1
fi

echo "=== Content-Type Fingerprinting ==="
echo "Target: $TARGET"
echo ""

# Phase 1: Standard Content-Type testing
echo "[Phase 1] Standard Content-Type Responses"
echo "==========================================="

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

# Phase 2: Type confusion testing
echo ""
echo "[Phase 2] Type Confusion Tests"
echo "================================"

# Send string where number expected
echo "[*] String where number expected:"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"user_id": "not_a_number"}')
echo "    {\"user_id\": \"not_a_number\"} -> HTTP $RESPONSE"

# Send object where string expected
echo "[*] Object where string expected:"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"query": {"nested": "object"}}')
echo "    {\"query\": {\"nested\": \"object\"}} -> HTTP $RESPONSE"

# Send very large number
echo "[*] Very large number:"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"amount": 99999999999999999999999999}')
echo "    {\"amount\": 99999999999999999999999999} -> HTTP $RESPONSE"

# Send empty array
echo "[*] Empty array as body:"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '[]')
echo "    [] -> HTTP $RESPONSE"

# Phase 3: Error message extraction
echo ""
echo "[Phase 3] Error Message Analysis"
echo "================================="

echo "[*] Sending malformed JSON to extract error details..."
ERROR_BODY=$(curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{invalid json}' 2>/dev/null | head -20)

if [ -n "$ERROR_BODY" ]; then
    echo "    Response body (first 500 chars):"
    echo "    ${ERROR_BODY:0:500}"
    echo ""

    # Check for framework signatures in error response
    echo "[*] Framework signature detection:"

    if echo "$ERROR_BODY" | grep -qi "django\|traceback.*views.py\|csrfmiddleware"; then
        echo "    [+] Django/Python detected"
    fi

    if echo "$ERROR_BODY" | grep -qi "syntaxerror.*json\|node_modules\|express"; then
        echo "    [+] Express/Node.js detected"
    fi

    if echo "$ERROR_BODY" | grep -qi "JSON parse error\|springframework\|java\.\|spring boot"; then
        echo "    [+] Spring/Java detected"
    fi

    if echo "$ERROR_BODY" | grep -qi "whoops\|laravel\|symfony\|illuminate"; then
        echo "    [+] Laravel/PHP detected"
    fi

    if echo "$ERROR_BODY" | grep -qi "asp\.net\|__dopostback\|viewstate\|\.net"; then
        echo "    [+] ASP.NET detected"
    fi

    if echo "$ERROR_BODY" | grep -qi "fastapi\|pydantic\|starlette"; then
        echo "    [+] FastAPI/Python detected"
    fi

    if echo "$ERROR_BODY" | grep -qi "gin-gonic\|gorilla\|go-chi"; then
        echo "    [+] Go framework detected"
    fi

    if echo "$ERROR_BODY" | grep -qi "rails\|activerecord\|actioncontroller"; then
        echo "    [+] Ruby on Rails detected"
    fi
else
    echo "    No error body returned (may indicate strict input validation)"
fi

echo ""
echo "[*] Content-Type fingerprinting complete."
echo ""
echo "Interpretation Guide:"
echo "  415 Unsupported Media Type = Strict type checking (modern framework)"
echo "  400 Bad Request            = Parser attempted, type recognized"
echo "  200 OK for all types       = Permissive/no type validation"
echo "  500 Internal Server Error  = Parser crash (potential vulnerability)"
echo "  Different errors per type  = Multiple parsers, examine each error"
