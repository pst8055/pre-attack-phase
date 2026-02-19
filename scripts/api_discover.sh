#!/bin/bash
# api_discover.sh - API endpoint discovery with method testing
# Description: Enumerates common API endpoints by testing multiple HTTP methods
#              against a target base URL. Also tests for GraphQL endpoints.
#              Non-404 responses indicate valid endpoints worth investigating.
# Usage: ./api_discover.sh https://target.com/api
#
# Dependencies: curl
#
# Tests: GET, POST, PUT, DELETE against common REST API paths
#        GraphQL introspection on common GraphQL endpoint paths

set -e

TARGET="${1:-https://target.com/api}"

if [ "$TARGET" = "https://target.com/api" ] && [ -z "$1" ]; then
    echo "Usage: $0 <target_api_base>"
    echo "  Example: $0 https://target.com/api"
    exit 1
fi

# Check required dependencies
if ! command -v curl &> /dev/null; then
    echo "[!] Required dependency not found: curl"
    exit 1
fi

# Common API endpoints to test
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
echo "Testing ${#ENDPOINTS[@]} endpoints x 4 methods"
echo ""

FOUND=0

for endpoint in "${ENDPOINTS[@]}"; do
    for method in GET POST PUT DELETE; do
        CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            -X "$method" "$TARGET/$endpoint" \
            -H "Content-Type: application/json" \
            -d '{}' \
            --connect-timeout 5 \
            --max-time 10 2>/dev/null)
        if [[ "$CODE" != "404" && "$CODE" != "000" ]]; then
            echo "$method $TARGET/$endpoint -> HTTP $CODE"
            FOUND=$((FOUND + 1))
        fi
    done
done

echo ""
echo "[+] Found $FOUND responsive endpoint/method combinations"

# GraphQL Detection
echo ""
echo "=== GraphQL Detection ==="
echo ""

GRAPHQL_PATHS=("graphql" "api/graphql" "v1/graphql" "query" "gql" "graphiql")

for path in "${GRAPHQL_PATHS[@]}"; do
    # Strip /api from TARGET if the path already includes it, to avoid /api/api/graphql
    BASE_URL=$(echo "$TARGET" | sed 's|/api$||')
    FULL_URL="$BASE_URL/$path"

    echo "[*] Testing $FULL_URL"

    # Test introspection query
    INTROSPECTION=$(curl -s -X POST "$FULL_URL" \
        -H "Content-Type: application/json" \
        -d '{"query":"{ __schema { types { name } } }"}' \
        --connect-timeout 5 \
        --max-time 10 2>/dev/null)

    if echo "$INTROSPECTION" | grep -q "__schema\|__typename\|types"; then
        echo "    [+] GraphQL endpoint found with introspection ENABLED!"
        echo "    [!] Full schema enumeration possible"
        echo "    Response preview: $(echo "$INTROSPECTION" | head -c 200)"
        echo ""
    fi

    # Also try simple typename query
    TYPENAME=$(curl -s -X POST "$FULL_URL" \
        -H "Content-Type: application/json" \
        -d '{"query":"{ __typename }"}' \
        --connect-timeout 5 \
        --max-time 10 2>/dev/null | head -1)

    if echo "$TYPENAME" | grep -q "Query\|Mutation\|data"; then
        echo "    [+] GraphQL endpoint confirmed at $FULL_URL"
        echo "    __typename response: $TYPENAME"
        echo ""
    fi
done

echo ""
echo "[*] API discovery complete."
echo ""
echo "Next steps for discovered endpoints:"
echo "  1. Test authentication requirements"
echo "  2. Check for IDOR with sequential IDs (e.g., /users/1, /users/2)"
echo "  3. Test rate limiting on auth endpoints"
echo "  4. Check OPTIONS method for CORS configuration"
echo "  5. For GraphQL: dump full schema if introspection is enabled"
