#!/bin/bash
# timing_fingerprint.sh - Timing-based reconnaissance
# Description: Identifies backend behavior through response timing analysis.
#              Sends payloads of varying size and complexity to detect:
#              - Input size limits (or lack thereof)
#              - Recursive parsing depth limits
#              - Array iteration limits
#              - Overall backend robustness
# Usage: ./timing_fingerprint.sh https://target.com/api/endpoint
#
# Dependencies: curl, python3 (for payload generation)
#
# Interpretation:
#   Large payload processed quickly    -> Size limits enforced (good security)
#   Large payload causes timeout       -> No size limit (potential DoS vector)
#   Deep nesting causes slow response  -> Recursive parsing (potential DoS)
#   Many array elements slow response  -> Iteration without limits (potential DoS)
#   Consistent timing regardless       -> Robust input handling, hardened target

set -e

TARGET="$1"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_url>"
    echo "  Example: $0 https://target.com/api/endpoint"
    exit 1
fi

# Check required dependencies
if ! command -v curl &> /dev/null; then
    echo "[!] Required dependency not found: curl"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "[!] Required dependency not found: python3 (used for payload generation)"
    exit 1
fi

echo "=== Timing-Based Fingerprinting ==="
echo "Target: $TARGET"
echo ""

# Test 1: Baseline (empty POST)
echo "=== Test 1: Baseline (empty POST) ==="
time curl -s -X POST "$TARGET" -d '' -o /dev/null 2>&1
echo ""

# Test 2: Large payload (~1MB)
echo "=== Test 2: Large payload (1MB) ==="
LARGE=$(python3 -c "print('x='+'A'*1000000)")
time curl -s -X POST "$TARGET" -d "$LARGE" -o /dev/null 2>&1
echo ""

# Test 3: Deeply nested JSON
echo "=== Test 3: Deeply nested JSON ==="
NESTED='{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":"deep"}}}}}}}}}}'
time curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d "$NESTED" -o /dev/null 2>&1
echo ""

# Test 4: Array with many elements
echo "=== Test 4: Array with many elements (10000) ==="
ARRAY=$(python3 -c "import json; print(json.dumps({'items': list(range(10000))}))")
time curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d "$ARRAY" -o /dev/null 2>&1
echo ""

# Test 5: Very deeply nested JSON (stress test)
echo "=== Test 5: Very deeply nested JSON (100 levels) ==="
DEEP_NESTED=$(python3 -c "
depth = 100
s = '{\"a\":' * depth + '\"deep\"' + '}' * depth
print(s)
")
time curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d "$DEEP_NESTED" -o /dev/null 2>&1
echo ""

# Test 6: Large JSON keys
echo "=== Test 6: Large JSON key names ==="
BIG_KEYS=$(python3 -c "
import json
d = {'A'*10000: 'value', 'B'*10000: 'value'}
print(json.dumps(d))
")
time curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d "$BIG_KEYS" -o /dev/null 2>&1
echo ""

# Test 7: Many small parameters (form data)
echo "=== Test 7: Many form parameters (1000) ==="
MANY_PARAMS=$(python3 -c "print('&'.join(f'param{i}=value{i}' for i in range(1000)))")
time curl -s -X POST "$TARGET" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "$MANY_PARAMS" -o /dev/null 2>&1
echo ""

echo "=== Timing Analysis Complete ==="
echo ""
echo "Interpretation Guide:"
echo "  - Compare each test's time against the baseline"
echo "  - Large payload quickly processed  -> Size limits enforced (good)"
echo "  - Large payload causes timeout     -> No size limit (DoS vector)"
echo "  - Deep nesting causes slow/error   -> Recursive parsing (DoS risk)"
echo "  - Many array elements slow         -> Iteration limits missing"
echo "  - Consistent timing across all     -> Robust, hardened target"
echo "  - 413 Payload Too Large response   -> Server enforces size limits"
