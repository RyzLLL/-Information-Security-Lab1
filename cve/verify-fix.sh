#!/usr/bin/env bash
# Verify the fix for CVE-2021-29441 on the patched Nacos 1.4.1 image.
# Usage: ./verify-fix.sh [http://127.0.0.1:8848]
set -uo pipefail

TARGET="${1:-http://127.0.0.1:8848}"
UA="Nacos-Server"
USERS="/nacos/v1/auth/users?pageNo=1&pageSize=9"
failures=0
section() { printf '\n%s\n%s\n%s\n' "==============================================================================" "$1" "=============================================================================="; }
check() {
  if [ "$2" = "1" ]; then printf '[PASS] %s\n' "$1"; else printf '[FAIL] %s -- %s\n' "$1" "$3"; failures=$((failures + 1)); fi
}

section "1. Regression check: GET /nacos/"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$TARGET/nacos/")
[ "$code" = "200" ] && ok=1 || ok=0
check "console still returns 200" "$ok" "got HTTP $code"

section "2. Bypass must fail: GET with 'User-Agent: $UA'"
status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "User-Agent: $UA" "$TARGET$USERS")
body=$(curl -s --max-time 10 -H "User-Agent: $UA" "$TARGET$USERS")
echo "GET $USERS -> HTTP $status"
echo "$body"
[ "$status" = "403" ] && ok=1 || ok=0
check "returns 403 instead of 200" "$ok" "got HTTP $status"
echo "$body" | grep -q '"pageItems"' && ok=0 || ok=1
check "no user table in the body" "$ok" "user table was disclosed"

section "3. Creating an account must fail"
new_user="attacker$RANDOM"
created=$(curl -s --max-time 10 -X POST -H "User-Agent: $UA" \
  "$TARGET/nacos/v1/auth/users?username=$new_user&password=Passw0rd123")
echo "POST /nacos/v1/auth/users?username=$new_user -> $created"
echo "$created" | grep -q "create user ok" && ok=0 || ok=1
check "no 'create user ok'" "$ok" "account was created"

section "4. Authentication is still enabled"
plain=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$TARGET$USERS")
echo "GET $USERS (no credentials) -> HTTP $plain"
[ "$plain" = "403" ] && ok=1 || ok=0
check "anonymous access still refused" "$ok" "got HTTP $plain"

echo
if [ "$failures" -eq 0 ]; then
  echo "RESULT: fix verified -- all checks passed."
  exit 0
else
  echo "RESULT: $failures check(s) failed -- the fix is NOT effective."
  exit 1
fi
