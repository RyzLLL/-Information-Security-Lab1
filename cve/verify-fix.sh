#!/usr/bin/env bash
# Verify the fix for CVE-2021-41773 on the patched Apache 2.4.51 image.
# Usage: ./verify-fix.sh [http://127.0.0.1:8080]
set -uo pipefail

TARGET="${1:-http://127.0.0.1:8080}"
failures=0
section() { printf '\n%s\n%s\n%s\n' "==============================================================================" "$1" "=============================================================================="; }
check() { # name ok detail
  if [ "$2" = "1" ]; then printf '[PASS] %s\n' "$1"; else printf '[FAIL] %s -- %s\n' "$1" "$3"; failures=$((failures + 1)); fi
}

section "1. Regression check: GET /"
code=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET/")
[ "$code" = "200" ] && ok=1 || ok=0
check "home page still returns 200" "$ok" "got HTTP $code"

section "2. Path traversal must fail"
TRAVERSAL="$TARGET/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
status=$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "$TRAVERSAL")
body=$(curl -s --path-as-is "$TRAVERSAL")
echo "curl --path-as-is \"$TRAVERSAL\" -> HTTP $status"
# Apache 2.4.51 rejects the un-normalisable path with 400 during normalisation;
# a hardened configuration may answer 403 or 404 instead. What matters is that
# it is neither 200 nor a disclosure.
case "$status" in
  400|403|404) ok=1 ;;
  *) ok=0 ;;
esac
check "traversal rejected with 400/403/404" "$ok" "got HTTP $status"
echo "$body" | grep -qE 'root:[x*]?:0:0:' && ok=0 || ok=1
check "no /etc/passwd content in the body" "$ok" "file was disclosed"

section "3. CGI traversal must not execute anything"
RCE_URL="$TARGET/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
rce_status=$(curl -s -o /dev/null -w '%{http_code}' --path-as-is --data "echo;id" "$RCE_URL")
rce=$(curl -s --path-as-is --data "echo;id" "$RCE_URL")
echo "POST $RCE_URL -> HTTP $rce_status"
echo "$rce" | grep -qE 'uid=[0-9]+' && ok=0 || ok=1
check "no uid= in the response" "$ok" "command was executed"

section "4. Extra traversal variants"
for v in \
  "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/hostname" \
  "/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh" \
  "/.%2e/.%2e/.%2e/.%2e/etc/passwd" \
  "/icons/..%2f..%2f..%2f..%2fetc%2fpasswd" ; do
  s=$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "$TARGET$v")
  b=$(curl -s --path-as-is "$TARGET$v")
  if echo "$b" | grep -qE 'root:[x*]?:0:0:'; then leak="  <-- LEAK"; ok=0; else leak=""; ok=1; fi
  printf '  %-55s HTTP %s%s\n' "$v" "$s" "$leak"
  check "no leak for $v" "$ok" "file content returned"
done

echo
if [ "$failures" -eq 0 ]; then
  echo "RESULT: fix verified -- all checks passed."
  exit 0
else
  echo "RESULT: $failures check(s) failed -- the fix is NOT effective."
  exit 1
fi
