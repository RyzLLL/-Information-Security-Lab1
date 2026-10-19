#requires -Version 5.1
<#
.SYNOPSIS
    Verifies the fix for CVE-2021-41773 on the patched Apache 2.4.51 image.

.DESCRIPTION
    Runs exactly the same requests as exploit.ps1 and asserts that
      * the traversal is answered with 404 (or 403) and no file content,
      * the CGI traversal does not execute a command,
      * the application itself still works (regression check).
#>
[CmdletBinding()]
param([string]$Target = "http://127.0.0.1:8080")

$ErrorActionPreference = "Stop"
$curl = "curl.exe"
$failures = 0

function Section([string]$text) {
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host $text -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkGray
}

function Check([string]$name, [bool]$ok, [string]$detail) {
    if ($ok) {
        Write-Host ("[PASS] {0}" -f $name) -ForegroundColor Green
    }
    else {
        Write-Host ("[FAIL] {0} -- {1}" -f $name, $detail) -ForegroundColor Red
        $script:failures++
    }
}

# --- 1. regression: the normal page still works -----------------------------
Section "1. Regression check: GET /"
$code = & $curl -s -o NUL -w "%{http_code}" "$Target/"
Check "home page still returns 200" ($code -eq "200") "got HTTP $code"

# --- 2. the traversal must be refused ---------------------------------------
Section "2. Path traversal must fail"
$traversal = "$Target/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
$status = & $curl -s -o NUL -w "%{http_code}" --path-as-is "$traversal"
$body = & $curl -s --path-as-is "$traversal"
Write-Host "curl --path-as-is `"$traversal`" -> HTTP $status"
Check "traversal answered with 404/403" ($status -in @("404", "403")) "got HTTP $status"
Check "no /etc/passwd content in the body" (-not ($body -match "root:[x*]?:0:0:")) "file was disclosed"

# --- 3. no command execution ------------------------------------------------
Section "3. CGI traversal must not execute anything"
$rceUrl = "$Target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
$rceStatus = & $curl -s -o NUL -w "%{http_code}" --path-as-is --data "echo;id" "$rceUrl"
$rce = & $curl -s --path-as-is --data "echo;id" "$rceUrl"
Write-Host "POST $rceUrl -> HTTP $rceStatus"
Check "no uid= in the response" (-not ($rce -match "uid=\d+")) "command was executed"

# --- 4. a few more traversal shapes (the 2.4.50 bypass family) --------------
Section "4. Extra traversal variants"
$variants = @(
    "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/hostname",
    "/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh",
    "/.%2e/.%2e/.%2e/.%2e/etc/passwd",
    "/icons/..%2f..%2f..%2f..%2fetc%2fpasswd"
)
foreach ($v in $variants) {
    $s = & $curl -s -o NUL -w "%{http_code}" --path-as-is "$Target$v"
    $b = & $curl -s --path-as-is "$Target$v"
    $leak = $b -match "root:[x*]?:0:0:"
    Write-Host ("  {0,-55} HTTP {1}{2}" -f $v, $s, $(if ($leak) { "  <-- LEAK" } else { "" }))
    Check ("no leak for " + $v) (-not $leak) "file content returned"
}

Write-Host ""
if ($failures -eq 0) {
    Write-Host "RESULT: fix verified -- all checks passed." -ForegroundColor Green
    exit 0
}
else {
    Write-Host "RESULT: $failures check(s) failed -- the fix is NOT effective." -ForegroundColor Red
    exit 1
}
