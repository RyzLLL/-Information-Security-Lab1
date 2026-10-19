#requires -Version 5.1
<#
.SYNOPSIS
    Verifies the fix for CVE-2021-29441 on the patched Nacos 1.4.1 image.

.DESCRIPTION
    Runs exactly the same requests as exploit.ps1 and asserts that
      * the spoofed User-Agent no longer returns the user table,
      * it can no longer create an account,
      * authentication is still ON (the fix must not be "turn auth off"),
      * the console still answers (regression).
#>
[CmdletBinding()]
param([string]$Target = "http://127.0.0.1:8848")

$ErrorActionPreference = "Stop"
$curl = "curl.exe"
$ua = "Nacos-Server"
$usersPath = "/nacos/v1/auth/users?pageNo=1&pageSize=9"
$failures = 0

function Section([string]$text) {
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host $text -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkGray
}

function Check([string]$name, [bool]$ok, [string]$detail) {
    if ($ok) { Write-Host ("[PASS] {0}" -f $name) -ForegroundColor Green }
    else {
        Write-Host ("[FAIL] {0} -- {1}" -f $name, $detail) -ForegroundColor Red
        $script:failures++
    }
}

# --- 1. regression: the console is still there ------------------------------
Section "1. Regression check: GET /nacos/"
$code = & $curl -s -o NUL -w "%{http_code}" --max-time 10 "$Target/nacos/"
Check "console still returns 200" ($code -eq "200") "got HTTP $code"

# --- 2. the spoofed header must no longer work ------------------------------
Section "2. Bypass must fail: GET with 'User-Agent: Nacos-Server'"
$leakStatus = & $curl -s -o NUL -w "%{http_code}" --max-time 10 -H "User-Agent: $ua" "$Target$usersPath"
$leakBody = & $curl -s --max-time 10 -H "User-Agent: $ua" "$Target$usersPath"
Write-Host "GET $usersPath -> HTTP $leakStatus"
Write-Host $leakBody
Check "returns 403 instead of 200" ($leakStatus -eq "403") "got HTTP $leakStatus"
Check "no user table in the body" (-not ($leakBody -match '"pageItems"')) "user table was disclosed"

# --- 3. no account creation -------------------------------------------------
Section "3. Creating an account must fail"
$newUser = "attacker$(Get-Random -Maximum 999)"
$created = & $curl -s --max-time 10 -X POST -H "User-Agent: $ua" `
    "$Target/nacos/v1/auth/users?username=$newUser&password=Passw0rd123"
Write-Host "POST /nacos/v1/auth/users?username=$newUser -> $created"
Check "no 'create user ok'" (-not ($created -match "create user ok")) "account was created"

# --- 4. the fix must not be "authentication switched off" -------------------
Section "4. Authentication is still enabled"
$plainStatus = & $curl -s -o NUL -w "%{http_code}" --max-time 10 "$Target$usersPath"
Write-Host "GET $usersPath (no credentials) -> HTTP $plainStatus"
Check "anonymous access still refused" ($plainStatus -eq "403") "got HTTP $plainStatus"

Write-Host ""
if ($failures -eq 0) {
    Write-Host "RESULT: fix verified -- all checks passed." -ForegroundColor Green
    exit 0
}
else {
    Write-Host "RESULT: $failures check(s) failed -- the fix is NOT effective." -ForegroundColor Red
    exit 1
}
