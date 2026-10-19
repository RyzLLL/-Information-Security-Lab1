#requires -Version 5.1
<#
.SYNOPSIS
    End-to-end walkthrough of the Lab 1 secure API.

.DESCRIPTION
    Exercises every endpoint and every security control so the transcript can
    be used directly as report evidence:

      1.  health check
      2.  login  -> JWT
      3.  protected endpoint without a token        -> 401
      4.  protected endpoint with a forged token    -> 401
      5.  protected endpoint with the real token    -> 200
      6.  create a post (the "own" endpoint)        -> 201
      7.  SQL injection attempt on login            -> 401
      8.  SQL injection attempt in the search query -> 200, no rows
      9.  stored XSS attempt                        -> escaped on output

.EXAMPLE
    .\scripts\demo.ps1
    .\scripts\demo.ps1 -BaseUrl http://127.0.0.1:5000 -Username alice -Password 'Passw0rd!Alice'
#>
[CmdletBinding()]
param(
    [string]$BaseUrl  = "http://127.0.0.1:5000",
    [string]$Username = "alice",
    [string]$Password = "Passw0rd!Alice"
)

$ErrorActionPreference = "Stop"
$script:step = 0

function Invoke-Api {
    param(
        [string]$Method = "GET",
        [string]$Path,
        [string]$Body,
        [hashtable]$Headers
    )
    $params = @{
        Uri                = "$BaseUrl$Path"
        Method             = $Method
        UseBasicParsing    = $true
        TimeoutSec         = 15
    }
    if ($Body)    { $params.Body = $Body; $params.ContentType = "application/json" }
    if ($Headers) { $params.Headers = $Headers }
    try {
        $r = Invoke-WebRequest @params
        [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$r.Content }
    }
    catch {
        $resp = $_.Exception.Response
        if (-not $resp) { throw }
        $stream = $resp.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        [pscustomobject]@{ Status = [int]$resp.StatusCode; Body = $reader.ReadToEnd() }
    }
}

function Show-Result {
    param([string]$Title, $Result, [int[]]$Expect)
    $script:step++
    $ok = if ($Expect) { $Expect -contains $Result.Status } else { $true }
    $flag = if ($ok) { "PASS" } else { "FAIL" }
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host ("[{0}] {1}" -f $script:step, $Title) -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkGray
    if ($Result.Body) {
        try   { $Result.Body | ConvertFrom-Json | ConvertTo-Json -Depth 8 }
        catch { $Result.Body }
    }
    $color = if ($ok) { "Green" } else { "Red" }
    Write-Host ("--> HTTP {0}  [{1}]" -f $Result.Status, $flag) -ForegroundColor $color
    if (-not $ok) { throw "Unexpected status $($Result.Status) for '$Title'" }
}

Write-Host "Target: $BaseUrl"

# 1 -----------------------------------------------------------------------
Show-Result "1. Health check" (Invoke-Api -Path "/health") @(200)

# 2 -----------------------------------------------------------------------
$login = Invoke-Api -Method POST -Path "/auth/login" `
    -Body (@{ username = $Username; password = $Password } | ConvertTo-Json)
Show-Result "2. Login ($Username) -> JWT" $login @(200)
$token = ($login.Body | ConvertFrom-Json).access_token
if (-not $token) { throw "No access_token in the login response." }
$auth = @{ Authorization = "Bearer $token" }

# 3 -----------------------------------------------------------------------
Show-Result "3. GET /api/data without a token (must be denied)" `
    (Invoke-Api -Path "/api/data") @(401)

# 4 -----------------------------------------------------------------------
Show-Result "4. GET /api/data with a forged token (must be denied)" `
    (Invoke-Api -Path "/api/data" -Headers @{ Authorization = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.forged" }) @(401)

# 5 -----------------------------------------------------------------------
Show-Result "5. GET /api/data with a valid token" `
    (Invoke-Api -Path "/api/data?limit=2" -Headers $auth) @(200)

# 6 -----------------------------------------------------------------------
Show-Result "6. POST /api/posts (own endpoint, authenticated)" `
    (Invoke-Api -Method POST -Path "/api/posts" -Headers $auth `
        -Body (@{ title = "Demo post"; body = "Created by scripts/demo.ps1" } | ConvertTo-Json)) @(201)

# 7 -----------------------------------------------------------------------
Show-Result "7. SQL injection in the login form (must not bypass auth)" `
    (Invoke-Api -Method POST -Path "/auth/login" `
        -Body (@{ username = "alice' OR '1'='1"; password = "x' OR '1'='1" } | ConvertTo-Json)) @(401)

# 8 -----------------------------------------------------------------------
Show-Result "8. SQL injection in the search parameter (treated as literal text)" `
    (Invoke-Api -Path "/api/data?q=%27%20OR%201%3D1%20--" -Headers $auth) @(200)

# 9 -----------------------------------------------------------------------
$result = Invoke-Api -Method POST -Path "/api/posts" -Headers $auth `
    -Body (@{ title = "XSS demo"; body = "<script>alert('XSS')</script>" } | ConvertTo-Json)
Show-Result "9. Stored XSS payload -> escaped in the response" $result @(201)
if ($result.Body -match "<script>") { throw "XSS payload was reflected unescaped!" }

Write-Host ""
Write-Host "All steps finished. Take a screenshot of this transcript for the report." -ForegroundColor Green
