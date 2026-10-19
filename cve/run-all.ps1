#requires -Version 5.1
<#
.SYNOPSIS
    One-command CVE-2021-41773 lab run: vulnerable -> exploit -> fixed -> verify.

.DESCRIPTION
    Runs the whole second half of the assignment and writes the transcripts to
    cve/evidence/, so the report can quote real output instead of a retyped
    summary.

      1. build + start the vulnerable 2.4.49 image
      2. exploit it (path traversal + RCE)                  -> evidence/vulnerable.txt
      3. tear it down
      4. build + start the patched 2.4.51 image (same config)
      5. replay the exploit and assert it fails             -> evidence/fixed.txt
      6. tear it down and print a summary

.PARAMETER Port
    Host port to publish (default 8080).

.PARAMETER KeepRunning
    Do not tear the containers down at the end (useful for taking screenshots).

.EXAMPLE
    .\run-all.ps1
    .\run-all.ps1 -Port 8081 -KeepRunning
#>
[CmdletBinding()]
param(
    [int]$Port = 8080,
    [switch]$KeepRunning
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$evidenceDir = Join-Path $here "evidence"
$target = "http://127.0.0.1:$Port"
$vulnCompose = Join-Path $here "docker-compose.yml"
$fixedCompose = Join-Path $here "docker-compose.fixed.yml"

function Step([string]$text) {
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host $text -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkGray
}

function Assert-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "docker is not installed or not on PATH. Install Docker Desktop and reopen the terminal."
    }
    & docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is installed but the daemon is not running. Start Docker Desktop and wait for 'Engine running'."
    }
}

function Wait-Http([string]$url, [int]$seconds = 90) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri "$url/" -UseBasicParsing -TimeoutSec 3
            if ($r.StatusCode -eq 200) { return $true }
        }
        catch { }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Compose([string]$file, [string[]]$arguments) {
    # -p keeps the two projects apart when they share a directory
    $project = if ($file -like "*fixed*") { "lab1-cve-fixed" } else { "lab1-cve-vulnerable" }
    & docker compose -p $project -f $file @arguments
    if ($LASTEXITCODE -ne 0) { throw "docker compose $($arguments -join ' ') failed (exit $LASTEXITCODE)" }
}

New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
$started = Get-Date

Assert-Docker
Write-Host "Docker OK, target $target" -ForegroundColor Gray

# ---------------------------------------------------------------------------
Step "1/5  Vulnerable Apache 2.4.49 -- build and start"
Compose $vulnCompose @("up", "-d", "--build")
if (-not (Wait-Http $target)) { throw "The container did not answer on $target within 90s." }
Write-Host "service is up" -ForegroundColor Green

# ---------------------------------------------------------------------------
Step "2/5  Exploit (path traversal + RCE)"
$exploitOut = Join-Path $evidenceDir "vulnerable.txt"
& (Join-Path $here "exploit.ps1") -Target $target *> $exploitOut
Get-Content $exploitOut
$vulnHit = (Get-Content $exploitOut -Raw) -match "VULNERABLE: /etc/passwd was disclosed"

# ---------------------------------------------------------------------------
Step "3/5  Stop the vulnerable build"
Compose $vulnCompose @("down", "-v")

# ---------------------------------------------------------------------------
Step "4/5  Patched Apache 2.4.51 -- build and start (same configuration)"
Compose $fixedCompose @("up", "-d", "--build")
if (-not (Wait-Http $target)) { throw "The patched container did not answer on $target within 90s." }
Write-Host "service is up" -ForegroundColor Green

# ---------------------------------------------------------------------------
Step "5/5  Replay the exploit and verify the fix"
$fixedOut = Join-Path $evidenceDir "fixed.txt"
& (Join-Path $here "verify-fix.ps1") -Target $target *> $fixedOut
$nativeExit = $LASTEXITCODE
Get-Content $fixedOut
# Read the verdict out of the transcript as well, so a wrapper that swallows
# the exit code cannot turn a failure into a pass.
$fixedText = Get-Content $fixedOut -Raw
$verifyOk = $fixedText -match "RESULT: fix verified"
Write-Host ("verify-fix.ps1 exit code: {0}" -f $nativeExit) -ForegroundColor DarkGray

if (-not $KeepRunning) {
    Compose $fixedCompose @("down", "-v")
}

# ---------------------------------------------------------------------------
Write-Host ""
Write-Host ("=" * 78) -ForegroundColor DarkGray
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 78) -ForegroundColor DarkGray
$elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds)
Write-Host ("  vulnerable build exploited : {0}" -f $(if ($vulnHit) { "YES (as expected)" } else { "NO -- investigate!" })) `
    -ForegroundColor $(if ($vulnHit) { "Yellow" } else { "Red" })
Write-Host ("  fixed build rejected attack: {0}" -f $(if ($verifyOk) { "YES (all checks passed)" } else { "NO -- see evidence/fixed.txt" })) `
    -ForegroundColor $(if ($verifyOk) { "Green" } else { "Red" })
Write-Host ("  elapsed                    : {0}s" -f $elapsed)
Write-Host ""
Write-Host "  evidence/vulnerable.txt  -- quote this in the report (section 4.2)"
Write-Host "  evidence/fixed.txt       -- quote this in the report (section 4.5)"
if ($KeepRunning) {
    Write-Host ""
    Write-Host "The fixed container is still running on $target (stop it with: docker compose -f `"$fixedCompose`" down -v)" -ForegroundColor Yellow
}

if ($vulnHit -and $verifyOk) {
    Write-Host ""
    Write-Host "RESULT: reproduce + fix verified." -ForegroundColor Green
    exit 0
}
exit 1
