#requires -Version 5.1
<#
.SYNOPSIS
    Run a command in a fresh console window and screenshot that window.

.DESCRIPTION
    Opens a titled console, runs the command, resizes the window so a full
    transcript fits, captures it from the desktop, saves a PNG and closes the
    console again.

    On Windows 11 console apps open inside Windows Terminal, so the window
    belongs to that process -- it is located by its title.

.EXAMPLE
    .\capture.ps1 -Command "powershell -File ..\scripts\demo.ps1" -Out shot.png -Settle 22
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Command,
    [Parameter(Mandatory = $true)][string]$Out,
    [int]$Settle = 20,
    [string]$Title = ""
)

$ErrorActionPreference = "Stop"
if (-not $Title) { $Title = "lab1-" + [guid]::NewGuid().ToString("N").Substring(0, 8) }

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
"@

$wrapped = "mode con: cols=96 lines=55 >`$null; `$host.UI.RawUI.WindowTitle='$Title'; $Command"
$proc = Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoExit", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $wrapped `
    -PassThru

$hwnd = [IntPtr]::Zero
for ($i = 0; $i -lt 24 -and $hwnd -eq [IntPtr]::Zero; $i++) {
    Start-Sleep -Milliseconds 500
    $win = Get-Process | Where-Object { $_.MainWindowTitle -eq $Title } | Select-Object -First 1
    if ($win) { $hwnd = $win.MainWindowHandle }
}
if ($hwnd -eq [IntPtr]::Zero) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    throw "Could not find the console window titled '$Title'."
}

# big enough for a whole transcript
[void][Win32]::SetWindowPos($hwnd, [IntPtr]::Zero, 8, 8, 1180, 1020, 0x0040)
[void][Win32]::ShowWindow($hwnd, 9)
[void][Win32]::SetForegroundWindow($hwnd)

Write-Host "running for $Settle s ..."
Start-Sleep -Seconds $Settle
[void][Win32]::SetForegroundWindow($hwnd)
Start-Sleep -Milliseconds 700

$rect = New-Object Win32+RECT
[void][Win32]::GetWindowRect($hwnd, [ref]$rect)
$width = $rect.Right - $rect.Left
$height = $rect.Bottom - $rect.Top
Write-Host "capturing ${width}x${height} at $($rect.Left),$($rect.Top)"

$bmp = New-Object System.Drawing.Bitmap $width, $height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bmp.Size)
$dir = Split-Path -Parent $Out
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()

Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Write-Host "saved $Out ($((Get-Item $Out).Length) bytes)"
