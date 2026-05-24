param(
    [switch]$Background,
    [switch]$DryRun
)

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdministrator) {
    Write-Warning "Packet sniffing usually requires PowerShell to be run as Administrator."
}

$pythonCommand = $null
if ($Background) {
    $pythonCommand = Get-Command pythonw -ErrorAction SilentlyContinue
}

if (-not $pythonCommand) {
    $pythonCommand = Get-Command python -ErrorAction Stop
}

$targetFile = Join-Path $projectRoot "monitor.py"

if ($DryRun) {
    if ($Background) {
        Write-Host "Would start: $($pythonCommand.Source) $targetFile in background"
    }
    else {
        Write-Host "Would run: $($pythonCommand.Source) $targetFile in foreground"
    }
    if (-not $isAdministrator) {
        Write-Host "Would warn: restart PowerShell as Administrator for packet capture."
    }
    return
}

if ($Background) {
    Start-Process -FilePath $pythonCommand.Source -ArgumentList $targetFile -WindowStyle Hidden
    Write-Host "Anomaly monitor started in background."
}
else {
    & $pythonCommand.Source $targetFile
}