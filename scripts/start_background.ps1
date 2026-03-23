$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

# Starts the monitor without opening a new console window.
Start-Process -FilePath pythonw -ArgumentList "monitor.py" -WindowStyle Hidden
Write-Host "Anomaly monitor started in background."
