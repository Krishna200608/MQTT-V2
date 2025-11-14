# MQTT Publisher Script (Network Config Based)

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "network_config.json"
$NetConfig = Get-Content $ConfigPath | ConvertFrom-Json

$BrokerIP = $NetConfig.broker_ip
$PythonExe = "python"

Write-Host "Publisher connecting to broker at $BrokerIP" -ForegroundColor Cyan

& $PythonExe "$PSScriptRoot\pi_publisher.py" --broker $BrokerIP --rate 5

Pause
