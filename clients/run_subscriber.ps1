$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "network_config.json"
$NetConfig = Get-Content $ConfigPath | ConvertFrom-Json

$BrokerIP = $NetConfig.broker_ip
$PythonExe = "python"

Write-Host "Subscriber connecting to broker at $BrokerIP" -ForegroundColor Cyan

& $PythonExe "$PSScriptRoot\pi_subscriber.py" --broker $BrokerIP --topic "sensors/#" --out "$PSScriptRoot\iot_messages.csv"

Pause
