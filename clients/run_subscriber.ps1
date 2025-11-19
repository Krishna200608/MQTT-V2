# MQTT Subscriber Script (Improved)

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "configs/network_config.json"

if (!(Test-Path $ConfigPath)) {
    Write-Host "ERROR: network_config.json not found!" -ForegroundColor Red
    Pause
    exit
}

$NetConfig = Get-Content $ConfigPath | ConvertFrom-Json
$BrokerIP  = $NetConfig.broker_ip
$PythonExe = "python"

# Timestamped output file (prevents overwrite)
$OutFile = Join-Path $PSScriptRoot ("iot_messages_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " MQTT Subscriber Starting..." -ForegroundColor Yellow
Write-Host " Broker : $BrokerIP" -ForegroundColor Cyan
Write-Host " Saving to : $OutFile" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

Try {
    & $PythonExe "$PSScriptRoot\pi_subscriber.py" --broker $BrokerIP --topic "sensors/#" --out "$OutFile"
}
Catch {
    Write-Host "Subscriber crashed with error: $_" -ForegroundColor Red
}

Pause
