# MQTT Publisher Script (Improved & Stable)

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
$Rate      = 5

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " MQTT Publisher Starting..." -ForegroundColor Yellow
Write-Host " Broker  : $BrokerIP" -ForegroundColor Cyan
Write-Host " Rate    : $Rate msgs/sec" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

Try {
    & $PythonExe "$PSScriptRoot\pi_publisher.py" --broker $BrokerIP --rate $Rate
}
Catch {
    Write-Host "Publisher crashed with error: $_" -ForegroundColor Red
}

Pause
