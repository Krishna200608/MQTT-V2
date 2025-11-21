# ============================================================
# MQTT IDS LAB - START CLIENT ENVIRONMENT (Publisher + Subscriber)
# ============================================================

Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "              MQTT IDS LAB - CLIENT ENVIRONMENT             " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Magenta

# ---------------------- Load Config --------------------------
$ScriptRoot  = $PSScriptRoot
$ProjectRoot = Split-Path $ScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "configs/network_config.json"

if (!(Test-Path $ConfigPath)) {
    Write-Host "ERROR: network_config.json not found at $ConfigPath" -ForegroundColor Red
    Pause
    exit
}

$NetConfig = Get-Content $ConfigPath | ConvertFrom-Json
$BrokerIP  = $NetConfig.broker_ip

Write-Host ""
Write-Host "Broker IP Loaded: $BrokerIP" -ForegroundColor Yellow

# ---------------------- Paths -------------------------------
$PythonExe     = "python"
$Publisher     = Join-Path $ScriptRoot "run_publisher.ps1"
$Subscriber    = Join-Path $ScriptRoot "run_subscriber.ps1"

if (!(Test-Path $Publisher)) {
    Write-Host "ERROR: run_publisher.ps1 missing!" -ForegroundColor Red
    Pause
    exit
}
if (!(Test-Path $Subscriber)) {
    Write-Host "ERROR: run_subscriber.ps1 missing!" -ForegroundColor Red
    Pause
    exit
}

# ---------------------- Start Publisher ----------------------
Write-Host "`n[1] Starting MQTT Publisher..." -ForegroundColor Green
Start-Process powershell.exe -ArgumentList "-NoExit", "-ExecutionPolicy Bypass", "-File `"$Publisher`""
Start-Sleep -Milliseconds 500

# ---------------------- Start Subscriber ---------------------
Write-Host "`n[2] Starting MQTT Subscriber..." -ForegroundColor Green
Start-Process powershell.exe -ArgumentList "-NoExit", "-ExecutionPolicy Bypass", "-File `"$Subscriber`""
Start-Sleep -Milliseconds 500

# ---------------------- Info Message -------------------------
Write-Host "`n============================================================"
Write-Host " CLIENT ENVIRONMENT STARTED SUCCESSFULLY!"
Write-Host "------------------------------------------------------------"
Write-Host " - Publisher is sending IoT sensor messages"
Write-Host " - Subscriber is logging MQTT topics to timestamped CSV"
Write-Host " - Both terminals opened separately"
Write-Host "============================================================"

Write-Host "`nPress ENTER to exit this script (clients will keep running)..."
Pause
