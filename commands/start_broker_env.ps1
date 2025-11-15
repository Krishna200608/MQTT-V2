# ============================================================
# MQTT IDS LAB - START BROKER + LIVE IDS + PACKET CAPTURE
# ============================================================

Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "      MQTT IDS LAB - START BROKER + LIVE IDS + CAPTURE      " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Magenta

# ---------------------- Load Config --------------------------
$ScriptRoot = $PSScriptRoot
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "network_config.json"

if (!(Test-Path $ConfigPath)) {
    Write-Host "ERROR: network_config.json not found!" -ForegroundColor Red
    exit
}

$NetConfig = Get-Content $ConfigPath | ConvertFrom-Json

$BrokerIP = $NetConfig.broker_ip
$Client1  = $NetConfig.client1_ip
$Client2  = $NetConfig.client2_ip
$Attacker = $NetConfig.attacker_ip
$Router   = $NetConfig.router_ip

Write-Host "Broker   : $BrokerIP" -ForegroundColor Yellow
Write-Host "Client 1 : $Client1" -ForegroundColor Yellow
Write-Host "Client 2 : $Client2" -ForegroundColor Yellow
Write-Host "Attacker : $Attacker" -ForegroundColor Yellow

# ---------------------- Directories --------------------------
$Base      = Split-Path $ScriptRoot -Parent
$PcapDir   = Join-Path $Base "pcap_files"
$PythonExe = "python"
$MosqConf  = "C:\mosquitto_data\mosquitto.conf"
$Dashboard = Join-Path $Base "live_ids_dashboard.py"

# ---------------------- Cleanup ------------------------------
Write-Host "`n[CLEANUP] Clearing PCAP directory..." -ForegroundColor Cyan
if (Test-Path $PcapDir) {
    Get-ChildItem $PcapDir -File | Remove-Item -Force
} else {
    New-Item -ItemType Directory -Path $PcapDir | Out-Null
}
Write-Host "[OK] pcap_files is clean." -ForegroundColor Green

Start-Sleep -Milliseconds 600

# ---------------------- Start Broker -------------------------
Write-Host "`n[1] Starting Mosquitto Broker..." -ForegroundColor Green
Start-Process "cmd.exe" -ArgumentList "/k mosquitto -c `"$MosqConf`" -v"
Start-Sleep -Seconds 2

# ---------------------- Auto Interface Selection -------------
Write-Host "`n[2] Selecting correct network interface..." -ForegroundColor Cyan

if ($BrokerIP -eq "127.0.0.1") {
    # All services on one PC → Loopback
    $Interface = "Npcap Loopback Adapter"
    Write-Host "Mode: Single Laptop (Localhost)" -ForegroundColor Green
    Write-Host "Selected Interface: LOOPBACK" -ForegroundColor Green
} else {
    # Multi-laptop network → Wi-Fi
    $Interface = "Wi-Fi"
    Write-Host "Mode: Multi-Laptop (LAN)" -ForegroundColor Green
    Write-Host "Selected Interface: WIFI" -ForegroundColor Green
}

# ------------------- Filter (host only) ----------------------
# $Filter = "(host $BrokerIP or host $Client1 or host $Client2 or host $Attacker)"
$Filter = "(host 192.168.0.100 or host 192.168.0.101)"

Write-Host "`nUsing Filter: " -ForegroundColor Cyan
Write-Host $Filter -ForegroundColor Yellow

# ---------------------- Start Tshark -------------------------
Write-Host "`n[3] Starting rotating capture..." -ForegroundColor Green

$CaptureCmd = "tshark -i `"$Interface`" -b duration:5 -w `"$PcapDir\capture.pcap`" -f `"$Filter`""

Start-Process "cmd.exe" -ArgumentList "/k $CaptureCmd"
Start-Sleep -Seconds 1

# ---------------------- Start Live IDS -----------------------
Write-Host "`n[4] Starting Live IDS..." -ForegroundColor Green

$IdsCmd = "$PythonExe `"$Base\live_ids.py`" --pcap-dir `"$PcapDir`" --models-config `"$Base\models_config.json`" --broker-ip $BrokerIP --broker-only"
Start-Process "cmd.exe" -ArgumentList "/k $IdsCmd"
Start-Sleep -Seconds 1

# ---------------------- Start Dashboard ----------------------
Write-Host "`n[5] Starting Dashboard..." -ForegroundColor Green
$DashCmd = "$PythonExe `"$Dashboard`""
Start-Process "cmd.exe" -ArgumentList "/k $DashCmd"
Start-Sleep -Seconds 1

Write-Host "`n============================================================"
Write-Host " EVERYTHING STARTED SUCCESSFULLY!"
Write-Host "============================================================"

Pause
