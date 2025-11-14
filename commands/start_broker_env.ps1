# ----------------------
# LOAD NETWORK CONFIG
# ----------------------
$ConfigPath = Join-Path $PSScriptRoot "network_config.json"
$NetConfig  = Get-Content $ConfigPath | ConvertFrom-Json

$BrokerIP = $NetConfig.broker_ip
$Client1  = $NetConfig.client1_ip
$Client2  = $NetConfig.client2_ip
$Router   = $NetConfig.router_ip

Write-Host "Broker IP: $BrokerIP" -ForegroundColor Yellow
Write-Host "Client 1:  $Client1" -ForegroundColor Yellow
Write-Host "Client 2:  $Client2" -ForegroundColor Yellow
Write-Host "Router:    $Router" -ForegroundColor Yellow

# ============================================================
# MQTT IDS LAB - BROKER + PCAP CAPTURE + LIVE IDS + DASHBOARD
# ============================================================

Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "      MQTT IDS LAB - START BROKER + LIVE IDS + CAPTURE      " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

# ----------------------
# BASE PROJECT DIRECTORY
# ----------------------
$Base = Split-Path $PSScriptRoot -Parent

# ----------------------
# PATHS
# ----------------------
$PcapDir    = Join-Path $Base "pcap_files"
$Model      = Join-Path $Base "model_outputs\biflow\random_forest\model_rf.joblib"
$Meta       = Join-Path $Base "model_outputs\biflow\random_forest\train_metadata.json"
$Dashboard  = Join-Path $Base "live_ids_dashboard.py"
$PythonExe  = "python"
$MosqConf   = "C:\mosquitto_data\mosquitto.conf"

Write-Host "Project Base: " $Base -ForegroundColor Yellow
Write-Host "PCAP DIR:    " $PcapDir -ForegroundColor Yellow
Write-Host "MODEL:       " $Model -ForegroundColor Yellow
Write-Host "DASHBOARD:   " $Dashboard -ForegroundColor Yellow
Write-Host ""

# ----------------------
# CLEAN PCAP DIRECTORY
# ----------------------
Write-Host "------------------------------------------------------------" -ForegroundColor Blue
Write-Host "[CLEANUP] Clearing old PCAP files..." -ForegroundColor Yellow
Write-Host "------------------------------------------------------------" -ForegroundColor Blue

if (Test-Path $PcapDir) {
    Get-ChildItem $PcapDir -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] PCAP directory cleaned." -ForegroundColor Green
} else {
    Write-Host "PCAP directory does not exist. Creating it now..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $PcapDir | Out-Null
}

Start-Sleep -Milliseconds 800

# ----------------------
# 1. Start Mosquitto Broker
# ----------------------
Write-Host "------------------------------------------------------------" -ForegroundColor Blue
Write-Host "[1] Starting Mosquitto Broker..." -ForegroundColor Green
Write-Host "------------------------------------------------------------" -ForegroundColor Blue

Start-Process "cmd.exe" -ArgumentList "/k mosquitto -c `"$MosqConf`" -v"
Start-Sleep -Seconds 3

# ----------------------
# 2. Start TShark capture (Filtered)
# ----------------------
Write-Host "------------------------------------------------------------" -ForegroundColor Blue
Write-Host "[2] Starting rotating packet capture (TShark, filtered)" -ForegroundColor Green
Write-Host "------------------------------------------------------------" -ForegroundColor Blue

$Filter = "(host $BrokerIP or host $Client1 or host $Client2) " +
          "and not host $Router " +
          "and not udp port 53 and not udp port 67 and not udp port 68 " +
          "and not udp port 137 and not udp port 138 " +
          "and not udp port 1900 and not udp port 5355 " +
          "and not arp and not icmp and not igmp"

$CaptureCmd = "tshark -i Wi-Fi -w `"$PcapDir\capture.pcap`" -b duration:5 -f `"$Filter`""
Start-Process "cmd.exe" -ArgumentList "/k $CaptureCmd"

Start-Sleep -Seconds 2

# ----------------------
# 3. Start Live IDS
# ----------------------
Write-Host "------------------------------------------------------------" -ForegroundColor Blue
Write-Host "[3] Starting Live IDS" -ForegroundColor Green
Write-Host "------------------------------------------------------------" -ForegroundColor Blue

$IdsCmd = "$PythonExe `"$Base\live_ids.py`" --pcap-dir `"$PcapDir`" --model `"$Model`" --meta `"$Meta`""
Start-Process "cmd.exe" -ArgumentList "/k $IdsCmd"
Start-Sleep -Seconds 2

# ----------------------
# 4. Start Dashboard
# ----------------------
Write-Host "------------------------------------------------------------" -ForegroundColor Blue
Write-Host "[4] Starting Live IDS Dashboard" -ForegroundColor Green
Write-Host "------------------------------------------------------------" -ForegroundColor Blue

$DashCmd = "$PythonExe `"$Dashboard`""
Start-Process "cmd.exe" -ArgumentList "/k $DashCmd"
Start-Sleep -Seconds 2

Write-Host "============================================================" -ForegroundColor Green
Write-Host "  EVERYTHING STARTED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "  Broker + Packet Capture + IDS + Dashboard Running" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

Pause
