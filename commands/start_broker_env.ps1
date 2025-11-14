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
# 1. Start Mosquitto Broker
# ----------------------
Write-Host "------------------------------------------------------------" -ForegroundColor Blue
Write-Host "[1] Starting Mosquitto Broker..." -ForegroundColor Green
Write-Host "------------------------------------------------------------" -ForegroundColor Blue

Start-Process "cmd.exe" -ArgumentList "/k mosquitto -c `"$MosqConf`" -v"
Start-Sleep -Seconds 3

# ----------------------
# Ensure PCAP directory exists
# ----------------------
if (-Not (Test-Path $PcapDir)) {
    Write-Host "Creating PCAP directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $PcapDir | Out-Null
}

# ----------------------
# 2. Start TShark capture
# ----------------------
Write-Host "------------------------------------------------------------" -ForegroundColor Blue
Write-Host "[2] Starting rotating packet capture (TShark)" -ForegroundColor Green
Write-Host "------------------------------------------------------------" -ForegroundColor Blue

$CaptureCmd = "tshark -i Wi-Fi -w `"$PcapDir\capture.pcap`" -b duration:5"
Start-Process "cmd.exe" -ArgumentList "/k $CaptureCmd"
Start-Sleep -Seconds 2

# ----------------------
# 3. Start Live IDS
# ----------------------
Write-Host "------------------------------------------------------------" -ForegroundColor Blue
Write-Host "[3] Starting Live IDS" -ForegroundColor Green
Write-Host "------------------------------------------------------------" -ForegroundColor Blue

$IdsCmd = "$PythonExe `"$Base\live_ids.py`" --pcap-dir `"$PcapDir`" --model `"$Model`" --meta `"$Meta`" --out-log `"$Base\ids_alerts.log`""
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

# ----------------------
# 5. Open PCAP directory
# ----------------------
# Write-Host "------------------------------------------------------------" -ForegroundColor Blue
# Write-Host "[5] Opening PCAP Directory" -ForegroundColor Green
# Write-Host "------------------------------------------------------------" -ForegroundColor Blue

# Start-Process $PcapDir

# ----------------------
# COMPLETE
# ----------------------
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  EVERYTHING STARTED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "  Broker + Packet Capture + IDS + Dashboard Running" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

Pause
