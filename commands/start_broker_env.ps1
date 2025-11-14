# ============================================================
# MQTT IDS LAB - START BROKER + IDS + PACKET CAPTURE
# ============================================================

Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "      MQTT IDS LAB - START BROKER + LIVE IDS + CAPTURE      " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Magenta

# ------------------------------------------------------------
# Load network_config.json (MUST BE IN ROOT)
# ------------------------------------------------------------
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
Write-Host "Router   : $Router" -ForegroundColor Yellow

# ------------------------------------------------------------
# Define project directories
# ------------------------------------------------------------
$Base      = Split-Path $ScriptRoot -Parent
$PcapDir   = Join-Path $Base "pcap_files"
$PythonExe = "python"
$MosqConf  = "C:\mosquitto_data\mosquitto.conf"
$Dashboard = Join-Path $Base "live_ids_dashboard.py"

# ------------------------------------------------------------
# CLEAN pcap_files directory
# ------------------------------------------------------------
Write-Host "`n[CLEANUP] Clearing PCAP directory..." -ForegroundColor Cyan
if (Test-Path $PcapDir) {
    Get-ChildItem $PcapDir -File -ErrorAction SilentlyContinue | Remove-Item -Force
} else {
    New-Item -ItemType Directory -Path $PcapDir | Out-Null
}
Write-Host "[OK] pcap_files is clean." -ForegroundColor Green

Start-Sleep -Milliseconds 700

# ------------------------------------------------------------
# START MOSQUITTO BROKER
# ------------------------------------------------------------
Write-Host "`n[1] Starting Mosquitto Broker..." -ForegroundColor Green
Start-Process "cmd.exe" -ArgumentList "/k mosquitto -c `"$MosqConf`" -v"
Start-Sleep -Seconds 2

# ------------------------------------------------------------
# Build VALID TSHARK CAPTURE FILTER (BPF SYNTAX)
# ------------------------------------------------------------
$Filter = "(host $BrokerIP or host $Client1 or host $Client2 or host $Attacker) " +
          "and not host $Router " +
          "and not udp port 53 and not udp port 67 and not udp port 68 " +
          "and not udp port 137 and not udp port 138 and not udp port 1900 and not udp port 5355 " +
          "and not arp and not icmp and not igmp"

Write-Host "`nUsing TShark Filter:" -ForegroundColor Cyan
Write-Host $Filter -ForegroundColor Yellow

# ------------------------------------------------------------
# START TSHARK
# ------------------------------------------------------------
Write-Host "`n[2] Starting TShark rotating capture..." -ForegroundColor Green

$CaptureCmd = "tshark -i Wi-Fi -b duration:5 -w `"$PcapDir\capture.pcap`" -f `"$Filter`""
Start-Process "cmd.exe" -ArgumentList "/k $CaptureCmd"

Start-Sleep -Seconds 1

# ------------------------------------------------------------
# START LIVE_IDS (MULTI-MODEL VERSION)
# ------------------------------------------------------------
Write-Host "`n[3] Starting Live IDS..." -ForegroundColor Green

$IdsCmd = "$PythonExe `"$Base\live_ids.py`" --pcap-dir `"$PcapDir`" --models-config `"$Base\models_config.json`" --broker-ip $BrokerIP --broker-only"
Start-Process "cmd.exe" -ArgumentList "/k $IdsCmd"

Start-Sleep -Seconds 1

# ------------------------------------------------------------
# START DASHBOARD
# ------------------------------------------------------------
Write-Host "`n[4] Starting Live IDS Dashboard..." -ForegroundColor Green
$DashCmd = "$PythonExe `"$Dashboard`""
Start-Process "cmd.exe" -ArgumentList "/k $DashCmd"

Start-Sleep -Seconds 1

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  EVERYTHING STARTED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

Pause
