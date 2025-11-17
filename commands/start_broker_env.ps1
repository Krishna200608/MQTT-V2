# ============================================================
# MQTT IDS LAB - START BROKER + LIVE IDS + PACKET CAPTURE
# ============================================================

Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "      MQTT IDS LAB - START BROKER + LIVE IDS + CAPTURE      " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Magenta

# ---------------------- Load Config --------------------------
$ScriptRoot  = $PSScriptRoot
$ProjectRoot = Split-Path $ScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "configs/network_config.json"

if (!(Test-Path $ConfigPath)) {
    Write-Host "ERROR: network_config.json not found at $ConfigPath" -ForegroundColor Red
    exit
}

$NetConfig = Get-Content $ConfigPath | ConvertFrom-Json

$BrokerIP = $NetConfig.broker_ip
$Client1  = $NetConfig.client1_ip
$Client2  = $NetConfig.client2_ip
$Attacker = $NetConfig.attacker_ip

Write-Host "Broker   : $BrokerIP" -ForegroundColor Yellow
Write-Host "Client 1 : $Client1" -ForegroundColor Yellow
Write-Host "Client 2 : $Client2" -ForegroundColor Yellow
Write-Host "Attacker : $Attacker" -ForegroundColor Yellow

# ---------------------- Directories --------------------------
$Base       = $ProjectRoot
$PcapDir    = Join-Path $Base "pcap_files"
$PythonExe  = "python"
$MosqConf   = "C:\mosquitto_data\mosquitto.conf"

# Correct paths for scripts
$LiveIDS    = Join-Path $Base "live_scripts/live_ids.py"
$Dashboard  = Join-Path $Base "live_scripts/live_ids_dashboard.py"
$ModelsConfig = Join-Path $Base "configs/models_config.json"

# ---------------------- Cleanup ------------------------------
Write-Host "`n[CLEANUP] Clearing PCAP directory..." -ForegroundColor Cyan
if (Test-Path $PcapDir) {
    Get-ChildItem $PcapDir -File | Remove-Item -Force
} else {
    New-Item -ItemType Directory -Path $PcapDir | Out-Null
}
Write-Host "[OK] pcap_files is clean." -ForegroundColor Green
Start-Sleep -Milliseconds 500

# ---------------------- Start Broker -------------------------
Write-Host "`n[1] Starting Mosquitto Broker..." -ForegroundColor Green
Start-Process "cmd.exe" -ArgumentList "/k mosquitto -c `"$MosqConf`" -v"
Start-Sleep -Seconds 2

# ---------------------- Network Interface --------------------
# Write-Host "`n[2] Selecting correct network interface..." -ForegroundColor Cyan

# # Attempt to auto-detect NIC that carries attacker traffic via tshark -D and short capture probe
# $DetectedNIC = $null
# try {
#     $Interfaces = & tshark -D 2>&1
#     foreach ($line in $Interfaces) {
#         if ($line -match '^\s*(\d+)\.\s+(.*)$') {
#             $idx = $matches[1]
#             $name = $matches[2]
#             Write-Host ("Testing NIC {0}: {1}" -f $idx, $name) -ForegroundColor Yellow
#             # Probe capture for 2 seconds to see if attacker IP appears
#             $probe = & tshark -i $idx -a duration:2 -f ("host {0}" -f $Attacker) 2>&1
#             if ($probe -match "Captured [1-9]") {
#                 Write-Host ">>> MATCH FOUND: $idx ($name)" -ForegroundColor Green
#                 $DetectedNIC = $idx
#                 break
#             }
#         }
#     }
# } catch {
#     Write-Host "[WARN] Could not enumerate interfaces via tshark -D. Falling back to configured Interface." -ForegroundColor Yellow
# }

# if ($DetectedNIC -ne $null) {
#     $Interface = $DetectedNIC
#     Write-Host "Using detected NIC index: $Interface" -ForegroundColor Green
# } else {
#     # Fallback: allow user to use friendly name or default "Wi-Fi"
#     if (-not $Interface) {
#         $Interface = "Wi-Fi"
#     }
#     Write-Host "Using NIC: $Interface (auto-detection failed or not available)" -ForegroundColor Yellow
# }
$Interface = "Wi-Fi"
# ---------------------- Tshark Filter ------------------------
# Strict capture filter: only traffic involving broker or attacker + basic protocols
# $Filter = "host $BrokerIP and host $Attacker and (tcp or udp or icmp)"
$Filter = "host $BrokerIP and host $Attacker and (tcp or udp) and (port 1883 or port 22)"
Write-Host "`nFilter Applied: $Filter" -ForegroundColor Yellow

# ---------------------- Start Tshark -------------------------
Write-Host "`n[3] Starting rotating capture..." -ForegroundColor Green

# rotate every 5 seconds, write to rotating capture.pcap files inside pcap_files
$CaptureCmd = "tshark -i `"$Interface`" -b duration:10 -w `"$PcapDir\capture.pcap`" -f `"$Filter`""
Start-Process "cmd.exe" -ArgumentList "/k $CaptureCmd"
Start-Sleep -Seconds 1


# ---------------------- Start Live IDS -----------------------
Write-Host "`n[4] Starting Live IDS..." -ForegroundColor Green

$IdsCmd = "$PythonExe `"$LiveIDS`" --pcap-dir `"$PcapDir`" --models-config `"$ModelsConfig`" --broker-ip $BrokerIP"
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
