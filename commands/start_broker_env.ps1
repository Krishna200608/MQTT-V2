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
Write-Host "`n[2] Selecting correct network interface..." -ForegroundColor Cyan
# Auto-detect NIC that carries attacker traffic
    # Write-Host "`n[2] Auto-detecting correct network interface..." -ForegroundColor Cyan

    # $AttackerIP = $Attacker

    # $Interfaces = @(tshark -D)

    # $DetectedNIC = $null

    # foreach ($line in $Interfaces) {
    #     if ($line -match '^\s*(\d+)\.\s+(.*)$') {
    #         $idx = $matches[1]
    #         $name = $matches[2]

    #         Write-Host ("Testing NIC {0}: {1}" -f $idx, $name) -ForegroundColor Yellow

    #         $out = tshark -i $idx -a duration:3 -f "host $AttackerIP" 2>&1

    #         if ($out -match "Captured [1-9]") {
    #             Write-Host ">>> MATCH FOUND: $idx ($name)" -ForegroundColor Green
    #             $DetectedNIC = $idx
    #             break
    #         }
    #     }
    # }

    # if ($DetectedNIC -eq $null) {
    #     Write-Host "ERROR: No NIC detected with attacker traffic!" -ForegroundColor Red
    #     pause
    #     exit
    # }

# $Interface = $DetectedNIC
$Interface = "Wi-Fi" || "4"
Write-Host "Using NIC index: $Interface" -ForegroundColor Green

# ---------------------- Tshark Filter ------------------------
$Filter = "tcp or udp or icmp"
Write-Host "`nFilter Applied: $Filter" -ForegroundColor Yellow

# ---------------------- Start Tshark -------------------------
Write-Host "`n[3] Starting rotating capture..." -ForegroundColor Green

$CaptureCmd = "tshark -i `"$Interface`" -b duration:30 -w `"$PcapDir\capture.pcap`" -f `"$Filter`""
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
