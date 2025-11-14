# ============================================================
# MQTT IDS LAB - CONTINUOUS ATTACK LOOP
# ============================================================

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "         MQTT IDS LAB - Continuous Attack Loop Runner        " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

# ----------------------------
# Load Config
# ----------------------------
$configPath = Join-Path $PSScriptRoot "broker_config.json"
$config = Get-Content $configPath | ConvertFrom-Json

$BROKER_IP = $config.broker_ip
$PY        = $config.python_exe

Write-Host "Broker Target: $BROKER_IP" -ForegroundColor Green
Write-Host "Attacks will run indefinitely (CTRL+C to stop)." -ForegroundColor Yellow
Write-Host "============================================================`n"

# ----------------------------
# LOOP FOREVER
# ----------------------------

while ($true) {

    Write-Host "------------------------------------------------------------" -ForegroundColor Blue
    Write-Host " [LOOP] Starting New Attack Cycle" -ForegroundColor Green
    Write-Host "------------------------------------------------------------`n" -ForegroundColor Blue

    # 1) Scan A
    Write-Host "[1/4] Aggressive Scan (Scan A)" -ForegroundColor Cyan
    Start-Sleep -Seconds 2
    & "$PSScriptRoot\scan_A.bat"
    Start-Sleep -Seconds 3

    # 2) Scan sU
    Write-Host "[2/4] UDP Scan (Scan sU)" -ForegroundColor Cyan
    Start-Sleep -Seconds 2
    & "$PSScriptRoot\scan_sU.bat"
    Start-Sleep -Seconds 3

    # 3) SSH brute force
    Write-Host "[3/4] SSH Brute Force Attack" -ForegroundColor Cyan
    Start-Sleep -Seconds 2
    & "$PSScriptRoot\ssh_bruteforce_nmap.bat"
    Start-Sleep -Seconds 3

    # 4) MQTT brute force
    Write-Host "[4/4] MQTT Brute Force Attack" -ForegroundColor Cyan
    Start-Sleep -Seconds 2
    & $PY "$PSScriptRoot\mqtt_bruteforce.py"
    Start-Sleep -Seconds 5

    Write-Host "------------------------------------------------------------" -ForegroundColor Blue
    Write-Host " [LOOP] Attack Cycle Finished — Restarting..." -ForegroundColor Green
    Write-Host " Press CTRL + C to stop." -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------`n"
}
