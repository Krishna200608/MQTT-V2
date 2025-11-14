# ============================================================
# MQTT IDS LAB - RUN ALL ATTACKS SEQUENTIALLY
# ============================================================

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "     MQTT IDS LAB - Running All Attacks Sequentially        " -ForegroundColor Cyan
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
Write-Host ""

# ----------------------------
# 1) Aggressive Scan (Scan A)
# ----------------------------
Write-Host "[1/4] Starting Aggressive Scan (Scan A)..." -ForegroundColor Cyan
Start-Sleep -Seconds 3

& "$PSScriptRoot\scan_A.bat"

Write-Host "Scan A completed.`n" -ForegroundColor Green
Start-Sleep -Seconds 5

# ----------------------------
# 2) UDP Scan (Scan sU)
# ----------------------------
Write-Host "[2/4] Starting UDP Scan (Scan sU)..." -ForegroundColor Cyan
Start-Sleep -Seconds 3

& "$PSScriptRoot\scan_sU.bat"

Write-Host "UDP Scan completed.`n" -ForegroundColor Green
Start-Sleep -Seconds 5

# ----------------------------
# 3) SSH Brute Force (Sparta Simulation)
# ----------------------------
Write-Host "[3/4] Starting SSH Brute Force Attack..." -ForegroundColor Cyan
Start-Sleep -Seconds 3

& "$PSScriptRoot\ssh_bruteforce_nmap.bat"

Write-Host "SSH brute-force completed.`n" -ForegroundColor Green
Start-Sleep -Seconds 5

# ----------------------------
# 4) MQTT Brute Force Attack
# ----------------------------
Write-Host "[4/4] Starting MQTT Brute Force Attack..." -ForegroundColor Cyan
Start-Sleep -Seconds 3

& $PY "$PSScriptRoot\mqtt_bruteforce.py"

Write-Host "MQTT brute-force attack completed.`n" -ForegroundColor Green
Start-Sleep -Seconds 5


Write-Host "============================================================" -ForegroundColor Green
Write-Host "           ALL ATTACKS EXECUTED SUCCESSFULLY                " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

Pause
