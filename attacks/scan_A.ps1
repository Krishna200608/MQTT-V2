# ============================================================
# Nmap Aggressive Scan (Config-Based)
# ============================================================

# Folder of this script
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
# Project root
$ProjectRoot = Split-Path $ScriptDir -Parent

# ------------------------------------------------------------
# Load network_config.json
# ------------------------------------------------------------
$ConfigPath = Join-Path $ProjectRoot "configs/network_config.json"
$NetConfig = Get-Content $ConfigPath | ConvertFrom-Json

$TARGET = $NetConfig.broker_ip

Write-Host "[INFO] Target IP from config: $TARGET" -ForegroundColor Cyan
Write-Host "[SCAN] Running Nmap Aggressive Scan (-A)..." -ForegroundColor Yellow

# ------------------------------------------------------------
# Execute scan
# ------------------------------------------------------------
# nmap -A $TARGET
nmap -sS -p 1-65535 --max-rate 500 $TARGET

Write-Host "`n[Done] Aggressive Scan completed." -ForegroundColor Green
