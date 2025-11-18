# ============================================================
# Nmap UDP Scan (Config-Based)
# ============================================================

# Get folder of this script (attacks/)
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
Write-Host "[SCAN] Running Nmap UDP Scan (-sU)..." -ForegroundColor Yellow

# ------------------------------------------------------------
# Execute scan
# ------------------------------------------------------------
nmap -sU --top-ports 50 $TARGET

Write-Host "`n[Done] UDP Scan completed." -ForegroundColor Green
