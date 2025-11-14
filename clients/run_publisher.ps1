# ============================================================
# MQTT CLIENT PUBLISHER - IOT SENSOR SIMULATOR
# ============================================================

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "        MQTT CLIENT PUBLISHER - SENSOR SIMULATOR           " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

# ----------------------------
# Load Config
# ----------------------------
$configPath = Join-Path $PSScriptRoot "broker_config.json"
$config = Get-Content $configPath | ConvertFrom-Json

$BROKER_IP = $config.broker_ip
$PY        = $config.python_exe

Write-Host "Using Broker: $BROKER_IP" -ForegroundColor Green
Write-Host "Starting Publisher..." -ForegroundColor Cyan

# ----------------------------
# Run publisher
# ----------------------------
& $PY "$PSScriptRoot\pi_publisher.py" --broker $BROKER_IP --rate 5

Write-Host "`nPublisher stopped." -ForegroundColor Yellow
Pause
