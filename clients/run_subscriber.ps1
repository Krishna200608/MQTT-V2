# ============================================================
# MQTT CLIENT SUBSCRIBER
# ============================================================

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "             MQTT CLIENT SUBSCRIBER STARTED                 " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

# ----------------------------
# Load Config
# ----------------------------
$configPath = Join-Path $PSScriptRoot "broker_config.json"
$config = Get-Content $configPath | ConvertFrom-Json

$BROKER_IP = $config.broker_ip
$PY        = $config.python_exe

Write-Host "Subscribing to sensors/# on broker $BROKER_IP..." -ForegroundColor Green

# ----------------------------
# Run subscriber
# ----------------------------
& $PY "$PSScriptRoot\pi_subscriber.py" --broker $BROKER_IP --topic "sensors/#" --out "$PSScriptRoot\iot_messages.csv"

Write-Host "`nSubscriber stopped." -ForegroundColor Yellow
Pause
