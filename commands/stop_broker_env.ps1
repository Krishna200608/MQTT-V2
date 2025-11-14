# ============================================================
# MQTT IDS LAB - STOP BROKER ENVIRONMENT
# ============================================================

Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "        MQTT IDS LAB - STOP BROKER ENVIRONMENT              " -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Magenta

# -----------------------------
# STOP TSHARK
# -----------------------------
Write-Host "Stopping TShark..." -ForegroundColor Cyan
Get-Process -Name "tshark" -ErrorAction SilentlyContinue | Stop-Process -Force

# -----------------------------
# STOP Python IDS Processes
# -----------------------------
Write-Host "Stopping live_ids.py & dashboard..." -ForegroundColor Cyan

$pythonProcs = Get-CimInstance Win32_Process | Where-Object { $_.Name -match "python" }

foreach ($p in $pythonProcs) {
    $cmd = $p.CommandLine
    if ($cmd -match "live_ids.py" -or $cmd -match "live_ids_dashboard.py") {
        Stop-Process -Id $p.ProcessId -Force
        Write-Host "✓ Killed $cmd" -ForegroundColor Green
    }
}

# -----------------------------
# STOP MOSQUITTO
# -----------------------------
Write-Host "Stopping Mosquitto..." -ForegroundColor Cyan
Get-Process -Name "mosquitto" -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "`nAll processes stopped successfully." -ForegroundColor Green
Pause
