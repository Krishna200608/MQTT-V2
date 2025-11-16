# ============================================================
# MQTT IDS LAB - STOP BROKER ENVIRONMENT
# ============================================================

Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "            MQTT IDS LAB - STOP BROKER ENVIRONMENT          " -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Magenta

# -----------------------------
# FUNCTION: Kill a process safely
# -----------------------------
function Kill-Proc($name, $matchText = $null) {
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -ieq $name
    }

    foreach ($p in $procs) {
        if ($null -ne $matchText) {
            if ($p.CommandLine -notmatch $matchText) {
                continue
            }
        }
        try {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Host ("✓ Killed: {0}" -f ($p.CommandLine)) -ForegroundColor Green
        }
        catch {
            Write-Host ("✗ Failed to kill: {0}" -f ($p.CommandLine)) -ForegroundColor Red
        }
    }
}

# -----------------------------
# STOP TSHARK
# -----------------------------
Write-Host "`n[1] Stopping TShark..." -ForegroundColor Cyan
Kill-Proc "tshark.exe"
Kill-Proc "tshark"

# -----------------------------
# STOP Live IDS & Dashboard
# -----------------------------
Write-Host "`n[2] Stopping live_ids.py and dashboard..." -ForegroundColor Cyan

Kill-Proc "python.exe" "live_ids.py"
Kill-Proc "python" "live_ids.py"

Kill-Proc "python.exe" "live_ids_dashboard.py"
Kill-Proc "python" "live_ids_dashboard.py"

# -----------------------------
# STOP MOSQUITTO BROKER
# -----------------------------
Write-Host "`n[3] Stopping Mosquitto Broker..." -ForegroundColor Cyan
Kill-Proc "mosquitto.exe"
Kill-Proc "mosquitto"

# -----------------------------
# FINISH
# -----------------------------
Write-Host "`n============================================================"
Write-Host "   ALL PROCESSES STOPPED CLEANLY AND SAFELY"
Write-Host "============================================================" -ForegroundColor Green

Pause
