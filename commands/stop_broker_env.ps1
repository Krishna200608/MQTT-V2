# ============================================================
# MQTT IDS LAB - STOP BROKER ENVIRONMENT
# ============================================================

Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "        MQTT IDS LAB - STOP BROKER ENVIRONMENT              " -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

Write-Host "Searching for running IDS, Dashboard, Packet Capture, Broker..." -ForegroundColor Yellow
Write-Host ""

# ------------------------------------------------------------
# 1. Stop TShark
# ------------------------------------------------------------
Write-Host "Stopping TShark processes..." -ForegroundColor Blue
$procs = Get-Process -Name "tshark" -ErrorAction SilentlyContinue
if ($procs) {
    $procs | Stop-Process -Force
}

# ------------------------------------------------------------
# 2. Stop live_ids.py and live_ids_dashboard.py
# ------------------------------------------------------------
Write-Host "Stopping live_ids.py and live_ids_dashboard.py..." -ForegroundColor Blue

$pythonProcs = Get-Process -Name "python", "python3" -ErrorAction SilentlyContinue

foreach ($p in $pythonProcs) {
    try {
        # Retrieve full command line
        $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)").CommandLine
        
        if ($cmd -match "live_ids.py") {
            Stop-Process -Id $p.Id -Force
            Write-Host "✓ Killed live_ids.py (PID $($p.Id))" -ForegroundColor Green
        }
        elseif ($cmd -match "live_ids_dashboard.py") {
            Stop-Process -Id $p.Id -Force
            Write-Host "✓ Killed live_ids_dashboard.py (PID $($p.Id))" -ForegroundColor Green
        }
    } catch {}
}

# ------------------------------------------------------------
# 3. Stop Mosquitto Broker
# ------------------------------------------------------------
Write-Host "Stopping Mosquitto broker..." -ForegroundColor Blue
$mosq = Get-Process -Name "mosquitto" -ErrorAction SilentlyContinue
if ($mosq) {
    $mosq | Stop-Process -Force
}

# ------------------------------------------------------------
# 4. Close CMD windows started by start script
#    Match: window title contains "MQTT IDS -"
# ------------------------------------------------------------
Write-Host "Closing CMD windows started by MQTT IDS environment..." -ForegroundColor Blue

$cmdProcs = Get-Process -Name "cmd" -ErrorAction SilentlyContinue
foreach ($p in $cmdProcs) {
    try {
        $title = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)").CommandLine
        if ($title -match "MQTT IDS -") {
            Stop-Process -Id $p.Id -Force
            Write-Host "✓ Closed CMD window (PID $($p.Id))" -ForegroundColor Green
        }
    } catch {}
}

# ------------------------------------------------------------
# DONE
# ------------------------------------------------------------
Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Green
Write-Host "   All IDS, Dashboard, Capture, and Broker Processes Stopped" -ForegroundColor Green
Write-Host "------------------------------------------------------------" -ForegroundColor Green
Write-Host ""

Pause
