# ============================================================
# MQTT IDS LAB - ATTACK LAUNCHER
# ============================================================

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "                MQTT IDS LAB - ATTACK LAUNCHER              " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

Write-Host " [1] Run all attacks once"
Write-Host " [2] Run attacks in a loop (25 cycles)"
Write-Host " [3] Exit"
Write-Host ""

$choice = Read-Host "Enter your choice"

switch ($choice) {

    "1" {
        Write-Host "`n============================================================" -ForegroundColor Yellow
        Write-Host "           Running ALL attacks ONCE" -ForegroundColor Green
        Write-Host "============================================================`n"
        & "$PSScriptRoot\run_all_attacks.ps1"
    }

    "2" {
        Write-Host "`n============================================================" -ForegroundColor Yellow
        Write-Host "         Running attack loop for 25 cycles" -ForegroundColor Green
        Write-Host "============================================================`n"

        $LOOP_COUNT = 25

        for ($i=1; $i -le $LOOP_COUNT; $i++) {

            Write-Host "------------------------------------------------------------" -ForegroundColor Blue
            Write-Host "[CYCLE $i/$LOOP_COUNT] Running full attack cycle..." -ForegroundColor Cyan
            Write-Host "Timestamp: $(Get-Date)" -ForegroundColor DarkGray
            Write-Host "------------------------------------------------------------`n"

            & "$PSScriptRoot\run_all_attacks.ps1"

            Write-Host "`n===== Completed Cycle $i =====`n" -ForegroundColor Green
            Start-Sleep -Seconds 5
        }

        Write-Host "============================================================" -ForegroundColor Green
        Write-Host "         All $LOOP_COUNT attack cycles completed!" -ForegroundColor Green
        Write-Host "============================================================"
    }

    "3" {
        Write-Host "Exiting Attack Launcher..." -ForegroundColor Yellow
        exit
    }

    default {
        Write-Host "Invalid choice." -ForegroundColor Red
    }
}

Pause
