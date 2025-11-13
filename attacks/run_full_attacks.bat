@echo off
title MQTT IDS - Attack Launcher
echo ============================================================
echo             MQTT IDS LAB - ATTACK LAUNCHER
echo ============================================================
echo.
echo This tool lets you choose how attacks should run:
echo.
echo   [1] Run all attacks once
echo   [2] Run attacks in a loop (25 cycles)
echo   [3] Exit
echo.
set /p choice="Enter your choice: "

if "%choice%"=="1" goto run_once
if "%choice%"=="2" goto run_loop
if "%choice%"=="3" goto exit_script

echo Invalid choice. Exiting...
goto exit_script


:run_once
echo.
echo ============================================================
echo            Running all attacks ONCE
echo ============================================================
echo.
call run_all_attacks.bat
goto exit_script


:run_loop
echo.
echo ============================================================
echo        Running attack loop for 25 cycles
echo ============================================================
echo.
set LOOP_COUNT=25

for /L %%i IN (1,1,%LOOP_COUNT%) DO (
    echo ------------------------------------------------------------
    echo [CYCLE %%i/%LOOP_COUNT%] Running full attack cycle...
    echo Timestamp: %date% %time%
    echo ------------------------------------------------------------
    echo.

    REM --- Run once ---
    call run_all_attacks.bat

    echo.
    echo ===== Completed Cycle %%i =====
    echo.
    timeout /t 5 >nul
)

echo ============================================================
echo          All 25 attack cycles completed!
echo ============================================================
goto exit_script


:exit_script
echo.
echo Exiting Attack Launcher...
echo.
pause
exit
