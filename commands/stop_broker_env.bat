@echo off
:: Enable ANSI escape processing
for /f "tokens=2 delims==" %%i in ('"prompt $E$S & for %%i in (1) do rem"') do (
    set "ESC=%%i"
)

title MQTT IDS - Stop Broker Environment

echo %ESC%[95m============================================================%ESC%[0m
echo %ESC%[91m           MQTT IDS LAB - STOP BROKER ENVIRONMENT           %ESC%[0m
echo %ESC%[95m============================================================%ESC%[0m
echo.

echo %ESC%[93mSearching for running IDS, Dashboard, Packet Capture, Broker...%ESC%[0m
echo.

REM ------------------------------------------------------------
REM 1. Kill TShark
REM ------------------------------------------------------------
echo %ESC%[94mStopping TShark processes...%ESC%[0m
taskkill /IM tshark.exe /F >nul 2>&1

REM ------------------------------------------------------------
REM 2. Kill specific Python scripts (safe)
REM ------------------------------------------------------------
echo %ESC%[94mStopping live_ids.py and live_ids_dashboard.py...%ESC%[0m
for /f "tokens=2 delims=," %%p in ('tasklist /v /fo csv ^| findstr /i "live_ids.py"') do taskkill /PID %%p /F >nul 2>&1
for /f "tokens=2 delims=," %%p in ('tasklist /v /fo csv ^| findstr /i "live_ids_dashboard.py"') do taskkill /PID %%p /F >nul 2>&1

REM ------------------------------------------------------------
REM 3. Kill Mosquitto broker (from bat)
REM ------------------------------------------------------------
echo %ESC%[94mStopping Mosquitto broker...%ESC%[0m
taskkill /IM mosquitto.exe /F >nul 2>&1

REM ------------------------------------------------------------
REM 4. Close all CMD windows spawned by start_broker_env.bat
REM    Matches partial title: "MQTT IDS -"
REM ------------------------------------------------------------
echo %ESC%[94mClosing CMD windows started by broker environment...%ESC%[0m
for /f "tokens=2 delims=," %%p in ('tasklist /v /fo csv ^| findstr /i "MQTT IDS -"') do taskkill /PID %%p /F >nul 2>&1

echo.
echo %ESC%[92m------------------------------------------------------------%ESC%[0m
echo %ESC%[92m   All IDS, Dashboard, Capture, and Broker Processes Stopped   %ESC%[0m
echo %ESC%[92m------------------------------------------------------------%ESC%[0m
echo.

pause
