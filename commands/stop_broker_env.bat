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

echo %ESC%[93mSearching for running IDS, Dashboard, and TShark...%ESC%[0m
echo.

REM -----------------------------------------------------------------
REM Kill TShark
REM -----------------------------------------------------------------
echo %ESC%[94mStopping TShark processes...%ESC%[0m
taskkill /IM tshark.exe /F >nul 2>&1

REM -----------------------------------------------------------------
REM Kill Python (live_ids.py, dashboard)
REM -----------------------------------------------------------------
echo %ESC%[94mStopping Python processes (IDS + Dashboard)...%ESC%[0m
taskkill /IM python.exe /F >nul 2>&1

REM -----------------------------------------------------------------
REM Kill CMD Windows started by start_broker_env.bat
REM -----------------------------------------------------------------
echo %ESC%[94mClosing CMD windows spawned by start_broker_env.bat...%ESC%[0m
taskkill /FI "WINDOWTITLE eq MQTT IDS - Broker Environment*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq Administrator: MQTT IDS - Broker Environment*" /F >nul 2>&1

echo.
echo %ESC%[92m------------------------------------------------------------%ESC%[0m
echo %ESC%[92m   All IDS + Dashboard + Packet Capture Processes Stopped!   %ESC%[0m
echo %ESC%[92m------------------------------------------------------------%ESC%[0m
echo.

pause
