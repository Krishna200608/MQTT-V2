@echo off
title MQTT IDS - Stop Broker Environment
echo ============================================================
echo          MQTT IDS LAB - STOP ALL BROKER SERVICES
echo ============================================================
echo.

echo Searching for running IDS and TShark processes...
echo.

REM --- Kill TShark (packet capture) ---
echo Stopping TShark...
taskkill /IM tshark.exe /F >nul 2>&1

REM --- Kill Python (live_ids.py or dashboard) ---
echo Stopping Python processes...
taskkill /IM python.exe /F >nul 2>&1

REM --- Kill CMD windows spawned by start_broker_env.bat ---
echo Closing CMD windows started for capture & IDS...
taskkill /FI "WINDOWTITLE eq MQTT IDS - Broker Environment*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq Administrator: MQTT IDS - Broker Environment*" /F >nul 2>&1

echo.
echo ------------------------------------------------------------
echo     All IDS + Packet Capture Processes Have Been Stopped
echo ------------------------------------------------------------
echo.

pause
