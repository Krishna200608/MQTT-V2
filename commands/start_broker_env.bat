@echo off
title MQTT IDS - Broker Environment Starter
echo ============================================================
echo      MQTT IDS LAB - Start Broker + Live IDS + Capture
echo ============================================================

REM --- BASE PROJECT DIRECTORY (parent of /commands) ---
set BASE=%~dp0..
set BASE=%BASE:~0,-1%

REM --- PATHS ---
set PCAP_DIR=%BASE%\pcap_files
set MODEL=%BASE%\model_outputs\biflow\random_forest\random_forest\model_rf.joblib
set META=%BASE%\model_outputs\biflow\random_forest\train_metadata.json
set DASH=%BASE%\live_ids_dashboard.py
set PY=python

echo Project Base: %BASE%
echo PCAP DIR: %PCAP_DIR%
echo MODEL: %MODEL%
echo DASHBOARD: %DASH%

REM --- Create PCAP directory if missing ---
if not exist "%PCAP_DIR%" (
    echo Creating PCAP directory...
    mkdir "%PCAP_DIR%"
)

echo ------------------------------------------------------------
echo Starting rotating packet capture (TShark)
echo ------------------------------------------------------------
start cmd /k "tshark -i Wi-Fi -w \"%PCAP_DIR%\capture.pcap\" -b duration:5"

timeout /t 2 >nul

echo ------------------------------------------------------------
echo Starting Live IDS
echo ------------------------------------------------------------
start cmd /k "%PY% \"%BASE%\live_ids.py\" --pcap-dir \"%PCAP_DIR%\" --model \"%MODEL%\" --meta \"%META%\" --out-log \"%BASE%\ids_alerts.log\""

timeout /t 2 >nul

echo ------------------------------------------------------------
echo Starting Live IDS Dashboard
echo ------------------------------------------------------------
start cmd /k "%PY% \"%DASH%\""

timeout /t 2 >nul

echo ------------------------------------------------------------
echo Opening PCAP Directory
echo ------------------------------------------------------------
start "" "%PCAP_DIR%"

echo ------------------------------------------------------------
echo Everything Started Successfully!
echo Packet Capture + IDS + Dashboard Now Running
echo Close windows to stop processes.
echo ------------------------------------------------------------

pause
