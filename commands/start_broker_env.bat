@echo off
:: Enable ANSI escape processing
for /f "tokens=2 delims==" %%i in ('"prompt $E$S & for %%i in (1) do rem"') do (
    set "ESC=%%i"
)

title MQTT IDS - Broker Environment Starter

echo %ESC%[95m============================================================%ESC%[0m
echo %ESC%[96m       MQTT IDS LAB - START BROKER + LIVE IDS + CAPTURE      %ESC%[0m
echo %ESC%[95m============================================================%ESC%[0m
echo.

REM --- BASE PROJECT DIRECTORY (parent of /commands) ---
pushd "%~dp0.." >nul
pushd ".." >nul
set BASE=%CD%
popd >nul
popd >nul

REM --- PATHS ---
set PCAP_DIR=%BASE%\data\pcap_files
set MODEL=%BASE%\model_outputs\biflow\random_forest\random_forest\model_rf.joblib
set META=%BASE%\model_outputs\biflow\random_forest\train_metadata.json
set DASH=%BASE%\live_ids_dashboard.py
set PY=python
set MOSQ_CONF=C:\mosquitto_data\mosquitto.conf

echo %ESC%[93mProject Base:%ESC%[0m %BASE%
echo %ESC%[93mPCAP DIR:%ESC%[0m    %PCAP_DIR%
echo %ESC%[93mMODEL:%ESC%[0m       %MODEL%
echo %ESC%[93mDASHBOARD:%ESC%[0m   %DASH%
echo.

echo %ESC%[94m------------------------------------------------------------%ESC%[0m
echo %ESC%[92m[1] Starting Mosquitto Broker...%ESC%[0m
echo %ESC%[94m------------------------------------------------------------%ESC%[0m
start cmd /k "mosquitto -c \"%MOSQ_CONF%\" -v"
timeout /t 3 >nul

if not exist "%PCAP_DIR%" (
    echo %ESC%[93mCreating PCAP directory...%ESC%[0m
    mkdir "%PCAP_DIR%"
)

echo %ESC%[94m------------------------------------------------------------%ESC%[0m
echo %ESC%[92m[2] Starting rotating packet capture (TShark)%ESC%[0m
echo %ESC%[94m------------------------------------------------------------%ESC%[0m
start cmd /k "tshark -i Wi-Fi -w \"%PCAP_DIR%\capture.pcap\" -b duration:5"
timeout /t 2 >nul

echo %ESC%[94m------------------------------------------------------------%ESC%[0m
echo %ESC%[92m[3] Starting Live IDS%ESC%[0m
echo %ESC%[94m------------------------------------------------------------%ESC%[0m
start cmd /k "%PY% \"%BASE%\live_ids.py\" --pcap-dir \"%PCAP_DIR%\" --model \"%MODEL%\" --meta \"%META%\" --out-log \"%BASE%\ids_alerts.log\""
timeout /t 2 >nul

echo %ESC%[94m------------------------------------------------------------%ESC%[0m
echo %ESC%[92m[4] Starting Live IDS Dashboard%ESC%[0m
echo %ESC%[94m------------------------------------------------------------%ESC%[0m
start cmd /k "%PY% \"%DASH%\""
timeout /t 2 >nul

echo %ESC%[94m------------------------------------------------------------%ESC%[0m
echo %ESC%[92m[5] Opening PCAP Directory%ESC%[0m
echo %ESC%[94m------------------------------------------------------------%ESC%[0m
start "" "%PCAP_DIR%"

echo %ESC%[92m============================================================%ESC%[0m
echo %ESC%[92m  EVERYTHING STARTED SUCCESSFULLY!%ESC%[0m
echo %ESC%[92m  Broker + Packet Capture + IDS + Dashboard Running%ESC%[0m
echo %ESC%[92m============================================================%ESC%[0m

pause
