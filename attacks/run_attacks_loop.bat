@echo off
title MQTT IDS - Continuous Attack Loop
echo ============================================================
echo        MQTT IDS LAB - Continuous Attack Loop Runner
echo ============================================================
echo.

REM === CONFIG ===
set BROKER_IP=192.168.0.100
set PY=python

echo Broker Target: %BROKER_IP%
echo Attacks will run forever until you press CTRL + C
echo ============================================================
echo.

:attack_loop

echo ------------------------------------------------------------
echo   [LOOP] Starting New Attack Cycle
echo ------------------------------------------------------------
echo.

REM ================================================
REM 1) Aggressive TCP Scan (Scan A)
REM ================================================
echo [1/4] Aggressive Scan (Scan A)
timeout /t 2 >nul
call scan_A.bat
echo Completed Scan A
echo.
timeout /t 3 >nul


REM ================================================
REM 2) UDP Scan (Scan sU)
REM ================================================
echo [2/4] UDP Scan (Scan sU)
timeout /t 2 >nul
call scan_sU.bat
echo Completed Scan sU
echo.
timeout /t 3 >nul


REM ================================================
REM 3) SSH Brute Force (Sparta-like via Nmap)
REM ================================================
echo [3/4] SSH Brute Force Attack
timeout /t 2 >nul
call ssh_bruteforce_nmap.bat
echo Completed SSH brute force simulation
echo.
timeout /t 3 >nul


REM ================================================
REM 4) MQTT Brute Force Attack
REM ================================================
echo [4/4] MQTT Brute Force Attack
timeout /t 2 >nul
%PY% mqtt_bruteforce.py
echo Completed MQTT brute force
echo.
timeout /t 5 >nul

echo ------------------------------------------------------------
echo   [LOOP] Attack Cycle Finished — Restarting...
echo   Press CTRL + C to stop.
echo ------------------------------------------------------------
echo.

goto attack_loop
