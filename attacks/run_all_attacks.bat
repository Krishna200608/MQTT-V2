@echo off
title MQTT IDS - Run All Attacks
echo ================================================
echo   MQTT IDS LAB - Running All Attacks Sequentially
echo ================================================
echo.

REM === CONFIGURATION ===
set BROKER_IP=192.168.0.102
set PY=python

echo Broker Target: %BROKER_IP%
echo.

REM ================================================
REM 1) Aggressive TCP Scan (Scan A)
REM ================================================
echo [1/4] Starting Aggressive Scan (Scan A)...
timeout /t 3 >nul

call scan_A.bat

echo Scan A completed.
echo.
timeout /t 5 >nul


REM ================================================
REM 2) UDP Scan (Scan sU)
REM ================================================
echo [2/4] Starting UDP Scan (Scan sU)...
timeout /t 3 >nul

call scan_sU.bat

echo UDP Scan completed.
echo.
timeout /t 5 >nul


REM ================================================
REM 3) SSH Brute Force (Sparta-like via Nmap NSE)
REM ================================================
echo [3/4] Starting SSH Brute Force Attack...
timeout /t 3 >nul

call ssh_bruteforce_nmap.bat

echo SSH brute-force simulation completed.
echo.
timeout /t 5 >nul


REM ================================================
REM 4) MQTT Brute Force Attack
REM ================================================
echo [4/4] Starting MQTT Brute Force Attack...
timeout /t 3 >nul

%PY% mqtt_bruteforce.py

echo MQTT brute-force completed.
echo.
timeout /t 5 >nul


echo ================================================
echo      ALL ATTACKS EXECUTED SUCCESSFULLY
echo ================================================
echo.
pause
