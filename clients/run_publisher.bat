@echo off
title MQTT Client Publisher
echo ================================================
echo   MQTT Client Publisher - IoT Sensor Simulator
echo ================================================

set BASE=%~dp0
set PY=python

echo Using Client Folder: %BASE%
echo Starting publisher...

%PY% "%BASE%pi_publisher.py" --broker 192.168.0.102 --rate 5

pause
