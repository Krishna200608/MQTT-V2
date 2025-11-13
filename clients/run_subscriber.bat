@echo off
title MQTT Client Subscriber
echo ================================================
echo        MQTT Client Subscriber Started
echo ================================================

set BASE=%~dp0
set PY=python

echo Subscribing to sensors/# on broker 192.168.0.100...

%PY% "%BASE%pi_subscriber.py" --broker 192.168.0.102 --topic sensors/# --out iot_messages.csv

pause
